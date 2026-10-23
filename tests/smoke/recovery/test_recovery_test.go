package recovery_test

import (
	"context"
	"crypto/rand"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/primecloud/primecloud-agent/internal/backup"
	"github.com/primecloud/primecloud-agent/internal/recovery"
	"github.com/primecloud/primecloud-agent/internal/runtime"
)

type mockRecoveryRuntime struct {
	inspectFunc func(ctx context.Context, id string) (*runtime.ContainerInspect, error)
	execFunc    func(ctx context.Context, id string, cmd []string, env []string, stdin io.Reader) ([]byte, []byte, int, error)
}

func (m *mockRecoveryRuntime) PullImage(ctx context.Context, ref string) error { return nil }
func (m *mockRecoveryRuntime) PullImageWithAuth(ctx context.Context, ref, auth string) error {
	return nil
}
func (m *mockRecoveryRuntime) CreateContainer(ctx context.Context, cfg *runtime.ContainerConfig, l *runtime.ResourceLimits, p *runtime.HardenedIsolationProfile) (string, error) {
	return "mock-cid", nil
}
func (m *mockRecoveryRuntime) StartContainer(ctx context.Context, id string) error { return nil }
func (m *mockRecoveryRuntime) StopContainer(ctx context.Context, id string, timeout *int) error {
	return nil
}
func (m *mockRecoveryRuntime) RemoveContainer(ctx context.Context, id string, force bool) error {
	return nil
}
func (m *mockRecoveryRuntime) InspectContainer(ctx context.Context, id string) (*runtime.ContainerInspect, error) {
	if m.inspectFunc != nil {
		return m.inspectFunc(ctx, id)
	}
	return &runtime.ContainerInspect{ID: id, Running: true, Health: "healthy"}, nil
}
func (m *mockRecoveryRuntime) GetContainerLogs(ctx context.Context, containerID string) (io.ReadCloser, error) {
	return nil, nil
}
func (m *mockRecoveryRuntime) ListContainers(ctx context.Context, all bool) ([]runtime.ContainerSummary, error) {
	return nil, nil
}
func (m *mockRecoveryRuntime) ExecContainer(ctx context.Context, containerID string, cmd []string, env []string, stdin io.Reader) ([]byte, []byte, int, error) {
	if m.execFunc != nil {
		return m.execFunc(ctx, containerID, cmd, env, stdin)
	}
	return nil, nil, 0, nil
}
func (m *mockRecoveryRuntime) GetContainerStats(ctx context.Context, containerID string) (io.ReadCloser, error) {
	return nil, nil
}
func (m *mockRecoveryRuntime) Ping(ctx context.Context) error { return nil }
func (m *mockRecoveryRuntime) Close() error                   { return nil }

func TestRecovery_FullPipeline(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	tempDir := t.TempDir()
	sourceDir := filepath.Join(tempDir, "source")
	backupDir := filepath.Join(tempDir, "backup")
	restoreDir := filepath.Join(tempDir, "restore")
	_ = os.MkdirAll(sourceDir, 0700)
	_ = os.MkdirAll(backupDir, 0700)
	_ = os.MkdirAll(restoreDir, 0700)

	// 1. Create a simulated PostgreSQL dump artifact
	origDump := []byte("-- PrimeCloud PostgreSQL Backup\n-- ResourceID: res-pg-recov-1\nSELECT 1;\n")
	origFile := filepath.Join(sourceDir, "source.dump")
	if err := os.WriteFile(origFile, origDump, 0600); err != nil {
		t.Fatalf("Failed to write source file: %v", err)
	}

	// 2. Encryption key
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("Failed to generate random key: %v", err)
	}

	// 3. Package and Upload backup
	uploader := backup.NewUploader(nil)
	manifest, encFile, err := uploader.PackageAndUpload(ctx, "bk-recov-1", "res-pg-recov-1", "postgres", "node-1", origFile, key, backupDir)
	if err != nil {
		t.Fatalf("PackageAndUpload failed: %v", err)
	}

	manifestFile := filepath.Join(backupDir, "bk-recov-1.manifest.json")

	// 4. Reconstruct artifact
	reconstructor := recovery.NewReconstructor(nil, nil)
	restoredPath, restoredManifest, err := reconstructor.ReconstructArtifact(ctx, encFile, manifestFile, key, restoreDir)
	if err != nil {
		t.Fatalf("ReconstructArtifact failed: %v", err)
	}

	if restoredManifest.ResourceID != "res-pg-recov-1" {
		t.Errorf("ResourceID mismatch: got %s, want res-pg-recov-1", restoredManifest.ResourceID)
	}

	// 5. Verify integrity and format
	verifier := recovery.NewVerifier(nil)
	if err := verifier.VerifyIntegrity(manifest, restoredPath); err != nil {
		t.Fatalf("VerifyIntegrity failed: %v", err)
	}
	if err := verifier.VerifyFormat("postgres", restoredPath); err != nil {
		t.Fatalf("VerifyFormat failed: %v", err)
	}

	// 6. Test Restore to Workload driver
	// 6a. Fails closed with nil runtime
	if err := reconstructor.RestoreToWorkload(ctx, manifest, restoredPath); err == nil {
		t.Fatal("Expected RestoreToWorkload to fail closed when runtime is nil")
	}

	// 6b. Succeeds with mock runtime
	mockRT := &mockRecoveryRuntime{}
	reconstructorWithRT := recovery.NewReconstructor(mockRT, nil)
	if err := reconstructorWithRT.RestoreToWorkload(ctx, manifest, restoredPath); err != nil {
		t.Fatalf("RestoreToWorkload with mock runtime failed: %v", err)
	}

	// 7. Verify tamper detection on corrupt payload
	corruptEncFile := filepath.Join(backupDir, "corrupt.enc")
	_ = os.WriteFile(corruptEncFile, []byte("random corrupted invalid data"), 0600)
	if _, _, err := reconstructor.ReconstructArtifact(ctx, corruptEncFile, manifestFile, key, restoreDir); err == nil {
		t.Error("Expected error decrypting corrupt artifact")
	}

	// 8. Verify CHECKSUM_MISMATCH fail-closed on tampered manifest checksum
	tamperedManifest := &backup.Manifest{
		BackupID:       manifest.BackupID,
		ResourceID:     manifest.ResourceID,
		ResourceType:   manifest.ResourceType,
		Algorithm:      manifest.Algorithm,
		ChecksumSHA256: "0000000000000000000000000000000000000000000000000000000000000000",
	}
	tamperedManifestFile := filepath.Join(backupDir, "tampered.manifest.json")
	if err := backup.SaveManifest(tamperedManifest, tamperedManifestFile); err != nil {
		t.Fatalf("Failed to save tampered manifest: %v", err)
	}
	if _, _, err := reconstructor.ReconstructArtifact(ctx, encFile, tamperedManifestFile, key, restoreDir); err == nil || !strings.Contains(err.Error(), "CHECKSUM_MISMATCH") {
		t.Errorf("Expected CHECKSUM_MISMATCH error on manifest hash mismatch, got %v", err)
	}
}
