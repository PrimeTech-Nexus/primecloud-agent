package recovery_test

import (
	"context"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/primecloud/primecloud-agent/internal/backup"
	"github.com/primecloud/primecloud-agent/internal/recovery"
)

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

	// 6. Restore to Workload driver
	if err := reconstructor.RestoreToWorkload(ctx, manifest, restoredPath); err != nil {
		t.Fatalf("RestoreToWorkload failed: %v", err)
	}

	// 7. Verify tamper detection on corrupt payload
	corruptEncFile := filepath.Join(backupDir, "corrupt.enc")
	_ = os.WriteFile(corruptEncFile, []byte("random corrupted invalid data"), 0600)
	if _, _, err := reconstructor.ReconstructArtifact(ctx, corruptEncFile, manifestFile, key, restoreDir); err == nil {
		t.Error("Expected error decrypting corrupt artifact")
	}
}
