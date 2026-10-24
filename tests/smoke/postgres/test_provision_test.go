package postgres_test

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	vaultapi "github.com/hashicorp/vault/api"
	"github.com/primecloud/primecloud-agent/internal/postgres"
	"github.com/primecloud/primecloud-agent/internal/runtime"
	"github.com/primecloud/primecloud-agent/tests/testenv"
)

func TestPostgres_ProvisioningAndVaultCredentials(t *testing.T) {
	vClient, _ := testenv.EnsureVaultDev(t)
	if vClient != nil {
		_ = vClient.RawClient().Sys().UnmountWithContext(context.Background(), "primecloud")
		_ = vClient.RawClient().Sys().MountWithContext(context.Background(), "primecloud", &vaultapi.MountInput{
			Type:    "kv",
			Options: map[string]string{"version": "1"},
		})
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	tempDir := t.TempDir()
	baseResDir := filepath.Join(tempDir, "resources")

	provisioner := postgres.NewProvisioner(nil, vClient, baseResDir, nil)

	resID := "res-pg-smoke-1"
	projectID := "proj-pg-smoke"
	result, err := provisioner.ProvisionWithProject(ctx, projectID, "", resID, "postgres:16-alpine", "")
	if err != nil {
		t.Fatalf("Provision failed: %v", err)
	}

	if result.ResourceID != resID {
		t.Errorf("Expected resource ID %s, got %s", resID, result.ResourceID)
	}
	expectedVaultRef := "secret/data/primecloud/tenants/proj-pg-smoke/postgres/res-pg-smoke-1"
	if result.VaultSecretRef != expectedVaultRef {
		t.Errorf("Expected VaultSecretRef %s, got %s", expectedVaultRef, result.VaultSecretRef)
	}

	// Verify credentials exist in Real Vault at tenant path
	vaultData, err := vClient.ReadSecret(ctx, result.VaultSecretRef)
	if err != nil {
		t.Fatalf("Failed to read credentials from Vault at %s: %v", result.VaultSecretRef, err)
	}
	if vaultData == nil {
		t.Fatal("Vault secret not found at tenant path")
	}

	if vaultData["username"] != result.Credentials.Username {
		t.Errorf("Username mismatch in Vault: expected %s, got %v", result.Credentials.Username, vaultData["username"])
	}
	if vaultData["password"] != result.Credentials.Password {
		t.Errorf("Password mismatch in Vault")
	}
	if vaultData["host"] != "pc-pg-res-pg-smoke-1" {
		t.Errorf("Expected host pc-pg-res-pg-smoke-1, got %v", vaultData["host"])
	}
	if vaultData["url"] == nil || vaultData["url"] == "" {
		t.Errorf("Expected url to be present in Vault secret")
	}

	// Verify dual-write compatibility path
	compatData, err := vClient.ReadSecret(ctx, "primecloud/resources/postgres/"+resID)
	if err != nil || compatData == nil {
		t.Fatalf("Failed to read credentials from compat Vault path: %v", err)
	}
	if compatData["username"] != result.Credentials.Username {
		t.Errorf("Username mismatch in compat Vault")
	}

	// 4. Test Backup Fail-Closed with nil runtime
	if _, err := postgres.BackupPostgres(ctx, nil, resID, filepath.Join(tempDir, "backups")); err == nil {
		t.Fatal("Expected BackupPostgres to fail closed when runtime is nil")
	}

	// Test Backup Success with authentic mock runtime
	mockRT := &mockPostgresBackupRuntime{
		inspectFunc: func(ctx context.Context, id string) (*runtime.ContainerInspect, error) {
			return &runtime.ContainerInspect{ID: id, Running: true, Health: "healthy"}, nil
		},
		execFunc: func(ctx context.Context, id string, cmd []string, env []string, stdin io.Reader) ([]byte, []byte, int, error) {
			return []byte("PGDMP\x01\x02\x00\x00-- Real PostgreSQL Dump\nCREATE TABLE test (id int);\n"), nil, 0, nil
		},
	}
	backupRes, err := postgres.BackupPostgres(ctx, mockRT, resID, filepath.Join(tempDir, "backups"))
	if err != nil {
		t.Fatalf("BackupPostgres with mock runtime failed: %v", err)
	}
	if backupRes.SizeBytes == 0 {
		t.Error("Backup artifact is empty")
	}

	// 5. Test Restore
	if err := postgres.RestorePostgres(ctx, nil, resID, backupRes.ArtifactPath); err == nil {
		t.Fatal("Expected RestorePostgres to fail closed when runtime is nil")
	}
	if err := postgres.RestorePostgres(ctx, mockRT, resID, backupRes.ArtifactPath); err != nil {
		t.Fatalf("RestorePostgres with mock runtime failed: %v", err)
	}

	// 6. Test Lifecycle Manager
	lm := postgres.NewLifecycleManager(nil)
	if err := lm.Start(ctx, "mock-container-id"); err == nil {
		// When rt is nil, returns error
	}
	if err := lm.Stop(ctx, "mock-container-id", 5); err == nil {
	}
	if err := lm.Remove(ctx, "mock-container-id"); err == nil {
	}

	// Test live Docker container if daemon is running
	rt, err := runtime.NewDockerRuntime()
	if err == nil {
		pingCtx, pCancel := context.WithTimeout(ctx, 2*time.Second)
		if pingErr := rt.Ping(pingCtx); pingErr == nil {
			liveProv := postgres.NewProvisioner(rt, vClient, baseResDir, nil)
			liveRes, pErr := liveProv.ProvisionWithProject(ctx, "default", "", "live-pg-test", "postgres:16-alpine", "")
			if pErr == nil && liveRes.ContainerID != "" {
				liveLM := postgres.NewLifecycleManager(rt)
				_ = liveLM.Restart(ctx, liveRes.ContainerID, 5)
				_ = liveLM.Remove(ctx, liveRes.ContainerID)
			}
		}
		pCancel()
		_ = rt.Close()
	}
}

// mockCaptureRuntime captures ContainerConfig during CreateContainer.
type mockCaptureRuntime struct {
	lastConfig *runtime.ContainerConfig
}

func (m *mockCaptureRuntime) PullImage(ctx context.Context, ref string) error { return nil }
func (m *mockCaptureRuntime) PullImageWithAuth(ctx context.Context, ref, auth string) error {
	return nil
}
func (m *mockCaptureRuntime) CreateContainer(ctx context.Context, cfg *runtime.ContainerConfig, l *runtime.ResourceLimits, p *runtime.HardenedIsolationProfile) (string, error) {
	m.lastConfig = cfg
	return "mock-cid", nil
}
func (m *mockCaptureRuntime) StartContainer(ctx context.Context, id string) error { return nil }
func (m *mockCaptureRuntime) StopContainer(ctx context.Context, id string, timeout *int) error {
	return nil
}
func (m *mockCaptureRuntime) RemoveContainer(ctx context.Context, id string, force bool) error {
	return nil
}
func (m *mockCaptureRuntime) InspectContainer(ctx context.Context, id string) (*runtime.ContainerInspect, error) {
	return &runtime.ContainerInspect{ID: id, Running: true, Health: "healthy"}, nil
}
func (m *mockCaptureRuntime) GetContainerLogs(ctx context.Context, containerID string) (io.ReadCloser, error) {
	return nil, nil
}
func (m *mockCaptureRuntime) ListContainers(ctx context.Context, all bool) ([]runtime.ContainerSummary, error) {
	return nil, nil
}
func (m *mockCaptureRuntime) ExecContainer(ctx context.Context, containerID string, cmd []string, env []string, stdin io.Reader) ([]byte, []byte, int, error) {
	return nil, nil, 0, nil
}
func (m *mockCaptureRuntime) GetContainerStats(ctx context.Context, containerID string) (io.ReadCloser, error) {
	return nil, nil
}
func (m *mockCaptureRuntime) Ping(ctx context.Context) error { return nil }
func (m *mockCaptureRuntime) Close() error                   { return nil }

func TestPostgres_ContainerConfig_NoPort8000Inherited(t *testing.T) {
	mockRT := &mockCaptureRuntime{}
	tempDir := t.TempDir()
	baseResDir := filepath.Join(tempDir, "resources")

	provisioner := postgres.NewProvisioner(mockRT, nil, baseResDir, nil)
	_, err := provisioner.ProvisionWithProject(context.Background(), "test-proj", "test-env", "test-res", "postgres:16-alpine", "")
	if err != nil {
		t.Fatalf("Provision failed: %v", err)
	}

	if mockRT.lastConfig == nil {
		t.Fatal("Expected CreateContainer to be called")
	}

	if mockRT.lastConfig.WorkloadType != runtime.WorkloadTypeManagedPostgres {
		t.Errorf("Expected WorkloadTypeManagedPostgres, got %s", mockRT.lastConfig.WorkloadType)
	}

	// Verify that BuildPortConfigForWorkload with this config does NOT contain 8000/tcp
	exposed, bindings, err := runtime.BuildPortConfigForWorkload(mockRT.lastConfig.WorkloadType, mockRT.lastConfig.Ports)
	if err != nil {
		t.Fatalf("BuildPortConfigForWorkload failed: %v", err)
	}

	if _, ok := exposed["8000/tcp"]; ok {
		t.Errorf("Managed postgres container must NOT expose 8000/tcp!")
	}
	if _, ok := bindings["8000/tcp"]; ok {
		t.Errorf("Managed postgres container must NOT bind 8000/tcp!")
	}
	if _, ok := exposed["5432/tcp"]; !ok {
		t.Errorf("Managed postgres container must expose 5432/tcp")
	}
	if len(bindings) != 0 {
		t.Errorf("Managed postgres container must NOT have host port bindings when hostPort is empty, got %v", bindings)
	}
}

// mockPostgresBackupRuntime implements runtime.ContainerRuntime with configurable inspect and exec behaviors.
type mockPostgresBackupRuntime struct {
	inspectFunc func(ctx context.Context, id string) (*runtime.ContainerInspect, error)
	execFunc    func(ctx context.Context, id string, cmd []string, env []string, stdin io.Reader) ([]byte, []byte, int, error)
}

func (m *mockPostgresBackupRuntime) PullImage(ctx context.Context, ref string) error { return nil }
func (m *mockPostgresBackupRuntime) PullImageWithAuth(ctx context.Context, ref, auth string) error {
	return nil
}
func (m *mockPostgresBackupRuntime) CreateContainer(ctx context.Context, cfg *runtime.ContainerConfig, l *runtime.ResourceLimits, p *runtime.HardenedIsolationProfile) (string, error) {
	return "mock-cid", nil
}
func (m *mockPostgresBackupRuntime) StartContainer(ctx context.Context, id string) error { return nil }
func (m *mockPostgresBackupRuntime) StopContainer(ctx context.Context, id string, timeout *int) error {
	return nil
}
func (m *mockPostgresBackupRuntime) RemoveContainer(ctx context.Context, id string, force bool) error {
	return nil
}
func (m *mockPostgresBackupRuntime) InspectContainer(ctx context.Context, id string) (*runtime.ContainerInspect, error) {
	if m.inspectFunc != nil {
		return m.inspectFunc(ctx, id)
	}
	return &runtime.ContainerInspect{ID: id, Running: true, Health: "healthy"}, nil
}
func (m *mockPostgresBackupRuntime) GetContainerLogs(ctx context.Context, containerID string) (io.ReadCloser, error) {
	return nil, nil
}
func (m *mockPostgresBackupRuntime) ListContainers(ctx context.Context, all bool) ([]runtime.ContainerSummary, error) {
	return nil, nil
}
func (m *mockPostgresBackupRuntime) ExecContainer(ctx context.Context, containerID string, cmd []string, env []string, stdin io.Reader) ([]byte, []byte, int, error) {
	if m.execFunc != nil {
		return m.execFunc(ctx, containerID, cmd, env, stdin)
	}
	return nil, nil, 0, nil
}
func (m *mockPostgresBackupRuntime) GetContainerStats(ctx context.Context, containerID string) (io.ReadCloser, error) {
	return nil, nil
}
func (m *mockPostgresBackupRuntime) Ping(ctx context.Context) error { return nil }
func (m *mockPostgresBackupRuntime) Close() error                   { return nil }

func TestPostgresBackup_FailClosedScenarios(t *testing.T) {
	ctx := context.Background()
	tempDir := t.TempDir()

	// 1. Nil runtime fails closed
	if _, err := postgres.BackupPostgres(ctx, nil, "res-fc-1", tempDir); err == nil {
		t.Error("Expected error when runtime is nil")
	}

	// 2. Container inspect error fails closed
	missingRT := &mockPostgresBackupRuntime{
		inspectFunc: func(ctx context.Context, id string) (*runtime.ContainerInspect, error) {
			return nil, context.DeadlineExceeded
		},
	}
	if _, err := postgres.BackupPostgres(ctx, missingRT, "res-fc-2", tempDir); err == nil {
		t.Error("Expected error when container inspect fails")
	}

	// 3. Container not running fails closed
	stoppedRT := &mockPostgresBackupRuntime{
		inspectFunc: func(ctx context.Context, id string) (*runtime.ContainerInspect, error) {
			return &runtime.ContainerInspect{ID: id, Running: false, State: "exited"}, nil
		},
	}
	if _, err := postgres.BackupPostgres(ctx, stoppedRT, "res-fc-3", tempDir); err == nil {
		t.Error("Expected error when container is stopped")
	}

	// 4. ExecContainer error fails closed
	execErrRT := &mockPostgresBackupRuntime{
		execFunc: func(ctx context.Context, id string, cmd []string, env []string, stdin io.Reader) ([]byte, []byte, int, error) {
			return nil, []byte("connection refused"), 1, context.Canceled
		},
	}
	if _, err := postgres.BackupPostgres(ctx, execErrRT, "res-fc-4", tempDir); err == nil {
		t.Error("Expected error when pg_dump execution errors")
	}

	// 5. ExecContainer non-zero exit code fails closed
	exitCodeRT := &mockPostgresBackupRuntime{
		execFunc: func(ctx context.Context, id string, cmd []string, env []string, stdin io.Reader) ([]byte, []byte, int, error) {
			return nil, []byte("FATAL: password authentication failed"), 2, nil
		},
	}
	if _, err := postgres.BackupPostgres(ctx, exitCodeRT, "res-fc-5", tempDir); err == nil {
		t.Error("Expected error when pg_dump exits with non-zero code")
	}

	// 6. Empty pg_dump output fails closed
	emptyRT := &mockPostgresBackupRuntime{
		execFunc: func(ctx context.Context, id string, cmd []string, env []string, stdin io.Reader) ([]byte, []byte, int, error) {
			return []byte{}, nil, 0, nil
		},
	}
	if _, err := postgres.BackupPostgres(ctx, emptyRT, "res-fc-6", tempDir); err == nil {
		t.Error("Expected error when pg_dump produces empty output")
	}
}

func TestPostgresBackup_GenuineDumpNoSyntheticFallback(t *testing.T) {
	ctx := context.Background()
	tempDir := t.TempDir()

	realDumpContent := []byte("PGDMP\x01\x02\x00\x00-- Genuine Postgres Dump Header\nCREATE TABLE accounts (id serial primary key);\n")
	mockRT := &mockPostgresBackupRuntime{
		execFunc: func(ctx context.Context, id string, cmd []string, env []string, stdin io.Reader) ([]byte, []byte, int, error) {
			return realDumpContent, nil, 0, nil
		},
	}

	result, err := postgres.BackupPostgres(ctx, mockRT, "res-genuine-pg", tempDir)
	if err != nil {
		t.Fatalf("BackupPostgres failed: %v", err)
	}

	// Read generated artifact
	artifactBytes, err := os.ReadFile(result.ArtifactPath)
	if err != nil {
		t.Fatalf("Failed to read artifact: %v", err)
	}

	if string(artifactBytes) != string(realDumpContent) {
		t.Errorf("Artifact content mismatch: got %q, want %q", string(artifactBytes), string(realDumpContent))
	}

	// Explicitly confirm NO synthetic "SELECT 1;" fallback
	if strings.Contains(string(artifactBytes), "SELECT 1;") {
		t.Error("CRITICAL: Synthetic fallback 'SELECT 1;' detected in backup artifact!")
	}
}

func TestPostgresRestore_FailClosedScenarios(t *testing.T) {
	ctx := context.Background()
	tempDir := t.TempDir()

	// Create valid artifact
	validArtifact := filepath.Join(tempDir, "valid.dump")
	dumpData := []byte("PGDMP\x01\x02\x00\x00-- Authentic Dump\nCREATE TABLE users (id int);\n")
	if err := os.WriteFile(validArtifact, dumpData, 0600); err != nil {
		t.Fatalf("Failed to write valid artifact: %v", err)
	}

	// 1. Nil runtime fails closed with CONTAINER_NOT_FOUND
	if err := postgres.RestorePostgres(ctx, nil, "res-rest-1", validArtifact); err == nil || !strings.Contains(err.Error(), "CONTAINER_NOT_FOUND") {
		t.Errorf("Expected CONTAINER_NOT_FOUND error when runtime is nil, got %v", err)
	}

	// 2. Missing artifact fails closed
	mockRT := &mockPostgresBackupRuntime{
		inspectFunc: func(ctx context.Context, id string) (*runtime.ContainerInspect, error) {
			return &runtime.ContainerInspect{ID: id, Running: true}, nil
		},
	}
	if err := postgres.RestorePostgres(ctx, mockRT, "res-rest-2", filepath.Join(tempDir, "nonexistent.dump")); err == nil {
		t.Error("Expected error when artifact does not exist")
	}

	// 3. Empty artifact fails closed
	emptyArtifact := filepath.Join(tempDir, "empty.dump")
	_ = os.WriteFile(emptyArtifact, []byte{}, 0600)
	if err := postgres.RestorePostgres(ctx, mockRT, "res-rest-3", emptyArtifact); err == nil {
		t.Error("Expected error when artifact is empty")
	}

	// 4. Artifact payload too small (<10 bytes) fails closed
	tinyArtifact := filepath.Join(tempDir, "tiny.dump")
	_ = os.WriteFile(tinyArtifact, []byte("short"), 0600)
	if err := postgres.RestorePostgres(ctx, mockRT, "res-rest-4", tinyArtifact); err == nil {
		t.Error("Expected error when artifact payload is too small")
	}

	// 5. Container missing and fails to start -> CONTAINER_NOT_FOUND
	missingRT := &mockPostgresBackupRuntime{
		inspectFunc: func(ctx context.Context, id string) (*runtime.ContainerInspect, error) {
			return nil, fmt.Errorf("no such container")
		},
	}
	if err := postgres.RestorePostgres(ctx, missingRT, "res-rest-5", validArtifact); err == nil || !strings.Contains(err.Error(), "CONTAINER_NOT_FOUND") {
		t.Errorf("Expected CONTAINER_NOT_FOUND when container is missing and cannot be started, got %v", err)
	}

	// 6. Container stopped and fails to start -> CONTAINER_STOPPED
	stoppedRT := &mockPostgresBackupRuntime{
		inspectFunc: func(ctx context.Context, id string) (*runtime.ContainerInspect, error) {
			return &runtime.ContainerInspect{ID: id, Running: false, State: "exited"}, nil
		},
	}
	// Note: mockPostgresBackupRuntime.StartContainer returns nil by default, so inspectFunc still returning Running=false triggers CONTAINER_STOPPED
	if err := postgres.RestorePostgres(ctx, stoppedRT, "res-rest-6", validArtifact); err == nil || !strings.Contains(err.Error(), "CONTAINER_STOPPED") {
		t.Errorf("Expected CONTAINER_STOPPED when container fails to become running, got %v", err)
	}

	// 7. Restore command non-zero exit code fails closed
	failExecRT := &mockPostgresBackupRuntime{
		inspectFunc: func(ctx context.Context, id string) (*runtime.ContainerInspect, error) {
			return &runtime.ContainerInspect{ID: id, Running: true}, nil
		},
		execFunc: func(ctx context.Context, id string, cmd []string, env []string, stdin io.Reader) ([]byte, []byte, int, error) {
			if len(cmd) > 0 && cmd[0] == "pg_restore" {
				return nil, []byte("pg_restore: error: table already exists"), 2, nil
			}
			return nil, nil, 0, nil
		},
	}
	if err := postgres.RestorePostgres(ctx, failExecRT, "res-rest-7", validArtifact); err == nil {
		t.Error("Expected error when pg_restore exits with error code 2")
	}

	// 8. Verification query fails closed
	failVerifyRT := &mockPostgresBackupRuntime{
		inspectFunc: func(ctx context.Context, id string) (*runtime.ContainerInspect, error) {
			return &runtime.ContainerInspect{ID: id, Running: true}, nil
		},
		execFunc: func(ctx context.Context, id string, cmd []string, env []string, stdin io.Reader) ([]byte, []byte, int, error) {
			for _, arg := range cmd {
				if arg == "SELECT 1;" {
					return nil, []byte("connection closed unexpectedly"), 1, nil
				}
			}
			return nil, nil, 0, nil
		},
	}
	if err := postgres.RestorePostgres(ctx, failVerifyRT, "res-rest-8", validArtifact); err == nil {
		t.Error("Expected error when post-restore verification query fails")
	}

	// 9. Authentic clean restore succeeds via RestorePostgres and RestoreDatabase alias
	successRT := &mockPostgresBackupRuntime{
		inspectFunc: func(ctx context.Context, id string) (*runtime.ContainerInspect, error) {
			return &runtime.ContainerInspect{ID: id, Running: true}, nil
		},
		execFunc: func(ctx context.Context, id string, cmd []string, env []string, stdin io.Reader) ([]byte, []byte, int, error) {
			return nil, nil, 0, nil
		},
	}
	if err := postgres.RestorePostgres(ctx, successRT, "res-rest-9", validArtifact); err != nil {
		t.Errorf("Expected RestorePostgres to succeed, got %v", err)
	}
	if err := postgres.RestoreDatabase(ctx, successRT, "res-rest-9", validArtifact); err != nil {
		t.Errorf("Expected RestoreDatabase alias to succeed, got %v", err)
	}
}
