package valkey_test

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	vaultapi "github.com/hashicorp/vault/api"
	"github.com/primecloud/primecloud-agent/internal/runtime"
	"github.com/primecloud/primecloud-agent/internal/valkey"
	"github.com/primecloud/primecloud-agent/tests/testenv"
)

func TestValkey_ProvisioningAndVaultCredentials(t *testing.T) {
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

	provisioner := valkey.NewProvisioner(nil, vClient, baseResDir, nil)

	resID := "res-vk-smoke-1"
	projectID := "proj-vk-smoke"
	result, err := provisioner.ProvisionWithProject(ctx, projectID, "", resID, "valkey/valkey:7.2-alpine", "")
	if err != nil {
		t.Fatalf("Provision failed: %v", err)
	}

	if result.ResourceID != resID {
		t.Errorf("Expected resource ID %s, got %s", resID, result.ResourceID)
	}
	expectedVaultRef := "secret/data/primecloud/tenants/proj-vk-smoke/keyvalue/res-vk-smoke-1"
	if result.VaultSecretRef != expectedVaultRef {
		t.Errorf("Expected VaultSecretRef %s, got %s", expectedVaultRef, result.VaultSecretRef)
	}

	// Verify credentials exist in Real Vault
	vaultData, err := vClient.ReadSecret(ctx, result.VaultSecretRef)
	if err != nil {
		t.Fatalf("Failed to read credentials from Vault at %s: %v", result.VaultSecretRef, err)
	}
	if vaultData == nil {
		t.Fatal("Vault secret not found")
	}

	if vaultData["auth_token"] != result.Credentials.AuthToken {
		t.Errorf("Auth token mismatch in Vault: expected %s, got %v", result.Credentials.AuthToken, vaultData["auth_token"])
	}
	if vaultData["password"] != result.Credentials.AuthToken {
		t.Errorf("Password mismatch in Vault: expected %s, got %v", result.Credentials.AuthToken, vaultData["password"])
	}
	if vaultData["host"] != "pc-vk-res-vk-smoke-1" {
		t.Errorf("Host mismatch in Vault: expected pc-vk-res-vk-smoke-1, got %v", vaultData["host"])
	}
	if vaultData["url"] == nil || vaultData["url"] == "" {
		t.Errorf("Expected url to be present in Vault secret")
	}

	// Verify dual-write redis compat path
	redisCompatData, err := vClient.ReadSecret(ctx, "secret/data/primecloud/tenants/proj-vk-smoke/redis/res-vk-smoke-1")
	if err != nil || redisCompatData == nil {
		t.Fatalf("Failed to read credentials from redis compat Vault path: %v", err)
	}
	if redisCompatData["auth_token"] != result.Credentials.AuthToken {
		t.Errorf("Auth token mismatch in redis compat Vault")
	}

	// Verify dual-write legacy compat path
	compatData, err := vClient.ReadSecret(ctx, "primecloud/resources/valkey/"+resID)
	if err != nil || compatData == nil {
		t.Fatalf("Failed to read credentials from legacy compat Vault path: %v", err)
	}
	if compatData["auth_token"] != result.Credentials.AuthToken {
		t.Errorf("Auth token mismatch in legacy compat Vault")
	}

	// Test Backup - Create a dummy RDB file in host volume to simulate
	rdbPath := filepath.Join(baseResDir, "valkey", resID, "dump.rdb")
	os.MkdirAll(filepath.Dir(rdbPath), 0700)
	os.WriteFile(rdbPath, []byte("REDIS0009fake"), 0600)

	backupRes, err := valkey.BackupValkeyWithVault(ctx, nil, nil, baseResDir, projectID, resID, filepath.Join(tempDir, "backups"))
	if err != nil {
		t.Fatalf("BackupValkey failed: %v", err)
	}
	if backupRes.SizeBytes == 0 {
		t.Error("Backup artifact is empty")
	}

	// Test Restore
	if err := valkey.RestoreValkey(ctx, nil, resID, backupRes.ArtifactPath); err != nil {
		t.Fatalf("RestoreValkey failed: %v", err)
	}

	// Test Lifecycle Manager
	lm := valkey.NewLifecycleManager(nil)
	if err := lm.Start(ctx, "mock-container-id"); err == nil {
		t.Error("Expected error for nil runtime")
	}
	if err := lm.Stop(ctx, "mock-container-id", 5); err == nil {
		t.Error("Expected error for nil runtime")
	}
	if err := lm.Remove(ctx, "mock-container-id"); err == nil {
		t.Error("Expected error for nil runtime")
	}

	// Test live Docker container if daemon is running
	rt, err := runtime.NewDockerRuntime()
	if err == nil {
		pingCtx, pCancel := context.WithTimeout(ctx, 2*time.Second)
		if pingErr := rt.Ping(pingCtx); pingErr == nil {
			liveProv := valkey.NewProvisioner(rt, vClient, baseResDir, nil)
			liveRes, pErr := liveProv.ProvisionWithProject(ctx, "default", "", "live-vk-test", "valkey/valkey:7.2-alpine", "")
			if pErr == nil && liveRes.ContainerID != "" {
				liveLM := valkey.NewLifecycleManager(rt)
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

func TestValkey_ContainerConfig_NoPort8000Inherited(t *testing.T) {
	mockRT := &mockCaptureRuntime{}
	tempDir := t.TempDir()
	baseResDir := filepath.Join(tempDir, "resources")

	provisioner := valkey.NewProvisioner(mockRT, nil, baseResDir, nil)
	_, err := provisioner.ProvisionWithProject(context.Background(), "test-proj", "test-env", "test-res", "valkey/valkey:7.2-alpine", "")
	if err != nil {
		t.Fatalf("Provision failed: %v", err)
	}

	if mockRT.lastConfig == nil {
		t.Fatal("Expected CreateContainer to be called")
	}

	if mockRT.lastConfig.WorkloadType != runtime.WorkloadTypeManagedValkey {
		t.Errorf("Expected WorkloadTypeManagedValkey, got %s", mockRT.lastConfig.WorkloadType)
	}

	// Verify that BuildPortConfigForWorkload with this config does NOT contain 8000/tcp
	exposed, bindings, err := runtime.BuildPortConfigForWorkload(mockRT.lastConfig.WorkloadType, mockRT.lastConfig.Ports)
	if err != nil {
		t.Fatalf("BuildPortConfigForWorkload failed: %v", err)
	}

	if _, ok := exposed["8000/tcp"]; ok {
		t.Errorf("Managed valkey container must NOT expose 8000/tcp!")
	}
	if _, ok := bindings["8000/tcp"]; ok {
		t.Errorf("Managed valkey container must NOT bind 8000/tcp!")
	}
	if _, ok := exposed["6379/tcp"]; !ok {
		t.Errorf("Managed valkey container must expose 6379/tcp")
	}
	if len(bindings) != 0 {
		t.Errorf("Managed valkey container must NOT have host port bindings when hostPort is empty, got %v", bindings)
	}
}

// mockValkeyBackupRuntime implements runtime.ContainerRuntime for Valkey backup tests.
type mockValkeyBackupRuntime struct {
	inspectFunc func(ctx context.Context, id string) (*runtime.ContainerInspect, error)
	execFunc    func(ctx context.Context, id string, cmd []string, env []string, stdin io.Reader) ([]byte, []byte, int, error)
}

func (m *mockValkeyBackupRuntime) PullImage(ctx context.Context, ref string) error { return nil }
func (m *mockValkeyBackupRuntime) PullImageWithAuth(ctx context.Context, ref, auth string) error {
	return nil
}
func (m *mockValkeyBackupRuntime) CreateContainer(ctx context.Context, cfg *runtime.ContainerConfig, l *runtime.ResourceLimits, p *runtime.HardenedIsolationProfile) (string, error) {
	return "mock-cid", nil
}
func (m *mockValkeyBackupRuntime) StartContainer(ctx context.Context, id string) error { return nil }
func (m *mockValkeyBackupRuntime) StopContainer(ctx context.Context, id string, timeout *int) error {
	return nil
}
func (m *mockValkeyBackupRuntime) RemoveContainer(ctx context.Context, id string, force bool) error {
	return nil
}
func (m *mockValkeyBackupRuntime) InspectContainer(ctx context.Context, id string) (*runtime.ContainerInspect, error) {
	if m.inspectFunc != nil {
		return m.inspectFunc(ctx, id)
	}
	return &runtime.ContainerInspect{ID: id, Running: true, Health: "healthy"}, nil
}
func (m *mockValkeyBackupRuntime) GetContainerLogs(ctx context.Context, containerID string) (io.ReadCloser, error) {
	return nil, nil
}
func (m *mockValkeyBackupRuntime) ListContainers(ctx context.Context, all bool) ([]runtime.ContainerSummary, error) {
	return nil, nil
}
func (m *mockValkeyBackupRuntime) ExecContainer(ctx context.Context, containerID string, cmd []string, env []string, stdin io.Reader) ([]byte, []byte, int, error) {
	if m.execFunc != nil {
		return m.execFunc(ctx, containerID, cmd, env, stdin)
	}
	return nil, nil, 0, nil
}
func (m *mockValkeyBackupRuntime) GetContainerStats(ctx context.Context, containerID string) (io.ReadCloser, error) {
	return nil, nil
}
func (m *mockValkeyBackupRuntime) Ping(ctx context.Context) error { return nil }
func (m *mockValkeyBackupRuntime) Close() error                   { return nil }

func TestValkeyBackup_BGSAVEPersistenceAndStreaming(t *testing.T) {
	ctx := context.Background()
	tempDir := t.TempDir()
	baseResDir := filepath.Join(tempDir, "resources")
	backupDir := filepath.Join(tempDir, "backups")
	resID := "res-vk-stream-1"

	// Prepare RDB file in volume directory
	volDir := filepath.Join(baseResDir, "valkey", resID)
	_ = os.MkdirAll(volDir, 0700)
	rdbPath := filepath.Join(volDir, "dump.rdb")
	genuineRDB := []byte("REDIS0009\xfa\x09redis-ver\x057.2.0\xff\x00\x00\x00\x00\x00\x00\x00\x00")
	if err := os.WriteFile(rdbPath, genuineRDB, 0600); err != nil {
		t.Fatalf("Failed writing dump.rdb: %v", err)
	}

	bgsaveCalled := false
	infoPersistenceCalled := false

	mockRT := &mockValkeyBackupRuntime{
		execFunc: func(ctx context.Context, id string, cmd []string, env []string, stdin io.Reader) ([]byte, []byte, int, error) {
			if len(cmd) > 0 && cmd[len(cmd)-1] == "BGSAVE" {
				bgsaveCalled = true
				return []byte("Background saving started\n"), nil, 0, nil
			}
			if len(cmd) >= 2 && cmd[len(cmd)-2] == "INFO" && cmd[len(cmd)-1] == "persistence" {
				infoPersistenceCalled = true
				return []byte("rdb_bgsave_in_progress:0\r\nrdb_last_bgsave_status:ok\r\n"), nil, 0, nil
			}
			return nil, nil, 0, nil
		},
	}

	res, err := valkey.BackupValkeyWithVault(ctx, mockRT, nil, baseResDir, "default", resID, backupDir)
	if err != nil {
		t.Fatalf("BackupValkeyWithVault failed: %v", err)
	}

	if !bgsaveCalled {
		t.Error("Expected BGSAVE command to be executed")
	}
	if !infoPersistenceCalled {
		t.Error("Expected INFO persistence polling to be executed")
	}

	// Verify artifact content
	artifactData, err := os.ReadFile(res.ArtifactPath)
	if err != nil {
		t.Fatalf("Failed reading artifact: %v", err)
	}
	if string(artifactData) != string(genuineRDB) {
		t.Errorf("Artifact content mismatch: got %v, want %v", artifactData, genuineRDB)
	}
}

func TestValkeyBackup_FailClosedScenarios(t *testing.T) {
	ctx := context.Background()
	tempDir := t.TempDir()
	baseResDir := filepath.Join(tempDir, "resources")
	backupDir := filepath.Join(tempDir, "backups")

	// 1. Missing volume snapshot fails closed
	if _, err := valkey.BackupValkeyWithVault(ctx, nil, nil, baseResDir, "default", "res-missing-rdb", backupDir); err == nil {
		t.Error("Expected error when no RDB is found")
	}

	// 2. Invalid REDIS header fails closed
	resBad := "res-bad-header"
	volBad := filepath.Join(baseResDir, "valkey", resBad)
	_ = os.MkdirAll(volBad, 0700)
	_ = os.WriteFile(filepath.Join(volBad, "dump.rdb"), []byte("NOT_REDIS_INVALID_MAGIC"), 0600)
	if _, err := valkey.BackupValkeyWithVault(ctx, nil, nil, baseResDir, "default", resBad, backupDir); err == nil {
		t.Error("Expected error when RDB header is invalid")
	}

	// 3. Container stopped fails closed
	stoppedRT := &mockValkeyBackupRuntime{
		inspectFunc: func(ctx context.Context, id string) (*runtime.ContainerInspect, error) {
			return &runtime.ContainerInspect{ID: id, Running: false}, nil
		},
	}
	if _, err := valkey.BackupValkeyWithVault(ctx, stoppedRT, nil, baseResDir, "default", "res-stopped", backupDir); err == nil {
		t.Error("Expected error when container is stopped")
	}
}
