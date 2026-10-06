package valkey_test

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/primecloud/primecloud-agent/internal/runtime"
	"github.com/primecloud/primecloud-agent/internal/valkey"
	"github.com/primecloud/primecloud-agent/tests/testenv"
)

func TestValkey_ProvisioningAndVaultCredentials(t *testing.T) {
	vClient, _ := testenv.EnsureVaultDev(t)

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
