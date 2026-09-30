package valkey_test

import (
	"context"
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
	result, err := provisioner.ProvisionWithProject(ctx, projectID, resID, "valkey/valkey:7.2-alpine", "")
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

	// Test Backup
	backupRes, err := valkey.BackupValkey(ctx, nil, resID, filepath.Join(tempDir, "backups"))
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
			liveRes, pErr := liveProv.ProvisionWithProject(ctx, "default", "live-vk-test", "valkey/valkey:7.2-alpine", "")
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
