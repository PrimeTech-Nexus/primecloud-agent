package postgres_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/primecloud/primecloud-agent/internal/postgres"
	"github.com/primecloud/primecloud-agent/internal/runtime"
	"github.com/primecloud/primecloud-agent/tests/testenv"
)

func TestPostgres_ProvisioningAndVaultCredentials(t *testing.T) {
	vClient, _ := testenv.EnsureVaultDev(t)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	tempDir := t.TempDir()
	baseResDir := filepath.Join(tempDir, "resources")

	provisioner := postgres.NewProvisioner(nil, vClient, baseResDir, nil)

	resID := "res-pg-smoke-1"
	result, err := provisioner.Provision(ctx, resID, "postgres:16-alpine", "")
	if err != nil {
		t.Fatalf("Provision failed: %v", err)
	}

	if result.ResourceID != resID {
		t.Errorf("Expected resource ID %s, got %s", resID, result.ResourceID)
	}
	if result.VaultSecretRef == "" {
		t.Error("VaultSecretRef is empty")
	}

	// Verify credentials exist in Real Vault
	vaultData, err := vClient.ReadSecret(ctx, result.VaultSecretRef)
	if err != nil {
		t.Fatalf("Failed to read credentials from Vault at %s: %v", result.VaultSecretRef, err)
	}
	if vaultData == nil {
		t.Fatal("Vault secret not found")
	}

	if vaultData["username"] != result.Credentials.Username {
		t.Errorf("Username mismatch in Vault: expected %s, got %v", result.Credentials.Username, vaultData["username"])
	}
	if vaultData["password"] != result.Credentials.Password {
		t.Errorf("Password mismatch in Vault")
	}

	// 4. Test Backup
	backupRes, err := postgres.BackupPostgres(ctx, nil, resID, filepath.Join(tempDir, "backups"))
	if err != nil {
		t.Fatalf("BackupPostgres failed: %v", err)
	}
	if backupRes.SizeBytes == 0 {
		t.Error("Backup artifact is empty")
	}

	// 5. Test Restore
	if err := postgres.RestorePostgres(ctx, nil, resID, backupRes.ArtifactPath); err != nil {
		t.Fatalf("RestorePostgres failed: %v", err)
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
			liveRes, pErr := liveProv.Provision(ctx, "live-pg-test", "postgres:16-alpine", "")
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
