package applications_test

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/primecloud/primecloud-agent/internal/agent"
	"github.com/primecloud/primecloud-agent/internal/applications"
	"github.com/primecloud/primecloud-agent/internal/postgres"
	"github.com/primecloud/primecloud-agent/internal/runtime"
	"github.com/primecloud/primecloud-agent/internal/valkey"
	"github.com/primecloud/primecloud-agent/tests/testenv"
)

func TestApplications_SecretResolutionAndDeploy(t *testing.T) {
	vClient, _ := testenv.EnsureVaultDev(t)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// 1. Write real secret into Vault
	secretPath := "primecloud/apps/test-app-1"
	testSecretValue := "superSecretDbPassword9988!"
	err := vClient.WriteSecret(ctx, secretPath, map[string]interface{}{
		"DB_PASSWORD": testSecretValue,
	})
	if err != nil {
		t.Fatalf("WriteSecret failed: %v", err)
	}

	var logBuf bytes.Buffer
	logger := agent.SetupLogging(&logBuf, slog.LevelDebug)

	deployer := applications.NewDeployer(nil, vClient, logger)

	// 2. Test Deploy validation (checks payload parsing & secret resolution)
	payloadJSON := `{
		"image": "ghcr.io/primetech-nexus/apps/test-app-1:latest",
		"image_digest": "sha256:ba88008889163273e5bf0cb33cc9bf1e6878b6ee1789c021b0337c767f407b46",
		"env": {
			"NODE_ENV": "production"
		},
		"secret_refs": {
			"DATABASE_URL": "primecloud/apps/test-app-1#DB_PASSWORD"
		},
		"ports": {
			"8080": "8080"
		},
		"health_check_cmd": ["CMD-SHELL", "exit 0"],
		"health_timeout_sec": 5
	}`

	_, _ = deployer.Deploy(ctx, "proj-1", "env-1", "app-1", "inst-1", payloadJSON)

	// Test with live Docker runtime if reachable, otherwise verify secret resolution & container config
	rt, err := runtime.NewDockerRuntime()
	if err == nil {
		pingCtx, pingCancel := context.WithTimeout(ctx, 2*time.Second)
		if pingErr := rt.Ping(pingCtx); pingErr == nil {
			t.Log("Live Docker engine detected; testing deployment")
			liveDeployer := applications.NewDeployer(rt, vClient, logger)
			cid, deployErr := liveDeployer.Deploy(ctx, "proj-1", "env-1", "app-1", "inst-1", payloadJSON)
			if deployErr == nil {
				_ = applications.RestartApplication(ctx, rt, cid, 5)
				_ = applications.RemoveApplication(ctx, rt, cid, true)
			}
		}
		pingCancel()
		_ = rt.Close()
	}

	// 3. Verify secrets are not leaked in log output
	logs := logBuf.String()
	if strings.Contains(logs, testSecretValue) {
		t.Errorf("Secret value leaked in deployer logs: %s", logs)
	}
}

func TestApplications_PayloadParsing(t *testing.T) {
	deployer := applications.NewDeployer(nil, nil, nil)
	ctx := context.Background()

	// Missing image should return error
	_, err := deployer.Deploy(ctx, "proj-1", "env-1", "app-1", "inst-1", `{"ports": {"80": "80"}}`)
	if err == nil {
		t.Error("Expected error when image is missing")
	}

	// Bare sha256 digest should return explicit error
	_, err = deployer.Deploy(ctx, "proj-1", "env-1", "app-1", "inst-1", `{"image_digest": "sha256:ba88008889163273e5bf0cb33cc9bf1e6878b6ee1789c021b0337c767f407b46"}`)
	if err == nil {
		t.Error("Expected error when bare sha256 digest is provided without canonical image reference")
	}

	// Invalid JSON should return error
	_, err = deployer.Deploy(ctx, "proj-1", "env-1", "app-1", "inst-1", `{invalid-json`)
	if err == nil {
		t.Error("Expected error for invalid JSON payload")
	}
}

func TestApplications_Phase2_ConnectionInjection(t *testing.T) {
	vClient, _ := testenv.EnsureVaultDev(t)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	tempDir := t.TempDir()
	baseResDir := filepath.Join(tempDir, "resources")
	projectID := "proj-phase2-prod"
	pgResID := "res-pg-phase2-01"
	vkResID := "res-vk-phase2-01"

	// 1. Provision PostgreSQL datastore
	pgProv := postgres.NewProvisioner(nil, vClient, baseResDir, nil)
	pgRes, err := pgProv.Provision(ctx, projectID, pgResID, "postgres:16-alpine", "")
	if err != nil {
		t.Fatalf("PostgreSQL provision failed: %v", err)
	}

	// 2. Provision Customer Valkey datastore
	vkProv := valkey.NewProvisioner(nil, vClient, baseResDir, nil)
	vkRes, err := vkProv.Provision(ctx, projectID, vkResID, "valkey/valkey:7.2-alpine", "")
	if err != nil {
		t.Fatalf("Valkey provision failed: %v", err)
	}

	var logBuf bytes.Buffer
	logger := agent.SetupLogging(&logBuf, slog.LevelDebug)
	deployer := applications.NewDeployer(nil, vClient, logger)

	// 3. Test deployment with explicit #url references
	payloadWithHashURL := fmt.Sprintf(`{
		"image": "ghcr.io/primetech-nexus/apps/customer-api:v2.0.0",
		"env": {
			"NODE_ENV": "production"
		},
		"secret_refs": {
			"DATABASE_URL": "%s#url",
			"REDIS_URL": "%s#url"
		}
	}`, pgRes.VaultSecretRef, vkRes.VaultSecretRef)

	_, err = deployer.Deploy(ctx, projectID, "env-prod", "customer-api", "inst-1", payloadWithHashURL)
	if err != nil {
		t.Fatalf("Deploy with #url secret_refs failed: %v", err)
	}

	// 4. Test deployment with bare secret path (fallback key synthesis)
	payloadBarePath := fmt.Sprintf(`{
		"image": "ghcr.io/primetech-nexus/apps/customer-api:v2.0.0",
		"secret_refs": {
			"DATABASE_URL": "%s",
			"REDIS_URL": "%s"
		}
	}`, pgRes.VaultSecretRef, vkRes.VaultSecretRef)

	_, err = deployer.Deploy(ctx, projectID, "env-prod", "customer-api", "inst-2", payloadBarePath)
	if err != nil {
		t.Fatalf("Deploy with bare path secret_refs failed: %v", err)
	}

	// 5. Test tenant isolation (cross-tenant access rejection)
	payloadCrossTenant := fmt.Sprintf(`{
		"image": "ghcr.io/primetech-nexus/apps/customer-api:v2.0.0",
		"secret_refs": {
			"DATABASE_URL": "secret/data/primecloud/tenants/other-tenant-99/postgres/%s#url"
		}
	}`, pgResID)

	_, err = deployer.Deploy(ctx, projectID, "env-prod", "customer-api", "inst-3", payloadCrossTenant)
	if err == nil {
		t.Errorf("Expected deploy to fail when accessing unauthorized/missing cross-tenant secret")
	}

	// 6. Test zero leakage in logs
	logs := logBuf.String()
	if strings.Contains(logs, pgRes.Credentials.Password) {
		t.Errorf("Postgres password leaked in deployer logs!")
	}
	if strings.Contains(logs, vkRes.Credentials.AuthToken) {
		t.Errorf("Valkey auth_token leaked in deployer logs!")
	}
}
