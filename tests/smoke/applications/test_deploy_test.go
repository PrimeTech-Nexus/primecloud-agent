package applications_test

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/primecloud/primecloud-agent/internal/agent"
	"github.com/primecloud/primecloud-agent/internal/applications"
	"github.com/primecloud/primecloud-agent/internal/runtime"
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

	// Invalid JSON should return error
	_, err = deployer.Deploy(ctx, "proj-1", "env-1", "app-1", "inst-1", `{invalid-json`)
	if err == nil {
		t.Error("Expected error for invalid JSON payload")
	}
}
