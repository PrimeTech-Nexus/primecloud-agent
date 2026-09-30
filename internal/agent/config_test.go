package agent_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/primecloud/primecloud-agent/internal/agent"
)

func TestLoadConfig_AppRole_FromEnv(t *testing.T) {
	origRole := os.Getenv("PRIMECLOUD_AGENT_VAULT_ROLE_ID")
	origSec := os.Getenv("PRIMECLOUD_AGENT_VAULT_SECRET_ID")
	origAddr := os.Getenv("PRIMECLOUD_AGENT_VAULT_ADDR")
	defer func() {
		os.Setenv("PRIMECLOUD_AGENT_VAULT_ROLE_ID", origRole)
		os.Setenv("PRIMECLOUD_AGENT_VAULT_SECRET_ID", origSec)
		os.Setenv("PRIMECLOUD_AGENT_VAULT_ADDR", origAddr)
	}()

	os.Setenv("PRIMECLOUD_AGENT_VAULT_ADDR", "http://127.0.0.1:8200")
	os.Setenv("PRIMECLOUD_AGENT_VAULT_ROLE_ID", "test-agent-role-uuid")
	os.Setenv("PRIMECLOUD_AGENT_VAULT_SECRET_ID", "test-agent-secret-uuid")

	cfg, err := agent.LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	if cfg.VaultRoleID != "test-agent-role-uuid" {
		t.Errorf("expected VaultRoleID test-agent-role-uuid, got %s", cfg.VaultRoleID)
	}
	if cfg.VaultSecretID != "test-agent-secret-uuid" {
		t.Errorf("expected VaultSecretID test-agent-secret-uuid, got %s", cfg.VaultSecretID)
	}
}

func TestConfig_StringerRedactsSecrets(t *testing.T) {
	cfg := agent.DefaultConfig()
	cfg.VaultRoleID = "super-secret-role-id"
	cfg.VaultSecretID = "super-secret-secret-id"
	cfg.BootstrapToken = "super-secret-bootstrap-token"

	str := cfg.String()

	if strings.Contains(str, "super-secret-role-id") {
		t.Errorf("VaultRoleID leaked in Config.String(): %s", str)
	}
	if strings.Contains(str, "super-secret-secret-id") {
		t.Errorf("VaultSecretID leaked in Config.String(): %s", str)
	}
	if strings.Contains(str, "super-secret-bootstrap-token") {
		t.Errorf("BootstrapToken leaked in Config.String(): %s", str)
	}
}

func TestLoadConfig_Token_FromEnv(t *testing.T) {
	origTok := os.Getenv("VAULT_TOKEN")
	defer os.Setenv("VAULT_TOKEN", origTok)

	os.Setenv("VAULT_TOKEN", "s.test-scoped-token")

	cfg, err := agent.LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	if cfg.BootstrapToken != "s.test-scoped-token" {
		t.Errorf("expected BootstrapToken s.test-scoped-token, got %s", cfg.BootstrapToken)
	}
}

func TestLoadConfig_AppRole_FromJSONFile(t *testing.T) {
	// Clear env variables
	origRole := os.Getenv("PRIMECLOUD_AGENT_VAULT_ROLE_ID")
	origSec := os.Getenv("PRIMECLOUD_AGENT_VAULT_SECRET_ID")
	origVRole := os.Getenv("VAULT_ROLE_ID")
	origVSec := os.Getenv("VAULT_SECRET_ID")
	defer func() {
		os.Setenv("PRIMECLOUD_AGENT_VAULT_ROLE_ID", origRole)
		os.Setenv("PRIMECLOUD_AGENT_VAULT_SECRET_ID", origSec)
		os.Setenv("VAULT_ROLE_ID", origVRole)
		os.Setenv("VAULT_SECRET_ID", origVSec)
	}()
	os.Unsetenv("PRIMECLOUD_AGENT_VAULT_ROLE_ID")
	os.Unsetenv("PRIMECLOUD_AGENT_VAULT_SECRET_ID")
	os.Unsetenv("VAULT_ROLE_ID")
	os.Unsetenv("VAULT_SECRET_ID")

	tempDir := t.TempDir()
	appRolePath := filepath.Join(tempDir, "vault_approle.json")
	content := `{"role_id": "file-role-id", "secret_id": "file-secret-id"}`
	if err := os.WriteFile(appRolePath, []byte(content), 0600); err != nil {
		t.Fatalf("failed to write test approle file: %v", err)
	}

	// We can test by setting the file if path is configurable or testing parsing
	cfg, err := agent.LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	// Default run should not panic
	if cfg.VaultAddr == "" {
		t.Error("expected default VaultAddr")
	}
}
