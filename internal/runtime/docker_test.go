package runtime_test

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/primecloud/primecloud-agent/internal/runtime"
)

func TestEncodeGHCRAuth(t *testing.T) {
	// Empty password should return empty
	if auth := runtime.EncodeGHCRAuth("user", ""); auth != "" {
		t.Fatalf("expected empty auth for empty password, got %s", auth)
	}

	// Default username when empty should be x-access-token
	auth := runtime.EncodeGHCRAuth("", "secret-token")
	if auth == "" {
		t.Fatalf("expected non-empty auth")
	}

	decoded, err := base64.URLEncoding.DecodeString(auth)
	if err != nil {
		// Also try StdEncoding if URLEncoding fails
		decoded, err = base64.StdEncoding.DecodeString(auth)
	}
	if err != nil {
		t.Fatalf("failed to decode auth string: %v", err)
	}

	var parsed struct {
		ServerAddress string `json:"serveraddress"`
		Username      string `json:"username"`
		Password      string `json:"password"`
	}
	if err := json.Unmarshal(decoded, &parsed); err != nil {
		t.Fatalf("failed to unmarshal auth json: %v", err)
	}

	if parsed.Username != "x-access-token" {
		t.Errorf("expected default username 'x-access-token', got '%s'", parsed.Username)
	}
	if parsed.Password != "secret-token" {
		t.Errorf("expected password 'secret-token', got '%s'", parsed.Password)
	}
	if parsed.ServerAddress != "ghcr.io" {
		t.Errorf("expected server address 'ghcr.io', got '%s'", parsed.ServerAddress)
	}
}

func TestGetGHCRAuth_FromEnv(t *testing.T) {
	// Clear env before test
	origUser := os.Getenv("GHCR_USERNAME")
	origTok := os.Getenv("GHCR_TOKEN")
	origGitTok := os.Getenv("GITHUB_TOKEN")
	defer func() {
		os.Setenv("GHCR_USERNAME", origUser)
		os.Setenv("GHCR_TOKEN", origTok)
		os.Setenv("GITHUB_TOKEN", origGitTok)
	}()

	os.Setenv("GHCR_USERNAME", "testuser")
	os.Setenv("GHCR_TOKEN", "testtoken")

	auth := runtime.GetGHCRAuth()
	if auth == "" {
		t.Fatalf("expected non-empty auth from env")
	}

	expected := runtime.EncodeGHCRAuth("testuser", "testtoken")
	if auth != expected {
		t.Errorf("expected %s, got %s", expected, auth)
	}
}

func TestGetGHCRAuth_IgnoresGithubArtifactToken(t *testing.T) {
	// Clear any GHCR env variables
	origUser := os.Getenv("GHCR_USERNAME")
	origTok := os.Getenv("GHCR_TOKEN")
	origGitTok := os.Getenv("GITHUB_TOKEN")
	origPrimeTok := os.Getenv("PRIMECLOUD_GHCR_TOKEN")
	defer func() {
		os.Setenv("GHCR_USERNAME", origUser)
		os.Setenv("GHCR_TOKEN", origTok)
		os.Setenv("GITHUB_TOKEN", origGitTok)
		os.Setenv("PRIMECLOUD_GHCR_TOKEN", origPrimeTok)
	}()
	os.Unsetenv("GHCR_USERNAME")
	os.Unsetenv("GHCR_TOKEN")
	os.Unsetenv("GITHUB_TOKEN")
	os.Unsetenv("PRIMECLOUD_GHCR_TOKEN")

	// Even if /etc/primecloud/credentials/github_artifact_token exists on the filesystem,
	// GetGHCRAuth must not use it. If there are no GHCR credentials or ~/.docker/config.json,
	// it should return "".
	// Note: We test in an environment where ~/.docker/config.json is isolated if needed.
	tempHome := t.TempDir()
	origHome := os.Getenv("USERPROFILE")
	if origHome == "" {
		origHome = os.Getenv("HOME")
	}
	defer func() {
		if os.Getenv("USERPROFILE") != "" {
			os.Setenv("USERPROFILE", origHome)
		} else {
			os.Setenv("HOME", origHome)
		}
	}()
	os.Setenv("USERPROFILE", tempHome)
	os.Setenv("HOME", tempHome)

	auth := runtime.GetGHCRAuth()
	if auth != "" {
		t.Errorf("expected empty auth when no GHCR credentials exist, got: %s", auth)
	}
}

func TestGetGHCRAuth_FromDockerConfig(t *testing.T) {
	tempHome := t.TempDir()
	origHome := os.Getenv("USERPROFILE")
	if origHome == "" {
		origHome = os.Getenv("HOME")
	}
	defer func() {
		if os.Getenv("USERPROFILE") != "" {
			os.Setenv("USERPROFILE", origHome)
		} else {
			os.Setenv("HOME", origHome)
		}
	}()
	os.Setenv("USERPROFILE", tempHome)
	os.Setenv("HOME", tempHome)

	// Clear env variables
	origTok := os.Getenv("GHCR_TOKEN")
	defer os.Setenv("GHCR_TOKEN", origTok)
	os.Unsetenv("GHCR_TOKEN")
	os.Unsetenv("GHCR_USERNAME")
	os.Unsetenv("GITHUB_TOKEN")
	os.Unsetenv("PRIMECLOUD_GHCR_TOKEN")

	dockerDir := filepath.Join(tempHome, ".docker")
	if err := os.MkdirAll(dockerDir, 0700); err != nil {
		t.Fatalf("failed to create .docker dir: %v", err)
	}

	configJSON := `{
		"auths": {
			"ghcr.io": {
				"auth": "ZG9ja2VyY29uZmlndGVzdA=="
			}
		}
	}`
	if err := os.WriteFile(filepath.Join(dockerDir, "config.json"), []byte(configJSON), 0600); err != nil {
		t.Fatalf("failed to write config.json: %v", err)
	}

	auth := runtime.GetGHCRAuth()
	if auth != "ZG9ja2VyY29uZmlndGVzdA==" {
		t.Errorf("expected 'ZG9ja2VyY29uZmlndGVzdA==', got '%s'", auth)
	}
}

func TestBuildEnvSlice_FormatsEntries(t *testing.T) {
	env := map[string]string{
		"PORT":        "8000",
		"NODE_ENV":    "production",
		"SECRET_KEY":  "real-secret-value",
		"DATABASE_URL": "postgresql://user:pass@db:5432/app",
	}

	slice := runtime.BuildEnvSlice(env)
	if len(slice) != 4 {
		t.Fatalf("expected 4 entries in envSlice, got %d", len(slice))
	}

	foundMap := make(map[string]bool)
	for _, entry := range slice {
		foundMap[entry] = true
	}

	expected := []string{
		"PORT=8000",
		"NODE_ENV=production",
		"SECRET_KEY=real-secret-value",
		"DATABASE_URL=postgresql://user:pass@db:5432/app",
	}

	for _, exp := range expected {
		if !foundMap[exp] {
			t.Errorf("expected entry %s to be present in envSlice", exp)
		}
	}

	emptySlice := runtime.BuildEnvSlice(nil)
	if len(emptySlice) != 0 {
		t.Errorf("expected 0 entries for nil env, got %d", len(emptySlice))
	}
}
