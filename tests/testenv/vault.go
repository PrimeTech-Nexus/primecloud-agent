// Package testenv provides utilities for managing real local test services (Vault, PKI, etc.).
package testenv

import (
	"context"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	vaultapi "github.com/hashicorp/vault/api"
	"github.com/primecloud/primecloud-agent/internal/vault"
)

const (
	DefaultVaultAddr  = "http://127.0.0.1:8200"
	DefaultVaultToken = "root"
)

var pkiMu sync.Mutex

// EnsureVaultDev ensures a real local Vault dev server is running on 127.0.0.1:8200 with PKI configured.
func EnsureVaultDev(t *testing.T) (*vault.Client, string) {
	t.Helper()

	addr := os.Getenv("VAULT_ADDR")
	if addr == "" {
		addr = DefaultVaultAddr
	}
	token := os.Getenv("VAULT_TOKEN")
	if token == "" {
		token = DefaultVaultToken
	}

	client, err := vault.NewClient(vault.Config{
		Address: addr,
		Token:   token,
		Timeout: 5 * time.Second,
	})
	if err == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		healthy, _ := client.IsHealthy(ctx)
		cancel()
		if healthy {
			ConfigurePKI(t, client)
			return client, token
		}
	}

	// Find vault executable
	vaultExe := findVaultExe()
	if vaultExe == "" {
		t.Skip("vault executable not found on host; skipping test requiring real Vault")
		return nil, ""
	}

	cmd := exec.Command(vaultExe, "server", "-dev", "-dev-listen-address=127.0.0.1:8200", "-dev-root-token-id="+token)
	if err := cmd.Start(); err != nil {
		t.Fatalf("Failed to start real Vault dev server: %v", err)
	}

	// Wait up to 5 seconds for Vault to listen on 127.0.0.1:8200
	ready := false
	for i := 0; i < 25; i++ {
		conn, err := net.DialTimeout("tcp", "127.0.0.1:8200", 200*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			ready = true
			break
		}
		time.Sleep(200 * time.Millisecond)
	}

	if !ready {
		t.Fatal("Real Vault dev server failed to start listening on 127.0.0.1:8200")
	}

	client, err = vault.NewClient(vault.Config{
		Address: addr,
		Token:   token,
		Timeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("Failed to initialize vault client after startup: %v", err)
	}

	ConfigurePKI(t, client)
	return client, token
}

// ConfigurePKI configures the root CA, intermediate CA, and agent role on Vault.
func ConfigurePKI(t *testing.T, client *vault.Client) {
	t.Helper()

	pkiMu.Lock()
	defer pkiMu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	raw := client.RawClient()

	// If role agent already exists and KV mounted, configuration is already complete
	if role, err := raw.Logical().ReadWithContext(ctx, "pki_int/roles/agent"); err == nil && role != nil && role.Data != nil {
		return
	}

	// 1. Enable and configure root PKI
	_ = raw.Sys().MountWithContext(ctx, "pki", &vaultapi.MountInput{
		Type: "pki",
		Config: vaultapi.MountConfigInput{
			MaxLeaseTTL: "87600h",
		},
	})

	_, _ = raw.Logical().WriteWithContext(ctx, "pki/root/generate/internal", map[string]interface{}{
		"common_name": "primecloud.internal",
		"ttl":         "87600h",
	})

	// 2. Enable and configure intermediate PKI
	_ = raw.Sys().MountWithContext(ctx, "pki_int", &vaultapi.MountInput{
		Type: "pki",
		Config: vaultapi.MountConfigInput{
			MaxLeaseTTL: "43800h",
		},
	})

	csrSecret, err := raw.Logical().WriteWithContext(ctx, "pki_int/intermediate/generate/internal", map[string]interface{}{
		"common_name": "primecloud.internal Intermediate Authority",
		"ttl":         "43800h",
	})
	if err == nil && csrSecret != nil && csrSecret.Data != nil {
		csr, _ := csrSecret.Data["csr"].(string)
		if csr != "" {
			certSecret, err := raw.Logical().WriteWithContext(ctx, "pki/root/sign-intermediate", map[string]interface{}{
				"csr":    csr,
				"format": "pem_bundle",
				"ttl":    "43800h",
			})
			if err == nil && certSecret != nil && certSecret.Data != nil {
				cert, _ := certSecret.Data["certificate"].(string)
				if cert != "" {
					_, _ = raw.Logical().WriteWithContext(ctx, "pki_int/intermediate/set-signed", map[string]interface{}{
						"certificate": cert,
					})
				}
			}
		}
	}

	// 3. Configure agent role
	_, err = raw.Logical().WriteWithContext(ctx, "pki_int/roles/agent", map[string]interface{}{
		"allowed_domains":    "primecloud.internal,agent.primecloud.internal,localhost,127.0.0.1",
		"allow_subdomains":   true,
		"allow_bare_domains": true,
		"allow_localhost":    true,
		"allow_ip_sans":      true,
		"max_ttl":            "720h",
		"ttl":                "24h",
	})
	if err != nil {
		t.Fatalf("Failed to configure pki_int/roles/agent: %v", err)
	}

	// 4. Enable kv secrets engine at primecloud
	_ = raw.Sys().MountWithContext(ctx, "primecloud", &vaultapi.MountInput{
		Type: "kv",
	})
}

func findVaultExe() string {
	if path, err := exec.LookPath("vault"); err == nil {
		return path
	}
	userProfile := os.Getenv("USERPROFILE")
	candidates := []string{
		filepath.Join(userProfile, ".gemini", "antigravity", "tools", "vault.exe"),
		`C:\ProgramData\chocolatey\bin\vault.exe`,
		`C:\tools\vault.exe`,
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	return ""
}
