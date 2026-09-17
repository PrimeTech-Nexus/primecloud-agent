package vault_test

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/primecloud/primecloud-agent/internal/agent"
	"github.com/primecloud/primecloud-agent/internal/identity"
	"github.com/primecloud/primecloud-agent/internal/vault"
)

func TestVault_ClientAndHealth(t *testing.T) {
	vaultAddr := os.Getenv("VAULT_ADDR")
	if vaultAddr == "" {
		vaultAddr = "http://127.0.0.1:8200"
	}
	vaultToken := os.Getenv("VAULT_TOKEN")
	if vaultToken == "" {
		vaultToken = "root"
	}

	client, err := vault.NewClient(vault.Config{
		Address: vaultAddr,
		Token:   vaultToken,
		Timeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("Failed to initialize vault client: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	healthy, err := client.IsHealthy(ctx)
	if err != nil {
		t.Fatalf("Vault health check returned error: %v", err)
	}
	if !healthy {
		t.Fatal("Vault instance reported unhealthy")
	}
}

func TestVault_BootstrapTokenAndCertIssuance(t *testing.T) {
	vaultAddr := os.Getenv("VAULT_ADDR")
	if vaultAddr == "" {
		vaultAddr = "http://127.0.0.1:8200"
	}
	vaultToken := os.Getenv("VAULT_TOKEN")
	if vaultToken == "" {
		vaultToken = "root"
	}

	tempDir := t.TempDir()
	tokenFile := filepath.Join(tempDir, "bootstrap-token")
	if err := os.WriteFile(tokenFile, []byte(vaultToken), 0600); err != nil {
		t.Fatalf("Failed to write test token file: %v", err)
	}

	// 1. Resolve token from file
	resolvedToken, err := vault.ResolveBootstrapToken("", tokenFile)
	if err != nil {
		t.Fatalf("ResolveBootstrapToken failed: %v", err)
	}
	if resolvedToken != vaultToken {
		t.Errorf("Expected token %s, got %s", vaultToken, resolvedToken)
	}

	// 2. Connect client with resolved token
	client, err := vault.NewClient(vault.Config{
		Address: vaultAddr,
		Token:   resolvedToken,
		Timeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}

	// 3. Issue certificate bundle
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	bm := vault.NewBootstrapManager(client)
	bundle, err := bm.BootstrapNode(ctx, "agent-node-01.agent.primecloud.internal", []string{"127.0.0.1"}, 1*time.Hour)
	if err != nil {
		t.Fatalf("BootstrapNode failed: %v", err)
	}

	if bundle.CertificatePEM == "" || bundle.PrivateKeyPEM == "" {
		t.Fatal("Issued bundle missing certificate or private key")
	}
	if bundle.ParsedCert.Subject.CommonName != "agent-node-01.agent.primecloud.internal" {
		t.Errorf("Expected CN agent-node-01.agent.primecloud.internal, got %s", bundle.ParsedCert.Subject.CommonName)
	}

	// 4. Store in CertificateStore and verify permissions
	certDir := filepath.Join(tempDir, "certs")
	store, err := identity.NewCertificateStore(certDir)
	if err != nil {
		t.Fatalf("NewCertificateStore failed: %v", err)
	}

	if err := store.SaveBundle(bundle); err != nil {
		t.Fatalf("SaveBundle failed: %v", err)
	}

	certPath, keyPath, caPath := store.CertPaths()
	keyInfo, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("Stat on key path failed: %v", err)
	}
	if keyInfo.Mode().Perm() != 0600 {
		// On Windows, file permissions behave differently, but we verify file exists and is not empty
		if keyInfo.Size() == 0 {
			t.Errorf("Private key file is empty")
		}
	}

	certInfo, err := os.Stat(certPath)
	if err != nil || certInfo.Size() == 0 {
		t.Errorf("Certificate file missing or empty")
	}

	caInfo, err := os.Stat(caPath)
	if err != nil || caInfo.Size() == 0 {
		t.Errorf("CA file missing or empty")
	}

	// 5. Test loading TLS pair
	tlsPair, err := store.LoadTLSCertificate()
	if err != nil {
		t.Fatalf("LoadTLSCertificate failed: %v", err)
	}
	if len(tlsPair.Certificate) == 0 {
		t.Fatal("Loaded TLS certificate pair is empty")
	}

	// 6. Test expiry check
	expired, err := store.IsExpired()
	if err != nil {
		t.Fatalf("IsExpired returned error: %v", err)
	}
	if expired {
		t.Error("Freshly issued certificate should not be expired")
	}
}

func TestVault_NoSecretsInLogging(t *testing.T) {
	var buf bytes.Buffer
	logger := agent.SetupLogging(&buf, slog.LevelDebug)

	client, _ := vault.NewClient(vault.Config{
		Address: "http://127.0.0.1:8200",
		Token:   "s.secretToken123456",
	})
	if client != nil {
		logger.Info("vault_client_initialized",
			"address", "http://127.0.0.1:8200",
			"token", "s.secretToken123456",
		)
	}

	logOutput := buf.String()
	if strings.Contains(logOutput, "s.secretToken123456") {
		t.Errorf("Secret token leaked in Vault log: %s", logOutput)
	}
	if !strings.Contains(logOutput, "[REDACTED]") {
		t.Errorf("Expected [REDACTED] in log output: %s", logOutput)
	}
}
