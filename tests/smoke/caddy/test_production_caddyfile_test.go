package caddy_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/primecloud/primecloud-agent/internal/caddy"
)

func TestProductionLikeCompleteCaddyfileIntegration(t *testing.T) {
	// Look up caddy executable on PATH or in TEMP
	caddyBin, err := exec.LookPath("caddy")
	if err != nil || caddyBin == "" {
		tempBin := filepath.Join(os.Getenv("TEMP"), "caddy_bin", "caddy.exe")
		if _, statErr := os.Stat(tempBin); statErr == nil {
			caddyBin = tempBin
		} else {
			t.Skip("caddy binary not found, skipping real caddy validate execution")
		}
	}

	tempDir := t.TempDir()
	confDir := filepath.Join(tempDir, "sites-enabled")
	certsDir := filepath.Join(tempDir, "certs")
	if err := os.MkdirAll(certsDir, 0755); err != nil {
		t.Fatalf("failed to create certs dir: %v", err)
	}

	// Create dummy origin cert and key
	certFile := filepath.Join(certsDir, "origin.crt")
	keyFile := filepath.Join(certsDir, "origin.key")
	_ = os.WriteFile(certFile, []byte("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"), 0644)
	_ = os.WriteFile(keyFile, []byte("-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----\n"), 0600)

	// Mock Caddy admin server
	adminServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/config/" && r.Method == http.MethodGet {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer adminServer.Close()

	mgr := caddy.NewManager(confDir, adminServer.URL, nil)
	ctx := context.Background()

	// 1. Configure Customer A: platelikbackend.primecloud.cloud -> 127.0.0.1:32768
	routeA := &caddy.RouteConfig{
		Domain:   "platelikbackend.primecloud.cloud",
		Upstream: "127.0.0.1:32768",
		TLS:      true,
	}
	if err := mgr.ConfigureRoute(ctx, routeA); err != nil {
		t.Fatalf("ConfigureRoute Customer A failed: %v", err)
	}

	// 2. Configure Customer B: customer-b.primecloud.cloud -> 127.0.0.1:32769
	routeB := &caddy.RouteConfig{
		Domain:   "customer-b.primecloud.cloud",
		Upstream: "127.0.0.1:32769",
		TLS:      true,
	}
	if err := mgr.ConfigureRoute(ctx, routeB); err != nil {
		t.Fatalf("ConfigureRoute Customer B failed: %v", err)
	}

	fileA := filepath.Join(confDir, "platelikbackend.primecloud.cloud.caddy")
	fileB := filepath.Join(confDir, "customer-b.primecloud.cloud.caddy")

	dataA, errA := os.ReadFile(fileA)
	if errA != nil {
		t.Fatalf("Failed to read fileA: %v", errA)
	}
	dataB, errB := os.ReadFile(fileB)
	if errB != nil {
		t.Fatalf("Failed to read fileB: %v", errB)
	}

	// Verify syntax generated
	if !strings.HasPrefix(string(dataA), "platelikbackend.primecloud.cloud {\n") {
		t.Fatalf("fileA missing expected domain block header: %s", string(dataA))
	}
	if strings.Contains(string(dataA), "http://") && strings.Contains(string(dataA), "tls ") {
		t.Fatalf("fileA illegally combines http:// and tls directive")
	}
	if strings.Contains(string(dataA), "header_up X-Forwarded-For") {
		t.Fatalf("fileA contains redundant X-Forwarded-For")
	}

	// Construct Complete Production Master Caddyfile
	// In the real system, Caddyfile imports /etc/caddy/sites-enabled/*.caddy
	// For local test validation, we concatenate the master Caddyfile and the customer route files
	masterCaddyfile := fmt.Sprintf(`{
    admin off
}

api.primecloud.cloud {
    tls internal
    reverse_proxy 127.0.0.1:8000
}

# --- CUSTOMER A ROUTE ---
%s

# --- CUSTOMER B ROUTE ---
%s
`, string(dataA), string(dataB))

	masterCaddyfilePath := filepath.Join(tempDir, "Caddyfile")
	if err := os.WriteFile(masterCaddyfilePath, []byte(masterCaddyfile), 0644); err != nil {
		t.Fatalf("Failed to write master Caddyfile: %v", err)
	}

	// Execute `caddy validate --adapter caddyfile --config <masterCaddyfilePath>`
	cmd := exec.Command(caddyBin, "validate", "--adapter", "caddyfile", "--config", masterCaddyfilePath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Full Caddy validation failed with output:\n%s\nError: %v", string(out), err)
	}
	t.Logf("Full Caddy validation succeeded:\n%s", string(out))

	// 3. Test Coexistence & Isolation: Removing Customer A preserves Customer B
	if err := mgr.RemoveRoute(ctx, "platelikbackend.primecloud.cloud"); err != nil {
		t.Fatalf("RemoveRoute Customer A failed: %v", err)
	}
	if _, statA := os.Stat(fileA); !os.IsNotExist(statA) {
		t.Fatalf("Expected fileA to be removed")
	}
	if _, statB := os.Stat(fileB); statB != nil {
		t.Fatalf("Expected fileB to remain intact after removing A: %v", statB)
	}

	// Validate remaining config with only Customer B
	masterOnlyB := fmt.Sprintf(`{
    admin off
}
api.primecloud.cloud {
    tls internal
    reverse_proxy 127.0.0.1:8000
}
%s
`, string(dataB))
	if err := os.WriteFile(masterCaddyfilePath, []byte(masterOnlyB), 0644); err != nil {
		t.Fatalf("Failed to write masterOnlyB: %v", err)
	}
	cmdB := exec.Command(caddyBin, "validate", "--adapter", "caddyfile", "--config", masterCaddyfilePath)
	outB, errB := cmdB.CombinedOutput()
	if errB != nil {
		t.Fatalf("Caddy validation for remaining Customer B failed:\n%s\nError: %v", string(outB), errB)
	}
	t.Logf("Caddy validation for remaining Customer B succeeded:\n%s", string(outB))

	// 4. Test Failure Isolation: Failed configuration for Customer C does not affect Customer B
	badRouteC := &caddy.RouteConfig{
		Domain:   "invalid domain name with spaces!!!",
		Upstream: "127.0.0.1:32770",
		TLS:      true,
	}
	if err := mgr.ConfigureRoute(ctx, badRouteC); err == nil {
		t.Fatalf("Expected ConfigureRoute to reject badRouteC, but got nil error")
	}

	// Verify Customer B is completely intact and unchanged
	dataBAfter, errBAfter := os.ReadFile(fileB)
	if errBAfter != nil {
		t.Fatalf("fileB missing after badRouteC rejection: %v", errBAfter)
	}
	if string(dataBAfter) != string(dataB) {
		t.Fatalf("fileB content modified by invalid Customer C attempt")
	}
}
