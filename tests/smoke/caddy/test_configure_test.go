package caddy_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/primecloud/primecloud-agent/internal/caddy"
)

func TestCaddy_ConfigureRemoveValidateReload(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	tempDir := t.TempDir()
	confDir := filepath.Join(tempDir, "sites-enabled")

	// 1. Setup mock Caddy admin server
	var reloadCalled bool
	adminServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if (r.URL.Path == "/load" && r.Method == http.MethodPost) || (r.URL.Path == "/config/" && r.Method == http.MethodGet) {
			reloadCalled = true
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer adminServer.Close()

	mgr := caddy.NewManager(confDir, adminServer.URL, nil)

	// 2. Test Snippet Generation & Validation
	route := &caddy.RouteConfig{
		Domain:   "api.primecloud.dev",
		Upstream: "127.0.0.1:8080",
		TLS:      true,
		Headers: map[string]string{
			"X-Custom-Auth": "enabled",
		},
		HealthCheckPath: "/healthz",
	}

	snippet, err := caddy.GenerateSnippet(route)
	if err != nil {
		t.Fatalf("GenerateSnippet failed: %v", err)
	}

	if !strings.Contains(snippet, "api.primecloud.dev {") {
		t.Errorf("Snippet missing domain block: %s", snippet)
	}
	if !strings.Contains(snippet, "reverse_proxy 127.0.0.1:8080") {
		t.Errorf("Snippet missing upstream: %s", snippet)
	}

	if err := caddy.ValidateConfig(snippet); err != nil {
		t.Fatalf("ValidateConfig failed on valid snippet: %v", err)
	}

	// 3. Test Invalid Config Validation
	badSnippet := "api.primecloud.dev { reverse_proxy 127.0.0.1:8080 "
	if err := caddy.ValidateConfig(badSnippet); err == nil {
		t.Error("Expected validation error for unclosed brace")
	}

	// 4. Test ConfigureRoute
	if err := mgr.ConfigureRoute(ctx, route); err != nil {
		t.Fatalf("ConfigureRoute failed: %v", err)
	}

	expectedFile := filepath.Join(confDir, "api.primecloud.dev.caddy")
	data, err := os.ReadFile(expectedFile)
	if err != nil {
		t.Fatalf("Failed to read configured file: %v", err)
	}
	if !strings.Contains(string(data), "reverse_proxy 127.0.0.1:8080") {
		t.Errorf("File contents mismatch: %s", string(data))
	}
	if !reloadCalled {
		t.Error("Expected admin reload to be invoked")
	}

	// 5. Test Explicit Reload
	reloadCalled = false
	if err := mgr.Reload(ctx); err != nil {
		t.Fatalf("Explicit Reload failed: %v", err)
	}
	if !reloadCalled {
		t.Error("Expected explicit reload to call admin server")
	}

	// 6. Test RemoveRoute
	if err := mgr.RemoveRoute(ctx, "api.primecloud.dev"); err != nil {
		t.Fatalf("RemoveRoute failed: %v", err)
	}
	if _, err := os.Stat(expectedFile); !os.IsNotExist(err) {
		t.Errorf("Expected route file to be removed, but it still exists")
	}
}
