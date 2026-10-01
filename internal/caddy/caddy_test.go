package caddy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCanonicalPath(t *testing.T) {
	mgr := NewManager("", "", nil)
	if got := mgr.ConfigDir(); got != "/etc/caddy/sites-enabled" {
		t.Fatalf("expected canonical path /etc/caddy/sites-enabled, got %q", got)
	}
}

func TestNoConfDReferences(t *testing.T) {
	mgr := NewManager("", "", nil)
	if strings.Contains(mgr.ConfigDir(), "conf.d") {
		t.Fatalf("Manager configDir must not contain conf.d, got %q", mgr.ConfigDir())
	}
}

func TestGenerateSnippet(t *testing.T) {
	tests := []struct {
		name        string
		route       *RouteConfig
		wantContain []string
		wantErr     bool
	}{
		{
			name: "valid tls route",
			route: &RouteConfig{
				Domain:   "app.example.com",
				Upstream: "127.0.0.1:8080",
				TLS:      true,
			},
			wantContain: []string{
				"http://app.example.com, https://app.example.com {",
				"reverse_proxy 127.0.0.1:8080 {",
				"header_up Host {host}",
			},
			wantErr: false,
		},
		{
			name: "valid non-tls route",
			route: &RouteConfig{
				Domain:   "test.local",
				Upstream: "127.0.0.1:3000",
				TLS:      false,
			},
			wantContain: []string{
				"http://test.local {",
				"reverse_proxy 127.0.0.1:3000 {",
			},
			wantErr: false,
		},
		{
			name: "route with headers and health check",
			route: &RouteConfig{
				Domain:          "headers.example.com",
				Upstream:        "127.0.0.1:4000",
				TLS:             true,
				Headers:         map[string]string{"X-App-Env": "production"},
				HealthCheckPath: "/health",
			},
			wantContain: []string{
				"header_up X-App-Env \"production\"",
				"health_path /health",
			},
			wantErr: false,
		},
		{
			name:    "nil config",
			route:   nil,
			wantErr: true,
		},
		{
			name: "empty domain",
			route: &RouteConfig{
				Domain:   "",
				Upstream: "127.0.0.1:8080",
			},
			wantErr: true,
		},
		{
			name: "empty upstream",
			route: &RouteConfig{
				Domain:   "app.com",
				Upstream: "",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GenerateSnippet(tt.route)
			if (err != nil) != tt.wantErr {
				t.Fatalf("GenerateSnippet() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr {
				for _, sub := range tt.wantContain {
					if !strings.Contains(got, sub) {
						t.Errorf("GenerateSnippet() missing expected substring %q in:\n%s", sub, got)
					}
				}
			}
		})
	}
}

func TestValidateConfig(t *testing.T) {
	valid := `app.example.com {
    reverse_proxy 127.0.0.1:8080
}`
	if err := ValidateConfig(valid); err != nil {
		t.Errorf("ValidateConfig(valid) error = %v", err)
	}

	unclosed := `app.example.com {
    reverse_proxy 127.0.0.1:8080
`
	if err := ValidateConfig(unclosed); err == nil {
		t.Errorf("ValidateConfig(unclosed) expected error, got nil")
	}

	mismatched := `app.example.com {
    reverse_proxy 127.0.0.1:8080
}}`
	if err := ValidateConfig(mismatched); err == nil {
		t.Errorf("ValidateConfig(mismatched) expected error, got nil")
	}

	noProxy := `app.example.com {
    respond "hello"
}`
	if err := ValidateConfig(noProxy); err == nil {
		t.Errorf("ValidateConfig(noProxy) expected error, got nil")
	}

	empty := `   `
	if err := ValidateConfig(empty); err == nil {
		t.Errorf("ValidateConfig(empty) expected error, got nil")
	}
}

func TestManager_ConfigureAndRemoveRoute(t *testing.T) {
	tmpDir := t.TempDir()

	adminServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer adminServer.Close()

	mgr := NewManager(tmpDir, adminServer.URL, nil)

	ctx := context.Background()
	route := &RouteConfig{
		Domain:   "test.primecloud.cloud",
		Upstream: "127.0.0.1:32768",
		TLS:      true,
	}

	// 1. Configure route
	if err := mgr.ConfigureRoute(ctx, route); err != nil {
		t.Fatalf("ConfigureRoute() failed: %v", err)
	}

	expectedFile := filepath.Join(tmpDir, "test.primecloud.cloud.caddy")
	data, err := os.ReadFile(expectedFile)
	if err != nil {
		t.Fatalf("Failed to read created route file: %v", err)
	}

	content := string(data)
	if !strings.Contains(content, "reverse_proxy 127.0.0.1:32768") {
		t.Errorf("Config file content missing upstream: %s", content)
	}

	// Ensure no .tmp files remain
	tmpFile := expectedFile + ".tmp"
	if _, err := os.Stat(tmpFile); !os.IsNotExist(err) {
		t.Errorf("Temporary file %s was not cleaned up", tmpFile)
	}

	// 2. Remove route
	if err := mgr.RemoveRoute(ctx, "test.primecloud.cloud"); err != nil {
		t.Fatalf("RemoveRoute() failed: %v", err)
	}

	if _, err := os.Stat(expectedFile); !os.IsNotExist(err) {
		t.Errorf("Expected route file to be removed, but still exists")
	}
}

func TestManager_AtomicUpdateDuplicateRoute(t *testing.T) {
	tmpDir := t.TempDir()

	adminServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer adminServer.Close()

	mgr := NewManager(tmpDir, adminServer.URL, nil)
	ctx := context.Background()

	route1 := &RouteConfig{
		Domain:   "duplicate.primecloud.cloud",
		Upstream: "127.0.0.1:3000",
		TLS:      true,
	}
	if err := mgr.ConfigureRoute(ctx, route1); err != nil {
		t.Fatalf("ConfigureRoute route1 failed: %v", err)
	}

	expectedFile := filepath.Join(tmpDir, "duplicate.primecloud.cloud.caddy")
	data1, _ := os.ReadFile(expectedFile)
	if !strings.Contains(string(data1), "127.0.0.1:3000") {
		t.Fatalf("Expected 127.0.0.1:3000 in route file")
	}

	// Reconfigure same domain with different upstream
	route2 := &RouteConfig{
		Domain:   "duplicate.primecloud.cloud",
		Upstream: "127.0.0.1:4000",
		TLS:      true,
	}
	if err := mgr.ConfigureRoute(ctx, route2); err != nil {
		t.Fatalf("ConfigureRoute route2 failed: %v", err)
	}

	data2, _ := os.ReadFile(expectedFile)
	if !strings.Contains(string(data2), "127.0.0.1:4000") {
		t.Fatalf("Expected atomic overwrite with 127.0.0.1:4000, got: %s", string(data2))
	}
	if strings.Contains(string(data2), "127.0.0.1:3000") {
		t.Fatalf("Old upstream 127.0.0.1:3000 remained after atomic update")
	}
}

func TestManager_ReloadFailurePropagatesOnConfigure(t *testing.T) {
	tmpDir := t.TempDir()

	// Unreachable admin port with no local Caddy CLI
	mgr := NewManager(tmpDir, "http://127.0.0.1:1", nil)

	ctx := context.Background()
	route := &RouteConfig{
		Domain:   "reload-fail.primecloud.cloud",
		Upstream: "127.0.0.1:8080",
		TLS:      true,
	}

	err := mgr.ConfigureRoute(ctx, route)
	if err == nil {
		t.Fatalf("Expected ConfigureRoute to fail when Caddy reload fails")
	}

	if !strings.Contains(err.Error(), "failed to reload caddy") {
		t.Errorf("Expected 'failed to reload caddy' in error message, got: %v", err)
	}

	// Ensure file is cleaned up after reload failure so no stale route exists
	targetFile := filepath.Join(tmpDir, "reload-fail.primecloud.cloud.caddy")
	if _, statErr := os.Stat(targetFile); !os.IsNotExist(statErr) {
		t.Errorf("Expected target file to be cleaned up after reload failure, but it exists")
	}
}

func TestManager_ReloadFailurePropagatesOnRemove(t *testing.T) {
	tmpDir := t.TempDir()

	// Pre-create route file
	targetFile := filepath.Join(tmpDir, "remove-reload-fail.caddy")
	if err := os.WriteFile(targetFile, []byte("test"), 0644); err != nil {
		t.Fatalf("Failed to create pre-existing route file: %v", err)
	}

	// Unreachable admin port
	mgr := NewManager(tmpDir, "http://127.0.0.1:1", nil)

	ctx := context.Background()
	err := mgr.RemoveRoute(ctx, "remove-reload-fail")
	if err == nil {
		t.Fatalf("Expected RemoveRoute to fail when Caddy reload fails")
	}

	if !strings.Contains(err.Error(), "failed to reload caddy") {
		t.Errorf("Expected 'failed to reload caddy' in error message, got: %v", err)
	}
}

func TestManager_ValidationFailurePropagates(t *testing.T) {
	tmpDir := t.TempDir()
	mgr := NewManager(tmpDir, "http://127.0.0.1:2019", nil)

	ctx := context.Background()
	// Route with empty domain
	err := mgr.ConfigureRoute(ctx, &RouteConfig{
		Domain:   "",
		Upstream: "127.0.0.1:8080",
	})
	if err == nil {
		t.Fatalf("Expected error for empty domain")
	}

	// Route with empty upstream
	err = mgr.ConfigureRoute(ctx, &RouteConfig{
		Domain:   "app.com",
		Upstream: "",
	})
	if err == nil {
		t.Fatalf("Expected error for empty upstream")
	}
}
