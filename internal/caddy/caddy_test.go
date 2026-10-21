package caddy

import (
	"context"
	"fmt"
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
				"app.example.com {",
				"reverse_proxy 127.0.0.1:8080 {",
				"header_up Host {host}",
				"header X-Prime-Request-Id {http.request.uuid}",
				"header_up X-Prime-Request-Id {http.request.uuid}",
				"log {",
				"/var/log/primecloud/caddy-access.log",
			},
			wantErr: false,
		},
		{
			name: "valid non-tls route",
			route: &RouteConfig{
				Domain:        "test.local",
				Upstream:      "127.0.0.1:3000",
				TLS:           false,
				AccessLogPath: "/tmp/custom-access.log",
			},
			wantContain: []string{
				"http://test.local {",
				"reverse_proxy 127.0.0.1:3000 {",
				"header X-Prime-Request-Id {http.request.uuid}",
				"header_up X-Prime-Request-Id {http.request.uuid}",
				"log {",
				"/tmp/custom-access.log",
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
			name: "wildcard fallback returns 404",
			route: &RouteConfig{
				Domain: "*.primecloud.cloud",
				TLS:    true,
			},
			wantContain: []string{
				"*.primecloud.cloud {",
				"respond \"Application Not Found\" 404",
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

	validRespond := `app.example.com {
    respond "Application Not Found" 404
}`
	if err := ValidateConfig(validRespond); err != nil {
		t.Errorf("ValidateConfig(validRespond) error = %v", err)
	}

	noRouting := `app.example.com {
    header_up Host {host}
}`
	if err := ValidateConfig(noRouting); err == nil {
		t.Errorf("ValidateConfig(noRouting) expected error, got nil")
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

func TestGenerateSnippet_CustomDomainACMETLS(t *testing.T) {
	tests := []struct {
		name  string
		route *RouteConfig
	}{
		{
			name: "explicit acme tls_mode",
			route: &RouteConfig{
				Domain:   "custom.example.com",
				Upstream: "127.0.0.1:8080",
				TLS:      true,
				TLSMode:  "acme",
			},
		},
		{
			name: "custom_domain flag true",
			route: &RouteConfig{
				Domain:       "custom2.example.com",
				Upstream:     "127.0.0.1:8080",
				TLS:          true,
				CustomDomain: true,
			},
		},
		{
			name: "default public custom domain without tls_mode",
			route: &RouteConfig{
				Domain:   "dashboard.customclient.org",
				Upstream: "127.0.0.1:9000",
				TLS:      true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			snippet, err := GenerateSnippet(tt.route)
			if err != nil {
				t.Fatalf("GenerateSnippet() unexpected error = %v", err)
			}

			// Clean virtual host snippet for Caddy automated ACME
			cleanDomain := strings.TrimSpace(tt.route.Domain)
			if !strings.Contains(snippet, cleanDomain+" {") {
				t.Errorf("Snippet missing site block declaration for %s in:\n%s", cleanDomain, snippet)
			}
			if !strings.Contains(snippet, "reverse_proxy "+tt.route.Upstream) {
				t.Errorf("Snippet missing reverse_proxy in:\n%s", snippet)
			}

			// Must NOT hardcode origin.crt or origin.key
			if strings.Contains(snippet, "origin.crt") || strings.Contains(snippet, "origin.key") {
				t.Errorf("Custom domain snippet must NOT contain origin.crt/key, got:\n%s", snippet)
			}

			// Must NOT output tls internal for public custom domains
			if strings.Contains(snippet, "tls internal") {
				t.Errorf("Custom domain snippet must NOT contain 'tls internal', got:\n%s", snippet)
			}

			// Must pass Caddyfile syntax validation
			if err := ValidateConfig(snippet); err != nil {
				t.Errorf("ValidateConfig failed on generated snippet: %v\nSnippet:\n%s", err, snippet)
			}
		})
	}
}

func TestGenerateSnippet_OriginDomain(t *testing.T) {
	t.Run("with origin cert present", func(t *testing.T) {
		tmpDir := t.TempDir()
		certPath := filepath.Join(tmpDir, "origin.crt")
		keyPath := filepath.Join(tmpDir, "origin.key")

		if err := os.WriteFile(certPath, []byte("fake-cert"), 0644); err != nil {
			t.Fatalf("failed to write fake cert: %v", err)
		}
		if err := os.WriteFile(keyPath, []byte("fake-key"), 0600); err != nil {
			t.Fatalf("failed to write fake key: %v", err)
		}

		t.Setenv("PRIMECLOUD_ORIGIN_CERT_PATH", certPath)
		t.Setenv("PRIMECLOUD_ORIGIN_KEY_PATH", keyPath)

		route := &RouteConfig{
			Domain:   "platform.primecloud.cloud",
			Upstream: "127.0.0.1:8080",
			TLS:      true,
			TLSMode:  "origin",
		}

		snippet, err := GenerateSnippet(route)
		if err != nil {
			t.Fatalf("GenerateSnippet() unexpected error = %v", err)
		}

		expectedTLS := fmt.Sprintf("tls %s %s", certPath, keyPath)
		if !strings.Contains(snippet, expectedTLS) {
			t.Errorf("Snippet missing origin tls directive %q, got:\n%s", expectedTLS, snippet)
		}
		if strings.Contains(snippet, "tls internal") {
			t.Errorf("Snippet should not contain 'tls internal' when origin cert exists, got:\n%s", snippet)
		}

		if err := ValidateConfig(snippet); err != nil {
			t.Errorf("ValidateConfig failed: %v", err)
		}
	})

	t.Run("without origin cert fallback to internal", func(t *testing.T) {
		t.Setenv("PRIMECLOUD_ORIGIN_CERT_PATH", filepath.Join(t.TempDir(), "nonexistent.crt"))
		t.Setenv("PRIMECLOUD_ORIGIN_KEY_PATH", filepath.Join(t.TempDir(), "nonexistent.key"))

		route := &RouteConfig{
			Domain:   "platform.primecloud.cloud",
			Upstream: "127.0.0.1:8080",
			TLS:      true,
			TLSMode:  "origin",
		}

		snippet, err := GenerateSnippet(route)
		if err != nil {
			t.Fatalf("GenerateSnippet() unexpected error = %v", err)
		}

		if !strings.Contains(snippet, "tls internal") {
			t.Errorf("Snippet expected 'tls internal' fallback when origin cert missing, got:\n%s", snippet)
		}

		if err := ValidateConfig(snippet); err != nil {
			t.Errorf("ValidateConfig failed: %v", err)
		}
	})
}

func TestGenerateSnippet_InternalTLS(t *testing.T) {
	t.Run("explicit internal tls_mode", func(t *testing.T) {
		route := &RouteConfig{
			Domain:   "svc.corp.internal",
			Upstream: "127.0.0.1:8080",
			TLS:      true,
			TLSMode:  "internal",
		}

		snippet, err := GenerateSnippet(route)
		if err != nil {
			t.Fatalf("GenerateSnippet() unexpected error: %v", err)
		}

		if !strings.Contains(snippet, "tls internal") {
			t.Errorf("Snippet missing 'tls internal', got:\n%s", snippet)
		}
		if strings.Contains(snippet, "origin.crt") {
			t.Errorf("Internal route must not reference origin.crt, got:\n%s", snippet)
		}

		if err := ValidateConfig(snippet); err != nil {
			t.Errorf("ValidateConfig failed: %v", err)
		}
	})

	t.Run("implicit internal domain .local", func(t *testing.T) {
		route := &RouteConfig{
			Domain:   "app.cluster.local",
			Upstream: "127.0.0.1:3000",
			TLS:      true,
			TLSMode:  "",
		}

		snippet, err := GenerateSnippet(route)
		if err != nil {
			t.Fatalf("GenerateSnippet() unexpected error: %v", err)
		}

		if !strings.Contains(snippet, "tls internal") {
			t.Errorf("Expected 'tls internal' for .local domain, got:\n%s", snippet)
		}

		if err := ValidateConfig(snippet); err != nil {
			t.Errorf("ValidateConfig failed: %v", err)
		}
	})
}

func TestGenerateSnippet_UpstreamHostPortMapping(t *testing.T) {
	upstreams := []string{
		"127.0.0.1:8080",
		"127.0.0.1:32768",
		"10.0.1.15:4000",
		"backend.service:9000",
	}

	for _, up := range upstreams {
		t.Run("upstream_"+up, func(t *testing.T) {
			route := &RouteConfig{
				Domain:   "api.example.com",
				Upstream: up,
				TLS:      true,
				TLSMode:  "acme",
			}

			snippet, err := GenerateSnippet(route)
			if err != nil {
				t.Fatalf("GenerateSnippet() error = %v", err)
			}

			expectedProxy := fmt.Sprintf("reverse_proxy %s {", up)
			if !strings.Contains(snippet, expectedProxy) {
				t.Errorf("Snippet missing %q in:\n%s", expectedProxy, snippet)
			}
			if !strings.Contains(snippet, "header_up Host {host}") {
				t.Errorf("Snippet missing Host header forward in:\n%s", snippet)
			}
			if !strings.Contains(snippet, "header_up X-Prime-Request-Id {http.request.uuid}") {
				t.Errorf("Snippet missing X-Prime-Request-Id header forward in:\n%s", snippet)
			}
		})
	}
}

func TestGenerateSnippet_MalformedHostnameRejection(t *testing.T) {
	badHostnames := []struct {
		name     string
		hostname string
	}{
		{"empty", ""},
		{"whitespace", "   "},
		{"ipv4 loopback literal", "127.0.0.1"},
		{"ipv6 loopback literal", "::1"},
		{"ipv4 private literal", "192.168.1.1"},
		{"ipv4 zero literal", "0.0.0.0"},
		{"cloud metadata ipv4", "169.254.169.254"},
		{"loopback localhost", "localhost"},
		{"loopback sub localhost", "api.localhost"},
		{"gcp metadata domain", "metadata.google.internal"},
		{"sub gcp metadata domain", "worker.metadata.google.internal"},
		{"aws metadata domain", "instance-data"},
		{"metadata word", "metadata"},
		{"path traversal slash", "example.com/../etc/passwd"},
		{"path component slash", "example.com/path"},
		{"backslash path", "example.com\\path"},
		{"port in hostname", "example.com:8080"},
		{"consecutive dots", "app..example.com"},
		{"leading dot", ".example.com"},
		{"trailing dot", "example.com."},
		{"leading hyphen in label", "-example.com"},
		{"trailing hyphen in label", "example-.com"},
		{"invalid underscore", "app_service.example.com"},
		{"all numeric tld", "example.123"},
		{"single label", "singlename"},
		{"wildcard in middle", "sub.*.example.com"},
		{"wildcard missing dot", "*example.com"},
		{"label exceeding 63 chars", strings.Repeat("a", 64) + ".example.com"},
		{"domain exceeding 253 chars", strings.Repeat("a.b", 86) + ".com"},
	}

	for _, tc := range badHostnames {
		t.Run(tc.name, func(t *testing.T) {
			route := &RouteConfig{
				Domain:   tc.hostname,
				Upstream: "127.0.0.1:8080",
				TLS:      true,
			}

			snippet, err := GenerateSnippet(route)
			if err == nil {
				t.Errorf("GenerateSnippet() expected error for invalid hostname %q, got snippet:\n%s", tc.hostname, snippet)
			}
		})
	}
}

func TestManager_RouteRemovalAndCleanup(t *testing.T) {
	tmpDir := t.TempDir()

	adminServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer adminServer.Close()

	mgr := NewManager(tmpDir, adminServer.URL, nil)
	ctx := context.Background()

	// Pre-create an unrelated customer route
	unrelatedRoute := &RouteConfig{
		Domain:   "unrelated-app.domain.com",
		Upstream: "127.0.0.1:7000",
		TLS:      true,
		TLSMode:  "acme",
	}
	if err := mgr.ConfigureRoute(ctx, unrelatedRoute); err != nil {
		t.Fatalf("Failed to configure unrelated route: %v", err)
	}

	unrelatedFile := filepath.Join(tmpDir, "unrelated-app.domain.com.caddy")
	if _, err := os.Stat(unrelatedFile); err != nil {
		t.Fatalf("Expected unrelated route file to exist: %v", err)
	}

	// Configure target route
	targetRoute := &RouteConfig{
		Domain:       "custom-shop.mystore.org",
		Upstream:     "127.0.0.1:8080",
		TLS:          true,
		TLSMode:      "acme",
		CustomDomain: true,
	}
	if err := mgr.ConfigureRoute(ctx, targetRoute); err != nil {
		t.Fatalf("Failed to configure target route: %v", err)
	}

	targetFile := filepath.Join(tmpDir, "custom-shop.mystore.org.caddy")
	content, err := os.ReadFile(targetFile)
	if err != nil {
		t.Fatalf("Expected target route file to exist: %v", err)
	}
	if strings.Contains(string(content), "origin.crt") {
		t.Errorf("Target route file must not contain origin.crt")
	}

	// Remove target route
	if err := mgr.RemoveRoute(ctx, "custom-shop.mystore.org"); err != nil {
		t.Fatalf("RemoveRoute failed: %v", err)
	}

	// Verify target file is removed
	if _, err := os.Stat(targetFile); !os.IsNotExist(err) {
		t.Errorf("Expected target route file %s to be deleted", targetFile)
	}

	// Verify unrelated route is still present and intact
	if _, err := os.Stat(unrelatedFile); err != nil {
		t.Errorf("Unrelated route was unexpectedly deleted or corrupted: %v", err)
	}

	// Verify idempotent removal succeeds
	if err := mgr.RemoveRoute(ctx, "custom-shop.mystore.org"); err != nil {
		t.Errorf("Expected idempotent RemoveRoute to succeed, got: %v", err)
	}
}

