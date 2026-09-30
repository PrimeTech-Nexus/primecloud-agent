package caddy

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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

	noProxy := `app.example.com {
    respond "hello"
}`
	if err := ValidateConfig(noProxy); err == nil {
		t.Errorf("ValidateConfig(noProxy) expected error, got nil")
	}
}

func TestManager_ConfigureAndRemoveRoute(t *testing.T) {
	tmpDir := t.TempDir()
	mgr := NewManager(tmpDir, "http://127.0.0.1:19999", nil)

	ctx := context.Background()
	route := &RouteConfig{
		Domain:   "test.primecloud.cloud",
		Upstream: "127.0.0.1:32768",
		TLS:      true,
	}

	// Configure route
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

	// Remove route
	if err := mgr.RemoveRoute(ctx, "test.primecloud.cloud"); err != nil {
		t.Fatalf("RemoveRoute() failed: %v", err)
	}

	if _, err := os.Stat(expectedFile); !os.IsNotExist(err) {
		t.Errorf("Expected route file to be removed, but still exists")
	}
}
