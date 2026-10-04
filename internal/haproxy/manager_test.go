package haproxy

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGenerateTCPSnippet(t *testing.T) {
	route := &TCPRouteConfig{
		ID:          "postgres-1",
		Port:        30005,
		ContainerIP: "172.18.0.2",
		TargetPort:  5432,
	}

	snippet, err := GenerateTCPSnippet(route)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(snippet, "frontend fe_tcp_postgres-1") {
		t.Errorf("missing frontend declaration in snippet: %s", snippet)
	}
	if !strings.Contains(snippet, "bind *:30005") {
		t.Errorf("missing bind port: %s", snippet)
	}
	if !strings.Contains(snippet, "mode tcp") {
		t.Errorf("missing mode tcp: %s", snippet)
	}
	if !strings.Contains(snippet, "server srv_postgres-1 172.18.0.2:5432 check") {
		t.Errorf("missing backend server line: %s", snippet)
	}
	if strings.Contains(snippet, "reverse_proxy") {
		t.Errorf("snippet must not contain HTTP reverse_proxy: %s", snippet)
	}
}

func TestValidateConfig(t *testing.T) {
	validSnippet := `
frontend fe_tcp_test
    bind *:30001
    mode tcp
    default_backend be_tcp_test

backend be_tcp_test
    mode tcp
    server srv_test 10.0.0.1:5432 check
`
	if err := ValidateConfig(validSnippet); err != nil {
		t.Errorf("expected valid snippet to pass: %v", err)
	}

	invalidHTTP := `
:30001 {
    reverse_proxy 10.0.0.1:5432
}
`
	if err := ValidateConfig(invalidHTTP); err == nil {
		t.Errorf("expected HTTP reverse_proxy to be rejected")
	}

	missingTCP := `
frontend fe_tcp_test
    bind *:30001
`
	if err := ValidateConfig(missingTCP); err == nil {
		t.Errorf("expected missing mode tcp to be rejected")
	}
}

func TestConfigureAndRemoveTCPRoute(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "haproxy_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	mgr := NewManager(tmpDir, nil)

	route := &TCPRouteConfig{
		ID:          "valkey-res-42",
		Port:        30009,
		ContainerIP: "172.18.0.3",
		TargetPort:  6379,
	}

	ctx := context.Background()
	if err := mgr.ConfigureTCPRoute(ctx, route); err != nil {
		t.Fatalf("ConfigureTCPRoute failed: %v", err)
	}

	cfgPath := filepath.Join(tmpDir, "tcp_valkey-res-42.cfg")
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("expected config file to exist: %v", err)
	}

	content := string(data)
	if !strings.Contains(content, "bind *:30009") || !strings.Contains(content, "mode tcp") {
		t.Fatalf("unexpected content in config: %s", content)
	}

	// Remove route
	if err := mgr.RemoveTCPRoute(ctx, "valkey-res-42"); err != nil {
		t.Fatalf("RemoveTCPRoute failed: %v", err)
	}

	if _, err := os.Stat(cfgPath); !os.IsNotExist(err) {
		t.Fatalf("expected file to be deleted")
	}

	// Test idempotency on removing non-existent
	if err := mgr.RemoveTCPRoute(ctx, "valkey-res-42"); err != nil {
		t.Fatalf("expected idempotent removal to succeed: %v", err)
	}
}

func TestPathTraversalProtection(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "haproxy_traversal_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	mgr := NewManager(tmpDir, nil)

	route := &TCPRouteConfig{
		ID:          "../../etc/passwd",
		Port:        30009,
		ContainerIP: "172.18.0.3",
		TargetPort:  6379,
	}

	ctx := context.Background()
	if err := mgr.ConfigureTCPRoute(ctx, route); err == nil {
		t.Fatalf("expected path traversal route ID to be rejected")
	}
}
