package caddy

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConfigureTCPRoute(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "caddy_test_tcp")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	mgr := NewManager(tempDir, "", nil)

	route := &TCPRouteConfig{
		ID:          "db-123",
		Port:        5432,
		ContainerIP: "10.0.0.5",
		TargetPort:  5432,
	}

	err = mgr.ConfigureTCPRoute(context.Background(), route)
	if err != nil {
		t.Fatalf("ConfigureTCPRoute failed: %v", err)
	}

	targetFile := filepath.Join(tempDir, "tcp_db-123.caddy")
	content, err := os.ReadFile(targetFile)
	if err != nil {
		t.Fatalf("failed to read caddy file: %v", err)
	}

	strContent := string(content)
	if !strings.Contains(strContent, ":5432 {") {
		t.Errorf("expected port in caddyfile, got: %s", strContent)
	}
	if !strings.Contains(strContent, "reverse_proxy 10.0.0.5:5432") {
		t.Errorf("expected reverse proxy in caddyfile, got: %s", strContent)
	}

	err = mgr.RemoveTCPRoute(context.Background(), "db-123")
	if err != nil {
		t.Fatalf("RemoveTCPRoute failed: %v", err)
	}

	if _, err := os.Stat(targetFile); !os.IsNotExist(err) {
		t.Errorf("file should have been removed: %v", err)
	}
}
