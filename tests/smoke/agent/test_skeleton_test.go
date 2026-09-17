package agent_test

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/primecloud/primecloud-agent/internal/agent"
)

func TestAgentSkeleton_BuildAndBoot(t *testing.T) {
	cfg := agent.DefaultConfig()
	cfg.ControlPlaneURL = "127.0.0.1:50051"
	cfg.VaultAddr = "http://127.0.0.1:8200"

	var buf bytes.Buffer
	logger := agent.SetupLogging(&buf, slog.LevelInfo)

	ag, err := agent.NewAgent(cfg, logger)
	if err != nil {
		t.Fatalf("Failed to instantiate agent: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	errCh := make(chan error, 1)
	go func() {
		errCh <- ag.Start(ctx)
	}()

	// Wait briefly to verify agent transitions to READY
	time.Sleep(50 * time.Millisecond)
	if ag.State() != agent.StateReady {
		t.Errorf("Expected agent state %s, got %s", agent.StateReady, ag.State())
	}

	// Trigger graceful stop
	cancel()

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("Agent returned error on exit: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Agent failed to stop within timeout")
	}

	if ag.State() != agent.StateStopped {
		t.Errorf("Expected final state %s, got %s", agent.StateStopped, ag.State())
	}
}

func TestAgentConfig_EnvironmentLoading(t *testing.T) {
	os.Setenv("PRIMECLOUD_AGENT_NODE_ID", "node-smoke-test-123")
	os.Setenv("PRIMECLOUD_AGENT_CONTROL_PLANE_URL", "127.0.0.1:9090")
	os.Setenv("PRIMECLOUD_AGENT_BOOTSTRAP_TOKEN", "super-secret-token-value")
	defer func() {
		os.Unsetenv("PRIMECLOUD_AGENT_NODE_ID")
		os.Unsetenv("PRIMECLOUD_AGENT_CONTROL_PLANE_URL")
		os.Unsetenv("PRIMECLOUD_AGENT_BOOTSTRAP_TOKEN")
	}()

	cfg, err := agent.LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	if cfg.NodeID != "node-smoke-test-123" {
		t.Errorf("Expected NodeID 'node-smoke-test-123', got '%s'", cfg.NodeID)
	}
	if cfg.ControlPlaneURL != "127.0.0.1:9090" {
		t.Errorf("Expected ControlPlaneURL '127.0.0.1:9090', got '%s'", cfg.ControlPlaneURL)
	}
	if cfg.BootstrapToken != "super-secret-token-value" {
		t.Errorf("Expected BootstrapToken loaded correctly")
	}

	// Verify String() redacts/excludes secret
	str := cfg.String()
	if strings.Contains(str, "super-secret-token-value") {
		t.Errorf("Config.String() leaked secret: %s", str)
	}
}

func TestAgentLogging_Redaction(t *testing.T) {
	var buf bytes.Buffer
	logger := agent.SetupLogging(&buf, slog.LevelInfo)

	logger.Info("testing_sensitive_log",
		"token", "s.sensitiveBootstrapTokenValue",
		"password", "p@ssw0rd123!",
		"certificate", "-----BEGIN CERTIFICATE-----\nMIIB...",
		"safe_attr", "normal_value",
	)

	logOutput := buf.String()
	if strings.Contains(logOutput, "s.sensitiveBootstrapTokenValue") {
		t.Errorf("Token was not redacted from log: %s", logOutput)
	}
	if strings.Contains(logOutput, "p@ssw0rd123!") {
		t.Errorf("Password was not redacted from log: %s", logOutput)
	}
	if strings.Contains(logOutput, "-----BEGIN CERTIFICATE-----") {
		t.Errorf("Certificate was not redacted from log: %s", logOutput)
	}
	if !strings.Contains(logOutput, "[REDACTED]") {
		t.Errorf("Expected [REDACTED] in log output: %s", logOutput)
	}
	if !strings.Contains(logOutput, "normal_value") {
		t.Errorf("Safe attribute missing in log output: %s", logOutput)
	}
}
