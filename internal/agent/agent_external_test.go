package agent

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/primecloud/primecloud-agent/internal/haproxy"
	pb "github.com/primecloud/primecloud-agent/internal/protocol"
	"github.com/primecloud/primecloud-agent/internal/runtime"
)

func TestAgentExternalGatewayIntegration(t *testing.T) {
	tempConfDir, err := os.MkdirTemp("", "agent_haproxy_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempConfDir)

	t.Setenv("PRIMECLOUD_HAPROXY_CONFIG_DIR", tempConfDir)

	cfg := DefaultConfig()
	agent, err := NewAgent(cfg, nil)
	if err != nil {
		t.Fatalf("failed to create agent: %v", err)
	}

	payload := haproxy.TCPRouteConfig{
		ID:          "test-db",
		Port:        30005,
		ContainerIP: "10.0.0.99",
		TargetPort:  5432,
	}
	payloadBytes, _ := json.Marshal(payload)

	op := &pb.OperationEnvelope{
		OperationId:   "op-1",
		OperationType: "enable_external_access",
		ResourceId:    "test-db",
		PayloadJson:   string(payloadBytes),
	}

	res, err := agent.dispatcher.Dispatch(context.Background(), op)
	if err != nil {
		t.Fatalf("enable_external_access failed: %v", err)
	}
	if res.Status != "SUCCEEDED" {
		t.Errorf("expected SUCCEEDED, got %s", res.Status)
	}

	// Verify HAProxy configuration file was created
	cfgFile := filepath.Join(tempConfDir, "tcp_test-db.cfg")
	data, err := os.ReadFile(cfgFile)
	if err != nil {
		t.Fatalf("expected HAProxy cfg file to exist: %v", err)
	}
	content := string(data)
	if !strings.Contains(content, "mode tcp") || !strings.Contains(content, "bind *:30005") {
		t.Fatalf("expected valid HAProxy tcp config, got: %s", content)
	}

	// Disable
	opDisable := &pb.OperationEnvelope{
		OperationId:   "op-2",
		OperationType: "disable_external_access",
		ResourceId:    "test-db",
	}
	res2, err := agent.dispatcher.Dispatch(context.Background(), opDisable)
	if err != nil {
		t.Fatalf("disable_external_access failed: %v", err)
	}
	if res2.Status != "SUCCEEDED" {
		t.Errorf("expected SUCCEEDED, got %s", res2.Status)
	}

	// Verify HAProxy configuration file was removed
	if _, err := os.Stat(cfgFile); !os.IsNotExist(err) {
		t.Fatalf("expected HAProxy cfg file to be removed")
	}

	// Reconcile
	opReconcile := &pb.OperationEnvelope{
		OperationId:   "op-3",
		OperationType: "reconcile_external_access",
		ResourceId:    "test-db",
		PayloadJson:   string(payloadBytes),
	}
	res3, err := agent.dispatcher.Dispatch(context.Background(), opReconcile)
	if err != nil {
		t.Fatalf("reconcile_external_access failed: %v", err)
	}
	if res3.Status != "SUCCEEDED" {
		t.Errorf("expected SUCCEEDED, got %s", res3.Status)
	}
	if _, err := os.Stat(cfgFile); err != nil {
		t.Fatalf("expected HAProxy cfg file to be recreated after reconcile")
	}
}

type mockAgentRuntime struct{}

func (m *mockAgentRuntime) PullImage(ctx context.Context, ref string) error { return nil }
func (m *mockAgentRuntime) PullImageWithAuth(ctx context.Context, ref, auth string) error {
	return nil
}
func (m *mockAgentRuntime) CreateContainer(ctx context.Context, cfg *runtime.ContainerConfig, l *runtime.ResourceLimits, p *runtime.HardenedIsolationProfile) (string, error) {
	return "mock-cid-pg", nil
}
func (m *mockAgentRuntime) StartContainer(ctx context.Context, id string) error { return nil }
func (m *mockAgentRuntime) StopContainer(ctx context.Context, id string, timeout *int) error {
	return nil
}
func (m *mockAgentRuntime) RemoveContainer(ctx context.Context, id string, force bool) error {
	return nil
}
func (m *mockAgentRuntime) InspectContainer(ctx context.Context, id string) (*runtime.ContainerInspect, error) {
	return &runtime.ContainerInspect{ID: id, Running: true, Health: "healthy", IPAddress: "10.0.0.99"}, nil
}
func (m *mockAgentRuntime) ListContainers(ctx context.Context, all bool) ([]runtime.ContainerSummary, error) {
	return nil, nil
}
func (m *mockAgentRuntime) GetContainerLogs(ctx context.Context, id string) (io.ReadCloser, error) {
	return nil, nil
}
func (m *mockAgentRuntime) GetContainerStats(ctx context.Context, id string) (io.ReadCloser, error) {
	return nil, nil
}
func (m *mockAgentRuntime) ExecContainer(ctx context.Context, id string, cmd []string, env []string, stdin io.Reader) ([]byte, []byte, int, error) {
	return nil, nil, 0, nil
}
func (m *mockAgentRuntime) Ping(ctx context.Context) error { return nil }
func (m *mockAgentRuntime) Close() error                   { return nil }

func TestPostgresProvisioning_PrivateDoesNotCallHAProxy(t *testing.T) {
	tempConfDir, err := os.MkdirTemp("", "agent_haproxy_priv_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempConfDir)
	t.Setenv("PRIMECLOUD_HAPROXY_CONFIG_DIR", tempConfDir)

	cfg := DefaultConfig()
	cfg.VaultAddr = ""
	cfg.ResourceDir = t.TempDir()
	agent, err := NewAgentWithRuntime(cfg, &mockAgentRuntime{}, nil)
	if err != nil {
		t.Fatalf("failed to create agent: %v", err)
	}

	payload := map[string]interface{}{
		"postgres_id":     "pg-private-1",
		"external_access": false,
		"external_port":   0,
	}
	payloadBytes, _ := json.Marshal(payload)

	op := &pb.OperationEnvelope{
		OperationId:   "op-priv-1",
		OperationType: "provision_postgres",
		ResourceId:    "pg-private-1",
		PayloadJson:   string(payloadBytes),
	}

	res, err := agent.dispatcher.Dispatch(context.Background(), op)
	if err != nil {
		t.Fatalf("provision_postgres failed: %v", err)
	}
	if res.Status != "SUCCEEDED" {
		t.Fatalf("expected SUCCEEDED, got %s (msg: %s, code: %s)", res.Status, res.Message, res.ErrorCode)
	}

	// Verify HAProxy configuration file was NOT created
	cfgFile := filepath.Join(tempConfDir, "tcp_pg-private-1.cfg")
	if _, err := os.Stat(cfgFile); !os.IsNotExist(err) {
		t.Fatalf("expected HAProxy cfg file to NOT exist for private postgres, but found it")
	}
}

func TestPostgresProvisioning_EnabledRequiresValidPort(t *testing.T) {
	tempConfDir, err := os.MkdirTemp("", "agent_haproxy_enabled_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempConfDir)
	t.Setenv("PRIMECLOUD_HAPROXY_CONFIG_DIR", tempConfDir)

	cfg := DefaultConfig()
	cfg.VaultAddr = ""
	cfg.ResourceDir = t.TempDir()
	agent, err := NewAgentWithRuntime(cfg, &mockAgentRuntime{}, nil)
	if err != nil {
		t.Fatalf("failed to create agent: %v", err)
	}

	payload := map[string]interface{}{
		"postgres_id":     "pg-ext-valid-1",
		"external_access": true,
		"external_port":   30010,
	}
	payloadBytes, _ := json.Marshal(payload)

	op := &pb.OperationEnvelope{
		OperationId:   "op-ext-valid-1",
		OperationType: "provision_postgres",
		ResourceId:    "pg-ext-valid-1",
		PayloadJson:   string(payloadBytes),
	}

	res, err := agent.dispatcher.Dispatch(context.Background(), op)
	if err != nil {
		t.Fatalf("provision_postgres failed: %v", err)
	}
	if res.Status != "SUCCEEDED" {
		t.Fatalf("expected SUCCEEDED, got %s (msg: %s, code: %s)", res.Status, res.Message, res.ErrorCode)
	}

	// Verify HAProxy configuration file WAS created with valid port
	cfgFile := filepath.Join(tempConfDir, "tcp_pg-ext-valid-1.cfg")
	data, err := os.ReadFile(cfgFile)
	if err != nil {
		t.Fatalf("expected HAProxy cfg file to exist: %v", err)
	}
	content := string(data)
	if !strings.Contains(content, "bind *:30010") {
		t.Fatalf("expected config to bind to 30010, got:\n%s", content)
	}
}

func TestPostgresProvisioning_Port0RejectedWhenExternalAccessEnabled(t *testing.T) {
	tempConfDir, err := os.MkdirTemp("", "agent_haproxy_zero_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempConfDir)
	t.Setenv("PRIMECLOUD_HAPROXY_CONFIG_DIR", tempConfDir)

	cfg := DefaultConfig()
	cfg.ResourceDir = t.TempDir()
	agent, err := NewAgentWithRuntime(cfg, &mockAgentRuntime{}, nil)
	if err != nil {
		t.Fatalf("failed to create agent: %v", err)
	}

	payload := map[string]interface{}{
		"postgres_id":     "pg-ext-zero-1",
		"external_access": true,
		"external_port":   0,
	}
	payloadBytes, _ := json.Marshal(payload)

	op := &pb.OperationEnvelope{
		OperationId:   "op-ext-zero-1",
		OperationType: "provision_postgres",
		ResourceId:    "pg-ext-zero-1",
		PayloadJson:   string(payloadBytes),
	}

	res, err := agent.dispatcher.Dispatch(context.Background(), op)
	if err == nil && res.Status == "SUCCEEDED" {
		t.Fatalf("expected failure for external access with port 0, but got SUCCEEDED")
	}
	if res.ErrorCode != "HAPROXY_CONFIG_FAILED" {
		t.Errorf("expected ErrorCode HAPROXY_CONFIG_FAILED, got %s", res.ErrorCode)
	}
	if !strings.Contains(res.Message, "invalid external port 0") {
		t.Errorf("expected message mentioning invalid external port 0, got: %s", res.Message)
	}

	// Verify HAProxy configuration file was NOT created
	cfgFile := filepath.Join(tempConfDir, "tcp_pg-ext-zero-1.cfg")
	if _, err := os.Stat(cfgFile); !os.IsNotExist(err) {
		t.Fatalf("expected HAProxy cfg file to NOT exist when port 0 is rejected")
	}
}
