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
		ID:          "test-vk",
		Port:        30005,
		ContainerIP: "10.0.0.99",
		TargetPort:  6379,
	}
	payloadBytes, _ := json.Marshal(payload)

	op := &pb.OperationEnvelope{
		OperationId:   "op-1",
		OperationType: "enable_external_access",
		ResourceId:    "test-vk",
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
	cfgFile := filepath.Join(tempConfDir, "tcp_test-vk.cfg")
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
		ResourceId:    "test-vk",
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
		ResourceId:    "test-vk",
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

type recordingMockRuntime struct {
	createdConfigs []*runtime.ContainerConfig
	removedIDs     []string
	stoppedIDs     []string
}

func (m *recordingMockRuntime) PullImage(ctx context.Context, ref string) error { return nil }
func (m *recordingMockRuntime) PullImageWithAuth(ctx context.Context, ref, auth string) error {
	return nil
}
func (m *recordingMockRuntime) CreateContainer(ctx context.Context, cfg *runtime.ContainerConfig, l *runtime.ResourceLimits, p *runtime.HardenedIsolationProfile) (string, error) {
	m.createdConfigs = append(m.createdConfigs, cfg)
	return "mock-cid-" + cfg.Name, nil
}
func (m *recordingMockRuntime) StartContainer(ctx context.Context, id string) error { return nil }
func (m *recordingMockRuntime) StopContainer(ctx context.Context, id string, timeout *int) error {
	m.stoppedIDs = append(m.stoppedIDs, id)
	return nil
}
func (m *recordingMockRuntime) RemoveContainer(ctx context.Context, id string, force bool) error {
	m.removedIDs = append(m.removedIDs, id)
	return nil
}
func (m *recordingMockRuntime) InspectContainer(ctx context.Context, id string) (*runtime.ContainerInspect, error) {
	return &runtime.ContainerInspect{ID: id, Running: true, Health: "healthy", IPAddress: "10.0.0.99"}, nil
}
func (m *recordingMockRuntime) ListContainers(ctx context.Context, all bool) ([]runtime.ContainerSummary, error) {
	return nil, nil
}
func (m *recordingMockRuntime) GetContainerLogs(ctx context.Context, id string) (io.ReadCloser, error) {
	return nil, nil
}
func (m *recordingMockRuntime) GetContainerStats(ctx context.Context, id string) (io.ReadCloser, error) {
	return nil, nil
}
func (m *recordingMockRuntime) ExecContainer(ctx context.Context, id string, cmd []string, env []string, stdin io.Reader) ([]byte, []byte, int, error) {
	return nil, nil, 0, nil
}
func (m *recordingMockRuntime) Ping(ctx context.Context) error { return nil }
func (m *recordingMockRuntime) Close() error                   { return nil }

func TestPostgresProvisioning_PrivateDoesNotPublishPort(t *testing.T) {
	tempConfDir := t.TempDir()
	t.Setenv("PRIMECLOUD_HAPROXY_CONFIG_DIR", tempConfDir)

	mockRT := &recordingMockRuntime{}
	cfg := DefaultConfig()
	cfg.VaultAddr = ""
	cfg.ResourceDir = t.TempDir()
	agent, err := NewAgentWithRuntime(cfg, mockRT, nil)
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

	if len(mockRT.createdConfigs) == 0 {
		t.Fatalf("expected container to be created")
	}
	lastCfg := mockRT.createdConfigs[len(mockRT.createdConfigs)-1]
	if len(lastCfg.Ports) != 0 {
		t.Errorf("expected no published host ports for private postgres, got: %v", lastCfg.Ports)
	}

	// Verify HAProxy configuration file was NOT created
	cfgFile := filepath.Join(tempConfDir, "tcp_pg-private-1.cfg")
	if _, err := os.Stat(cfgFile); !os.IsNotExist(err) {
		t.Fatalf("expected HAProxy cfg file to NOT exist for private postgres, but found it")
	}
}

func TestPostgresProvisioning_ExternalAccessPublishesDirectPort(t *testing.T) {
	tempConfDir := t.TempDir()
	t.Setenv("PRIMECLOUD_HAPROXY_CONFIG_DIR", tempConfDir)

	mockRT := &recordingMockRuntime{}
	cfg := DefaultConfig()
	cfg.VaultAddr = ""
	cfg.ResourceDir = t.TempDir()
	agent, err := NewAgentWithRuntime(cfg, mockRT, nil)
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

	if len(mockRT.createdConfigs) == 0 {
		t.Fatalf("expected container to be created")
	}
	lastCfg := mockRT.createdConfigs[len(mockRT.createdConfigs)-1]
	if lastCfg.Ports["5432"] != "30010" {
		t.Errorf("expected direct container port 5432 published to host port 30010, got: %v", lastCfg.Ports)
	}

	// Verify HAProxy is bypassed for postgres
	cfgFile := filepath.Join(tempConfDir, "tcp_pg-ext-valid-1.cfg")
	if _, err := os.Stat(cfgFile); !os.IsNotExist(err) {
		t.Fatalf("expected HAProxy to be bypassed for direct postgres port publishing")
	}
}

func TestPostgresExternalAccess_EnableAndDisableDirectPort(t *testing.T) {
	tempConfDir := t.TempDir()
	t.Setenv("PRIMECLOUD_HAPROXY_CONFIG_DIR", tempConfDir)

	mockRT := &recordingMockRuntime{}
	cfg := DefaultConfig()
	cfg.VaultAddr = ""
	cfg.ResourceDir = t.TempDir()
	agent, err := NewAgentWithRuntime(cfg, mockRT, nil)
	if err != nil {
		t.Fatalf("failed to create agent: %v", err)
	}

	// 1. Initially provision Private Only
	provPayload := map[string]interface{}{
		"postgres_id":     "pg-lifecycle-1",
		"external_access": false,
		"external_port":   30005, // allocated port exists, but external access is disabled
	}
	provBytes, _ := json.Marshal(provPayload)
	opProv := &pb.OperationEnvelope{
		OperationId:   "op-p-1",
		OperationType: "provision_postgres",
		ResourceId:    "pg-lifecycle-1",
		PayloadJson:   string(provBytes),
	}
	resProv, err := agent.dispatcher.Dispatch(context.Background(), opProv)
	if err != nil || resProv.Status != "SUCCEEDED" {
		t.Fatalf("provision failed: %v, res: %+v", err, resProv)
	}

	initialCfg := mockRT.createdConfigs[len(mockRT.createdConfigs)-1]
	if len(initialCfg.Ports) != 0 {
		t.Errorf("expected no published port initially, got: %v", initialCfg.Ports)
	}

	// 2. Explicitly Enable External Access
	enablePayload := map[string]interface{}{
		"postgres_id":   "pg-lifecycle-1",
		"external_port": 30005,
	}
	enableBytes, _ := json.Marshal(enablePayload)
	opEnable := &pb.OperationEnvelope{
		OperationId:   "op-enable-1",
		OperationType: "enable_external_access",
		ResourceId:    "pg-lifecycle-1",
		PayloadJson:   string(enableBytes),
	}
	resEnable, err := agent.dispatcher.Dispatch(context.Background(), opEnable)
	if err != nil || resEnable.Status != "SUCCEEDED" {
		t.Fatalf("enable_external_access failed: %v, res: %+v", err, resEnable)
	}

	enabledCfg := mockRT.createdConfigs[len(mockRT.createdConfigs)-1]
	if enabledCfg.Ports["5432"] != "30005" {
		t.Errorf("expected host port 30005 on container recreation, got: %v", enabledCfg.Ports)
	}

	// 3. Explicitly Disable External Access
	disablePayload := map[string]interface{}{
		"postgres_id": "pg-lifecycle-1",
	}
	disableBytes, _ := json.Marshal(disablePayload)
	opDisable := &pb.OperationEnvelope{
		OperationId:   "op-disable-1",
		OperationType: "disable_external_access",
		ResourceId:    "pg-lifecycle-1",
		PayloadJson:   string(disableBytes),
	}
	resDisable, err := agent.dispatcher.Dispatch(context.Background(), opDisable)
	if err != nil || resDisable.Status != "SUCCEEDED" {
		t.Fatalf("disable_external_access failed: %v, res: %+v", err, resDisable)
	}

	disabledCfg := mockRT.createdConfigs[len(mockRT.createdConfigs)-1]
	if len(disabledCfg.Ports) != 0 {
		t.Errorf("expected no host ports after disabling external access, got: %v", disabledCfg.Ports)
	}
}

func TestPostgresProvisioning_Port0RejectedWhenExternalAccessEnabled(t *testing.T) {
	tempConfDir := t.TempDir()
	t.Setenv("PRIMECLOUD_HAPROXY_CONFIG_DIR", tempConfDir)

	mockRT := &recordingMockRuntime{}
	cfg := DefaultConfig()
	cfg.ResourceDir = t.TempDir()
	agent, err := NewAgentWithRuntime(cfg, mockRT, nil)
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
	if !strings.Contains(res.Message, "invalid external port 0") {
		t.Errorf("expected message mentioning invalid external port 0, got: %s", res.Message)
	}
}
