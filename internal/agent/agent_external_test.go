package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/primecloud/primecloud-agent/internal/haproxy"
	pb "github.com/primecloud/primecloud-agent/internal/protocol"
	"github.com/primecloud/primecloud-agent/internal/runtime"
)

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

func TestPostgresExternalAccess_EnableDisableReenableGatewayContract(t *testing.T) {
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

	// 1. Provision PostgreSQL container privately
	provPayload := map[string]interface{}{
		"postgres_id": "pg-gateway-1",
	}
	provBytes, _ := json.Marshal(provPayload)
	opProv := &pb.OperationEnvelope{
		OperationId:   "op-p-1",
		OperationType: "provision_postgres",
		ResourceId:    "pg-gateway-1",
		PayloadJson:   string(provBytes),
	}
	resProv, err := agent.dispatcher.Dispatch(context.Background(), opProv)
	if err != nil || resProv.Status != "SUCCEEDED" {
		t.Fatalf("provision failed: %v, res: %+v", err, resProv)
	}

	// Verify container has no host ports
	containerCount := len(mockRT.createdConfigs)
	if containerCount != 1 {
		t.Fatalf("expected 1 container created, got %d", containerCount)
	}
	if len(mockRT.createdConfigs[0].Ports) != 0 {
		t.Fatalf("expected private postgres container to have no host ports, got: %v", mockRT.createdConfigs[0].Ports)
	}

	// 2. Enable PostgreSQL External Access
	enablePayload := map[string]interface{}{
		"postgres_id":   "pg-gateway-1",
		"external_port": 30005,
	}
	enableBytes, _ := json.Marshal(enablePayload)
	opEnable := &pb.OperationEnvelope{
		OperationId:   "op-enable-1",
		OperationType: "enable_external_access",
		ResourceId:    "pg-gateway-1",
		PayloadJson:   string(enableBytes),
	}
	resEnable, err := agent.dispatcher.Dispatch(context.Background(), opEnable)
	if err != nil || resEnable.Status != "SUCCEEDED" {
		t.Fatalf("enable_external_access failed: %v, res: %+v", err, resEnable)
	}

	// Database container MUST NOT be recreated or stopped or touched
	if len(mockRT.createdConfigs) != containerCount {
		t.Fatalf("database container was mutated/recreated during enable! count changed from %d to %d", containerCount, len(mockRT.createdConfigs))
	}
	if len(mockRT.stoppedIDs) != 0 || len(mockRT.removedIDs) != 0 {
		t.Fatalf("database container was stopped or removed during enable! stopped: %v, removed: %v", mockRT.stoppedIDs, mockRT.removedIDs)
	}

	// HAProxy route MUST be generated with mode tcp and upstream pointing to container private IP 10.0.0.99:5432
	cfgFile := filepath.Join(tempConfDir, "tcp_pg-gateway-1.cfg")
	data, err := os.ReadFile(cfgFile)
	if err != nil {
		t.Fatalf("expected HAProxy cfg file to exist: %v", err)
	}
	content := string(data)
	if !strings.Contains(content, "bind *:30005") || !strings.Contains(content, "mode tcp") || !strings.Contains(content, "10.0.0.99:5432") {
		t.Fatalf("unexpected content in HAProxy cfg: %s", content)
	}

	// 3. Disable PostgreSQL External Access
	disablePayload := map[string]interface{}{
		"postgres_id": "pg-gateway-1",
	}
	disableBytes, _ := json.Marshal(disablePayload)
	opDisable := &pb.OperationEnvelope{
		OperationId:   "op-disable-1",
		OperationType: "disable_external_access",
		ResourceId:    "pg-gateway-1",
		PayloadJson:   string(disableBytes),
	}
	resDisable, err := agent.dispatcher.Dispatch(context.Background(), opDisable)
	if err != nil || resDisable.Status != "SUCCEEDED" {
		t.Fatalf("disable_external_access failed: %v, res: %+v", err, resDisable)
	}

	// Container still MUST NOT be touched
	if len(mockRT.createdConfigs) != containerCount || len(mockRT.stoppedIDs) != 0 || len(mockRT.removedIDs) != 0 {
		t.Fatalf("database container was mutated/stopped/removed during disable!")
	}

	// HAProxy route MUST be removed
	if _, err := os.Stat(cfgFile); !os.IsNotExist(err) {
		t.Fatalf("expected HAProxy cfg file to be deleted after disable")
	}

	// 4. Re-enable with same public port 30005
	opReEnable := &pb.OperationEnvelope{
		OperationId:   "op-enable-2",
		OperationType: "enable_external_access",
		ResourceId:    "pg-gateway-1",
		PayloadJson:   string(enableBytes),
	}
	resReEnable, err := agent.dispatcher.Dispatch(context.Background(), opReEnable)
	if err != nil || resReEnable.Status != "SUCCEEDED" {
		t.Fatalf("re-enable failed: %v, res: %+v", err, resReEnable)
	}

	// Route recreated with same port
	dataRe, err := os.ReadFile(cfgFile)
	if err != nil {
		t.Fatalf("expected HAProxy cfg file to exist on re-enable: %v", err)
	}
	if !strings.Contains(string(dataRe), "bind *:30005") {
		t.Fatalf("expected route recreated with same port 30005")
	}
	// Container still untouched
	if len(mockRT.createdConfigs) != containerCount {
		t.Fatalf("database container was recreated on re-enable!")
	}
}

func TestValkeyExternalAccess_GatewayContract(t *testing.T) {
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

	// 1. Enable Valkey external access
	enablePayload := map[string]interface{}{
		"keyvalue_id":   "vk-res-1",
		"external_port": 30008,
	}
	enableBytes, _ := json.Marshal(enablePayload)
	opEnable := &pb.OperationEnvelope{
		OperationId:   "op-enable-vk-1",
		OperationType: "enable_external_access",
		ResourceId:    "vk-res-1",
		PayloadJson:   string(enableBytes),
	}
	resEnable, err := agent.dispatcher.Dispatch(context.Background(), opEnable)
	if err != nil || resEnable.Status != "SUCCEEDED" {
		t.Fatalf("enable_external_access valkey failed: %v, res: %+v", err, resEnable)
	}

	cfgFile := filepath.Join(tempConfDir, "tcp_vk-res-1.cfg")
	data, err := os.ReadFile(cfgFile)
	if err != nil {
		t.Fatalf("expected HAProxy cfg file for valkey to exist: %v", err)
	}
	content := string(data)
	if !strings.Contains(content, "bind *:30008") || !strings.Contains(content, "mode tcp") || !strings.Contains(content, "10.0.0.99:6379") {
		t.Fatalf("unexpected content in HAProxy cfg for valkey: %s", content)
	}

	// 2. Disable Valkey external access
	opDisable := &pb.OperationEnvelope{
		OperationId:   "op-disable-vk-1",
		OperationType: "disable_external_access",
		ResourceId:    "vk-res-1",
	}
	resDisable, err := agent.dispatcher.Dispatch(context.Background(), opDisable)
	if err != nil || resDisable.Status != "SUCCEEDED" {
		t.Fatalf("disable_external_access valkey failed: %v, res: %+v", err, resDisable)
	}
	if _, err := os.Stat(cfgFile); !os.IsNotExist(err) {
		t.Fatalf("expected HAProxy cfg file to be removed for valkey")
	}
}

func TestExternalAccess_Port0AndMissingPortFailsClosed(t *testing.T) {
	tempConfDir := t.TempDir()
	t.Setenv("PRIMECLOUD_HAPROXY_CONFIG_DIR", tempConfDir)

	mockRT := &recordingMockRuntime{}
	cfg := DefaultConfig()
	agent, err := NewAgentWithRuntime(cfg, mockRT, nil)
	if err != nil {
		t.Fatalf("failed to create agent: %v", err)
	}

	// Port 0 test
	payload0 := map[string]interface{}{
		"postgres_id":   "pg-fail-1",
		"external_port": 0,
	}
	b0, _ := json.Marshal(payload0)
	op0 := &pb.OperationEnvelope{
		OperationId:   "op-fail-0",
		OperationType: "enable_external_access",
		ResourceId:    "pg-fail-1",
		PayloadJson:   string(b0),
	}
	res0, err0 := agent.dispatcher.Dispatch(context.Background(), op0)
	if err0 == nil && res0.Status == "SUCCEEDED" {
		t.Fatalf("expected failure for external_port 0, got SUCCEEDED")
	}
	if res0.ErrorCode != "INVALID_EXTERNAL_PORT" {
		t.Errorf("expected INVALID_EXTERNAL_PORT error code, got %s", res0.ErrorCode)
	}

	// Missing port test
	payloadMissing := map[string]interface{}{
		"postgres_id": "pg-fail-2",
	}
	bMissing, _ := json.Marshal(payloadMissing)
	opMissing := &pb.OperationEnvelope{
		OperationId:   "op-fail-missing",
		OperationType: "enable_external_access",
		ResourceId:    "pg-fail-2",
		PayloadJson:   string(bMissing),
	}
	resM, errM := agent.dispatcher.Dispatch(context.Background(), opMissing)
	if errM == nil && resM.Status == "SUCCEEDED" {
		t.Fatalf("expected failure for missing external_port, got SUCCEEDED")
	}
	if resM.ErrorCode != "INVALID_EXTERNAL_PORT" {
		t.Errorf("expected INVALID_EXTERNAL_PORT error code, got %s", resM.ErrorCode)
	}
}

func TestHAProxy_ReloadFailureCausesOperationFailure(t *testing.T) {
	tempConfDir := t.TempDir()
	mgr := haproxy.NewManager(tempConfDir, nil)
	mgr.SetReloadFunc(func(ctx context.Context) error {
		return fmt.Errorf("simulated systemctl reload haproxy failure")
	})

	route := &haproxy.TCPRouteConfig{
		ID:          "pg-reload-fail",
		Port:        30015,
		ContainerIP: "10.0.0.10",
		TargetPort:  5432,
	}

	err := mgr.ConfigureTCPRoute(context.Background(), route)
	if err == nil {
		t.Fatalf("expected error due to reload failure, got nil")
	}
	if !strings.Contains(err.Error(), "failed to reload haproxy") {
		t.Errorf("expected reload failure error, got: %v", err)
	}

	// Verify config was rolled back / removed on reload failure
	cfgFile := filepath.Join(tempConfDir, "tcp_pg-reload-fail.cfg")
	if _, statErr := os.Stat(cfgFile); !os.IsNotExist(statErr) {
		t.Fatalf("expected config file to be rolled back/cleaned up on reload failure")
	}
}

func TestHAProxy_RouteVerificationFailureCausesOperationFailure(t *testing.T) {
	tempConfDir := t.TempDir()
	mgr := haproxy.NewManager(tempConfDir, nil)
	mgr.SetVerifyFunc(func(ctx context.Context, id string, port int) error {
		return fmt.Errorf("simulated route verification check failure")
	})

	route := &haproxy.TCPRouteConfig{
		ID:          "pg-verify-fail",
		Port:        30016,
		ContainerIP: "10.0.0.10",
		TargetPort:  5432,
	}

	err := mgr.ConfigureTCPRoute(context.Background(), route)
	if err == nil {
		t.Fatalf("expected error due to verification failure, got nil")
	}
	if !strings.Contains(err.Error(), "failed to verify haproxy route") {
		t.Errorf("expected verify failure error, got: %v", err)
	}

	// Verify config was rolled back
	cfgFile := filepath.Join(tempConfDir, "tcp_pg-verify-fail.cfg")
	if _, statErr := os.Stat(cfgFile); !os.IsNotExist(statErr) {
		t.Fatalf("expected config file to be rolled back on verify failure")
	}
}
