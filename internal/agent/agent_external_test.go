package agent

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/primecloud/primecloud-agent/internal/haproxy"
	pb "github.com/primecloud/primecloud-agent/internal/protocol"
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
