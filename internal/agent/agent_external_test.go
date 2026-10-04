package agent

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/primecloud/primecloud-agent/internal/caddy"
	pb "github.com/primecloud/primecloud-agent/internal/protocol"
)

func TestAgentExternalGatewayIntegration(t *testing.T) {
	cfg := DefaultConfig()

	agent, err := NewAgent(cfg, nil)
	if err != nil {
		t.Fatalf("failed to create agent: %v", err)
	}

	payload := caddy.TCPRouteConfig{
		ID:          "test-db",
		Port:        5432,
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
}
