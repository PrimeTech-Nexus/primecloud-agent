package metrics

import (
	"context"
	"testing"
	"time"

	agentruntime "github.com/primecloud/primecloud-agent/internal/runtime"
)

type mockRuntime struct {
	agentruntime.ContainerRuntime
}

func (m *mockRuntime) ListContainers(ctx context.Context, all bool) ([]agentruntime.ContainerSummary, error) {
	return []agentruntime.ContainerSummary{
		{ID: "cnt1234567890", Image: "nginx:alpine", State: "running", Status: "Up 2 hours"},
	}, nil
}

func TestCollectorSample(t *testing.T) {
	rt := &mockRuntime{}
	coll := NewCollector(100*time.Millisecond, "node-001", "agent-001", rt, nil, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	payload, err := coll.Sample(ctx)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if payload.NodeID != "node-001" {
		t.Errorf("expected nodeID node-001, got %s", payload.NodeID)
	}
	if payload.ContainerCount != 1 {
		t.Errorf("expected container count 1, got %d", payload.ContainerCount)
	}
}

func TestCollectorDrainMode(t *testing.T) {
	coll := NewCollector(100*time.Millisecond, "node-001", "agent-001", nil, nil, nil)
	coll.SetDrain(true)

	payload, err := coll.Sample(context.Background())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if payload == nil {
		t.Fatal("expected payload non-nil")
	}
}
