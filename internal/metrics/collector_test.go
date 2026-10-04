package metrics

import (
	"context"
	"io"
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

func (m *mockRuntime) GetContainerStats(ctx context.Context, containerID string) (io.ReadCloser, error) {
	return nil, nil
}

func (m *mockRuntime) InspectContainer(ctx context.Context, containerID string) (*agentruntime.ContainerInspect, error) {
	return &agentruntime.ContainerInspect{
		ID:      containerID,
		Running: true,
	}, nil
}

func (m *mockRuntime) ExecContainer(ctx context.Context, containerID string, cmd []string, env []string, stdin io.Reader) ([]byte, []byte, int, error) {
	return nil, nil, 0, nil
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

type mockLabeledRuntime struct {
	agentruntime.ContainerRuntime
}

func (m *mockLabeledRuntime) ListContainers(ctx context.Context, all bool) ([]agentruntime.ContainerSummary, error) {
	return []agentruntime.ContainerSummary{
		{ID: "cnt-pg-123456789", Names: []string{"/pc-pg-b73f8a42-5f6e-4a9c-b17f-8d23e59b20d1"}, Image: "postgres:16", State: "running"},
		{ID: "cnt-vk-987654321", Names: []string{"/pc-vk-e89a1b2c-3d4e-5f60-7182-93a4b5c6d7e8"}, Image: "valkey/valkey:7.2", State: "running"},
	}, nil
}

func (m *mockLabeledRuntime) InspectContainer(ctx context.Context, containerID string) (*agentruntime.ContainerInspect, error) {
	if containerID == "cnt-pg-123456789" {
		return &agentruntime.ContainerInspect{
			ID:      containerID,
			Name:    "/pc-pg-b73f8a42-5f6e-4a9c-b17f-8d23e59b20d1",
			Running: true,
			Labels: map[string]string{
				"primecloud.resource_id": "b73f8a42-5f6e-4a9c-b17f-8d23e59b20d1",
				"primecloud.managed":     "true",
			},
		}, nil
	}
	return &agentruntime.ContainerInspect{
		ID:      containerID,
		Name:    "/pc-vk-e89a1b2c-3d4e-5f60-7182-93a4b5c6d7e8",
		Running: true,
		Labels: map[string]string{
			"primecloud.resource_id": "e89a1b2c-3d4e-5f60-7182-93a4b5c6d7e8",
			"primecloud.managed":     "true",
		},
	}, nil
}

func (m *mockLabeledRuntime) GetContainerStats(ctx context.Context, containerID string) (io.ReadCloser, error) {
	return nil, nil
}

func (m *mockLabeledRuntime) ExecContainer(ctx context.Context, containerID string, cmd []string, env []string, stdin io.Reader) ([]byte, []byte, int, error) {
	return nil, nil, 0, nil
}

func TestCollectorAuthoritativeResourceUUID(t *testing.T) {
	rt := &mockLabeledRuntime{}
	coll := NewCollector(100*time.Millisecond, "node-001", "agent-001", rt, nil, nil)

	payload, err := coll.Sample(context.Background())
	if err != nil {
		t.Fatalf("unexpected sampling error: %v", err)
	}

	if payload.ContainerCount != 2 {
		t.Fatalf("expected 2 containers, got %d", payload.ContainerCount)
	}

	foundPG := false
	foundVK := false
	for _, stat := range payload.ContainerStats {
		if stat.ResourceID == "b73f8a42-5f6e-4a9c-b17f-8d23e59b20d1" {
			foundPG = true
			if stat.Engine != "postgres" {
				t.Errorf("expected engine postgres, got %s", stat.Engine)
			}
		}
		if stat.ResourceID == "e89a1b2c-3d4e-5f60-7182-93a4b5c6d7e8" {
			foundVK = true
			if stat.Engine != "valkey" {
				t.Errorf("expected engine valkey, got %s", stat.Engine)
			}
		}
	}

	if !foundPG {
		t.Errorf("authoritative Postgres resource UUID b73f8a42-5f6e-4a9c-b17f-8d23e59b20d1 was not found in ContainerStats")
	}
	if !foundVK {
		t.Errorf("authoritative Valkey resource UUID e89a1b2c-3d4e-5f60-7182-93a4b5c6d7e8 was not found in ContainerStats")
	}
}
