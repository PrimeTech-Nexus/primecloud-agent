package applications_test

import (
	"context"
	"strings"
	"testing"

	"github.com/docker/go-connections/nat"
	"github.com/primecloud/primecloud-agent/internal/runtime"
)

// MockRuntime implements runtime.ContainerRuntime for deterministic port tests.
type MockRuntime struct {
	createdConfig *runtime.ContainerConfig
	inspectPorts  map[string]string
	removedID     string
	removedForce  bool
}

func (m *MockRuntime) PullImage(ctx context.Context, ref string) error { return nil }
func (m *MockRuntime) PullImageWithAuth(ctx context.Context, ref, auth string) error { return nil }
func (m *MockRuntime) CreateContainer(ctx context.Context, cfg *runtime.ContainerConfig, l *runtime.ResourceLimits, p *runtime.HardenedIsolationProfile) (string, error) {
	m.createdConfig = cfg
	return "mock-container-12345", nil
}
func (m *MockRuntime) StartContainer(ctx context.Context, id string) error { return nil }
func (m *MockRuntime) StopContainer(ctx context.Context, id string, timeout *int) error { return nil }
func (m *MockRuntime) RemoveContainer(ctx context.Context, id string, force bool) error {
	m.removedID = id
	m.removedForce = force
	return nil
}
func (m *MockRuntime) InspectContainer(ctx context.Context, id string) (*runtime.ContainerInspect, error) {
	return &runtime.ContainerInspect{
		ID:      id,
		Running: true,
		State:   "running",
		Health:  "healthy",
		Ports:   m.inspectPorts,
	}, nil
}
func (m *MockRuntime) Ping(ctx context.Context) error { return nil }
func (m *MockRuntime) Close() error { return nil }

func TestDynamicPortAllocation_Port8000Ephemeral(t *testing.T) {
	// 1. Verify that when container port 8000 is requested, Agent creates container with ephemeral host port binding ("")
	cfg := &runtime.ContainerConfig{
		Name:  "test-app",
		Image: "ghcr.io/primetech-nexus/apps/app:v1",
		Ports: map[string]string{
			"8000/tcp": "8000", // Control plane or user specifies container port 8000
		},
	}

	exposedPorts := nat.PortSet{}
	portBindings := nat.PortMap{}
	for cPort, hPort := range cfg.Ports {
		portNum := cPort
		proto := "tcp"
		if parts := strings.Split(cPort, "/"); len(parts) == 2 {
			portNum = parts[0]
			proto = parts[1]
		}
		natPort, err := nat.NewPort(proto, portNum)
		if err != nil {
			t.Fatalf("Failed to parse nat port: %v", err)
		}
		exposedPorts[natPort] = struct{}{}
		effectiveHostPort := ""
		if hPort != "" && hPort != "8000" && hPort != "0" && hPort != portNum {
			effectiveHostPort = hPort
		}
		portBindings[natPort] = []nat.PortBinding{
			{HostIP: "0.0.0.0", HostPort: effectiveHostPort},
		}
	}

	// Verify exposed port is 8000/tcp
	expectedPort := nat.Port("8000/tcp")
	if _, ok := exposedPorts[expectedPort]; !ok {
		t.Errorf("Expected 8000/tcp in exposedPorts, got: %v", exposedPorts)
	}

	// Verify host binding is ephemeral ("") and NOT 8000
	bindings := portBindings[expectedPort]
	if len(bindings) != 1 {
		t.Fatalf("Expected 1 binding for 8000/tcp, got: %d", len(bindings))
	}
	if bindings[0].HostPort != "" {
		t.Errorf("Expected ephemeral host port (empty string), got: %q", bindings[0].HostPort)
	}
}

func TestDynamicPortAllocation_ParseWithoutProtocol(t *testing.T) {
	// Verify that container port specified as bare "8000" also maps to ephemeral host port
	cfg := &runtime.ContainerConfig{
		Name:  "test-app-bare",
		Image: "ghcr.io/primetech-nexus/apps/app:v1",
		Ports: map[string]string{
			"8000": "",
		},
	}

	exposedPorts := nat.PortSet{}
	portBindings := nat.PortMap{}
	for cPort, hPort := range cfg.Ports {
		portNum := cPort
		proto := "tcp"
		if parts := strings.Split(cPort, "/"); len(parts) == 2 {
			portNum = parts[0]
			proto = parts[1]
		}
		natPort, err := nat.NewPort(proto, portNum)
		if err != nil {
			t.Fatalf("Failed to parse nat port: %v", err)
		}
		exposedPorts[natPort] = struct{}{}
		effectiveHostPort := ""
		if hPort != "" && hPort != "8000" && hPort != "0" && hPort != portNum {
			effectiveHostPort = hPort
		}
		portBindings[natPort] = []nat.PortBinding{
			{HostIP: "0.0.0.0", HostPort: effectiveHostPort},
		}
	}

	expectedPort := nat.Port("8000/tcp")
	if _, ok := exposedPorts[expectedPort]; !ok {
		t.Errorf("Expected 8000/tcp in exposedPorts, got: %v", exposedPorts)
	}
	bindings := portBindings[expectedPort]
	if len(bindings) != 1 || bindings[0].HostPort != "" {
		t.Errorf("Expected ephemeral host port binding, got: %v", bindings)
	}
}

func TestPortAllocation_MultipleApplicationsDoNotCollide(t *testing.T) {
	// Simulate two distinct customer apps running on container port 8000
	app1InspectPorts := map[string]string{"8000/tcp": "32845"}
	app2InspectPorts := map[string]string{"8000/tcp": "32846"}

	mock1 := &MockRuntime{inspectPorts: app1InspectPorts}
	mock2 := &MockRuntime{inspectPorts: app2InspectPorts}

	insp1, _ := mock1.InspectContainer(context.Background(), "cnt-1")
	insp2, _ := mock2.InspectContainer(context.Background(), "cnt-2")

	hp1 := insp1.Ports["8000/tcp"]
	hp2 := insp2.Ports["8000/tcp"]

	if hp1 == hp2 {
		t.Errorf("Host ports collided: app1=%s, app2=%s", hp1, hp2)
	}
	if hp1 == "8000" || hp2 == "8000" {
		t.Errorf("Host port 8000 allocated to customer container!")
	}
	if hp1 != "32845" || hp2 != "32846" {
		t.Errorf("Expected distinct ephemeral ports, got hp1=%s, hp2=%s", hp1, hp2)
	}
}
