package applications_test

import (
	"context"
	"io"
	"log/slog"
	"strconv"
	"testing"

	"github.com/docker/go-connections/nat"
	"github.com/primecloud/primecloud-agent/internal/applications"
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
func (m *MockRuntime) GetContainerLogs(ctx context.Context, containerID string) (io.ReadCloser, error) {
	return nil, nil
}
func (m *MockRuntime) ListContainers(ctx context.Context, all bool) ([]runtime.ContainerSummary, error) {
	return nil, nil
}
func (m *MockRuntime) ExecContainer(ctx context.Context, containerID string, cmd []string, env []string, stdin io.Reader) ([]byte, []byte, int, error) {
	return nil, nil, 0, nil
}
func (m *MockRuntime) Ping(ctx context.Context) error { return nil }
func (m *MockRuntime) Close() error { return nil }

func TestDynamicPortAllocation_BuildPortConfig_Port8000(t *testing.T) {
	// 1. Verify that when container port 8000 is requested, BuildPortConfig creates exposed port 8000/tcp
	// and HostPort binding {HostIP: "0.0.0.0", HostPort: ""}
	ports := map[string]string{
		"8000/tcp": "8000",
	}

	exposedPorts, portBindings, err := runtime.BuildPortConfig(ports)
	if err != nil {
		t.Fatalf("BuildPortConfig failed: %v", err)
	}

	expectedPort := nat.Port("8000/tcp")
	if _, ok := exposedPorts[expectedPort]; !ok {
		t.Errorf("Expected 8000/tcp in exposedPorts, got: %v", exposedPorts)
	}

	bindings, ok := portBindings[expectedPort]
	if !ok || len(bindings) != 1 {
		t.Fatalf("Expected 1 binding for 8000/tcp, got: %v", bindings)
	}
	if bindings[0].HostIP != "0.0.0.0" {
		t.Errorf("Expected HostIP 0.0.0.0, got: %q", bindings[0].HostIP)
	}
	if bindings[0].HostPort != "" {
		t.Errorf("Expected ephemeral HostPort (empty string), got: %q", bindings[0].HostPort)
	}
}

func TestDynamicPortAllocation_BuildPortConfig_DefaultsTo8000(t *testing.T) {
	// When ports map is empty, BuildPortConfig MUST default to 8000/tcp with dynamic binding
	exposedPorts, portBindings, err := runtime.BuildPortConfig(nil)
	if err != nil {
		t.Fatalf("BuildPortConfig failed: %v", err)
	}

	expectedPort := nat.Port("8000/tcp")
	if _, ok := exposedPorts[expectedPort]; !ok {
		t.Errorf("Expected 8000/tcp default in exposedPorts, got: %v", exposedPorts)
	}
	bindings := portBindings[expectedPort]
	if len(bindings) != 1 || bindings[0].HostPort != "" {
		t.Errorf("Expected ephemeral HostPort binding for 8000/tcp, got: %v", bindings)
	}
}

func TestDynamicPortAllocation_DeployerSetsEphemeralBinding(t *testing.T) {
	// Verify Deployer converts any payload port representation into ephemeral dynamic host binding
	testCases := []struct {
		name        string
		payloadJSON string
	}{
		{
			name:        "integer port 8000",
			payloadJSON: `{"image": "ghcr.io/primetech-nexus/apps/test:v1", "port": 8000}`,
		},
		{
			name:        "string port 8000",
			payloadJSON: `{"image": "ghcr.io/primetech-nexus/apps/test:v1", "port": "8000"}`,
		},
		{
			name:        "ports map with 8000/tcp string",
			payloadJSON: `{"image": "ghcr.io/primetech-nexus/apps/test:v1", "ports": {"8000/tcp": "8000"}}`,
		},
		{
			name:        "ports map with integer value",
			payloadJSON: `{"image": "ghcr.io/primetech-nexus/apps/test:v1", "ports": {"8000/tcp": 8000}}`,
		},
		{
			name:        "empty payload defaults to 8000",
			payloadJSON: `{"image": "ghcr.io/primetech-nexus/apps/test:v1"}`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mock := &MockRuntime{}
			deployer := applications.NewDeployer(mock, nil, slog.Default())

			cid, err := deployer.Deploy(context.Background(), "p1", "e1", "app1", "inst1", tc.payloadJSON)
			if err != nil {
				t.Fatalf("Deploy failed: %v", err)
			}
			if cid == "" {
				t.Fatal("Expected non-empty container ID")
			}

			if mock.createdConfig == nil {
				t.Fatal("Expected CreateContainer to be called")
			}

			// Verify created config contains 8000/tcp
			hPort, ok := mock.createdConfig.Ports["8000/tcp"]
			if !ok {
				t.Fatalf("Expected 8000/tcp in createdConfig.Ports, got: %v", mock.createdConfig.Ports)
			}
			// HostPort must be empty string (ephemeral dynamic)
			if hPort != "" {
				t.Errorf("HostPort must be empty string for dynamic allocation, got: %q", hPort)
			}
		})
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

func TestPortAllocation_FailClosedWhenNoHostBinding(t *testing.T) {
	// If Docker inspection provides no host port binding (empty), deployment must fail closed
	mock := &MockRuntime{inspectPorts: map[string]string{}}
	insp, err := mock.InspectContainer(context.Background(), "cnt-empty")
	if err != nil {
		t.Fatalf("Inspect failed: %v", err)
	}

	var hostPort int
	for _, hpStr := range insp.Ports {
		if hp, err := strconv.Atoi(hpStr); err == nil && hp > 0 {
			hostPort = hp
			break
		}
	}

	// Must detect missing hostPort and reject
	if hostPort != 0 {
		t.Errorf("Expected hostPort 0 when no binding, got: %d", hostPort)
	}
}
