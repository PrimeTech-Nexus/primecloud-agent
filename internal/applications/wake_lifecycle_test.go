package applications

import (
	"context"
	"io"
	"strings"
	"testing"

	"github.com/primecloud/primecloud-agent/internal/runtime"
)

type mockWakeRuntime struct {
	running    bool
	health     string
	startCalls int
	stopCalls  int
}

func (m *mockWakeRuntime) PullImage(ctx context.Context, imageRef string) error {
	return nil
}
func (m *mockWakeRuntime) PullImageWithAuth(ctx context.Context, imageRef string, authBase64 string) error {
	return nil
}
func (m *mockWakeRuntime) CreateContainer(ctx context.Context, cfg *runtime.ContainerConfig, limits *runtime.ResourceLimits, profile *runtime.HardenedIsolationProfile) (string, error) {
	return "cnt-wake-1", nil
}
func (m *mockWakeRuntime) StartContainer(ctx context.Context, id string) error {
	m.startCalls++
	m.running = true
	return nil
}
func (m *mockWakeRuntime) StopContainer(ctx context.Context, id string, timeoutSec *int) error {
	m.stopCalls++
	m.running = false
	return nil
}
func (m *mockWakeRuntime) RemoveContainer(ctx context.Context, id string, force bool) error {
	return nil
}
func (m *mockWakeRuntime) InspectContainer(ctx context.Context, id string) (*runtime.ContainerInspect, error) {
	return &runtime.ContainerInspect{
		ID:      id,
		Running: m.running,
		Health:  m.health,
		State:   "running",
	}, nil
}
func (m *mockWakeRuntime) ListContainers(ctx context.Context, all bool) ([]runtime.ContainerSummary, error) {
	return nil, nil
}
func (m *mockWakeRuntime) GetContainerLogs(ctx context.Context, id string) (io.ReadCloser, error) {
	return nil, nil
}
func (m *mockWakeRuntime) ExecContainer(ctx context.Context, id string, cmd []string, env []string, stdin io.Reader) ([]byte, []byte, int, error) {
	return nil, nil, 0, nil
}
func (m *mockWakeRuntime) GetContainerStats(ctx context.Context, id string) (io.ReadCloser, error) {
	return nil, nil
}
func (m *mockWakeRuntime) Ping(ctx context.Context) error {
	return nil
}
func (m *mockWakeRuntime) Close() error {
	return nil
}

func TestStartApplication_Tier3Idempotency(t *testing.T) {
	ctx := context.Background()
	rt := &mockWakeRuntime{
		running: false,
		health:  "healthy",
	}

	// First start transitions stopped -> running
	if err := StartApplication(ctx, rt, "cnt-wake-1"); err != nil {
		t.Fatalf("First StartApplication failed: %v", err)
	}
	if rt.startCalls != 1 {
		t.Fatalf("Expected 1 StartContainer call, got %d", rt.startCalls)
	}

	// Second concurrent start is a no-op (Tier 3 idempotency)
	if err := StartApplication(ctx, rt, "cnt-wake-1"); err != nil {
		t.Fatalf("Second StartApplication failed: %v", err)
	}
	if rt.startCalls != 1 {
		t.Fatalf("Expected StartContainer to not be called again when already running, got %d calls", rt.startCalls)
	}
}

func TestSanitizeCrashLogs_RedactsSecretsAndBoundsSize(t *testing.T) {
	raw := "Error connecting: password=mySuperSecret123 api_key=sk_live_998877 token:abc999"
	sanitized := SanitizeCrashLogs(raw)

	if strings.Contains(sanitized, "mySuperSecret123") || strings.Contains(sanitized, "sk_live_998877") || strings.Contains(sanitized, "abc999") {
		t.Fatalf("SanitizeCrashLogs leaked secret values: %s", sanitized)
	}
	if !strings.Contains(sanitized, "***REDACTED***") {
		t.Fatalf("Expected ***REDACTED*** marker in: %s", sanitized)
	}

	huge := strings.Repeat("x", 8192)
	bounded := SanitizeCrashLogs(huge)
	if len(bounded) != 4096 {
		t.Fatalf("Expected crash logs bounded to 4096 bytes, got %d", len(bounded))
	}
}

func TestSanitizeCrashLogs_PreservesCustomerTracebackAndRedactsPlatformInternals(t *testing.T) {
	raw := `Traceback (most recent call last):
  File "/app/app/main.py", line 19, in <module>
    from app.middleware.csrf import CSRFProtectionMiddleware
ModuleNotFoundError: No module named 'app.middleware.csrf'
Failed to connect to postgresql://dbuser:supersecretpass@10.240.171.12:5432/proddb on node pc-node-001 via /var/run/docker.sock (node ip 167.86.73.226)`

	sanitized := SanitizeCrashLogs(raw)

	// Customer traceback and error must be preserved
	if !strings.Contains(sanitized, "ModuleNotFoundError: No module named 'app.middleware.csrf'") {
		t.Fatalf("SanitizeCrashLogs wiped customer exception: %s", sanitized)
	}
	if !strings.Contains(sanitized, "/app/app/main.py") {
		t.Fatalf("SanitizeCrashLogs wiped customer source path: %s", sanitized)
	}

	// Platform internals must be redacted
	if strings.Contains(sanitized, "supersecretpass") {
		t.Fatalf("SanitizeCrashLogs leaked DB password: %s", sanitized)
	}
	if strings.Contains(sanitized, "10.240.171.12") || strings.Contains(sanitized, "167.86.73.226") {
		t.Fatalf("SanitizeCrashLogs leaked internal node IP: %s", sanitized)
	}
	if strings.Contains(sanitized, "pc-node-001") {
		t.Fatalf("SanitizeCrashLogs leaked internal node name: %s", sanitized)
	}
	if strings.Contains(sanitized, "/var/run/docker.sock") {
		t.Fatalf("SanitizeCrashLogs leaked internal docker socket: %s", sanitized)
	}
}
