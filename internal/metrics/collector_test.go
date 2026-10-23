package metrics

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
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

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
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

type mockAppAndInfraRuntime struct {
	agentruntime.ContainerRuntime
}

func (m *mockAppAndInfraRuntime) ListContainers(ctx context.Context, all bool) ([]agentruntime.ContainerSummary, error) {
	return []agentruntime.ContainerSummary{
		{ID: "cnt-app-label", Names: []string{"/pc-app-labeled"}, State: "running"},
		{ID: "cnt-app-name", Names: []string{"/pc-app-01a134a0-bbfb-73fe-a2d1-c23a5ab815ec-3dbb740b-8e7a-4403-b71c-cb5f5b57704c"}, State: "running"},
		{ID: "cnt-infra-cp", Names: []string{"/primecloud-control-plane"}, State: "running"},
		{ID: "cnt-infra-vk", Names: []string{"/primecloud-valkey"}, State: "running"},
	}, nil
}

func (m *mockAppAndInfraRuntime) InspectContainer(ctx context.Context, containerID string) (*agentruntime.ContainerInspect, error) {
	if containerID == "cnt-app-label" {
		return &agentruntime.ContainerInspect{
			ID:      containerID,
			Name:    "/pc-app-labeled",
			Running: true,
			Labels: map[string]string{
				"primecloud.application_id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
				"primecloud.managed":        "true",
			},
		}, nil
	}
	if containerID == "cnt-app-name" {
		return &agentruntime.ContainerInspect{
			ID:      containerID,
			Name:    "/pc-app-01a134a0-bbfb-73fe-a2d1-c23a5ab815ec-3dbb740b-8e7a-4403-b71c-cb5f5b57704c",
			Running: true,
		}, nil
	}
	if containerID == "cnt-infra-cp" {
		return &agentruntime.ContainerInspect{
			ID:      containerID,
			Name:    "/primecloud-control-plane",
			Running: true,
		}, nil
	}
	return &agentruntime.ContainerInspect{
		ID:      containerID,
		Name:    "/primecloud-valkey",
		Running: true,
	}, nil
}

func (m *mockAppAndInfraRuntime) GetContainerStats(ctx context.Context, containerID string) (io.ReadCloser, error) {
	return nil, nil
}

func (m *mockAppAndInfraRuntime) ExecContainer(ctx context.Context, containerID string, cmd []string, env []string, stdin io.Reader) ([]byte, []byte, int, error) {
	return nil, nil, 0, nil
}

func TestCollectorApplicationResolutionAndInfraFilter(t *testing.T) {
	rt := &mockAppAndInfraRuntime{}
	coll := NewCollector(100*time.Millisecond, "node-001", "agent-001", rt, nil, nil)

	payload, err := coll.Sample(context.Background())
	if err != nil {
		t.Fatalf("unexpected sampling error: %v", err)
	}

	// Infra containers (primecloud-control-plane, primecloud-valkey) must be skipped from tenant stats
	if len(payload.ContainerStats) != 2 {
		t.Fatalf("expected 2 tenant containers in stats, got %d", len(payload.ContainerStats))
	}

	appByLabel := payload.ContainerStats["cnt-app-labe"]
	if appByLabel.ResourceID != "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee" {
		t.Errorf("expected label resolved UUID aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee, got %s", appByLabel.ResourceID)
	}

	appByName := payload.ContainerStats["cnt-app-name"]
	if appByName.ResourceID != "3dbb740b-8e7a-4403-b71c-cb5f5b57704c" {
		t.Errorf("expected name resolved UUID 3dbb740b-8e7a-4403-b71c-cb5f5b57704c, got %s", appByName.ResourceID)
	}
}

func TestHostMetricsLinuxProcAndDf(t *testing.T) {
	coll := NewCollector(100*time.Millisecond, "node-linux-01", "agent-linux-01", nil, nil, nil)
	coll.goos = "linux"

	step := 0
	coll.readFileFunc = func(path string) ([]byte, error) {
		switch path {
		case "/proc/stat":
			if step == 0 {
				return []byte("cpu  1000 0 500 8500 0 0 0 0 0 0\n"), nil
			}
			// Delta: user+500, system+500, idle+1000 => active=1000, total=2000 => 50.0%
			return []byte("cpu  1500 0 1000 9500 0 0 0 0 0 0\n"), nil
		case "/proc/loadavg":
			return []byte("1.20 0.80 0.50 1/200 1234\n"), nil
		case "/proc/meminfo":
			// 16 GB total, 4 GB available => 75% used (12288 MB used / 16384 MB total)
			return []byte("MemTotal:       16777216 kB\nMemFree:         2097152 kB\nMemAvailable:    4194304 kB\n"), nil
		}
		return nil, errors.New("file not found")
	}
	coll.runCommandFunc = func(ctx context.Context, name string, args ...string) ([]byte, error) {
		// 40% disk usage (40,000,000 used / 60,000,000 avail)
		return []byte("Filesystem     1024-blocks     Used Available Capacity Mounted on\n/dev/sda1        100000000 40000000  60000000      40% /\n"), nil
	}

	// Sample 1: primes prevCPU and uses /proc/loadavg fallback
	p1, err := coll.Sample(context.Background())
	if err != nil {
		t.Fatalf("unexpected error on sample 1: %v", err)
	}
	if !p1.CPUAvailable || !p1.MemoryAvailable || !p1.DiskAvailable {
		t.Fatalf("expected all host metrics available on sample 1, got cpu=%v mem=%v disk=%v", p1.CPUAvailable, p1.MemoryAvailable, p1.DiskAvailable)
	}

	// Sample 2: computes exact /proc/stat delta (50.0% CPU), 75.0% Memory, 40.0% Disk
	step = 1
	p2, err := coll.Sample(context.Background())
	if err != nil {
		t.Fatalf("unexpected error on sample 2: %v", err)
	}
	if math.Abs(p2.CPUUsagePercent-50.0) > 0.01 {
		t.Errorf("expected CPU 50.0%%, got %.2f%%", p2.CPUUsagePercent)
	}
	if math.Abs(p2.MemoryUsagePercent-75.0) > 0.01 {
		t.Errorf("expected Memory 75.0%%, got %.2f%%", p2.MemoryUsagePercent)
	}
	if p2.AllocatedMemoryMB != 12288 || p2.TotalMemoryMB != 16384 {
		t.Errorf("expected 12288/16384 MB memory, got %d/%d MB", p2.AllocatedMemoryMB, p2.TotalMemoryMB)
	}
	if math.Abs(p2.DiskUsagePercent-40.0) > 0.01 {
		t.Errorf("expected Disk 40.0%%, got %.2f%%", p2.DiskUsagePercent)
	}

	batch := coll.BuildIngestBatch(p2)
	if len(batch.Metrics) != 3 {
		t.Fatalf("expected 3 host metric points in batch, got %d", len(batch.Metrics))
	}
	for _, pt := range batch.Metrics {
		if pt.ResourceType != "node" || pt.ResourceID != "node-linux-01" || pt.Unit != "percent" {
			t.Errorf("unexpected host point metadata: %+v", pt)
		}
	}
}

func TestHostMetricsMissingDataAndUnsupportedOSNoFakeZeros(t *testing.T) {
	// 1. Linux with unreadable /proc and failing df must NOT emit fake 0.0 metrics
	coll := NewCollector(100*time.Millisecond, "node-missing-01", "agent-01", nil, nil, nil)
	coll.goos = "linux"
	coll.readFileFunc = func(path string) ([]byte, error) {
		return nil, errors.New("permission denied")
	}
	coll.runCommandFunc = func(ctx context.Context, name string, args ...string) ([]byte, error) {
		return nil, errors.New("df failed")
	}

	pMissing, err := coll.Sample(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pMissing.CPUAvailable || pMissing.MemoryAvailable || pMissing.DiskAvailable {
		t.Errorf("expected all availability flags false when OS probes fail, got cpu=%v mem=%v disk=%v",
			pMissing.CPUAvailable, pMissing.MemoryAvailable, pMissing.DiskAvailable)
	}
	batchMissing := coll.BuildIngestBatch(pMissing)
	if len(batchMissing.Metrics) != 0 {
		t.Errorf("expected 0 emitted points when host metrics are unavailable (never emit fake zeros), got %d: %+v",
			len(batchMissing.Metrics), batchMissing.Metrics)
	}

	// 2. Unsupported OS (e.g. freebsd) must also set availability flags false and emit 0 host points
	collUnsupported := NewCollector(100*time.Millisecond, "node-bsd-01", "agent-01", nil, nil, nil)
	collUnsupported.goos = "freebsd"
	pUnsupported, err := collUnsupported.Sample(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pUnsupported.CPUAvailable || pUnsupported.MemoryAvailable || pUnsupported.DiskAvailable {
		t.Errorf("expected availability flags false on unsupported OS")
	}
	batchUnsupported := collUnsupported.BuildIngestBatch(pUnsupported)
	if len(batchUnsupported.Metrics) != 0 {
		t.Errorf("expected 0 emitted points on unsupported OS, got %d", len(batchUnsupported.Metrics))
	}
}

func TestHostMetricsWindowsAndHTTPTransmission(t *testing.T) {
	var receivedBatch IngestMetricBatch
	var receivedKey, receivedSender, receivedIdemp string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedKey = r.Header.Get("X-Agent-Key")
		receivedSender = r.Header.Get("X-Sender-Identity")
		receivedIdemp = r.Header.Get("Idempotency-Key")
		_ = json.NewDecoder(r.Body).Decode(&receivedBatch)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	coll := NewCollectorWithAuth(100*time.Millisecond, "node-win-01", "agent-win-01", nil, srv.URL, "secret-agent-key", nil)
	coll.goos = "windows"
	coll.runCommandFunc = func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if len(args) > 0 && args[0] == "cpu" {
			return []byte("LoadPercentage\r\n35\r\n"), nil
		}
		if len(args) > 0 && args[0] == "OS" {
			return []byte("FreePhysicalMemory  TotalVisibleMemorySize\r\n4194304             8388608\r\n"), nil
		}
		if len(args) > 0 && args[0] == "logicaldisk" {
			return []byte("FreeSpace     Size\r\n150000000000  200000000000\r\n"), nil
		}
		return nil, errors.New("unknown command")
	}

	payload, err := coll.Sample(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !payload.CPUAvailable || math.Abs(payload.CPUUsagePercent-35.0) > 0.01 {
		t.Errorf("expected Windows CPU 35.0%%, got avail=%v val=%.2f", payload.CPUAvailable, payload.CPUUsagePercent)
	}
	if !payload.MemoryAvailable || math.Abs(payload.MemoryUsagePercent-50.0) > 0.01 {
		t.Errorf("expected Windows Memory 50.0%%, got avail=%v val=%.2f", payload.MemoryAvailable, payload.MemoryUsagePercent)
	}
	if !payload.DiskAvailable || math.Abs(payload.DiskUsagePercent-25.0) > 0.01 {
		t.Errorf("expected Windows Disk 25.0%%, got avail=%v val=%.2f", payload.DiskAvailable, payload.DiskUsagePercent)
	}

	coll.transmitHTTP(context.Background(), payload)
	if receivedKey != "secret-agent-key" || receivedSender != "agent:node-win-01" || receivedIdemp == "" {
		t.Errorf("unexpected auth headers: key=%q sender=%q idemp=%q", receivedKey, receivedSender, receivedIdemp)
	}
	if len(receivedBatch.Metrics) != 3 {
		t.Fatalf("expected 3 metrics transmitted over HTTP, got %d", len(receivedBatch.Metrics))
	}
}
