package metrics

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"sync"
	"testing"
	"time"

	"github.com/docker/docker/api/types"
	agentruntime "github.com/primecloud/primecloud-agent/internal/runtime"
)

// mockStressRuntime allows injecting custom container stats readers and inspect payloads
type mockStressRuntime struct {
	agentruntime.ContainerRuntime
	mu         sync.Mutex
	containers []agentruntime.ContainerSummary
	statsJSON  map[string]types.StatsJSON
	inspectMap map[string]*agentruntime.ContainerInspect
}

func (m *mockStressRuntime) ListContainers(ctx context.Context, all bool) ([]agentruntime.ContainerSummary, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.containers, nil
}

func (m *mockStressRuntime) GetContainerStats(ctx context.Context, containerID string) (io.ReadCloser, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if stat, ok := m.statsJSON[containerID]; ok {
		b, _ := json.Marshal(stat)
		return io.NopCloser(bytes.NewReader(b)), nil
	}
	return nil, nil
}

func (m *mockStressRuntime) InspectContainer(ctx context.Context, containerID string) (*agentruntime.ContainerInspect, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if insp, ok := m.inspectMap[containerID]; ok {
		return insp, nil
	}
	return &agentruntime.ContainerInspect{ID: containerID, Running: true}, nil
}

func (m *mockStressRuntime) ExecContainer(ctx context.Context, containerID string, cmd []string, env []string, stdin io.Reader) ([]byte, []byte, int, error) {
	return []byte("0\n"), nil, 0, nil
}

// mockFastCollector creates a collector with mocked OS readers so tests do not spawn slow OS subprocesses
func mockFastCollector(rt agentruntime.ContainerRuntime) *Collector {
	c := NewCollector(50*time.Millisecond, "node-test-01", "agent-test-01", rt, nil, nil)
	c.runCommandFunc = func(ctx context.Context, name string, args ...string) ([]byte, error) {
		return nil, errors.New("mocked cmd error")
	}
	c.readFileFunc = func(path string) ([]byte, error) {
		return nil, errors.New("mocked read error")
	}
	return c
}

// TestStressCPUNumericalEdgeCases verifies that container CPU calculations never divide by zero,
// never produce negative values, and never output NaN or Inf under degenerate or extreme inputs.
func TestStressCPUNumericalEdgeCases(t *testing.T) {
	testCases := []struct {
		name          string
		cpuTotal      uint64
		preCPUTotal   uint64
		systemUsage   uint64
		preSystem     uint64
		onlineCPUs    uint32
		perCPU        []uint64
		expectZeroCPU bool
	}{
		{
			name:          "Zero system delta (system ticks unchanged)",
			cpuTotal:      1000,
			preCPUTotal:   500,
			systemUsage:   10000,
			preSystem:     10000, // delta = 0
			onlineCPUs:    2,
			expectZeroCPU: true,
		},
		{
			name:          "Negative system delta (clock anomaly or counter wrap)",
			cpuTotal:      1000,
			preCPUTotal:   500,
			systemUsage:   5000,
			preSystem:     10000, // delta = -5000
			onlineCPUs:    2,
			expectZeroCPU: true,
		},
		{
			name:          "Zero CPU delta (container idle)",
			cpuTotal:      1000,
			preCPUTotal:   1000, // delta = 0
			systemUsage:   20000,
			preSystem:     10000,
			onlineCPUs:    4,
			expectZeroCPU: true,
		},
		{
			name:          "Negative CPU delta (container restart or counter reset)",
			cpuTotal:      500,
			preCPUTotal:   1000, // delta = -500
			systemUsage:   20000,
			preSystem:     10000,
			onlineCPUs:    4,
			expectZeroCPU: true,
		},
		{
			name:          "Zero onlineCPUs and empty perCPU defaults safely to 1 core",
			cpuTotal:      2000,
			preCPUTotal:   1000,
			systemUsage:   20000,
			preSystem:     10000,
			onlineCPUs:    0,
			perCPU:        nil,
			expectZeroCPU: false,
		},
		{
			name:          "Near MaxUint64 values (counter near 64-bit ceiling)",
			cpuTotal:      math.MaxUint64 - 10000000,
			preCPUTotal:   math.MaxUint64 - 20000000,
			systemUsage:   math.MaxUint64 - 100000000,
			preSystem:     math.MaxUint64 - 200000000,
			onlineCPUs:    8,
			expectZeroCPU: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			containerID := "cnt-edge-test-12345678"
			rt := &mockStressRuntime{
				containers: []agentruntime.ContainerSummary{
					{ID: containerID, State: "running", Status: "Up"},
				},
				statsJSON: map[string]types.StatsJSON{
					containerID: {
						Stats: types.Stats{
							CPUStats: types.CPUStats{
								CPUUsage: types.CPUUsage{
									TotalUsage:  tc.cpuTotal,
									PercpuUsage: tc.perCPU,
								},
								SystemUsage: tc.systemUsage,
								OnlineCPUs:  tc.onlineCPUs,
							},
							PreCPUStats: types.CPUStats{
								CPUUsage: types.CPUUsage{
									TotalUsage: tc.preCPUTotal,
								},
								SystemUsage: tc.preSystem,
							},
							MemoryStats: types.MemoryStats{
								Usage: 1024 * 1024,
								Limit: 512 * 1024 * 1024,
							},
						},
					},
				},
				inspectMap: map[string]*agentruntime.ContainerInspect{
					containerID: {
						ID:      containerID,
						Running: true,
						Health:  "healthy",
					},
				},
			}

			coll := mockFastCollector(rt)
			payload, err := coll.Sample(context.Background())
			if err != nil {
				t.Fatalf("unexpected Sample error: %v", err)
			}

			var stat ContainerMetric
			found := false
			for _, s := range payload.ContainerStats {
				stat = s
				found = true
				break
			}
			if !found {
				t.Fatalf("no container stats found in payload")
			}

			if math.IsNaN(stat.CPUUsagePercent) {
				t.Fatalf("CPUUsagePercent is NaN for case %s", tc.name)
			}
			if math.IsInf(stat.CPUUsagePercent, 0) {
				t.Fatalf("CPUUsagePercent is Infinite for case %s", tc.name)
			}
			if stat.CPUUsagePercent < 0.0 {
				t.Fatalf("CPUUsagePercent is negative (%f) for case %s", stat.CPUUsagePercent, tc.name)
			}
			if tc.expectZeroCPU && stat.CPUUsagePercent != 0.0 {
				t.Fatalf("expected 0.0 CPU, got %f for case %s", stat.CPUUsagePercent, tc.name)
			}
			if !tc.expectZeroCPU && stat.CPUUsagePercent <= 0.0 {
				t.Fatalf("expected positive CPU, got %f for case %s", stat.CPUUsagePercent, tc.name)
			}

			// Verify BuildIngestBatch points
			batch := coll.BuildIngestBatch(payload)
			for _, pt := range batch.Metrics {
				if math.IsNaN(pt.Value) {
					t.Fatalf("emitted metric point %s has NaN value", pt.MetricName)
				}
				if math.IsInf(pt.Value, 0) {
					t.Fatalf("emitted metric point %s has Inf value", pt.MetricName)
				}
				if pt.Value < 0.0 {
					t.Fatalf("emitted metric point %s has negative value %f", pt.MetricName, pt.Value)
				}
			}
		})
	}
}

// TestStressContainerMemoryLimitAndStatusCalculations checks cgroup limit conversions
// and container status mappings under all edge states.
func TestStressContainerMemoryLimitAndStatusCalculations(t *testing.T) {
	coll := mockFastCollector(nil)

	// Test 1: ContainerStatus under various State and HealthStatus combinations
	stateCases := []struct {
		state        string
		health       string
		expectStatus float64
	}{
		{"running", "healthy", 1.0},
		{"running", "", 1.0},
		{"running", "starting", 0.5},
		{"running", "unhealthy", 0.0},
		{"exited", "healthy", 0.0},
		{"stopped", "", 0.0},
		{"dead", "", 0.0},
		{"paused", "healthy", 0.0},
		{"restarting", "", 0.0},
		{"", "", 0.0},
	}

	for _, sc := range stateCases {
		payload := &MetricPayload{
			SampledAt: time.Now(),
			ContainerStats: map[string]ContainerMetric{
				"test-cnt": {
					ResourceID:   "res-status-test",
					State:        sc.state,
					HealthStatus: sc.health,
				},
			},
		}
		batch := coll.BuildIngestBatch(payload)
		found := false
		for _, pt := range batch.Metrics {
			if pt.MetricName == "container_status" {
				found = true
				if pt.Value != sc.expectStatus {
					t.Errorf("state=%q health=%q expected status=%f, got %f", sc.state, sc.health, sc.expectStatus, pt.Value)
				}
				if pt.Unit != "status" {
					t.Errorf("expected unit status, got %s", pt.Unit)
				}
			}
		}
		if !found {
			t.Errorf("container_status not emitted for state=%q health=%q", sc.state, sc.health)
		}
	}

	// Test 2: MemoryLimitBytes handling for zero, negative (cast of MaxUint64), and normal values
	memLimitCases := []struct {
		name        string
		limitBytes  int64
		shouldEmit  bool
		expectValue float64
	}{
		{"Zero limit (unspecified)", 0, false, 0},
		{"Negative limit (from uint64 overflow / -1)", -1, false, 0},
		{"Valid 512MB limit", 536870912, true, 536870912},
		{"Valid 8GB limit", 8589934592, true, 8589934592},
	}

	for _, ml := range memLimitCases {
		payload := &MetricPayload{
			SampledAt: time.Now(),
			ContainerStats: map[string]ContainerMetric{
				"test-mem": {
					ResourceID:       "res-mem-test",
					State:            "running",
					MemoryLimitBytes: ml.limitBytes,
				},
			},
		}
		batch := coll.BuildIngestBatch(payload)
		found := false
		for _, pt := range batch.Metrics {
			if pt.MetricName == "memory_limit_bytes" {
				found = true
				if !ml.shouldEmit {
					t.Errorf("case %s: memory_limit_bytes should NOT be emitted for %d", ml.name, ml.limitBytes)
				}
				if pt.Value != ml.expectValue {
					t.Errorf("case %s: expected %f, got %f", ml.name, ml.expectValue, pt.Value)
				}
			}
		}
		if ml.shouldEmit && !found {
			t.Errorf("case %s: memory_limit_bytes was expected but not emitted", ml.name)
		}
	}
}

// TestStressHostLinuxProcStatAndMeminfoEdgeCases tests procfs parsers against corrupted or extreme files.
func TestStressHostLinuxProcStatAndMeminfoEdgeCases(t *testing.T) {
	// 1. parseLinuxProcStat tests
	procStatTests := []struct {
		name     string
		input    string
		expectOk bool
	}{
		{"Empty string", "", false},
		{"Random garbage", "hello world not proc stat", false},
		{"cpu line too short", "cpu 100 200", false},
		{"cpu line with non-numbers", "cpu abc def ghi jkl", false},
		{"cpu line all zeros", "cpu 0 0 0 0 0 0 0 0", false},
		{
			"Standard Linux proc stat",
			"cpu  2255 34 2290 22625563 6290 127 456 0 0 0\ncpu0 1132 17 1441 11311718 3675 127 438 0 0 0\n",
			true,
		},
	}

	for _, tc := range procStatTests {
		tot, idle, ok := parseLinuxProcStat(tc.input)
		if ok != tc.expectOk {
			t.Errorf("parseLinuxProcStat(%s): expected ok=%v, got %v (total=%d, idle=%d)", tc.name, tc.expectOk, ok, tot, idle)
		}
		if ok && tot == 0 {
			t.Errorf("parseLinuxProcStat(%s): returned ok=true but total is 0", tc.name)
		}
	}

	// 2. parseLinuxMeminfo tests
	meminfoTests := []struct {
		name          string
		input         string
		expectOk      bool
		expectUsedPct float64
	}{
		{"Empty string", "", false, 0},
		{"MemTotal missing", "MemFree: 500000 kB\n", false, 0},
		{"MemTotal zero", "MemTotal: 0 kB\nMemFree: 0 kB\n", false, 0},
		{
			"MemAvailable > MemTotal (clamped)",
			"MemTotal: 1000000 kB\nMemAvailable: 2000000 kB\n",
			true,
			0.0, // usedPct clamped to 0
		},
		{
			"Standard meminfo with MemAvailable",
			"MemTotal: 16000000 kB\nMemAvailable: 8000000 kB\nMemFree: 4000000 kB\n",
			true,
			50.0,
		},
		{
			"Fallback without MemAvailable",
			"MemTotal: 10000000 kB\nMemFree: 5000000 kB\nBuffers: 1000000 kB\nCached: 2000000 kB\n",
			true,
			20.0, // avail = 5M + 1M + 2M = 8M, used = 2M (20%)
		},
	}

	for _, tc := range meminfoTests {
		pct, allocMB, totalMB, ok := parseLinuxMeminfo(tc.input)
		if ok != tc.expectOk {
			t.Errorf("parseLinuxMeminfo(%s): expected ok=%v, got %v", tc.name, tc.expectOk, ok)
		}
		if ok {
			if math.IsNaN(pct) || pct < 0.0 || pct > 100.0 {
				t.Errorf("parseLinuxMeminfo(%s): invalid pct %f", tc.name, pct)
			}
			if math.Abs(pct-tc.expectUsedPct) > 0.01 {
				t.Errorf("parseLinuxMeminfo(%s): expected usedPct=%f, got %f", tc.name, tc.expectUsedPct, pct)
			}
			if allocMB < 0 || totalMB <= 0 {
				t.Errorf("parseLinuxMeminfo(%s): invalid allocMB=%d totalMB=%d", tc.name, allocMB, totalMB)
			}
		}
	}
}

// TestStressCollectorConcurrentSampling runs concurrent samplings and batch builds
// to stress-test mutex synchronization and prevent race conditions.
func TestStressCollectorConcurrentSampling(t *testing.T) {
	rt := &mockStressRuntime{
		containers: []agentruntime.ContainerSummary{
			{ID: "cnt-concurrent-1", State: "running", Status: "Up"},
			{ID: "cnt-concurrent-2", State: "running", Status: "Up"},
		},
		inspectMap: map[string]*agentruntime.ContainerInspect{
			"cnt-concurrent-1": {ID: "cnt-concurrent-1", Running: true, Health: "healthy"},
			"cnt-concurrent-2": {ID: "cnt-concurrent-2", Running: true, Health: "unhealthy"},
		},
	}

	coll := mockFastCollector(rt)

	var wg sync.WaitGroup
	workers := 20
	iterations := 50

	for i := 0; i < workers; i++ {
		wg.Add(1)
		workerID := i
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				// Toggle drain mode concurrently
				if j%5 == 0 {
					coll.SetDrain(workerID%2 == 0)
				}
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				payload, err := coll.Sample(ctx)
				cancel()
				if err != nil {
					t.Errorf("worker %d iteration %d Sample failed: %v", workerID, j, err)
					return
				}
				if payload == nil {
					t.Errorf("worker %d iteration %d payload is nil", workerID, j)
					return
				}
				batch := coll.BuildIngestBatch(payload)
				if len(batch.Metrics) == 0 {
					t.Errorf("worker %d iteration %d batch has 0 metrics", workerID, j)
					return
				}
			}
		}()
	}

	wg.Wait()
}
