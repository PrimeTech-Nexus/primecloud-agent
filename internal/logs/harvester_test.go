package logs

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	agentruntime "github.com/primecloud/primecloud-agent/internal/runtime"
)

// Helper to construct a Docker-multiplexed frame header (8 bytes)
// [stream_type (1 byte), 3 bytes 0, 4 bytes payload size (big endian)]
func makeDockerFrame(stream byte, payload string) []byte {
	header := make([]byte, 8)
	header[0] = stream
	binary.BigEndian.PutUint32(header[4:], uint32(len(payload)))
	return append(header, []byte(payload)...)
}

func TestDemuxDockerLogStream(t *testing.T) {
	// Construct a stream with mixed stdout (1) and stderr (2) frames
	ts1 := "2026-10-13T20:00:00.123456789Z"
	ts2 := "2026-10-13T20:00:01.000000000Z"

	frame1 := makeDockerFrame(1, ts1+" Application started successfully\n")
	frame2 := makeDockerFrame(2, ts2+" Database connection failed: error timeout\n")

	var rawStream bytes.Buffer
	rawStream.Write(frame1)
	rawStream.Write(frame2)

	items, err := DemuxDockerLogStream(&rawStream, "stdout")
	if err != nil {
		t.Fatalf("unexpected demux error: %v", err)
	}

	if len(items) != 2 {
		t.Fatalf("expected 2 demuxed items, got %d", len(items))
	}

	// Verify Item 1 (stdout)
	if items[0].Stream != StreamStdout {
		t.Errorf("expected stream stdout, got %s", items[0].Stream)
	}
	if items[0].Severity != SeverityInfo {
		t.Errorf("expected severity INFO, got %s", items[0].Severity)
	}
	if items[0].Message != "Application started successfully" {
		t.Errorf("expected message 'Application started successfully', got '%s'", items[0].Message)
	}
	expectedT1, _ := time.Parse(time.RFC3339Nano, ts1)
	expectedT2, _ := time.Parse(time.RFC3339Nano, ts2)

	if items[0].Timestamp == nil || !items[0].Timestamp.Equal(expectedT1) {
		t.Errorf("expected parsed timestamp %v, got %v", expectedT1, items[0].Timestamp)
	}

	// Verify Item 2 (stderr)
	if items[1].Stream != StreamStderr {
		t.Errorf("expected stream stderr, got %s", items[1].Stream)
	}
	if items[1].Severity != SeverityError {
		t.Errorf("expected severity ERROR, got %s", items[1].Severity)
	}
	if items[1].Message != "Database connection failed: error timeout" {
		t.Errorf("expected message 'Database connection failed: error timeout', got '%s'", items[1].Message)
	}
	if items[1].Timestamp == nil || !items[1].Timestamp.Equal(expectedT2) {
		t.Errorf("expected parsed timestamp %v, got %v", expectedT2, items[1].Timestamp)
	}
}

func TestDemuxRawStreamFallback(t *testing.T) {
	// Plain text without Docker multiplex headers
	raw := "2026-10-13T20:00:00Z Standard raw log line\nSecond line without timestamp\n"
	reader := strings.NewReader(raw)

	items, err := DemuxDockerLogStream(reader, "stdout")
	if err != nil {
		t.Fatalf("unexpected demux error: %v", err)
	}

	if len(items) != 2 {
		t.Fatalf("expected 2 items, got %d", len(items))
	}
	if items[0].Stream != StreamStdout {
		t.Errorf("expected stream stdout, got %s", items[0].Stream)
	}
}

func TestRedactSecrets(t *testing.T) {
	input := "api_key=sk_test_123456789012345678901234 secret_token: abc123xyz password='mySuperSecretPassword'"
	redacted := RedactSecrets(input)

	if strings.Contains(redacted, "sk_test_") {
		t.Errorf("expected sk_test token to be redacted, got: %s", redacted)
	}
	if strings.Contains(redacted, "abc123xyz") {
		t.Errorf("expected secret_token to be redacted, got: %s", redacted)
	}
	if strings.Contains(redacted, "mySuperSecretPassword") {
		t.Errorf("expected password to be redacted, got: %s", redacted)
	}
}

func TestStableIdempotencyKeyAcrossRetries(t *testing.T) {
	var requestCount int32
	var receivedKeys []string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count := atomic.AddInt32(&requestCount, 1)
		idempKey := r.Header.Get("Idempotency-Key")
		receivedKeys = append(receivedKeys, idempKey)

		// First request fails with transient 503
		if count == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			w.Write([]byte(`{"error":"temporarily overloaded"}`))
			return
		}

		// Second request succeeds with 202 Accepted
		w.WriteHeader(http.StatusAccepted)
		w.Write([]byte(`{"accepted_count":1,"status":"persisted"}`))
	}))
	defer server.Close()

	h := NewHarvesterWithAuth(nil, server.URL, "test-agent-key", "node-01", 10, 1*time.Second, nil)
	h.EnqueueLog(LogItem{
		ResourceID: "app-uuid-1",
		Message:    "Log message needing retry",
	})

	// Attempt 1: Should fail due to 503
	err1 := h.Flush(context.Background())
	if err1 == nil {
		t.Fatal("expected flush attempt 1 to fail with transient error")
	}

	// Verify inflight batch is preserved with stable key
	h.mu.Lock()
	if h.inflight == nil {
		t.Fatal("expected inflight batch to be preserved after transient failure")
	}
	savedKey := h.inflight.Key
	h.mu.Unlock()

	// Attempt 2: Should succeed and reuse the exact same key
	err2 := h.Flush(context.Background())
	if err2 != nil {
		t.Fatalf("expected flush attempt 2 to succeed, got %v", err2)
	}

	if len(receivedKeys) != 2 {
		t.Fatalf("expected 2 HTTP requests, got %d", len(receivedKeys))
	}
	if receivedKeys[0] != receivedKeys[1] {
		t.Errorf("expected stable Idempotency-Key across retries, got %s vs %s", receivedKeys[0], receivedKeys[1])
	}
	if receivedKeys[0] != savedKey {
		t.Errorf("expected key to match saved inflight key, got %s vs %s", receivedKeys[0], savedKey)
	}

	// Verify inflight batch is cleared after success
	h.mu.Lock()
	if h.inflight != nil {
		t.Error("expected inflight batch to be cleared after success")
	}
	h.mu.Unlock()
}

func TestPermanentAuthenticationAndConflictFailures(t *testing.T) {
	// Test 401 Unauthorized permanently drops the batch to prevent infinite queue blockage
	server401 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"detail":"Invalid agent key"}`))
	}))
	defer server401.Close()

	h := NewHarvesterWithAuth(nil, server401.URL, "bad-key", "node-01", 10, 1*time.Second, nil)
	h.EnqueueLog(LogItem{ResourceID: "app-1", Message: "Droppable log"})

	err := h.Flush(context.Background())
	if err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("expected 401 error, got %v", err)
	}

	h.mu.Lock()
	if h.inflight != nil {
		t.Error("expected inflight batch to be dropped on 401 permanent error")
	}
	h.mu.Unlock()

	// Test 409 Conflict also drops the poisoned batch
	server409 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
		w.Write([]byte(`{"detail":"Payload mismatch for idempotency key"}`))
	}))
	defer server409.Close()

	hConflict := NewHarvesterWithAuth(nil, server409.URL, "valid-key", "node-01", 10, 1*time.Second, nil)
	hConflict.EnqueueLog(LogItem{ResourceID: "app-2", Message: "Poisoned log"})

	errConflict := hConflict.Flush(context.Background())
	if errConflict == nil || !strings.Contains(errConflict.Error(), "409") {
		t.Fatalf("expected 409 error, got %v", errConflict)
	}

	hConflict.mu.Lock()
	if hConflict.inflight != nil {
		t.Error("expected inflight batch to be dropped on 409 conflict")
	}
	hConflict.mu.Unlock()
}

func TestHeadersAndPayloadContract(t *testing.T) {
	var capturedAgentKey, capturedSender, capturedIdempKey string
	var capturedPayload LogBatchPayload

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedAgentKey = r.Header.Get("X-Agent-Key")
		capturedSender = r.Header.Get("X-Sender-Identity")
		capturedIdempKey = r.Header.Get("Idempotency-Key")

		bodyBytes, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(bodyBytes, &capturedPayload)

		w.WriteHeader(http.StatusAccepted)
		w.Write([]byte(`{"accepted_count":1,"status":"persisted"}`))
	}))
	defer server.Close()

	h := NewHarvesterWithAuth(nil, server.URL, "cluster-agent-shared-key-123", "pc-node-01", 10, 1*time.Second, nil)
	h.EnqueueLog(LogItem{
		ResourceID:   "0191c000-0000-7000-8000-000000000001",
		ResourceType: ResourceTypeApplication,
		Stream:       "stdout",
		Severity:     "INFO",
		Message:      "Test log contract payload",
	})

	err := h.Flush(context.Background())
	if err != nil {
		t.Fatalf("expected flush to succeed, got %v", err)
	}

	if capturedAgentKey != "cluster-agent-shared-key-123" {
		t.Errorf("expected X-Agent-Key header, got '%s'", capturedAgentKey)
	}
	if capturedSender != "agent:pc-node-01" {
		t.Errorf("expected X-Sender-Identity 'agent:pc-node-01', got '%s'", capturedSender)
	}
	if capturedIdempKey == "" {
		t.Error("expected non-empty Idempotency-Key header")
	}
	if len(capturedPayload.Logs) != 1 {
		t.Fatalf("expected 1 log entry in payload, got %d", len(capturedPayload.Logs))
	}
	if capturedPayload.Logs[0].ResourceID != "0191c000-0000-7000-8000-000000000001" {
		t.Errorf("expected ResourceID in payload, got %s", capturedPayload.Logs[0].ResourceID)
	}
}

func TestBoundedBatchingAndBackpressure(t *testing.T) {
	h := NewHarvester(nil, "http://localhost:59999", 5, 1*time.Second, nil)
	h.maxBuffer = 10 // Set small backpressure limit

	// Enqueue 15 logs (exceeding limit of 10)
	for i := 1; i <= 15; i++ {
		h.EnqueueLog(LogItem{
			ResourceID: "app-1",
			Message:    "Log message",
		})
	}

	h.mu.Lock()
	bufLen := len(h.buffer)
	h.mu.Unlock()

	if bufLen != 10 {
		t.Errorf("expected buffer capped at maxBuffer=10, got %d", bufLen)
	}
}

func TestNetworkTimeoutHandling(t *testing.T) {
	// Server that sleeps longer than HTTP client timeout
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	h := NewHarvester(nil, server.URL, 10, 1*time.Second, nil)
	h.httpClient = &http.Client{Timeout: 10 * time.Millisecond} // ultra short timeout

	h.EnqueueLog(LogItem{ResourceID: "app-1", Message: "Timeout test"})

	err := h.Flush(context.Background())
	if err == nil {
		t.Fatal("expected flush to return network timeout error")
	}

	// Verify inflight batch retained for retry
	h.mu.Lock()
	if h.inflight == nil {
		t.Error("expected inflight batch to be preserved on network timeout")
	}
	h.mu.Unlock()
}

// MockContainerRuntime for testing DiscoverAndHarvestOnce
type mockRuntime struct {
	agentruntime.ContainerRuntime
	containers []agentruntime.ContainerSummary
	logOutput  map[string][]byte
	sinceCalls map[string][]time.Time
	errOutput  map[string]error
}

func (m *mockRuntime) ListContainers(ctx context.Context, all bool) ([]agentruntime.ContainerSummary, error) {
	return m.containers, nil
}

func (m *mockRuntime) GetContainerLogs(ctx context.Context, containerID string) (io.ReadCloser, error) {
	if m.errOutput != nil {
		if err, ok := m.errOutput[containerID]; ok && err != nil {
			return nil, err
		}
	}
	data, ok := m.logOutput[containerID]
	if !ok {
		return io.NopCloser(bytes.NewReader(nil)), nil
	}
	return io.NopCloser(bytes.NewReader(data)), nil
}

func (m *mockRuntime) GetContainerLogsSince(ctx context.Context, containerID string, since time.Time) (io.ReadCloser, error) {
	if m.sinceCalls == nil {
		m.sinceCalls = make(map[string][]time.Time)
	}
	m.sinceCalls[containerID] = append(m.sinceCalls[containerID], since)

	if m.errOutput != nil {
		if err, ok := m.errOutput[containerID]; ok && err != nil {
			return nil, err
		}
	}
	data, ok := m.logOutput[containerID]
	if !ok {
		return io.NopCloser(bytes.NewReader(nil)), nil
	}
	return io.NopCloser(bytes.NewReader(data)), nil
}

// mockBasicRuntime implements ContainerRuntime without IncrementalLogReader to test fallback behavior.
type mockBasicRuntime struct {
	agentruntime.ContainerRuntime
	containers []agentruntime.ContainerSummary
	logOutput  map[string][]byte
	errOutput  map[string]error
}

func (m *mockBasicRuntime) ListContainers(ctx context.Context, all bool) ([]agentruntime.ContainerSummary, error) {
	return m.containers, nil
}

func (m *mockBasicRuntime) GetContainerLogs(ctx context.Context, containerID string) (io.ReadCloser, error) {
	if m.errOutput != nil {
		if err, ok := m.errOutput[containerID]; ok && err != nil {
			return nil, err
		}
	}
	data, ok := m.logOutput[containerID]
	if !ok {
		return io.NopCloser(bytes.NewReader(nil)), nil
	}
	return io.NopCloser(bytes.NewReader(data)), nil
}

func TestDiscoverAndHarvestOnce(t *testing.T) {
	mockRT := &mockRuntime{
		containers: []agentruntime.ContainerSummary{
			{
				ID:    "cnt-1",
				Names: []string{"/pc-app-prod"},
				Labels: map[string]string{
					"primecloud.resource_id": "res-app-1",
				},
			},
			{
				ID:    "cnt-2",
				Names: []string{"/pc-pg-database-uuid-2"},
				Labels: map[string]string{
					"primecloud.managed": "true",
				},
			},
		},
		logOutput: map[string][]byte{
			"cnt-1": makeDockerFrame(1, "2026-10-13T20:00:00Z App log line\n"),
			"cnt-2": makeDockerFrame(2, "2026-10-13T20:00:01Z Postgres log error\n"),
		},
	}

	h := NewHarvester(mockRT, "http://localhost:59999", 50, 1*time.Second, nil)
	err := h.DiscoverAndHarvestOnce(context.Background())
	if err != nil {
		t.Fatalf("unexpected discover error: %v", err)
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	if len(h.buffer) != 2 {
		t.Fatalf("expected 2 harvested logs in buffer, got %d", len(h.buffer))
	}

	if h.buffer[0].ResourceID != "res-app-1" {
		t.Errorf("expected ResourceID res-app-1, got %s", h.buffer[0].ResourceID)
	}
	if h.buffer[1].ResourceID != "database-uuid-2" {
		t.Errorf("expected fallback ResourceID database-uuid-2, got %s", h.buffer[1].ResourceID)
	}
	if h.buffer[1].ResourceType != ResourceTypeDatabase {
		t.Errorf("expected ResourceType database, got %s", h.buffer[1].ResourceType)
	}
}

func TestHarvester_URLRewrite_Port50051(t *testing.T) {
	cases := []struct {
		input    string
		expected string
	}{
		{"10.50.0.20:50051", "http://10.50.0.20:8000"},
		{"http://10.50.0.20:50051", "http://10.50.0.20:8000"},
		{"127.0.0.1:50051/", "http://127.0.0.1:8000"},
		{"http://10.50.0.20:8000", "http://10.50.0.20:8000"},
		{"https://api.primecloud.internal", "https://api.primecloud.internal"},
	}

	for _, tc := range cases {
		h := NewHarvesterWithAuth(nil, tc.input, "test-key", "test-node", 100, 5*time.Second, nil)
		if h.controlPlaneURL != tc.expected {
			t.Errorf("input %s: expected %s, got %s", tc.input, tc.expected, h.controlPlaneURL)
		}
	}
}

func TestDiscoverAndHarvestOnce_DeploymentAndTypeMetadata(t *testing.T) {
	mockRT := &mockRuntime{
		containers: []agentruntime.ContainerSummary{
			{
				ID:    "cnt-app-123",
				Names: []string{"/pc-app-prod"},
				Labels: map[string]string{
					"primecloud.resource_id":   "app-uuid-1",
					"primecloud.deployment_id": "dep-uuid-999",
				},
			},
			{
				ID:    "cnt-db-456",
				Names: []string{"/pc-pg-database-uuid-2"},
				Labels: map[string]string{
					"primecloud.managed": "true",
				},
			},
		},
		logOutput: map[string][]byte{
			"cnt-app-123": makeDockerFrame(1, "2026-10-13T20:00:00Z App log line\n"),
			"cnt-db-456":  makeDockerFrame(2, "2026-10-13T20:00:01Z Postgres log error\n"),
		},
	}

	h := NewHarvester(mockRT, "http://localhost:59999", 50, 1*time.Second, nil)
	err := h.DiscoverAndHarvestOnce(context.Background())
	if err != nil {
		t.Fatalf("unexpected discover error: %v", err)
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	if len(h.buffer) != 2 {
		t.Fatalf("expected 2 harvested logs, got %d", len(h.buffer))
	}

	appLog := h.buffer[0]
	if appLog.ResourceID != "app-uuid-1" {
		t.Errorf("expected ResourceID app-uuid-1, got %s", appLog.ResourceID)
	}
	if appLog.DeploymentID != "dep-uuid-999" {
		t.Errorf("expected DeploymentID dep-uuid-999, got %s", appLog.DeploymentID)
	}
	if appLog.ResourceType != ResourceTypeApplication {
		t.Errorf("expected ResourceType application, got %s", appLog.ResourceType)
	}

	dbLog := h.buffer[1]
	if dbLog.ResourceID != "database-uuid-2" {
		t.Errorf("expected ResourceID database-uuid-2, got %s", dbLog.ResourceID)
	}
	if dbLog.ResourceType != ResourceTypeDatabase {
		t.Errorf("expected ResourceType database, got %s", dbLog.ResourceType)
	}
}

// TestHarvester_IncrementalHarvesting_NoDuplicates verifies that repeated harvesting cycles
// on an unchanged container log stream do not duplicate log entries in the harvester buffer.
func TestHarvester_IncrementalHarvesting_NoDuplicates(t *testing.T) {
	stream := makeDockerFrame(1, "2026-10-17T12:00:00.100Z Log message 1\n")
	stream = append(stream, makeDockerFrame(1, "2026-10-17T12:00:01.200Z Log message 2\n")...)
	stream = append(stream, makeDockerFrame(2, "2026-10-17T12:00:02.300Z Error message 3\n")...)

	mockRT := &mockRuntime{
		containers: []agentruntime.ContainerSummary{
			{ID: "cnt-dup-test", Names: []string{"/pc-app"}, Labels: map[string]string{"primecloud.resource_id": "app-1"}},
		},
		logOutput: map[string][]byte{
			"cnt-dup-test": stream,
		},
	}

	h := NewHarvester(mockRT, "http://localhost:8000", 100, 1*time.Second, nil)

	// Cycle 1: initial discovery and harvest
	if err := h.DiscoverAndHarvestOnce(context.Background()); err != nil {
		t.Fatalf("cycle 1 failed: %v", err)
	}

	h.mu.Lock()
	initialLen := len(h.buffer)
	h.mu.Unlock()
	if initialLen != 3 {
		t.Fatalf("expected 3 entries in buffer after cycle 1, got %d", initialLen)
	}

	// Verify cursor was updated
	cursorTS, ok := h.GetCursor("cnt-dup-test")
	if !ok || cursorTS.IsZero() {
		t.Fatalf("expected active cursor for cnt-dup-test, got %v (exists: %v)", cursorTS, ok)
	}

	// Cycle 2: harvest again without container log changes
	if err := h.DiscoverAndHarvestOnce(context.Background()); err != nil {
		t.Fatalf("cycle 2 failed: %v", err)
	}

	// Cycle 3: harvest once more
	if err := h.DiscoverAndHarvestOnce(context.Background()); err != nil {
		t.Fatalf("cycle 3 failed: %v", err)
	}

	h.mu.Lock()
	finalLen := len(h.buffer)
	h.mu.Unlock()

	if finalLen != 3 {
		t.Fatalf("expected buffer to remain strictly at 3 entries (zero duplicates), got %d", finalLen)
	}
}

// TestHarvester_IncrementalHarvesting_IngestsNewEntriesOnly verifies that subsequent harvest
// cycles incrementally pick up only new entries appended since the previous cursor.
func TestHarvester_IncrementalHarvesting_IngestsNewEntriesOnly(t *testing.T) {
	stream1 := makeDockerFrame(1, "2026-10-17T12:00:00.100Z Log message 1\n")
	stream1 = append(stream1, makeDockerFrame(1, "2026-10-17T12:00:01.200Z Log message 2\n")...)

	mockRT := &mockRuntime{
		containers: []agentruntime.ContainerSummary{
			{ID: "cnt-inc-test", Names: []string{"/pc-app"}, Labels: map[string]string{"primecloud.resource_id": "app-1"}},
		},
		logOutput: map[string][]byte{
			"cnt-inc-test": stream1,
		},
	}

	h := NewHarvester(mockRT, "http://localhost:8000", 100, 1*time.Second, nil)

	if err := h.DiscoverAndHarvestOnce(context.Background()); err != nil {
		t.Fatalf("cycle 1 failed: %v", err)
	}

	h.mu.Lock()
	if len(h.buffer) != 2 {
		t.Fatalf("expected 2 entries in cycle 1, got %d", len(h.buffer))
	}
	h.mu.Unlock()

	// Append new logs to the container stream
	stream2 := append(stream1, makeDockerFrame(1, "2026-10-17T12:00:02.300Z Log message 3\n")...)
	stream2 = append(stream2, makeDockerFrame(2, "2026-10-17T12:00:03.400Z Log message 4\n")...)
	mockRT.logOutput["cnt-inc-test"] = stream2

	if err := h.DiscoverAndHarvestOnce(context.Background()); err != nil {
		t.Fatalf("cycle 2 failed: %v", err)
	}

	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.buffer) != 4 {
		t.Fatalf("expected 4 total entries in buffer, got %d", len(h.buffer))
	}

	// Verify exact messages in order
	expectedMsgs := []string{"Log message 1", "Log message 2", "Log message 3", "Log message 4"}
	for i, exp := range expectedMsgs {
		if h.buffer[i].Message != exp {
			t.Errorf("buffer[%d] expected message %q, got %q", i, exp, h.buffer[i].Message)
		}
	}
}

// TestHarvester_IndependentPerContainerCursors verifies that multiple containers maintain
// independent harvesting cursors and do not interfere with each other.
func TestHarvester_IndependentPerContainerCursors(t *testing.T) {
	streamA := makeDockerFrame(1, "2026-10-17T12:00:05.000Z Container A log 1\n")
	streamB := makeDockerFrame(1, "2026-10-17T12:00:01.000Z Container B log 1\n")

	mockRT := &mockRuntime{
		containers: []agentruntime.ContainerSummary{
			{ID: "cnt-A", Names: []string{"/pc-app-a"}, Labels: map[string]string{"primecloud.resource_id": "app-a"}},
			{ID: "cnt-B", Names: []string{"/pc-app-b"}, Labels: map[string]string{"primecloud.resource_id": "app-b"}},
		},
		logOutput: map[string][]byte{
			"cnt-A": streamA,
			"cnt-B": streamB,
		},
	}

	h := NewHarvester(mockRT, "http://localhost:8000", 100, 1*time.Second, nil)
	if err := h.DiscoverAndHarvestOnce(context.Background()); err != nil {
		t.Fatalf("cycle 1 failed: %v", err)
	}

	cursorA, okA := h.GetCursor("cnt-A")
	cursorB, okB := h.GetCursor("cnt-B")

	if !okA || !okB {
		t.Fatalf("expected both containers to have cursors: okA=%v, okB=%v", okA, okB)
	}

	expectedTA, _ := time.Parse(time.RFC3339, "2026-10-17T12:00:05.000Z")
	expectedTB, _ := time.Parse(time.RFC3339, "2026-10-17T12:00:01.000Z")

	if !cursorA.Equal(expectedTA) {
		t.Errorf("expected cursor A %v, got %v", expectedTA, cursorA)
	}
	if !cursorB.Equal(expectedTB) {
		t.Errorf("expected cursor B %v, got %v", expectedTB, cursorB)
	}

	// Update only container B
	streamB2 := append(streamB, makeDockerFrame(1, "2026-10-17T12:00:02.000Z Container B log 2\n")...)
	mockRT.logOutput["cnt-B"] = streamB2

	if err := h.DiscoverAndHarvestOnce(context.Background()); err != nil {
		t.Fatalf("cycle 2 failed: %v", err)
	}

	h.mu.Lock()
	count := len(h.buffer)
	h.mu.Unlock()

	// Should have 1 from A + 2 from B = 3 logs total (A produced no new logs, so 0 from A in cycle 2)
	if count != 3 {
		t.Fatalf("expected 3 total logs in buffer, got %d", count)
	}
}

// TestHarvester_TimestampOverlapAtBoundary verifies deduplication when multiple entries
// share identical nanosecond timestamps across harvest cycles.
func TestHarvester_TimestampOverlapAtBoundary(t *testing.T) {
	tsBoundary := "2026-10-17T12:00:00.999999999Z"

	// Cycle 1 has two messages at identical timestamp tsBoundary
	stream1 := makeDockerFrame(1, tsBoundary+" First message at boundary\n")
	stream1 = append(stream1, makeDockerFrame(1, tsBoundary+" Second message at boundary\n")...)

	mockRT := &mockRuntime{
		containers: []agentruntime.ContainerSummary{
			{ID: "cnt-overlap", Names: []string{"/pc-app"}, Labels: map[string]string{"primecloud.resource_id": "app-1"}},
		},
		logOutput: map[string][]byte{
			"cnt-overlap": stream1,
		},
	}

	h := NewHarvester(mockRT, "http://localhost:8000", 100, 1*time.Second, nil)
	if err := h.DiscoverAndHarvestOnce(context.Background()); err != nil {
		t.Fatalf("cycle 1 failed: %v", err)
	}

	h.mu.Lock()
	if len(h.buffer) != 2 {
		t.Fatalf("expected 2 items after cycle 1, got %d", len(h.buffer))
	}
	h.mu.Unlock()

	// Cycle 2: Docker returns stream including a 3rd new message at tsBoundary plus a message after tsBoundary
	stream2 := append(stream1, makeDockerFrame(1, tsBoundary+" Third message at same boundary\n")...)
	stream2 = append(stream2, makeDockerFrame(1, "2026-10-17T12:00:01.000000000Z Subsequent message\n")...)
	mockRT.logOutput["cnt-overlap"] = stream2

	if err := h.DiscoverAndHarvestOnce(context.Background()); err != nil {
		t.Fatalf("cycle 2 failed: %v", err)
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	if len(h.buffer) != 4 {
		t.Fatalf("expected 4 total items (2 from cycle 1 + 2 from cycle 2), got %d", len(h.buffer))
	}

	if h.buffer[2].Message != "Third message at same boundary" {
		t.Errorf("expected buffer[2] to be third message, got %q", h.buffer[2].Message)
	}
	if h.buffer[3].Message != "Subsequent message" {
		t.Errorf("expected buffer[3] to be subsequent message, got %q", h.buffer[3].Message)
	}
}

// TestHarvester_ContainerLifecycle_RecreationAndPruning verifies that replacing a container
// starts harvesting afresh, and stopped container cursors are safely pruned.
func TestHarvester_ContainerLifecycle_RecreationAndPruning(t *testing.T) {
	mockRT := &mockRuntime{
		containers: []agentruntime.ContainerSummary{
			{ID: "cnt-old", Names: []string{"/pc-app"}, Labels: map[string]string{"primecloud.resource_id": "app-1"}},
		},
		logOutput: map[string][]byte{
			"cnt-old": makeDockerFrame(1, "2026-10-17T12:00:00Z Old container log\n"),
		},
	}

	h := NewHarvester(mockRT, "http://localhost:8000", 100, 1*time.Second, nil)
	if err := h.DiscoverAndHarvestOnce(context.Background()); err != nil {
		t.Fatalf("cycle 1 failed: %v", err)
	}

	if _, ok := h.GetCursor("cnt-old"); !ok {
		t.Fatal("expected cursor for cnt-old")
	}

	// Container is recreated: new container ID replaces cnt-old in running containers
	mockRT.containers = []agentruntime.ContainerSummary{
		{ID: "cnt-new", Names: []string{"/pc-app"}, Labels: map[string]string{"primecloud.resource_id": "app-1"}},
	}
	mockRT.logOutput["cnt-new"] = makeDockerFrame(1, "2026-10-17T12:00:05Z New container initial log\n")

	if err := h.DiscoverAndHarvestOnce(context.Background()); err != nil {
		t.Fatalf("cycle 2 failed: %v", err)
	}

	h.mu.Lock()
	if len(h.buffer) != 2 {
		t.Fatalf("expected 2 logs (old + new), got %d", len(h.buffer))
	}
	if h.buffer[1].ContainerID != "cnt-new" {
		t.Errorf("expected second log to come from cnt-new, got %s", h.buffer[1].ContainerID)
	}
	h.mu.Unlock()

	// Test cursor pruning for stopped containers: backdate cnt-old beyond 10-minute threshold
	h.mu.Lock()
	if cur, ok := h.cursors["cnt-old"]; ok {
		cur.lastSeenAt = time.Now().Add(-15 * time.Minute)
	}
	h.mu.Unlock()

	purged := h.PurgeStaleCursors(10 * time.Minute)
	if purged != 1 {
		t.Errorf("expected exactly 1 purged cursor for cnt-old, got %d", purged)
	}

	if _, ok := h.GetCursor("cnt-old"); ok {
		t.Error("cnt-old cursor should have been pruned")
	}
	if _, ok := h.GetCursor("cnt-new"); !ok {
		t.Error("cnt-new cursor should have been preserved")
	}
}

// TestHarvester_TransientErrorPreservesCursor verifies that temporary container log read
// failures do not reset or corrupt the cursor.
func TestHarvester_TransientErrorPreservesCursor(t *testing.T) {
	ts1 := "2026-10-17T12:00:00.100Z"
	stream := makeDockerFrame(1, ts1+" Initial log line\n")

	mockRT := &mockRuntime{
		containers: []agentruntime.ContainerSummary{
			{ID: "cnt-err", Names: []string{"/pc-app"}, Labels: map[string]string{"primecloud.resource_id": "app-1"}},
		},
		logOutput: map[string][]byte{
			"cnt-err": stream,
		},
	}

	h := NewHarvester(mockRT, "http://localhost:8000", 100, 1*time.Second, nil)
	if err := h.DiscoverAndHarvestOnce(context.Background()); err != nil {
		t.Fatalf("cycle 1 failed: %v", err)
	}

	cursorBefore, ok := h.GetCursor("cnt-err")
	if !ok {
		t.Fatal("expected cursor before transient error")
	}

	// Inject transient error in cycle 2
	mockRT.errOutput = map[string]error{
		"cnt-err": fmt.Errorf("transient docker daemon timeout"),
	}

	_ = h.DiscoverAndHarvestOnce(context.Background())

	cursorAfter, ok := h.GetCursor("cnt-err")
	if !ok {
		t.Fatal("cursor was lost after error")
	}
	if !cursorAfter.Equal(cursorBefore) {
		t.Fatalf("cursor changed after transient error: before=%v, after=%v", cursorBefore, cursorAfter)
	}

	// Cycle 3: recovery with new log appended
	mockRT.errOutput = nil
	stream2 := append(stream, makeDockerFrame(1, "2026-10-17T12:00:01.000Z Post-recovery log line\n")...)
	mockRT.logOutput["cnt-err"] = stream2

	if err := h.DiscoverAndHarvestOnce(context.Background()); err != nil {
		t.Fatalf("cycle 3 failed: %v", err)
	}

	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.buffer) != 2 {
		t.Fatalf("expected 2 items in buffer after recovery, got %d", len(h.buffer))
	}
}

// TestHarvester_BoundedBufferCapacity verifies that buffer strictly respects maxBuffer.
func TestHarvester_BoundedBufferCapacity(t *testing.T) {
	h := NewHarvester(nil, "http://localhost:8000", 100, 1*time.Second, nil)
	h.maxBuffer = 200

	for i := 0; i < 500; i++ {
		h.EnqueueLog(LogItem{
			ResourceID: "app-test",
			Message:    fmt.Sprintf("Log message %d", i),
		})
	}

	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.buffer) != 200 {
		t.Fatalf("expected buffer length capped at 200, got %d", len(h.buffer))
	}
	if h.droppedCount != 300 {
		t.Fatalf("expected droppedCount=300, got %d", h.droppedCount)
	}
	if h.totalDropped != 300 {
		t.Fatalf("expected totalDropped=300, got %d", h.totalDropped)
	}
}

// captureHandler records all emitted slog records for test verification.
type captureHandler struct {
	mu      sync.Mutex
	records []slog.Record
}

func (c *captureHandler) Enabled(context.Context, slog.Level) bool { return true }
func (c *captureHandler) Handle(ctx context.Context, r slog.Record) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.records = append(c.records, r)
	return nil
}
func (c *captureHandler) WithAttrs(attrs []slog.Attr) slog.Handler { return c }
func (c *captureHandler) WithGroup(name string) slog.Handler       { return c }

// TestHarvester_WarningFloodElimination verifies that dropping entries emits ZERO per-drop warnings
// and exactly ONE aggregated drop summary warning on Flush().
func TestHarvester_WarningFloodElimination(t *testing.T) {
	capture := &captureHandler{}
	logger := slog.New(capture)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"status": "ok"})
	}))
	defer server.Close()

	h := NewHarvester(nil, server.URL, 50, 1*time.Second, logger)
	h.maxBuffer = 50

	// Enqueue 250 items: buffer holds 50, so 200 entries must be dropped
	for i := 0; i < 250; i++ {
		h.EnqueueLog(LogItem{
			ResourceID: "flood-test",
			Message:    fmt.Sprintf("Item %d", i),
		})
	}

	// Verify dropped counters
	if h.DroppedCount() != 200 {
		t.Fatalf("expected DroppedCount=200, got %d", h.DroppedCount())
	}
	if h.TotalDropped() != 200 {
		t.Fatalf("expected TotalDropped=200, got %d", h.TotalDropped())
	}

	// Check captured log records before Flush:
	// CRITICAL: There must be ZERO log_buffer_backpressure_drop_oldest warnings!
	capture.mu.Lock()
	for _, rec := range capture.records {
		if strings.Contains(rec.Message, "log_buffer_backpressure_drop_oldest") {
			capture.mu.Unlock()
			t.Fatal("CRITICAL VIOLATION: emitted per-entry log_buffer_backpressure_drop_oldest warning!")
		}
	}
	capture.mu.Unlock()

	// Now execute Flush(): must emit exactly ONE aggregated summary warning
	if err := h.Flush(context.Background()); err != nil {
		t.Fatalf("flush failed: %v", err)
	}

	capture.mu.Lock()
	summaryCount := 0
	for _, rec := range capture.records {
		if rec.Message == "log_buffer_backpressure_drop_summary" {
			summaryCount++
			if rec.Level != slog.LevelWarn {
				t.Errorf("expected drop summary to be WARN level, got %v", rec.Level)
			}
		}
		if strings.Contains(rec.Message, "log_buffer_backpressure_drop_oldest") {
			t.Fatal("CRITICAL VIOLATION: emitted per-entry drop warning during flush!")
		}
	}
	capture.mu.Unlock()

	if summaryCount != 1 {
		t.Fatalf("expected exactly 1 aggregated drop summary warning, got %d", summaryCount)
	}

	// Verify DroppedCount was reset while TotalDropped was retained
	if h.DroppedCount() != 0 {
		t.Fatalf("expected DroppedCount to reset to 0 after flush, got %d", h.DroppedCount())
	}
	if h.TotalDropped() != 200 {
		t.Fatalf("expected TotalDropped to remain 200, got %d", h.TotalDropped())
	}
}

// TestHarvester_IncrementalLogReader_SincePassThrough verifies that GetContainerLogsSince
// is invoked with the exact timestamp from the previous harvest.
func TestHarvester_IncrementalLogReader_SincePassThrough(t *testing.T) {
	ts1 := "2026-10-17T12:00:00.123456789Z"
	expectedT1, _ := time.Parse(time.RFC3339Nano, ts1)

	mockRT := &mockRuntime{
		containers: []agentruntime.ContainerSummary{
			{ID: "cnt-since", Names: []string{"/pc-app"}, Labels: map[string]string{"primecloud.resource_id": "app-1"}},
		},
		logOutput: map[string][]byte{
			"cnt-since": makeDockerFrame(1, ts1+" Frame 1\n"),
		},
	}

	h := NewHarvester(mockRT, "http://localhost:8000", 100, 1*time.Second, nil)
	if err := h.DiscoverAndHarvestOnce(context.Background()); err != nil {
		t.Fatalf("cycle 1 failed: %v", err)
	}

	// In cycle 1, cursor was zero, so GetContainerLogs was called
	// Now in cycle 2, GetContainerLogsSince must be called with expectedT1
	if err := h.DiscoverAndHarvestOnce(context.Background()); err != nil {
		t.Fatalf("cycle 2 failed: %v", err)
	}

	sinceCalls := mockRT.sinceCalls["cnt-since"]
	if len(sinceCalls) != 1 {
		t.Fatalf("expected 1 call to GetContainerLogsSince in cycle 2, got %d", len(sinceCalls))
	}
	if !sinceCalls[0].Equal(expectedT1) {
		t.Fatalf("expected since timestamp %v, got %v", expectedT1, sinceCalls[0])
	}
}

// TestHarvester_BasicRuntimeFallback_Deduplicates verifies that runtimes without IncrementalLogReader
// still receive proper client-side deduplication against historical logs.
func TestHarvester_BasicRuntimeFallback_Deduplicates(t *testing.T) {
	stream := makeDockerFrame(1, "2026-10-17T12:00:00Z Fallback frame 1\n")
	stream = append(stream, makeDockerFrame(1, "2026-10-17T12:00:01Z Fallback frame 2\n")...)

	basicRT := &mockBasicRuntime{
		containers: []agentruntime.ContainerSummary{
			{ID: "cnt-basic", Names: []string{"/pc-app"}, Labels: map[string]string{"primecloud.resource_id": "app-1"}},
		},
		logOutput: map[string][]byte{
			"cnt-basic": stream,
		},
	}

	h := NewHarvester(basicRT, "http://localhost:8000", 100, 1*time.Second, nil)
	if err := h.DiscoverAndHarvestOnce(context.Background()); err != nil {
		t.Fatalf("cycle 1 failed: %v", err)
	}

	h.mu.Lock()
	if len(h.buffer) != 2 {
		t.Fatalf("expected 2 items after cycle 1, got %d", len(h.buffer))
	}
	h.mu.Unlock()

	// Cycle 2 with basic runtime: returns all historical logs from inception
	if err := h.DiscoverAndHarvestOnce(context.Background()); err != nil {
		t.Fatalf("cycle 2 failed: %v", err)
	}

	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.buffer) != 2 {
		t.Fatalf("expected buffer to remain at 2 items (no duplicates even with basic runtime), got %d", len(h.buffer))
	}
}
