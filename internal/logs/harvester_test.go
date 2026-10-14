package logs

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
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
}

func (m *mockRuntime) ListContainers(ctx context.Context, all bool) ([]agentruntime.ContainerSummary, error) {
	return m.containers, nil
}

func (m *mockRuntime) GetContainerLogs(ctx context.Context, containerID string) (io.ReadCloser, error) {
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
}
