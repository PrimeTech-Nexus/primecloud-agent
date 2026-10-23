package logs

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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

func TestDiscoverAndHarvestOnce_ApplicationNameFallback(t *testing.T) {
	mockRT := &mockRuntime{
		containers: []agentruntime.ContainerSummary{
			{
				ID:     "cnt-sam-999",
				Names:  []string{"/pc-sambackend-0-3e2849fb"},
				Labels: map[string]string{}, // No labels attached
			},
			{
				ID:     "cnt-sys-111",
				Names:  []string{"/primecloud-control-plane"},
				Labels: map[string]string{}, // Infrastructure container without labels
			},
		},
		logOutput: map[string][]byte{
			"cnt-sam-999": makeDockerFrame(1, "2026-10-18T17:00:00Z Mini-Mart POS API running\n"),
			"cnt-sys-111": makeDockerFrame(1, "2026-10-18T17:00:00Z Internal CP log\n"),
		},
	}

	h := NewHarvester(mockRT, "http://localhost:59999", 50, 1*time.Second, nil)
	err := h.DiscoverAndHarvestOnce(context.Background())
	if err != nil {
		t.Fatalf("unexpected discover error: %v", err)
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	// Should harvest cnt-sam-999 and skip cnt-sys-111
	if len(h.buffer) != 1 {
		t.Fatalf("expected 1 harvested log, got %d", len(h.buffer))
	}

	item := h.buffer[0]
	if item.ResourceID != "sambackend" {
		t.Errorf("expected ResourceID sambackend, got %s", item.ResourceID)
	}
	if item.DeploymentID != "3e2849fb" {
		t.Errorf("expected DeploymentID 3e2849fb, got %s", item.DeploymentID)
	}
	if item.ResourceType != ResourceTypeApplication {
		t.Errorf("expected ResourceType application, got %s", item.ResourceType)
	}
	if item.Message != "Mini-Mart POS API running" {
		t.Errorf("expected message 'Mini-Mart POS API running', got '%s'", item.Message)
	}
}

func TestAggregateMultilineItems_PythonTraceback(t *testing.T) {
	ts := time.Now().UTC()
	rawItems := []LogItem{
		{Stream: StreamStderr, Severity: SeverityError, Message: "Traceback (most recent call last):", Timestamp: &ts},
		{Stream: StreamStderr, Severity: SeverityError, Message: "  File \"/app/main.py\", line 42, in handle_request", Timestamp: &ts},
		{Stream: StreamStderr, Severity: SeverityError, Message: "    res = db.execute(query)", Timestamp: &ts},
		{Stream: StreamStderr, Severity: SeverityError, Message: "psycopg2.OperationalError: server closed the connection unexpectedly", Timestamp: &ts},
		{Stream: StreamStdout, Severity: SeverityInfo, Message: "INFO: Normal log continues", Timestamp: &ts},
	}

	aggregated := AggregateMultilineItems(rawItems)
	if len(aggregated) != 2 {
		t.Fatalf("expected 2 items after multiline aggregation, got %d", len(aggregated))
	}

	first := aggregated[0]
	if first.Severity != SeverityError {
		t.Errorf("expected Severity ERROR, got %s", first.Severity)
	}
	if first.Message != "psycopg2.OperationalError: server closed the connection unexpectedly" {
		t.Errorf("expected summary error line, got: %s", first.Message)
	}
	if first.StructuredData == nil || first.StructuredData["is_multiline"] != true {
		t.Errorf("expected is_multiline structured data to be true")
	}
	if rawTb, ok := first.StructuredData["raw_traceback"].(string); !ok || !strings.Contains(rawTb, "Traceback (most recent call last):") {
		t.Errorf("expected raw_traceback to contain full traceback, got: %v", rawTb)
	}

	second := aggregated[1]
	if second.Message != "INFO: Normal log continues" {
		t.Errorf("expected second item to be unaffected, got: %s", second.Message)
	}
}

func TestHarvestContainer_CursorDeduplication(t *testing.T) {
	t1 := "2026-10-18T17:00:00.000000000Z"
	t2 := "2026-10-18T17:00:05.000000000Z"
	t3 := "2026-10-18T17:00:10.000000000Z"

	mockRT := &mockRuntime{
		logOutput: map[string][]byte{
			"cnt-sam-1": makeDockerFrame(1, t1+" First log\n"+t2+" Second log\n"),
		},
	}

	h := NewHarvester(mockRT, "http://localhost:59999", 50, 1*time.Second, nil)

	// Harvest pass 1
	err := h.HarvestContainerWithMetadata(context.Background(), "cnt-sam-1", "app-1", "dep-1", ResourceTypeApplication)
	if err != nil {
		t.Fatalf("unexpected harvest error: %v", err)
	}
	if len(h.buffer) != 2 {
		t.Fatalf("expected 2 logs buffered on pass 1, got %d", len(h.buffer))
	}

	// Clear buffer (simulating flush)
	h.buffer = h.buffer[:0]

	// Harvest pass 2 with same logs -> should enqueue 0 logs
	err = h.HarvestContainerWithMetadata(context.Background(), "cnt-sam-1", "app-1", "dep-1", ResourceTypeApplication)
	if err != nil {
		t.Fatalf("unexpected harvest error: %v", err)
	}
	if len(h.buffer) != 0 {
		t.Fatalf("expected 0 logs buffered on duplicate pass, got %d", len(h.buffer))
	}

	// Update container stream with a new 3rd log
	mockRT.logOutput["cnt-sam-1"] = makeDockerFrame(1, t1+" First log\n"+t2+" Second log\n"+t3+" Third log\n")

	// Harvest pass 3 -> should only enqueue the 3rd log
	err = h.HarvestContainerWithMetadata(context.Background(), "cnt-sam-1", "app-1", "dep-1", ResourceTypeApplication)
	if err != nil {
		t.Fatalf("unexpected harvest error: %v", err)
	}
	if len(h.buffer) != 1 {
		t.Fatalf("expected 1 log buffered on pass 3, got %d", len(h.buffer))
	}
	if h.buffer[0].Message != "Third log" {
		t.Errorf("expected 'Third log', got '%s'", h.buffer[0].Message)
	}
}

func TestPermanentFailure404(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"detail":"Resource not found"}`))
	}))
	defer server.Close()

	h := NewHarvester(nil, server.URL, 50, 1*time.Second, nil)
	now := time.Now().UTC()
	h.EnqueueLog(LogItem{
		ResourceID: "non-existent-resource",
		Message:    "Dead log",
		Timestamp:  &now,
	})

	err := h.Flush(context.Background())
	if err == nil {
		t.Fatalf("expected 404 error from flush, got nil")
	}

	// Verify that inflight batch was dropped to prevent wedging
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.inflight != nil {
		t.Errorf("expected inflight to be nil after permanent 404 rejection, got %v", h.inflight)
	}
}

func TestHarvester_EndToEndDurableCheckpointCommitOnAck(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "harvester_cursor_e2e_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	cursorPath := filepath.Join(tmpDir, "cursors.json")
	store := NewFileCursorStore(cursorPath, 100, nil)

	var serverHits int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&serverHits, 1)
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"status":"persisted","accepted_count":2}`))
	}))
	defer server.Close()

	t1 := "2026-10-19T05:00:00.000000000Z"
	t2 := "2026-10-19T05:00:05.000000000Z"

	mockRT := &mockRuntime{
		logOutput: map[string][]byte{
			"cnt-sam-e2e": makeDockerFrame(1, t1+" Application boot\n"+t2+" Server listening on :8000\n"),
		},
	}

	h := NewHarvester(mockRT, server.URL, 50, 1*time.Second, nil)
	h.SetCursorStore(store)

	// Step 1: Harvest logs
	err = h.HarvestContainerWithMetadata(context.Background(), "cnt-sam-e2e", "app-sam", "dep-sam", ResourceTypeApplication)
	if err != nil {
		t.Fatalf("unexpected harvest error: %v", err)
	}

	// Step 2: Before flush, store checkpoint must NOT have advanced yet!
	if _, ok := store.Get("cnt-sam-e2e"); ok {
		t.Fatalf("checkpoint must NOT advance before batch is acknowledged by Control Plane!")
	}

	// Step 3: Flush to Control Plane
	err = h.Flush(context.Background())
	if err != nil {
		t.Fatalf("unexpected flush error: %v", err)
	}

	// Step 4: After successful flush, checkpoint must be committed in store and persisted on disk!
	expectedT2, _ := time.Parse(time.RFC3339Nano, t2)
	savedT, ok := store.Get("cnt-sam-e2e")
	if !ok || !savedT.Equal(expectedT2) {
		t.Fatalf("expected committed checkpoint %v, got %v (ok=%v)", expectedT2, savedT, ok)
	}

	// Step 5: Simulate Agent Restart - create new harvester with new store reloading from disk
	storeReloaded := NewFileCursorStore(cursorPath, 100, nil)
	if err := storeReloaded.Load(); err != nil {
		t.Fatalf("failed to reload store from disk: %v", err)
	}

	hRestarted := NewHarvester(mockRT, server.URL, 50, 1*time.Second, nil)
	hRestarted.SetCursorStore(storeReloaded)

	// Harvest same container on restarted agent -> must NOT re-read historical logs!
	err = hRestarted.HarvestContainerWithMetadata(context.Background(), "cnt-sam-e2e", "app-sam", "dep-sam", ResourceTypeApplication)
	if err != nil {
		t.Fatalf("unexpected harvest error on restart: %v", err)
	}

	if len(hRestarted.buffer) != 0 {
		t.Fatalf("expected 0 logs buffered after restart (historical logs skipped), got %d", len(hRestarted.buffer))
	}
}

func TestHarvester_SameTimestampBatchSplitsAndCrashSafety(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "harvester_same_ts_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	cursorPath := filepath.Join(tmpDir, "cursors.json")
	store := NewFileCursorStore(cursorPath, 100, nil)

	var serverBatchesReceived int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&serverBatchesReceived, 1)
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"status":"persisted","accepted_count":2}`))
	}))
	defer server.Close()

	// 3 lines sharing the EXACT same timestamp T1
	sameTS := "2026-10-19T05:30:00.123456789Z"
	parsedTS, _ := time.Parse(time.RFC3339Nano, sameTS)

	mockRT := &mockRuntime{
		logOutput: map[string][]byte{
			"cnt-same-ts": makeDockerFrame(1,
				sameTS+" Line 1\n"+
					sameTS+" Line 2\n"+
					sameTS+" Line 3\n"),
		},
	}

	// Batch size of 2 ensures the 3 items must be split across 2 batches
	h := NewHarvester(mockRT, server.URL, 2, 1*time.Second, nil)
	h.SetCursorStore(store)

	// Harvest
	err = h.HarvestContainerWithMetadata(context.Background(), "cnt-same-ts", "app-same", "dep-same", ResourceTypeApplication)
	if err != nil {
		t.Fatalf("harvest error: %v", err)
	}
	if len(h.buffer) != 3 {
		t.Fatalf("expected 3 items buffered, got %d", len(h.buffer))
	}

	// Flush Batch 1: sends Line 1 and Line 2; Line 3 remains in buffer
	err = h.Flush(context.Background())
	if err != nil {
		t.Fatalf("flush 1 error: %v", err)
	}
	if len(h.buffer) != 1 {
		t.Fatalf("expected 1 item remaining in buffer, got %d", len(h.buffer))
	}

	// CRITICAL SAFETY CHECK: Store checkpoint must NOT have advanced to T1 yet,
	// because Line 3 with timestamp T1 is still waiting in buffer!
	if savedTS, ok := store.Get("cnt-same-ts"); ok && !savedTS.Before(parsedTS) {
		t.Fatalf("cursor prematurely advanced to %v while un-sent items with same timestamp remained in buffer", savedTS)
	}

	// Flush Batch 2: sends Line 3
	err = h.Flush(context.Background())
	if err != nil {
		t.Fatalf("flush 2 error: %v", err)
	}
	if len(h.buffer) != 0 {
		t.Fatalf("expected buffer empty, got %d", len(h.buffer))
	}

	// Now that ALL items with timestamp T1 are flushed, checkpoint advances to T1!
	savedTS, ok := store.Get("cnt-same-ts")
	if !ok || !savedTS.Equal(parsedTS) {
		t.Fatalf("expected committed checkpoint %v, got %v (ok=%v)", parsedTS, savedTS, ok)
	}
}

func TestHarvester_EmptyAndWhitespaceLogFiltering(t *testing.T) {
	ts1 := "2026-10-19T06:00:00.100000000Z"
	ts2 := "2026-10-19T06:00:01.200000000Z"
	ts3 := "2026-10-19T06:00:02.300000000Z"

	// Frame with Docker timestamp followed by empty string and whitespace string
	frame := makeDockerFrame(1,
		ts1+" Valid leading message\n"+
			ts2+" \n"+
			ts3+"    \t  \n"+
			ts3+" Valid trailing message\n")

	items, err := DemuxDockerLogStream(bytes.NewReader(frame), "stdout")
	if err != nil {
		t.Fatalf("unexpected demux error: %v", err)
	}

	if len(items) != 2 {
		t.Fatalf("expected 2 items after filtering empty messages, got %d", len(items))
	}
	if items[0].Message != "Valid leading message" {
		t.Errorf("expected 'Valid leading message', got '%s'", items[0].Message)
	}
	if items[1].Message != "Valid trailing message" {
		t.Errorf("expected 'Valid trailing message', got '%s'", items[1].Message)
	}
}

func TestHarvester_AggregateMultiline_PreservesMeaningfulBlankLines(t *testing.T) {
	now := time.Now().UTC()
	items := []LogItem{
		{Stream: StreamStderr, Severity: SeverityError, Message: "Traceback (most recent call last):", Timestamp: &now},
		{Stream: StreamStderr, Severity: SeverityError, Message: "  File \"main.py\", line 10, in <module>", Timestamp: &now},
		{Stream: StreamStderr, Severity: SeverityError, Message: "    run()", Timestamp: &now},
		{Stream: StreamStderr, Severity: SeverityError, Message: " ", Timestamp: &now}, // meaningful blank separator line in traceback
		{Stream: StreamStderr, Severity: SeverityError, Message: "ZeroDivisionError: division by zero", Timestamp: &now},
	}

	aggregated := AggregateMultilineItems(items)
	if len(aggregated) != 1 {
		t.Fatalf("expected 1 aggregated multiline item, got %d", len(aggregated))
	}

	base := aggregated[0]
	if base.Message != "ZeroDivisionError: division by zero" {
		t.Errorf("expected summary 'ZeroDivisionError: division by zero', got '%s'", base.Message)
	}

	rawTraceback, ok := base.StructuredData["raw_traceback"].(string)
	if !ok {
		t.Fatalf("expected raw_traceback in structured data")
	}
	if !strings.Contains(rawTraceback, "ZeroDivisionError: division by zero") {
		t.Errorf("raw_traceback missing exception message: %s", rawTraceback)
	}
	if !strings.Contains(rawTraceback, "  File \"main.py\"") {
		t.Errorf("raw_traceback missing frame: %s", rawTraceback)
	}
}

func TestHarvester_MixedBatchDeliveryAndEnqueueFilter(t *testing.T) {
	var receivedLogs []LogItem
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload LogBatchPayload
		_ = json.NewDecoder(r.Body).Decode(&payload)
		receivedLogs = append(receivedLogs, payload.Logs...)
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"status":"persisted","accepted_count":2}`))
	}))
	defer server.Close()

	h := NewHarvester(nil, server.URL, 10, 1*time.Second, nil)

	// Enqueue valid, empty, whitespace-only, and valid
	h.EnqueueLog(LogItem{ResourceID: "app-1", Message: "First valid message"})
	h.EnqueueLog(LogItem{ResourceID: "app-1", Message: ""})
	h.EnqueueLog(LogItem{ResourceID: "app-1", Message: "   \t  \n"})
	h.EnqueueLog(LogItem{ResourceID: "app-1", Message: "Second valid message"})

	if len(h.buffer) != 2 {
		t.Fatalf("expected exactly 2 items in buffer after EnqueueLog filtering, got %d", len(h.buffer))
	}

	err := h.Flush(context.Background())
	if err != nil {
		t.Fatalf("flush error: %v", err)
	}

	if len(receivedLogs) != 2 {
		t.Fatalf("expected server to receive 2 logs, got %d", len(receivedLogs))
	}
	if receivedLogs[0].Message != "First valid message" || receivedLogs[1].Message != "Second valid message" {
		t.Errorf("unexpected logs received: %+v", receivedLogs)
	}
}

func TestHarvester_PermanentRejectionOnHTTP422(t *testing.T) {
	var attempts int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&attempts, 1)
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = w.Write([]byte(`{"error":{"code":"VALIDATION_ERROR","message":"String should have at least 1 character"}}`))
	}))
	defer server.Close()

	h := NewHarvester(nil, server.URL, 10, 1*time.Second, nil)
	h.buffer = append(h.buffer, LogItem{ResourceID: "app-1", Message: "invalid-batch"})

	// First flush encounters HTTP 422
	err := h.Flush(context.Background())
	if err == nil {
		t.Fatalf("expected error on HTTP 422, got nil")
	}
	if !strings.Contains(err.Error(), "permanent log ingestion rejection (status 422)") {
		t.Errorf("expected permanent rejection error string, got: %v", err)
	}

	// CRITICAL: inflight batch must be cleared so it does not loop infinitely
	if h.inflight != nil {
		t.Fatalf("expected h.inflight to be nil after permanent 422 rejection, got: %+v", h.inflight)
	}

	// Subsequent flush must see empty buffer and do nothing (no HTTP calls)
	err = h.Flush(context.Background())
	if err != nil {
		t.Fatalf("unexpected error on second flush: %v", err)
	}
	if atomic.LoadInt32(&attempts) != 1 {
		t.Fatalf("expected exactly 1 attempt to server, got %d", attempts)
	}
}

func TestAggregateMultilineItems_NodeJSV8Traceback(t *testing.T) {
	ts := time.Now().UTC()
	rawItems := []LogItem{
		{Stream: StreamStderr, Severity: SeverityError, Message: "TypeError: Cannot read properties of undefined (reading 'token')", Timestamp: &ts},
		{Stream: StreamStderr, Severity: SeverityError, Message: "    at authenticateUser (/app/src/auth.js:84:19)", Timestamp: &ts},
		{Stream: StreamStderr, Severity: SeverityError, Message: "    at processTicksAndRejections (node:internal/process/task_queues:95:5)", Timestamp: &ts},
		{Stream: StreamStderr, Severity: SeverityError, Message: "  [cause]: Error: Invalid token structure", Timestamp: &ts},
		{Stream: StreamStdout, Severity: SeverityInfo, Message: "Server listening on port 3000", Timestamp: &ts},
	}

	aggregated := AggregateMultilineItems(rawItems)
	if len(aggregated) != 2 {
		t.Fatalf("expected 2 items after Node.js V8 multiline aggregation, got %d", len(aggregated))
	}

	first := aggregated[0]
	if first.Severity != SeverityError {
		t.Errorf("expected Severity ERROR, got %s", first.Severity)
	}
	if first.Message != "TypeError: Cannot read properties of undefined (reading 'token')" {
		t.Errorf("expected Node.js error header as summary Message, got: %s", first.Message)
	}
	if first.StructuredData == nil || first.StructuredData["is_multiline"] != true {
		t.Fatalf("expected is_multiline=true in StructuredData")
	}
	if first.StructuredData["line_count"] != 4 {
		t.Errorf("expected line_count=4, got %v", first.StructuredData["line_count"])
	}
	rawTb, _ := first.StructuredData["raw_traceback"].(string)
	if !strings.Contains(rawTb, "at authenticateUser") || !strings.Contains(rawTb, "[cause]: Error:") {
		t.Errorf("expected raw_traceback to contain all frames, got:\n%s", rawTb)
	}

	if aggregated[1].Message != "Server listening on port 3000" {
		t.Errorf("expected trailing single-line log to remain separate, got: %s", aggregated[1].Message)
	}
}

func TestAggregateMultilineItems_Python3ChainedExceptions(t *testing.T) {
	ts := time.Now().UTC()
	rawItems := []LogItem{
		{Stream: StreamStderr, Severity: SeverityError, Message: "Traceback (most recent call last):", Timestamp: &ts},
		{Stream: StreamStderr, Severity: SeverityError, Message: "  File \"/app/db.py\", line 19, in connect", Timestamp: &ts},
		{Stream: StreamStderr, Severity: SeverityError, Message: "    conn = low_level_connect()", Timestamp: &ts},
		{Stream: StreamStderr, Severity: SeverityError, Message: "ConnectionRefusedError: [Errno 111] Connection refused", Timestamp: &ts},
		{Stream: StreamStderr, Severity: SeverityError, Message: "During handling of the above exception, another exception occurred:", Timestamp: &ts},
		{Stream: StreamStderr, Severity: SeverityError, Message: "Traceback (most recent call last):", Timestamp: &ts},
		{Stream: StreamStderr, Severity: SeverityError, Message: "  File \"/app/service.py\", line 55, in get_user", Timestamp: &ts},
		{Stream: StreamStderr, Severity: SeverityError, Message: "    db.connect()", Timestamp: &ts},
		{Stream: StreamStderr, Severity: SeverityError, Message: "RuntimeError: Database unavailable while fetching user", Timestamp: &ts},
		{Stream: StreamStdout, Severity: SeverityInfo, Message: "Health check completed", Timestamp: &ts},
	}

	aggregated := AggregateMultilineItems(rawItems)
	if len(aggregated) != 2 {
		t.Fatalf("expected 2 items after Python 3 chained exception aggregation, got %d", len(aggregated))
	}

	chained := aggregated[0]
	if chained.Severity != SeverityError {
		t.Errorf("expected Severity ERROR, got %s", chained.Severity)
	}
	if chained.Message != "RuntimeError: Database unavailable while fetching user" {
		t.Errorf("expected final exception line as summary Message, got: %s", chained.Message)
	}
	rawTb, _ := chained.StructuredData["raw_traceback"].(string)
	if !strings.Contains(rawTb, "ConnectionRefusedError:") ||
		!strings.Contains(rawTb, "During handling of the above exception, another exception occurred:") ||
		!strings.Contains(rawTb, "RuntimeError: Database unavailable while fetching user") {
		t.Errorf("expected complete chained traceback in raw_traceback, got:\n%s", rawTb)
	}
}

type mockRuntimeWithSince struct {
	mockRuntime
	lastSince map[string]string
}

func (m *mockRuntimeWithSince) GetContainerLogsSince(ctx context.Context, containerID string, since string) (io.ReadCloser, error) {
	if m.lastSince == nil {
		m.lastSince = make(map[string]string)
	}
	m.lastSince[containerID] = since
	return m.GetContainerLogs(ctx, containerID)
}

func TestHarvestContainer_UsesGetContainerLogsSinceWhenCursorExists(t *testing.T) {
	t1 := "2026-10-22T10:00:00.123456789Z"
	t2 := "2026-10-22T10:00:05.000000000Z"

	mockRT := &mockRuntimeWithSince{
		mockRuntime: mockRuntime{
			logOutput: map[string][]byte{
				"cnt-since-1": makeDockerFrame(1, t1+" First line\n"),
			},
		},
	}

	h := NewHarvester(mockRT, "http://localhost:59999", 50, 1*time.Second, nil)

	// Pass 1: No prior cursor -> falls back to GetContainerLogs (lastSince not set)
	if err := h.HarvestContainerWithMetadata(context.Background(), "cnt-since-1", "app-1", "dep-1", ResourceTypeApplication); err != nil {
		t.Fatalf("pass 1 error: %v", err)
	}
	if sinceVal := mockRT.lastSince["cnt-since-1"]; sinceVal != "" {
		t.Errorf("expected empty since on initial harvest without cursor, got %q", sinceVal)
	}

	// Pass 2: Cursor exists from pass 1 -> calls GetContainerLogsSince with t1
	mockRT.logOutput["cnt-since-1"] = makeDockerFrame(1, t2+" Second line\n")
	if err := h.HarvestContainerWithMetadata(context.Background(), "cnt-since-1", "app-1", "dep-1", ResourceTypeApplication); err != nil {
		t.Fatalf("pass 2 error: %v", err)
	}
	if sinceVal := mockRT.lastSince["cnt-since-1"]; sinceVal != t1 {
		t.Errorf("expected GetContainerLogsSince called with %q, got %q", t1, sinceVal)
	}
}





