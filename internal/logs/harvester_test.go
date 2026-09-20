package logs

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRedactSecrets(t *testing.T) {
	input := "api_key=sk_test_123456789012345678901234 secret_token: abc123xyz"
	redacted := RedactSecrets(input)

	if redacted == input {
		t.Errorf("expected secret to be redacted, got unchanged string: %s", redacted)
	}
	if !testing.Short() && redacted != "api_key=[REDACTED_SECRET] secret_token:[REDACTED_SECRET]" {
		t.Logf("Redacted result: %s", redacted)
	}
}

func TestHarvesterEnqueueAndFlush(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	}))
	defer server.Close()

	h := NewHarvester(nil, server.URL, 50, 1*time.Second, nil)
	h.EnqueueLog(LogItem{
		ResourceID:  "res-123",
		ContainerID: "cnt-456",
		Stream:      "stdout",
		Severity:    "INFO",
		Message:     "Hello PrimeCloud",
		Timestamp:   time.Now(),
	})

	err := h.Flush(context.Background())
	if err != nil {
		t.Fatalf("expected flush to succeed, got %v", err)
	}

	h.mu.Lock()
	bufLen := len(h.buffer)
	h.mu.Unlock()

	if bufLen != 0 {
		t.Errorf("expected buffer length 0 after flush, got %d", bufLen)
	}
}

func TestHarvesterOutageReenqueue(t *testing.T) {
	// Point to non-existent server
	h := NewHarvester(nil, "http://localhost:59999", 50, 1*time.Second, nil)
	h.EnqueueLog(LogItem{
		ResourceID:  "res-123",
		ContainerID: "cnt-456",
		Stream:      "stdout",
		Severity:    "INFO",
		Message:     "Important log line",
		Timestamp:   time.Now(),
	})

	err := h.Flush(context.Background())
	if err == nil {
		t.Fatal("expected flush error for dead server")
	}

	h.mu.Lock()
	bufLen := len(h.buffer)
	h.mu.Unlock()

	if bufLen != 1 {
		t.Errorf("expected un-flushed logs to be re-enqueued (len=1), got %d", bufLen)
	}
}
