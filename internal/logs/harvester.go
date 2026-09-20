// Package logs provides continuous container log harvesting, secret redaction, and batch ingestion.
package logs

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	agentruntime "github.com/primecloud/primecloud-agent/internal/runtime"
)

var (
	// Secret redaction regex patterns matching API keys, tokens, passwords, private keys
	secretPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)(api[_-]?key|secret|password|passwd|token|auth|bearer)\s*[:=]\s*["']?([^\s"']+)["']?`),
		regexp.MustCompile(`-----BEGIN [A-Z ]+ PRIVATE KEY-----[\s\S]*?-----END [A-Z ]+ PRIVATE KEY-----`),
		regexp.MustCompile(`sk_test_[0-9a-zA-Z]{24,}`),
		regexp.MustCompile(`sk_live_[0-9a-zA-Z]{24,}`),
	}
)

// LogItem represents a single redacted log record.
type LogItem struct {
	ResourceID  string    `json:"resource_id"`
	ContainerID string    `json:"container_id"`
	Stream      string    `json:"stream"`
	Severity    string    `json:"severity"`
	Message     string    `json:"message"`
	Timestamp   time.Time `json:"timestamp"`
}

// LogBatchPayload represents batch request payload to Control Plane log ingestion API.
type LogBatchPayload struct {
	AccountID string    `json:"account_id,omitempty"`
	Logs      []LogItem `json:"logs"`
}

// Harvester tails application containers and streams redacted logs.
type Harvester struct {
	mu             sync.Mutex
	rt             agentruntime.ContainerRuntime
	controlPlaneURL string
	httpClient     *http.Client
	logger         *slog.Logger
	batchSize      int
	batchInterval  time.Duration
	buffer         []LogItem
	maxBuffer      int
}

// NewHarvester constructs a Harvester instance.
func NewHarvester(
	rt agentruntime.ContainerRuntime,
	controlPlaneURL string,
	batchSize int,
	batchInterval time.Duration,
	logger *slog.Logger,
) *Harvester {
	if batchSize <= 0 {
		batchSize = 100
	}
	if batchInterval <= 0 {
		batchInterval = 5 * time.Second
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Harvester{
		rt:             rt,
		controlPlaneURL: strings.TrimRight(controlPlaneURL, "/"),
		httpClient:     &http.Client{Timeout: 10 * time.Second},
		batchSize:      batchSize,
		batchInterval:  batchInterval,
		buffer:         make([]LogItem, 0, batchSize),
		maxBuffer:      10000, // Backpressure limit
		logger:         logger.With("component", "log_harvester"),
	}
}

// RedactSecrets applies regex masking to sensitive log content.
func RedactSecrets(msg string) string {
	redacted := msg
	for _, pattern := range secretPatterns {
		redacted = pattern.ReplaceAllStringFunc(redacted, func(match string) string {
			if strings.Contains(match, "PRIVATE KEY") {
				return "[REDACTED_PRIVATE_KEY]"
			}
			parts := strings.SplitN(match, "=", 2)
			if len(parts) == 2 {
				return parts[0] + "=[REDACTED_SECRET]"
			}
			partsCol := strings.SplitN(match, ":", 2)
			if len(partsCol) == 2 {
				return partsCol[0] + ":[REDACTED_SECRET]"
			}
			return "[REDACTED_SECRET]"
		})
	}
	return redacted
}

// EnqueueLog adds a log item to the backpressure-controlled batch buffer.
func (h *Harvester) EnqueueLog(item LogItem) {
	h.mu.Lock()
	defer h.mu.Unlock()

	item.Message = RedactSecrets(item.Message)

	// Backpressure: drop oldest logs if buffer exceeds max limit
	if len(h.buffer) >= h.maxBuffer {
		h.buffer = h.buffer[1:]
		h.logger.Warn("log_buffer_backpressure_drop_oldest")
	}

	h.buffer = append(h.buffer, item)
}

// Flush transmits buffered logs to the Control Plane.
func (h *Harvester) Flush(ctx context.Context) error {
	h.mu.Lock()
	if len(h.buffer) == 0 {
		h.mu.Unlock()
		return nil
	}

	toSend := h.buffer
	h.buffer = make([]LogItem, 0, h.batchSize)
	h.mu.Unlock()

	payload := LogBatchPayload{Logs: toSend}
	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal log payload: %w", err)
	}

	url := fmt.Sprintf("%s/api/v1/monitoring/logs", h.controlPlaneURL)
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := h.httpClient.Do(req)
	if err != nil {
		// Control plane outage: re-enqueue un-flushed logs safely
		h.mu.Lock()
		h.buffer = append(toSend, h.buffer...)
		if len(h.buffer) > h.maxBuffer {
			h.buffer = h.buffer[len(h.buffer)-h.maxBuffer:]
		}
		h.mu.Unlock()
		return fmt.Errorf("control plane log ingestion unreachable: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("log ingestion failed with status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	h.logger.Debug("logs_flushed_successfully", "count", len(toSend))
	return nil
}

// StatusCodeBodyReader safe helper
func (h *Harvester) HarvestContainer(ctx context.Context, containerID, resourceID string) error {
	if h.rt == nil {
		return nil
	}
	reader, err := h.rt.GetContainerLogs(ctx, containerID)
	if err != nil {
		return err
	}
	defer reader.Close()

	buf, err := io.ReadAll(reader)
	if err != nil {
		return err
	}

	lines := strings.Split(string(buf), "\n")
	now := time.Now()
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		h.EnqueueLog(LogItem{
			ResourceID:  resourceID,
			ContainerID: containerID,
			Stream:      "stdout",
			Severity:    "INFO",
			Message:     trimmed,
			Timestamp:   now,
		})
	}
	return nil
}

// Start boots background flush ticker.
func (h *Harvester) Start(ctx context.Context) {
	h.logger.Info("log_harvester_started", "batch_size", h.batchSize, "interval_sec", h.batchInterval.Seconds())
	ticker := time.NewTicker(h.batchInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			// Final flush on shutdown
			flushCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			_ = h.Flush(flushCtx)
			cancel()
			h.logger.Info("log_harvester_stopped")
			return
		case <-ticker.C:
			flushCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			if err := h.Flush(flushCtx); err != nil {
				h.logger.Warn("log_flush_failed", "error", err)
			}
			cancel()
		}
	}
}
