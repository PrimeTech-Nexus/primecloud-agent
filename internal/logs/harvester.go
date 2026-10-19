// Package logs provides continuous container log harvesting, secret redaction, and batch ingestion.
package logs

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/docker/docker/pkg/stdcopy"
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

// Allowed enums and limits matching Control Plane schema and models
const (
	MaxBatchSize     = 500
	DefaultBatchSize = 100
	MaxBufferLimit   = 10000
	MaxMessageLength = 65536

	SeverityDebug = "DEBUG"
	SeverityInfo  = "INFO"
	SeverityWarn  = "WARN"
	SeverityError = "ERROR"
	SeverityFatal = "FATAL"

	StreamStdout = "stdout"
	StreamStderr = "stderr"
	StreamSystem = "system"
	StreamAccess = "access"

	ResourceTypeApplication = "application"
	ResourceTypeBuild       = "build"
	ResourceTypeDeployment  = "deployment"
	ResourceTypeDatabase    = "database"
	ResourceTypeIngress     = "ingress"
)

// LogItem represents a single redacted log record matching the canonical Control Plane schema.
type LogItem struct {
	ResourceType   string                 `json:"resource_type"`
	ResourceID     string                 `json:"resource_id"`
	DeploymentID   string                 `json:"deployment_id,omitempty"`
	ContainerID    string                 `json:"container_id,omitempty"`
	Stream         string                 `json:"stream"`
	Severity       string                 `json:"severity"`
	Message        string                 `json:"message"`
	StructuredData map[string]interface{} `json:"structured_data,omitempty"`
	Timestamp      *time.Time             `json:"timestamp,omitempty"`
}

// LogBatchPayload represents batch request payload to Control Plane log ingestion API.
type LogBatchPayload struct {
	AccountID string    `json:"account_id,omitempty"`
	Logs      []LogItem `json:"logs"`
}

// LogIngestResponse represents acknowledgment from Control Plane.
type LogIngestResponse struct {
	AcceptedCount  int    `json:"accepted_count"`
	IdempotencyKey string `json:"idempotency_key,omitempty"`
	Status         string `json:"status"`
	Message        string `json:"message"`
}

// BatchWithKey pairs a batch of log items with a stable idempotency key for reliable retries.
type BatchWithKey struct {
	Key           string               `json:"key"`
	Logs          []LogItem            `json:"logs"`
	MaxTimestamps map[string]time.Time `json:"max_timestamps,omitempty"`
}

// GenerateUUIDv4 generates a compliant RFC 4122 v4 UUID string.
func GenerateUUIDv4() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40 // Version 4
	b[8] = (b[8] & 0x3f) | 0x80 // Variant 10
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// Harvester tails application containers and streams redacted logs.
type Harvester struct {
	mu                sync.Mutex
	rt                agentruntime.ContainerRuntime
	controlPlaneURL   string
	agentKey          string
	nodeID            string
	httpClient        *http.Client
	logger            *slog.Logger
	batchSize         int
	batchInterval     time.Duration
	buffer            []LogItem
	inflight          *BatchWithKey // Pending batch awaiting acknowledgment or retry
	maxBuffer         int
	containerCursors  map[string]time.Time
	pendingWatermarks map[string]time.Time
	cursorStore       CursorStore
}

// NewHarvester constructs a Harvester instance.
func NewHarvester(
	rt agentruntime.ContainerRuntime,
	controlPlaneURL string,
	batchSize int,
	batchInterval time.Duration,
	logger *slog.Logger,
) *Harvester {
	return NewHarvesterWithAuth(rt, controlPlaneURL, "", "", batchSize, batchInterval, logger)
}

// NewHarvesterWithAuth constructs a Harvester instance with authentication parameters.
func NewHarvesterWithAuth(
	rt agentruntime.ContainerRuntime,
	controlPlaneURL string,
	agentKey string,
	nodeID string,
	batchSize int,
	batchInterval time.Duration,
	logger *slog.Logger,
) *Harvester {
	if batchSize <= 0 || batchSize > MaxBatchSize {
		batchSize = DefaultBatchSize
	}
	if batchInterval <= 0 {
		batchInterval = 5 * time.Second
	}
	if logger == nil {
		logger = slog.Default()
	}

	cleanURL := strings.TrimRight(controlPlaneURL, "/")
	if cleanURL != "" {
		if strings.HasSuffix(cleanURL, ":50051") {
			cleanURL = strings.TrimSuffix(cleanURL, ":50051") + ":8000"
		}
		if !strings.HasPrefix(cleanURL, "http://") && !strings.HasPrefix(cleanURL, "https://") {
			cleanURL = "http://" + cleanURL
		}
	}

	cursorPath := os.Getenv("PRIMECLOUD_LOG_CURSOR_FILE")
	if cursorPath == "" {
		cursorPath = "/var/lib/primecloud/log_cursors.json"
	}
	store := NewFileCursorStore(cursorPath, DefaultMaxCursorEntries, logger)
	_ = store.Load()

	return &Harvester{
		rt:                rt,
		controlPlaneURL:   cleanURL,
		agentKey:          agentKey,
		nodeID:            nodeID,
		httpClient:        &http.Client{Timeout: 10 * time.Second},
		batchSize:         batchSize,
		batchInterval:     batchInterval,
		buffer:            make([]LogItem, 0, batchSize),
		maxBuffer:         MaxBufferLimit,
		containerCursors:  make(map[string]time.Time),
		pendingWatermarks: make(map[string]time.Time),
		cursorStore:       store,
		logger:            logger.With("component", "log_harvester"),
	}
}

// SetCursorStore configures an explicit cursor checkpoint store (e.g. for testing).
func (h *Harvester) SetCursorStore(store CursorStore) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.cursorStore = store
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

// NormalizeSeverity maps arbitrary string levels to allowed enums.
func NormalizeSeverity(sev string) string {
	switch strings.ToUpper(strings.TrimSpace(sev)) {
	case "DEBUG", "TRACE":
		return SeverityDebug
	case "INFO", "NOTICE":
		return SeverityInfo
	case "WARN", "WARNING":
		return SeverityWarn
	case "ERROR", "ERR":
		return SeverityError
	case "FATAL", "CRITICAL", "PANIC":
		return SeverityFatal
	default:
		return SeverityInfo
	}
}

// NormalizeStream maps stream names to allowed enums.
func NormalizeStream(stream string) string {
	switch strings.ToLower(strings.TrimSpace(stream)) {
	case "stdout":
		return StreamStdout
	case "stderr":
		return StreamStderr
	case "system":
		return StreamSystem
	case "access":
		return StreamAccess
	default:
		return StreamStdout
	}
}

// EnqueueLog adds a log item to the backpressure-controlled batch buffer.
func (h *Harvester) EnqueueLog(item LogItem) {
	h.mu.Lock()
	defer h.mu.Unlock()

	// Redact message secrets
	item.Message = RedactSecrets(item.Message)
	if len(item.Message) > MaxMessageLength {
		item.Message = item.Message[:MaxMessageLength]
	}

	// Normalize defaults
	if item.ResourceType == "" {
		item.ResourceType = ResourceTypeApplication
	}
	item.Stream = NormalizeStream(item.Stream)
	item.Severity = NormalizeSeverity(item.Severity)

	// Backpressure: drop oldest logs if buffer exceeds max limit
	if len(h.buffer) >= h.maxBuffer {
		h.buffer = h.buffer[1:]
		h.logger.Warn("log_buffer_backpressure_drop_oldest")
	}

	h.buffer = append(h.buffer, item)
}

// AggregateMultilineItems groups consecutive traceback or panic frames into a single LogItem.
func AggregateMultilineItems(items []LogItem) []LogItem {
	if len(items) <= 1 {
		return items
	}

	isTracebackStart := func(msg string) bool {
		lower := strings.ToLower(msg)
		return strings.HasPrefix(lower, "traceback (most recent call last):") ||
			strings.HasPrefix(msg, "panic:")
	}

	isTracebackContinuation := func(msg string) bool {
		return strings.HasPrefix(msg, " ") ||
			strings.HasPrefix(msg, "\t") ||
			strings.HasPrefix(msg, "goroutine ") ||
			strings.HasPrefix(msg, "[signal ")
	}

	var result []LogItem
	var currentGroup []LogItem

	flushGroup := func() {
		if len(currentGroup) == 0 {
			return
		}
		if len(currentGroup) == 1 {
			result = append(result, currentGroup[0])
			currentGroup = nil
			return
		}

		base := currentGroup[0]
		var sb strings.Builder
		for i, itm := range currentGroup {
			if i > 0 {
				sb.WriteString("\n")
			}
			sb.WriteString(itm.Message)
		}
		fullText := sb.String()

		summary := base.Message
		lastLine := currentGroup[len(currentGroup)-1].Message
		if strings.Contains(lastLine, ": ") && !strings.HasPrefix(lastLine, " ") && !strings.HasPrefix(lastLine, "\t") {
			summary = lastLine
		}

		if base.StructuredData == nil {
			base.StructuredData = make(map[string]interface{})
		}
		base.StructuredData["is_multiline"] = true
		base.StructuredData["line_count"] = len(currentGroup)
		base.StructuredData["raw_traceback"] = fullText
		base.Severity = SeverityError
		base.Message = summary
		result = append(result, base)
		currentGroup = nil
	}

	for _, item := range items {
		if len(currentGroup) == 0 {
			if isTracebackStart(item.Message) {
				currentGroup = append(currentGroup, item)
			} else {
				result = append(result, item)
			}
		} else {
			if isTracebackContinuation(item.Message) {
				currentGroup = append(currentGroup, item)
			} else {
				lastMsg := currentGroup[len(currentGroup)-1].Message
				if isTracebackContinuation(lastMsg) && (strings.Contains(item.Message, "Error") || strings.Contains(item.Message, "Exception") || strings.Contains(item.Message, ":")) {
					currentGroup = append(currentGroup, item)
					flushGroup()
				} else {
					flushGroup()
					if isTracebackStart(item.Message) {
						currentGroup = append(currentGroup, item)
					} else {
						result = append(result, item)
					}
				}
			}
		}
	}
	flushGroup()
	return result
}

// DemuxDockerLogStream separates multiplexed Docker stdout and stderr streams via stdcopy.StdCopy.
// If the stream contains raw text rather than Docker multiplex headers, it gracefully falls back
// to parsing line-by-line into the fallbackStream.
func DemuxDockerLogStream(reader io.Reader, fallbackStream string) ([]LogItem, error) {
	rawBytes, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}

	var stdoutBuf, stderrBuf bytes.Buffer

	// Attempt stdcopy demultiplexing on the buffered bytes
	_, err = stdcopy.StdCopy(&stdoutBuf, &stderrBuf, bytes.NewReader(rawBytes))
	if err == nil && (stdoutBuf.Len() > 0 || stderrBuf.Len() > 0) {
		var items []LogItem
		now := time.Now().UTC()

		parseLines := func(buf *bytes.Buffer, streamName string, defaultSev string) {
			lines := strings.Split(buf.String(), "\n")
			for _, line := range lines {
				trimmed := strings.TrimRight(line, "\r\n")
				if trimmed == "" {
					continue
				}

				// Check if line begins with Docker timestamp (RFC3339 or RFC3339Nano)
				ts := now
				msg := trimmed
				parts := strings.SplitN(trimmed, " ", 2)
				if len(parts) == 2 {
					if parsedTS, parseErr := time.Parse(time.RFC3339Nano, parts[0]); parseErr == nil {
						ts = parsedTS
						msg = parts[1]
					} else if parsedTS, parseErr := time.Parse(time.RFC3339, parts[0]); parseErr == nil {
						ts = parsedTS
						msg = parts[1]
					}
				}

				sev := defaultSev
				lowerMsg := strings.ToLower(msg)
				if strings.Contains(lowerMsg, "error") || strings.Contains(lowerMsg, "fatal") || strings.Contains(lowerMsg, "panic") {
					sev = SeverityError
				} else if strings.Contains(lowerMsg, "warn") {
					sev = SeverityWarn
				}

				items = append(items, LogItem{
					Stream:    streamName,
					Severity:  sev,
					Message:   msg,
					Timestamp: &ts,
				})
			}
		}

		parseLines(&stdoutBuf, StreamStdout, SeverityInfo)
		parseLines(&stderrBuf, StreamStderr, SeverityError)
		return AggregateMultilineItems(items), nil
	}

	// Fallback for non-multiplexed raw text streams (e.g. mock reader or TTY output)
	lines := strings.Split(string(rawBytes), "\n")
	var fallbackItems []LogItem
	now := time.Now().UTC()

	for _, line := range lines {
		trimmed := strings.TrimRight(line, "\r\n")
		if trimmed == "" {
			continue
		}
		fallbackItems = append(fallbackItems, LogItem{
			Stream:    NormalizeStream(fallbackStream),
			Severity:  SeverityInfo,
			Message:   trimmed,
			Timestamp: &now,
		})
	}

	return AggregateMultilineItems(fallbackItems), nil
}

// Flush transmits buffered logs to the Control Plane using sender-scoped idempotency.
// Retries of the same batch NEVER generate a new Idempotency-Key.
func (h *Harvester) Flush(ctx context.Context) error {
	h.mu.Lock()

	// If there is an existing inflight batch that previously failed, prioritize sending it with its original key
	var currentBatch BatchWithKey
	if h.inflight != nil {
		currentBatch = *h.inflight
	} else {
		if len(h.buffer) == 0 {
			h.mu.Unlock()
			return nil
		}

		count := h.batchSize
		if count > len(h.buffer) {
			count = len(h.buffer)
		}

		toSend := h.buffer[:count]
		h.buffer = h.buffer[count:]

		maxTimestamps := make(map[string]time.Time)
		for _, item := range toSend {
			if item.ContainerID != "" && item.Timestamp != nil {
				if cur, ok := maxTimestamps[item.ContainerID]; !ok || item.Timestamp.After(cur) {
					maxTimestamps[item.ContainerID] = *item.Timestamp
				}
			}
		}

		currentBatch = BatchWithKey{
			Key:           GenerateUUIDv4(),
			Logs:          toSend,
			MaxTimestamps: maxTimestamps,
		}
		h.inflight = &currentBatch
	}
	h.mu.Unlock()

	// Transmit batch with stable key
	err := h.transmitBatch(ctx, &currentBatch)
	if err != nil {
		return err
	}

	// On success, advance and commit durable checkpoints ONLY upon verified Control Plane acceptance (Requirement B3)
	if h.cursorStore != nil && len(currentBatch.MaxTimestamps) > 0 {
		_ = h.cursorStore.Commit(currentBatch.MaxTimestamps)
	}

	// On success, clear inflight batch and update in-memory high-water marks
	h.mu.Lock()
	for cid, ts := range currentBatch.MaxTimestamps {
		h.containerCursors[cid] = ts
	}
	h.inflight = nil
	h.mu.Unlock()

	h.logger.Debug("logs_flushed_successfully", "count", len(currentBatch.Logs))
	return nil
}

// transmitBatch performs the HTTP POST to /v1/monitoring/ingest/logs.
func (h *Harvester) transmitBatch(ctx context.Context, batch *BatchWithKey) error {
	payload := LogBatchPayload{Logs: batch.Logs}
	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal log payload: %w", err)
	}

	url := fmt.Sprintf("%s/v1/monitoring/ingest/logs", h.controlPlaneURL)
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", batch.Key)

	if h.agentKey != "" {
		req.Header.Set("X-Agent-Key", h.agentKey)
	}
	if h.nodeID != "" {
		senderID := h.nodeID
		if !strings.HasPrefix(senderID, "agent:") {
			senderID = "agent:" + senderID
		}
		req.Header.Set("X-Sender-Identity", senderID)
	}

	resp, err := h.httpClient.Do(req)
	if err != nil {
		// Network timeout / connection error: keep inflight batch with stable key for next retry
		return fmt.Errorf("control plane log ingestion unreachable: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusAccepted || resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusMultiStatus {
		return nil
	}

	// Permanent failures (401/403 auth errors, 400 validation, 404 unmapped resource, 409 conflict):
	// Drop the rejected batch to avoid permanently stalling the ingestion queue.
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden ||
		resp.StatusCode == http.StatusBadRequest || resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusConflict {
		bodyBytes, _ := io.ReadAll(resp.Body)
		h.mu.Lock()
		h.inflight = nil
		h.mu.Unlock()
		return fmt.Errorf("permanent log ingestion rejection (status %d): %s", resp.StatusCode, string(bodyBytes))
	}

	// Transient server error (500, 502, 503, 504, 429): retain inflight batch with same key
	bodyBytes, _ := io.ReadAll(resp.Body)
	return fmt.Errorf("transient log ingestion failure (status %d): %s", resp.StatusCode, string(bodyBytes))
}

// HarvestContainer pulls and demultiplexes logs for a container and enqueues them.
func (h *Harvester) HarvestContainer(ctx context.Context, containerID, resourceID string) error {
	return h.HarvestContainerWithMetadata(ctx, containerID, resourceID, "", ResourceTypeApplication)
}

// HarvestContainerWithMetadata pulls and demultiplexes logs for a container with explicit deployment and resource type context.
func (h *Harvester) HarvestContainerWithMetadata(ctx context.Context, containerID, resourceID, deploymentID, resourceType string) error {
	if h.rt == nil {
		return nil
	}

	reader, err := h.rt.GetContainerLogs(ctx, containerID)
	if err != nil {
		return err
	}
	defer reader.Close()

	items, err := DemuxDockerLogStream(reader, StreamStdout)
	if err != nil {
		return err
	}

	h.mu.Lock()
	var lastAcked time.Time
	var hasAcked bool
	if h.cursorStore != nil {
		lastAcked, hasAcked = h.cursorStore.Get(containerID)
	}
	if !hasAcked {
		lastAcked, hasAcked = h.containerCursors[containerID]
	}
	pendingMax := h.pendingWatermarks[containerID]
	h.mu.Unlock()

	var newMaxSeen time.Time
	if hasAcked {
		newMaxSeen = lastAcked
	}
	if pendingMax.After(newMaxSeen) {
		newMaxSeen = pendingMax
	}

	for _, item := range items {
		if item.Timestamp != nil {
			if hasAcked && !item.Timestamp.After(lastAcked) {
				continue
			}
			if !pendingMax.IsZero() && !item.Timestamp.After(pendingMax) {
				continue
			}
			if item.Timestamp.After(newMaxSeen) {
				newMaxSeen = *item.Timestamp
			}
		}
		item.ResourceID = resourceID
		item.ContainerID = containerID
		if deploymentID != "" {
			item.DeploymentID = deploymentID
		}
		if resourceType != "" {
			item.ResourceType = resourceType
		}
		h.EnqueueLog(item)
	}

	if !newMaxSeen.IsZero() {
		h.mu.Lock()
		h.pendingWatermarks[containerID] = newMaxSeen
		h.containerCursors[containerID] = newMaxSeen
		h.mu.Unlock()
	}

	return nil
}

// HarvestIngressStream parses Caddy access logs from a reader and enqueues them into the harvester buffer.
func (h *Harvester) HarvestIngressStream(ctx context.Context, reader io.Reader, domainMap map[string]string) error {
	items, err := ParseCaddyAccessStream(reader, domainMap)
	if err != nil {
		return err
	}
	for _, item := range items {
		h.EnqueueLog(item)
	}
	return nil
}

// DiscoverAndHarvestOnce inspects all running and exited containers and harvests their logs.
func (h *Harvester) DiscoverAndHarvestOnce(ctx context.Context) error {
	if h.rt == nil {
		return nil
	}

	containers, err := h.rt.ListContainers(ctx, true) // Include exited/crashed containers to capture crash logs
	if err != nil {
		return fmt.Errorf("failed to list containers: %w", err)
	}

	for _, cnt := range containers {
		resourceID := ""
		deploymentID := ""
		resourceType := ResourceTypeApplication

		if cnt.Labels != nil {
			if rid, ok := cnt.Labels["primecloud.resource_id"]; ok && rid != "" {
				resourceID = rid
			} else if rid, ok := cnt.Labels["primecloud.application_id"]; ok && rid != "" {
				resourceID = rid
			}

			if did, ok := cnt.Labels["primecloud.deployment_id"]; ok && did != "" {
				deploymentID = did
			} else if did, ok := cnt.Labels["primecloud.instance_id"]; ok && did != "" {
				deploymentID = did
			}
		}

		if resourceID == "" && len(cnt.Names) > 0 {
			cleanName := strings.TrimPrefix(cnt.Names[0], "/")
			if strings.HasPrefix(cleanName, "pc-pg-") {
				resourceID = strings.TrimPrefix(cleanName, "pc-pg-")
				resourceType = ResourceTypeDatabase
			} else if strings.HasPrefix(cleanName, "pc-vk-") {
				resourceID = strings.TrimPrefix(cleanName, "pc-vk-")
				resourceType = ResourceTypeDatabase
			} else if strings.HasPrefix(cleanName, "pc-app-") {
				resourceID = strings.TrimPrefix(cleanName, "pc-app-")
				resourceType = ResourceTypeApplication
			} else if strings.HasPrefix(cleanName, "pc-") && !strings.HasPrefix(cleanName, "primecloud-") {
				// Canonical application container naming: pc-{slug}-{replica_index}-{dep_short}
				// E.g. pc-sambackend-0-3e2849fb
				parts := strings.Split(cleanName, "-")
				if len(parts) >= 4 {
					resourceID = strings.Join(parts[1:len(parts)-2], "-")
					if deploymentID == "" {
						deploymentID = parts[len(parts)-1]
					}
				} else if len(parts) >= 2 {
					resourceID = strings.TrimPrefix(cleanName, "pc-")
				}
				resourceType = ResourceTypeApplication
			}
		}

		if resourceID == "" {
			continue
		}

		harvestCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		if err := h.HarvestContainerWithMetadata(harvestCtx, cnt.ID, resourceID, deploymentID, resourceType); err != nil {
			h.logger.Debug("container_log_harvest_skipped", "container_id", cnt.ID, "error", err)
		}
		cancel()
	}

	return nil
}

// Start boots background harvesting and flush loop.
func (h *Harvester) Start(ctx context.Context) {
	h.logger.Info("log_harvester_started",
		"batch_size", h.batchSize,
		"interval_sec", h.batchInterval.Seconds(),
		"control_plane_url", h.controlPlaneURL,
	)
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
			// 1. Periodically harvest running containers
			harvestCtx, cancelHarvest := context.WithTimeout(ctx, 5*time.Second)
			_ = h.DiscoverAndHarvestOnce(harvestCtx)
			cancelHarvest()

			// 2. Flush batches to Control Plane
			flushCtx, cancelFlush := context.WithTimeout(ctx, 5*time.Second)
			if err := h.Flush(flushCtx); err != nil {
				h.logger.Warn("log_flush_failed", "error", err)
			}
			cancelFlush()
		}
	}
}
