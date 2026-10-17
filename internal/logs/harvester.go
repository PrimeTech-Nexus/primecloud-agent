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
	"regexp"
	"sort"
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
	Key  string
	Logs []LogItem
}

// GenerateUUIDv4 generates a compliant RFC 4122 v4 UUID string.
func GenerateUUIDv4() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40 // Version 4
	b[8] = (b[8] & 0x3f) | 0x80 // Variant 10
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// containerCursor tracks harvesting progress and deduplication state for a specific container.
type containerCursor struct {
	lastTimestamp time.Time
	seenCounts    map[string]int // Disambiguates identical timestamps at boundary
	lastSeenAt    time.Time      // Pruning timestamp for stopped/removed containers
}

// Harvester tails application containers and streams redacted logs.
type Harvester struct {
	mu              sync.Mutex
	rt              agentruntime.ContainerRuntime
	controlPlaneURL string
	agentKey        string
	nodeID          string
	httpClient      *http.Client
	logger          *slog.Logger
	batchSize       int
	batchInterval   time.Duration
	buffer          []LogItem
	inflight        *BatchWithKey // Pending batch awaiting acknowledgment or retry
	maxBuffer       int

	cursors      map[string]*containerCursor
	droppedCount int64 // Dropped in current flush cycle
	totalDropped int64 // Cumulative lifetime dropped entries
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

	return &Harvester{
		rt:              rt,
		controlPlaneURL: cleanURL,
		agentKey:        agentKey,
		nodeID:          nodeID,
		httpClient:      &http.Client{Timeout: 10 * time.Second},
		batchSize:       batchSize,
		batchInterval:   batchInterval,
		buffer:          make([]LogItem, 0, batchSize),
		maxBuffer:       MaxBufferLimit,
		logger:          logger.With("component", "log_harvester"),
		cursors:         make(map[string]*containerCursor),
	}
}

// DroppedCount returns the count of dropped log items in the current flush cycle.
func (h *Harvester) DroppedCount() int64 {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.droppedCount
}

// TotalDropped returns the cumulative lifetime count of log items dropped due to backpressure.
func (h *Harvester) TotalDropped() int64 {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.totalDropped
}

// GetCursor returns the recorded cursor timestamp and whether a cursor exists for the container.
func (h *Harvester) GetCursor(containerID string) (time.Time, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.cursors == nil {
		return time.Time{}, false
	}
	cur, ok := h.cursors[containerID]
	if !ok {
		return time.Time{}, false
	}
	return cur.lastTimestamp, true
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
	h.enqueueLogLocked(item)
}

func (h *Harvester) enqueueLogLocked(item LogItem) {
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

	// Backpressure: drop oldest logs if buffer exceeds max limit.
	// Warning is aggregated and logged once per Flush() cycle to prevent log flood.
	if len(h.buffer) >= h.maxBuffer {
		h.buffer = h.buffer[1:]
		h.droppedCount++
		h.totalDropped++
	}

	h.buffer = append(h.buffer, item)
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
		return items, nil
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

		sev := SeverityInfo
		lowerMsg := strings.ToLower(msg)
		if strings.Contains(lowerMsg, "error") || strings.Contains(lowerMsg, "fatal") || strings.Contains(lowerMsg, "panic") {
			sev = SeverityError
		} else if strings.Contains(lowerMsg, "warn") {
			sev = SeverityWarn
		}

		fallbackItems = append(fallbackItems, LogItem{
			Stream:    NormalizeStream(fallbackStream),
			Severity:  sev,
			Message:   msg,
			Timestamp: &ts,
		})
	}

	return fallbackItems, nil
}

// Flush transmits buffered logs to the Control Plane using sender-scoped idempotency.
// Retries of the same batch NEVER generate a new Idempotency-Key.
func (h *Harvester) Flush(ctx context.Context) error {
	h.mu.Lock()
	droppedInCycle := h.droppedCount
	h.droppedCount = 0
	totalDropped := h.totalDropped

	// If there is an existing inflight batch that previously failed, prioritize sending it with its original key
	var currentBatch BatchWithKey
	if h.inflight != nil {
		currentBatch = *h.inflight
	} else {
		if len(h.buffer) == 0 {
			h.mu.Unlock()
			if droppedInCycle > 0 {
				h.logger.Warn("log_buffer_backpressure_drop_summary",
					"dropped_count", droppedInCycle,
					"total_dropped", totalDropped,
					"buffer_capacity", h.maxBuffer,
				)
			}
			return nil
		}

		count := h.batchSize
		if count > len(h.buffer) {
			count = len(h.buffer)
		}

		toSend := h.buffer[:count]
		h.buffer = h.buffer[count:]

		currentBatch = BatchWithKey{
			Key:  GenerateUUIDv4(),
			Logs: toSend,
		}
		h.inflight = &currentBatch
	}
	h.mu.Unlock()

	if droppedInCycle > 0 {
		h.logger.Warn("log_buffer_backpressure_drop_summary",
			"dropped_count", droppedInCycle,
			"total_dropped", totalDropped,
			"buffer_capacity", h.maxBuffer,
		)
	}

	// Transmit batch with stable key
	err := h.transmitBatch(ctx, &currentBatch)
	if err != nil {
		return err
	}

	// On success, clear inflight batch
	h.mu.Lock()
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

	if resp.StatusCode == http.StatusAccepted || resp.StatusCode == http.StatusOK {
		return nil
	}

	// Permanent failures (401/403 auth errors, 400 validation, 409 conflict):
	// Drop the rejected batch to avoid permanently stalling the ingestion queue.
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden ||
		resp.StatusCode == http.StatusBadRequest || resp.StatusCode == http.StatusConflict {
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

	h.mu.Lock()
	if h.cursors == nil {
		h.cursors = make(map[string]*containerCursor)
	}
	cursor, exists := h.cursors[containerID]
	if !exists {
		cursor = &containerCursor{
			seenCounts: make(map[string]int),
			lastSeenAt: time.Now(),
		}
		h.cursors[containerID] = cursor
	} else {
		cursor.lastSeenAt = time.Now()
	}
	since := cursor.lastTimestamp
	h.mu.Unlock()

	var reader io.ReadCloser
	var err error

	// If runtime supports incremental log reading, query since cursor timestamp
	if incReader, ok := h.rt.(agentruntime.IncrementalLogReader); ok && !since.IsZero() {
		reader, err = incReader.GetContainerLogsSince(ctx, containerID, since)
	} else {
		reader, err = h.rt.GetContainerLogs(ctx, containerID)
	}
	if err != nil {
		return err
	}
	defer reader.Close()

	items, err := DemuxDockerLogStream(reader, StreamStdout)
	if err != nil {
		return err
	}

	// Sort items by timestamp to ensure chronological processing across demultiplexed streams
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].Timestamp == nil || items[j].Timestamp == nil {
			return false
		}
		return items[i].Timestamp.Before(*items[j].Timestamp)
	})

	h.mu.Lock()
	defer h.mu.Unlock()

	// Track occurrences seen in this harvest cycle for boundary timestamp
	cycleCounts := make(map[string]int)

	for _, item := range items {
		ts := item.Timestamp
		if ts == nil {
			now := time.Now().UTC()
			ts = &now
			item.Timestamp = ts
		}

		key := item.Stream + ":" + item.Message

		if !cursor.lastTimestamp.IsZero() {
			if ts.Before(cursor.lastTimestamp) {
				// Historical entry already processed
				continue
			}
			if ts.Equal(cursor.lastTimestamp) {
				cycleCounts[key]++
				if cycleCounts[key] <= cursor.seenCounts[key] {
					// Duplicate occurrence already processed in previous cycle
					continue
				}
				cursor.seenCounts[key] = cycleCounts[key]
			} else { // ts.After(cursor.lastTimestamp)
				cursor.lastTimestamp = *ts
				cursor.seenCounts = map[string]int{key: 1}
				cycleCounts = map[string]int{key: 1}
			}
		} else {
			// First harvest of this container
			if cursor.lastTimestamp.IsZero() || ts.After(cursor.lastTimestamp) {
				cursor.lastTimestamp = *ts
				cursor.seenCounts = map[string]int{key: 1}
				cycleCounts = map[string]int{key: 1}
			} else if ts.Equal(cursor.lastTimestamp) {
				cycleCounts[key]++
				cursor.seenCounts[key] = cycleCounts[key]
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
		h.enqueueLogLocked(item)
	}

	return nil
}

// DiscoverAndHarvestOnce inspects all running containers and harvests their logs.
func (h *Harvester) DiscoverAndHarvestOnce(ctx context.Context) error {
	if h.rt == nil {
		return nil
	}

	containers, err := h.rt.ListContainers(ctx, false) // Running containers only
	if err != nil {
		return fmt.Errorf("failed to list containers: %w", err)
	}

	activeIDs := make(map[string]struct{}, len(containers))
	for _, cnt := range containers {
		activeIDs[cnt.ID] = struct{}{}

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

	// Purge stale cursors for containers not observed running for > 10 minutes
	h.mu.Lock()
	now := time.Now()
	for id, cur := range h.cursors {
		if _, active := activeIDs[id]; !active {
			if now.Sub(cur.lastSeenAt) > 10*time.Minute {
				delete(h.cursors, id)
			}
		}
	}
	h.mu.Unlock()

	return nil
}

// ResetCursor clears cursor tracking for a given container (e.g. on manual container recreation).
func (h *Harvester) ResetCursor(containerID string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.cursors != nil {
		delete(h.cursors, containerID)
	}
}

// PurgeStaleCursors removes cursors for containers that have not been observed running for longer than maxAge.
func (h *Harvester) PurgeStaleCursors(maxAge time.Duration) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.cursors == nil {
		return 0
	}
	now := time.Now()
	purged := 0
	for id, cur := range h.cursors {
		if now.Sub(cur.lastSeenAt) >= maxAge {
			delete(h.cursors, id)
			purged++
		}
	}
	return purged
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
