// Package logs provides Caddy edge ingress access log parsing, request correlation, and telemetry harvesting.
package logs

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

// HeaderXPrimeRequestID is the canonical HTTP request correlation header (ADR-0004).
const HeaderXPrimeRequestID = "X-Prime-Request-Id"

// caddySensitiveQueryRegex strips passwords, tokens, API keys, and session IDs from URLs.
var caddySensitiveQueryRegex = regexp.MustCompile(`(?i)(token|key|api_key|secret|password|auth|access_token|refresh_token|session_id)=([^&]+)`)

// CaddyAccessLogEntry models Caddy v2's structured JSON access log format.
type CaddyAccessLogEntry struct {
	Level       string                 `json:"level"`
	Ts          json.RawMessage        `json:"ts"`
	Logger      string                 `json:"logger"`
	Msg         string                 `json:"msg"`
	Request     CaddyRequestDetails    `json:"request"`
	BytesRead   int64                  `json:"bytes_read"`
	Duration    float64                `json:"duration"` // Duration in seconds
	Size        int64                  `json:"size"`
	Status      int                    `json:"status"`
	RespHeaders map[string][]string    `json:"resp_headers"`
}

// CaddyRequestDetails captures incoming HTTP request metadata.
type CaddyRequestDetails struct {
	RemoteIP   string              `json:"remote_ip"`
	RemotePort string              `json:"remote_port"`
	Proto      string              `json:"proto"`
	Method     string              `json:"method"`
	Host       string              `json:"host"`
	URI        string              `json:"uri"`
	Headers    map[string][]string `json:"headers"`
}

// SanitizeURI redacts secrets and credentials from query parameters.
func SanitizeURI(rawURI string) string {
	if rawURI == "" {
		return "/"
	}
	// Redact sensitive query parameters
	sanitized := caddySensitiveQueryRegex.ReplaceAllString(rawURI, "$1=[REDACTED]")
	return sanitized
}

// ExtractRequestID extracts the canonical X-Prime-Request-Id from request or response headers.
func ExtractRequestID(entry *CaddyAccessLogEntry) string {
	if entry == nil {
		return ""
	}
	// 1. Check request headers (preferred if injected by edge or forwarded)
	if entry.Request.Headers != nil {
		for k, v := range entry.Request.Headers {
			if strings.EqualFold(k, HeaderXPrimeRequestID) || strings.EqualFold(k, "X-Request-Id") {
				if len(v) > 0 && v[0] != "" {
					return v[0]
				}
			}
		}
	}
	// 2. Check response headers (if echoed by Caddy)
	if entry.RespHeaders != nil {
		for k, v := range entry.RespHeaders {
			if strings.EqualFold(k, HeaderXPrimeRequestID) || strings.EqualFold(k, "X-Request-Id") {
				if len(v) > 0 && v[0] != "" {
					return v[0]
				}
			}
		}
	}
	return ""
}

// ParseCaddyAccessLogLine transforms a raw Caddy JSON access line into a normalized LogItem.
func ParseCaddyAccessLogLine(line string, domainMap map[string]string) (*LogItem, error) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return nil, fmt.Errorf("empty log line")
	}

	var entry CaddyAccessLogEntry
	if err := json.Unmarshal([]byte(trimmed), &entry); err != nil {
		return nil, fmt.Errorf("invalid caddy json access log: %w", err)
	}

	reqID := ExtractRequestID(&entry)
	sanitizedURI := SanitizeURI(entry.Request.URI)
	durationMs := entry.Duration * 1000.0

	// Resolve ResourceID using authoritative domain mapping or domain slug
	hostClean := strings.ToLower(entry.Request.Host)
	if idx := strings.Index(hostClean, ":"); idx != -1 {
		hostClean = hostClean[:idx]
	}

	resourceID := ""
	if domainMap != nil {
		if mappedID, ok := domainMap[hostClean]; ok && mappedID != "" {
			resourceID = mappedID
		}
	}
	if resourceID == "" {
		// Fallback: derive from subdomain (e.g. sambackend.primecloud.cloud -> sambackend)
		parts := strings.Split(hostClean, ".")
		if len(parts) >= 2 {
			resourceID = parts[0]
		} else {
			resourceID = hostClean
		}
	}

	// Status code severity normalization
	severity := SeverityInfo
	if entry.Status >= 500 {
		severity = SeverityError
	} else if entry.Status >= 400 {
		severity = SeverityWarn
	}

	// Clean formatted summary message (e.g. "GET /api/v1/salon/services 500 (45.2ms)")
	msg := fmt.Sprintf("%s %s %d (%.1fms)", entry.Request.Method, sanitizedURI, entry.Status, durationMs)

	// Timestamp
	var ts time.Time
	if len(entry.Ts) > 0 {
		var tsFloat float64
		if err := json.Unmarshal(entry.Ts, &tsFloat); err == nil && tsFloat > 0 {
			sec := int64(tsFloat)
			nsec := int64((tsFloat - float64(sec)) * 1e9)
			ts = time.Unix(sec, nsec).UTC()
		} else {
			var tsStr string
			if err := json.Unmarshal(entry.Ts, &tsStr); err == nil && tsStr != "" {
				if parsedTs, err := time.Parse(time.RFC3339Nano, tsStr); err == nil {
					ts = parsedTs.UTC()
				} else if parsedTs, err := time.Parse(time.RFC3339, tsStr); err == nil {
					ts = parsedTs.UTC()
				}
			}
		}
	}
	if ts.IsZero() {
		ts = time.Now().UTC()
	}

	// Build structured HTTP metadata
	structuredData := map[string]interface{}{
		"status_code": entry.Status,
		"duration_ms": durationMs,
		"http": map[string]interface{}{
			"method":      entry.Request.Method,
			"host":        entry.Request.Host,
			"route":       sanitizedURI,
			"status_code": entry.Status,
			"duration_ms": durationMs,
			"client_ip":   entry.Request.RemoteIP,
		},
	}
	if reqID != "" {
		structuredData["request_id"] = reqID
		if httpMap, ok := structuredData["http"].(map[string]interface{}); ok {
			httpMap["request_id"] = reqID
		}
	}

	return &LogItem{
		ResourceID:     resourceID,
		ResourceType:   ResourceTypeIngress,
		Stream:         StreamAccess,
		Severity:       severity,
		Message:        msg,
		StructuredData: structuredData,
		Timestamp:      &ts,
	}, nil
}

// ParseCaddyAccessStream reads newline-delimited Caddy access log lines and returns parsed LogItems.
func ParseCaddyAccessStream(reader io.Reader, domainMap map[string]string) ([]LogItem, error) {
	scanner := bufio.NewScanner(reader)
	// Support up to 1MB log lines for large headers
	buf := make([]byte, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	var items []LogItem
	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}
		item, err := ParseCaddyAccessLogLine(line, domainMap)
		if err != nil {
			continue // Skip unparseable line
		}
		items = append(items, *item)
	}

	return items, scanner.Err()
}

// RedactAuthHeaders removes Authorization and Cookie tokens from Caddy log structures.
func RedactAuthHeaders(headers map[string][]string) map[string][]string {
	if headers == nil {
		return nil
	}
	cleaned := make(map[string][]string, len(headers))
	for k, v := range headers {
		lowerK := strings.ToLower(k)
		if lowerK == "authorization" || lowerK == "proxy-authorization" {
			cleaned[k] = []string{"[REDACTED]"}
		} else if lowerK == "cookie" {
			// Scrub cookie values
			cleaned[k] = []string{"[REDACTED_COOKIES]"}
		} else {
			cleaned[k] = v
		}
	}
	return cleaned
}

// CaddyLogTailer tracks file offsets, detects log rotation, handles partial line writes,
// and streams new parsed LogItems to the agent harvester.
type CaddyLogTailer struct {
	mu           sync.Mutex
	filePath     string
	lastOffset   int64
	lastFileInfo os.FileInfo
	partial      string
	domainMap    map[string]string
	logger       *slog.Logger
}

// NewCaddyLogTailer constructs an offset-tracking tailer for Caddy's access log file.
func NewCaddyLogTailer(filePath string, domainMap map[string]string, logger *slog.Logger) *CaddyLogTailer {
	if filePath == "" {
		filePath = os.Getenv("PRIMECLOUD_CADDY_ACCESS_LOG")
		if filePath == "" {
			filePath = "/var/log/primecloud/caddy-access.log"
		}
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &CaddyLogTailer{
		filePath:  filePath,
		domainMap: domainMap,
		logger:    logger.With("component", "caddy_log_tailer"),
	}
}

// DrainNewLogs reads all complete lines appended to the log file since last offset.
// Detects rotation (truncation or file identity change), buffers incomplete trailing lines, and parses valid lines.
func (t *CaddyLogTailer) DrainNewLogs() ([]LogItem, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	f, err := os.Open(t.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			// File not created yet by Caddy; normal during initial startup
			return nil, nil
		}
		return nil, fmt.Errorf("failed to open caddy access log: %w", err)
	}
	defer f.Close()

	stat, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("failed to stat caddy access log: %w", err)
	}

	curSize := stat.Size()

	// Detect log rotation via file identity (e.g. rename-and-recreate rotation where the new file
	// is already larger than lastOffset, or inode/file-index has changed) or in-place truncation.
	isRotated := false
	if t.lastFileInfo != nil && !os.SameFile(t.lastFileInfo, stat) {
		isRotated = true
	} else if curSize < t.lastOffset {
		isRotated = true
	}

	if isRotated {
		t.logger.Info("caddy_access_log_rotated", "old_offset", t.lastOffset, "new_size", curSize)
		t.lastOffset = 0
		t.partial = ""
	}

	t.lastFileInfo = stat

	// No new data written
	if curSize == t.lastOffset {
		return nil, nil
	}

	if _, err := f.Seek(t.lastOffset, io.SeekStart); err != nil {
		return nil, fmt.Errorf("failed to seek caddy access log: %w", err)
	}

	readBytes, err := io.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("failed to read caddy access log: %w", err)
	}

	if len(readBytes) == 0 {
		return nil, nil
	}

	// Advance offset by bytes read
	t.lastOffset += int64(len(readBytes))

	// Prepend leftover partial chunk from previous cycle if any
	chunk := t.partial + string(readBytes)
	t.partial = ""

	// If the chunk doesn't end with newline, preserve the trailing partial fragment
	if !strings.HasSuffix(chunk, "\n") {
		lastNewline := strings.LastIndex(chunk, "\n")
		if lastNewline == -1 {
			// Entire chunk is partial; wait for next read
			t.partial = chunk
			return nil, nil
		}
		t.partial = chunk[lastNewline+1:]
		chunk = chunk[:lastNewline+1]
	}

	var items []LogItem
	lines := strings.Split(chunk, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		item, err := ParseCaddyAccessLogLine(trimmed, t.domainMap)
		if err != nil {
			t.logger.Debug("caddy_access_line_parse_skipped", "line", trimmed, "error", err)
			continue
		}
		items = append(items, *item)
	}

	return items, nil
}

