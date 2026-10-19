// Package logs provides Caddy edge ingress access log parsing, request correlation, and telemetry harvesting.
package logs

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"
)

// HeaderXPrimeRequestID is the canonical HTTP request correlation header (ADR-0004).
const HeaderXPrimeRequestID = "X-Prime-Request-Id"

// caddySensitiveQueryRegex strips passwords, tokens, API keys, and session IDs from URLs.
var caddySensitiveQueryRegex = regexp.MustCompile(`(?i)(token|key|api_key|secret|password|auth|access_token|refresh_token|session_id)=([^&]+)`)

// CaddyAccessLogEntry models Caddy v2's structured JSON access log format.
type CaddyAccessLogEntry struct {
	Level       string                 `json:"level"`
	Ts          float64                `json:"ts"`
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
	if entry.Ts > 0 {
		sec := int64(entry.Ts)
		nsec := int64((entry.Ts - float64(sec)) * 1e9)
		ts = time.Unix(sec, nsec).UTC()
	} else {
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
