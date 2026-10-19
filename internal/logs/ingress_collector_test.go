package logs

import (
	"strings"
	"testing"
)

func TestParseCaddyAccessLogLine_HTTP500AndRequestCorrelation(t *testing.T) {
	// Raw JSON emitted by Caddy for an HTTP 500 error on sambackend
	rawJSON := `{
		"level": "error",
		"ts": 1792353600.5,
		"logger": "http.log.access",
		"msg": "handled request",
		"request": {
			"remote_ip": "10.0.0.5",
			"remote_port": "54321",
			"proto": "HTTP/1.1",
			"method": "POST",
			"host": "sambackend.primecloud.cloud",
			"uri": "/api/v1/salon/services?token=secret123&user=john",
			"headers": {
				"X-Prime-Request-Id": ["0192a3f4-5678-7123-8abc-def012345678"],
				"User-Agent": ["curl/8.5.0"]
			}
		},
		"bytes_read": 128,
		"duration": 0.0452,
		"size": 512,
		"status": 500,
		"resp_headers": {
			"Content-Type": ["application/json"],
			"X-Prime-Request-Id": ["0192a3f4-5678-7123-8abc-def012345678"]
		}
	}`

	domainMap := map[string]string{
		"sambackend.primecloud.cloud": "01a134a0-bbfb-73fe-a2d1-c23a5ab815ec",
	}

	item, err := ParseCaddyAccessLogLine(rawJSON, domainMap)
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}

	// 1. Authoritative resource ID from domain map
	if item.ResourceID != "01a134a0-bbfb-73fe-a2d1-c23a5ab815ec" {
		t.Errorf("expected ResourceID 01a134a0-bbfb-73fe-a2d1-c23a5ab815ec, got %s", item.ResourceID)
	}

	// 2. ResourceType and Stream
	if item.ResourceType != ResourceTypeIngress {
		t.Errorf("expected ResourceType ingress, got %s", item.ResourceType)
	}
	if item.Stream != StreamAccess {
		t.Errorf("expected Stream access, got %s", item.Stream)
	}

	// 3. Severity must be ERROR for HTTP 500
	if item.Severity != SeverityError {
		t.Errorf("expected Severity ERROR, got %s", item.Severity)
	}

	// 4. Secret redaction from URI
	if strings.Contains(item.Message, "secret123") {
		t.Errorf("sensitive token not redacted from message: %s", item.Message)
	}
	if !strings.Contains(item.Message, "token=[REDACTED]") {
		t.Errorf("expected token=[REDACTED] in message: %s", item.Message)
	}

	// 5. Request ID extraction in structured data
	if item.StructuredData == nil {
		t.Fatalf("StructuredData must not be nil")
	}
	reqID, ok := item.StructuredData["request_id"].(string)
	if !ok || reqID != "0192a3f4-5678-7123-8abc-def012345678" {
		t.Errorf("expected request_id 0192a3f4-5678-7123-8abc-def012345678, got %v", item.StructuredData["request_id"])
	}

	// 6. HTTP details inside structured data
	httpMap, ok := item.StructuredData["http"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected http structured metadata map")
	}
	if httpMap["method"] != "POST" {
		t.Errorf("expected POST method, got %v", httpMap["method"])
	}
	if httpMap["status_code"] != 500 {
		t.Errorf("expected status 500, got %v", httpMap["status_code"])
	}
}

func TestParseCaddyAccessLogLine_HTTP502BadGateway(t *testing.T) {
	// Raw JSON emitted when upstream container is down (Caddy generates 502)
	rawJSON := `{
		"level": "error",
		"ts": 1792353601.0,
		"logger": "http.log.access",
		"msg": "handled request",
		"request": {
			"remote_ip": "1.2.3.4",
			"method": "GET",
			"host": "my-app.primecloud.cloud",
			"uri": "/health",
			"headers": {}
		},
		"duration": 0.002,
		"status": 502,
		"resp_headers": {
			"X-Prime-Request-Id": ["edge-gen-uuid-502"]
		}
	}`

	item, err := ParseCaddyAccessLogLine(rawJSON, nil)
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}

	if item.Severity != SeverityError {
		t.Errorf("expected 502 to produce ERROR severity, got %s", item.Severity)
	}
	if item.ResourceID != "my-app" {
		t.Errorf("expected fallback subdomain resource ID 'my-app', got %s", item.ResourceID)
	}
	if item.StructuredData["request_id"] != "edge-gen-uuid-502" {
		t.Errorf("expected response header request ID 'edge-gen-uuid-502', got %v", item.StructuredData["request_id"])
	}
}

func TestParseCaddyAccessLogLine_HTTP404And200Severity(t *testing.T) {
	json404 := `{"level":"info","request":{"method":"GET","host":"app.test","uri":"/missing"},"status":404}`
	item404, _ := ParseCaddyAccessLogLine(json404, nil)
	if item404.Severity != SeverityWarn {
		t.Errorf("expected 404 to produce WARN severity, got %s", item404.Severity)
	}

	json200 := `{"level":"info","request":{"method":"GET","host":"app.test","uri":"/ok"},"status":200}`
	item200, _ := ParseCaddyAccessLogLine(json200, nil)
	if item200.Severity != SeverityInfo {
		t.Errorf("expected 200 to produce INFO severity, got %s", item200.Severity)
	}
}

func TestParseCaddyAccessStream(t *testing.T) {
	streamData := strings.Join([]string{
		`{"level":"info","request":{"method":"GET","host":"app.test","uri":"/1"},"status":200}`,
		`{"level":"info","request":{"method":"GET","host":"app.test","uri":"/2"},"status":200}`,
		`{"level":"error","request":{"method":"GET","host":"app.test","uri":"/3"},"status":500}`,
	}, "\n")

	items, err := ParseCaddyAccessStream(strings.NewReader(streamData), nil)
	if err != nil {
		t.Fatalf("unexpected stream parse error: %v", err)
	}
	if len(items) != 3 {
		t.Fatalf("expected 3 parsed items, got %d", len(items))
	}
	if items[2].Severity != SeverityError {
		t.Errorf("expected 3rd item to be ERROR, got %s", items[2].Severity)
	}
}
