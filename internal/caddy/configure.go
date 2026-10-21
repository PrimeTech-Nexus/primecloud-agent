// Package caddy provides the reverse proxy and ingress driver for Caddy.
package caddy

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// RouteConfig defines routing rules for an application or service.
type RouteConfig struct {
	Domain          string            `json:"domain"`
	Upstream        string            `json:"upstream"`
	TLS             bool              `json:"tls"`
	TLSMode         string            `json:"tls_mode,omitempty"`
	CustomDomain    bool              `json:"custom_domain,omitempty"`
	Headers         map[string]string `json:"headers,omitempty"`
	HealthCheckPath string            `json:"health_check_path,omitempty"`
	ResourceID      string            `json:"resource_id,omitempty"`
	AccessLogPath   string            `json:"access_log_path,omitempty"`
}

// Manager orchestrates Caddy reverse proxy configuration.
type Manager struct {
	mu         sync.RWMutex
	configDir  string
	adminURL   string
	httpClient *http.Client
	logger     *slog.Logger
}

// NewManager constructs a Caddy Manager.
func NewManager(configDir, adminURL string, logger *slog.Logger) *Manager {
	if configDir == "" {
		configDir = "/etc/caddy/sites-enabled"
	}
	if adminURL == "" {
		adminURL = "http://127.0.0.1:2019"
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Manager{
		configDir:  configDir,
		adminURL:   adminURL,
		httpClient: &http.Client{Timeout: 5 * time.Second},
		logger:     logger.With("component", "caddy_manager"),
	}
}

// ConfigDir returns the active configuration directory.
func (m *Manager) ConfigDir() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.configDir
}

var validDomainRegex = regexp.MustCompile(`^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`)

// ValidateHostname enforces RFC 1123 compliance and rejects SSRF, loopbacks, IP literals, and path traversal.
func ValidateHostname(rawDomain string) (string, error) {
	domain := strings.TrimSpace(rawDomain)
	domain = strings.TrimPrefix(domain, "http://")
	domain = strings.TrimPrefix(domain, "https://")
	domain = strings.TrimSuffix(domain, "/")

	if domain == "" {
		return "", fmt.Errorf("domain cannot be empty")
	}

	// Reject path separators, control characters, colons, query parameters, fragments, or path traversals
	if strings.ContainsAny(domain, "/\\?#@:") || strings.Contains(domain, "..") {
		return "", fmt.Errorf("domain contains invalid characters, path components, or port: %q", rawDomain)
	}

	for _, ch := range domain {
		if ch <= 32 || ch >= 127 {
			return "", fmt.Errorf("domain contains whitespace or non-printable character: %q", rawDomain)
		}
	}

	// RFC 1035 / RFC 1123 max length is 253 characters
	if len(domain) > 253 {
		return "", fmt.Errorf("domain exceeds maximum length of 253 characters: length=%d", len(domain))
	}

	lower := strings.ToLower(domain)

	// Reject IP literals (both IPv4 and IPv6)
	ipStr := strings.TrimPrefix(strings.TrimSuffix(lower, "]"), "[")
	if ip := net.ParseIP(ipStr); ip != nil {
		return "", fmt.Errorf("IP literal hostnames are rejected for ingress routes: %q", rawDomain)
	}

	// Reject loopback hostnames
	if lower == "localhost" || strings.HasSuffix(lower, ".localhost") {
		return "", fmt.Errorf("loopback hostnames are rejected for ingress routes: %q", rawDomain)
	}

	// Reject cloud metadata SSRF endpoints
	if lower == "metadata" || lower == "instance-data" ||
		lower == "metadata.google.internal" || strings.HasSuffix(lower, ".metadata.google.internal") ||
		strings.Contains(lower, "169.254") {
		return "", fmt.Errorf("cloud metadata service endpoints are rejected for ingress routes: %q", rawDomain)
	}

	// Wildcard handling: wildcards are strictly allowed only as a leading "*." prefix
	checkDomain := lower
	if strings.HasPrefix(checkDomain, "*.") {
		checkDomain = strings.TrimPrefix(checkDomain, "*.")
		if checkDomain == "" || strings.Contains(checkDomain, "*") {
			return "", fmt.Errorf("malformed wildcard domain: %q", rawDomain)
		}
	} else if strings.Contains(checkDomain, "*") {
		return "", fmt.Errorf("wildcards are only permitted as a leading '*.' prefix: %q", rawDomain)
	}

	labels := strings.Split(checkDomain, ".")
	if len(labels) < 2 {
		return "", fmt.Errorf("hostname must contain at least two labels (e.g. example.com): %q", rawDomain)
	}

	for i, label := range labels {
		if len(label) == 0 {
			return "", fmt.Errorf("hostname contains empty label: %q", rawDomain)
		}
		if len(label) > 63 {
			return "", fmt.Errorf("hostname label %q exceeds maximum length of 63 characters", label)
		}
		if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return "", fmt.Errorf("hostname label %q cannot start or end with a hyphen", label)
		}
		for _, r := range label {
			if !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-') {
				return "", fmt.Errorf("hostname label %q contains invalid character %q (only alphanumeric and hyphens are permitted)", label, r)
			}
		}
		// Last label (TLD) must not be all-numeric (RFC 1123 / RFC 3696)
		if i == len(labels)-1 {
			isAllDigits := true
			for _, r := range label {
				if r < '0' || r > '9' {
					isAllDigits = false
					break
				}
			}
			if isAllDigits {
				return "", fmt.Errorf("top-level domain cannot be all-numeric: %q", label)
			}
		}
	}

	return lower, nil
}

// isInternalDomain checks if the given hostname corresponds to an internal or local domain.
func isInternalDomain(domain string) bool {
	lower := strings.ToLower(domain)
	return strings.HasSuffix(lower, ".local") ||
		strings.HasSuffix(lower, ".internal") ||
		strings.HasSuffix(lower, ".intra") ||
		strings.HasSuffix(lower, ".test") ||
		lower == "localhost"
}

// GenerateSnippet renders a Caddyfile configuration block for the route.
func GenerateSnippet(route *RouteConfig) (string, error) {
	if route == nil {
		return "", fmt.Errorf("route config cannot be nil")
	}

	cleanDomain, err := ValidateHostname(route.Domain)
	if err != nil {
		return "", err
	}

	isWildcard := strings.HasPrefix(cleanDomain, "*.")

	upstream := strings.TrimSpace(route.Upstream)
	if !isWildcard && upstream == "" {
		return "", fmt.Errorf("upstream cannot be empty")
	}
	upstream = strings.TrimPrefix(upstream, "http://")
	upstream = strings.TrimPrefix(upstream, "https://")

	var sb strings.Builder

	tlsMode := strings.ToLower(strings.TrimSpace(route.TLSMode))
	isTLSDisabled := !route.TLS || tlsMode == "none" || tlsMode == "off" || tlsMode == "http"

	if isTLSDisabled {
		sb.WriteString(fmt.Sprintf("http://%s {\n", cleanDomain))
	} else {
		// In Caddy, an unqualified domain name triggers automated TLS.
		sb.WriteString(fmt.Sprintf("%s {\n", cleanDomain))

		isInternal := isInternalDomain(cleanDomain)
		if tlsMode == "internal" || (tlsMode == "" && !route.CustomDomain && isInternal) {
			sb.WriteString("    tls internal\n")
		} else if tlsMode == "origin" {
			certPath := os.Getenv("PRIMECLOUD_ORIGIN_CERT_PATH")
			if certPath == "" {
				certPath = "/etc/primecloud/certs/origin.crt"
			}
			keyPath := os.Getenv("PRIMECLOUD_ORIGIN_KEY_PATH")
			if keyPath == "" {
				keyPath = "/etc/primecloud/certs/origin.key"
			}
			if _, err := os.Stat(certPath); err == nil {
				sb.WriteString(fmt.Sprintf("    tls %s %s\n", certPath, keyPath))
			} else {
				sb.WriteString("    tls internal\n")
			}
		} else {
			// TLSMode == "acme", route.CustomDomain == true, or standard custom domain:
			// Automated ACME TLS: Caddy automatically manages public certificates via Let's Encrypt / ZeroSSL.
			// No origin certificate or explicit tls directive is attached.
		}
	}

	// Request Correlation: Return X-Prime-Request-Id downstream to client (ADR-0004)
	sb.WriteString("    header X-Prime-Request-Id {http.request.uuid}\n")

	// Structured Ingress Access Logging (ADR-0003)
	logPath := route.AccessLogPath
	if logPath == "" {
		logPath = "/var/log/primecloud/caddy-access.log"
	}
	sb.WriteString(fmt.Sprintf("    log {\n        output file %s {\n            roll_size 20mb\n            roll_keep 3\n        }\n        format json {\n            time_format \"iso8601\"\n        }\n    }\n", logPath))

	if isWildcard {
		// Wildcard fallback: unconfigured customer domain does NOT proxy to dead port; returns deterministic 404
		sb.WriteString("    respond \"Application Not Found\" 404\n")
	} else {
		sb.WriteString(fmt.Sprintf("    reverse_proxy %s {\n", upstream))
		sb.WriteString("        header_up Host {host}\n")
		sb.WriteString("        header_up X-Real-IP {remote_host}\n")
		sb.WriteString("        header_up X-Prime-Request-Id {http.request.uuid}\n")

		for k, v := range route.Headers {
			sb.WriteString(fmt.Sprintf("        header_up %s %q\n", k, v))
		}

		if route.HealthCheckPath != "" {
			sb.WriteString(fmt.Sprintf("        health_path %s\n", route.HealthCheckPath))
			sb.WriteString("        health_interval 5s\n")
			sb.WriteString("        health_timeout 2s\n")
		}

		sb.WriteString("    }\n")
	}
	sb.WriteString("}\n")

	return sb.String(), nil
}

// ConfigureRoute validates and writes a Caddy route snippet and reloads.
func (m *Manager) ConfigureRoute(ctx context.Context, route *RouteConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if route == nil {
		return fmt.Errorf("route config cannot be nil")
	}
	cleanDomain, err := ValidateHostname(route.Domain)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(m.configDir, 0755); err != nil {
		return fmt.Errorf("failed to create caddy config dir: %w", err)
	}

	snippet, err := GenerateSnippet(route)
	if err != nil {
		return fmt.Errorf("failed to generate caddy snippet: %w", err)
	}

	if err := ValidateConfig(snippet); err != nil {
		return fmt.Errorf("invalid caddy snippet: %w", err)
	}

	fileName := cleanDomain
	if strings.HasPrefix(fileName, "*.") {
		fileName = "wildcard_" + strings.TrimPrefix(fileName, "*.")
	}
	targetFile := filepath.Join(m.configDir, fmt.Sprintf("%s.caddy", fileName))
	cleanConfigDir := filepath.Clean(m.configDir)
	cleanTargetFile := filepath.Clean(targetFile)
	if !strings.HasPrefix(cleanTargetFile, cleanConfigDir) {
		return fmt.Errorf("path traversal detected: target file %q is outside config directory %q", cleanTargetFile, cleanConfigDir)
	}

	// Backup existing file if present, so failed reload leaves the previous valid configuration untouched
	var existingContent []byte
	hadExisting := false
	if data, err := os.ReadFile(targetFile); err == nil {
		existingContent = data
		hadExisting = true
	}

	tmpFile := targetFile + ".tmp"

	if err := os.WriteFile(tmpFile, []byte(snippet), 0644); err != nil {
		return fmt.Errorf("failed to write temporary caddy config: %w", err)
	}

	if err := os.Rename(tmpFile, targetFile); err != nil {
		_ = os.Remove(tmpFile)
		return fmt.Errorf("failed to commit caddy config file: %w", err)
	}

	m.logger.Info("caddy_route_configured", "domain", cleanDomain, "upstream", route.Upstream, "file", targetFile)

	// Trigger reload
	if err := m.reloadInternal(ctx); err != nil {
		if hadExisting {
			_ = os.WriteFile(targetFile, existingContent, 0644)
			_ = m.reloadInternal(ctx)
		} else {
			_ = os.Remove(targetFile)
		}
		return fmt.Errorf("failed to reload caddy after configuring route for domain %s: %w", cleanDomain, err)
	}

	return nil
}
