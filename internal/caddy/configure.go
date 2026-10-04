// Package caddy provides the reverse proxy and ingress driver for Caddy.
package caddy

import (
	"context"
	"fmt"
	"log/slog"
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
	Headers         map[string]string `json:"headers,omitempty"`
	HealthCheckPath string            `json:"health_check_path,omitempty"`
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

// GenerateSnippet renders a Caddyfile configuration block for the route.
func GenerateSnippet(route *RouteConfig) (string, error) {
	if route == nil {
		return "", fmt.Errorf("route config cannot be nil")
	}
	domain := strings.TrimSpace(route.Domain)
	if domain == "" {
		return "", fmt.Errorf("domain cannot be empty")
	}
	domain = strings.TrimPrefix(domain, "http://")
	domain = strings.TrimPrefix(domain, "https://")
	domain = strings.TrimSuffix(domain, "/")
	if !validDomainRegex.MatchString(domain) && domain != "localhost" && !strings.HasSuffix(domain, ".local") {
		return "", fmt.Errorf("invalid domain format: %q", route.Domain)
	}

	upstream := strings.TrimSpace(route.Upstream)
	if upstream == "" {
		return "", fmt.Errorf("upstream cannot be empty")
	}
	upstream = strings.TrimPrefix(upstream, "http://")
	upstream = strings.TrimPrefix(upstream, "https://")

	var sb strings.Builder
	if route.TLS {
		// In Caddy, an unqualified domain name (or https://domain) triggers standard TLS.
		// Never combine http:// and https:// in a block that specifies tls directives.
		sb.WriteString(fmt.Sprintf("%s {\n", domain))
		certPath := "/etc/primecloud/certs/origin.crt"
		keyPath := "/etc/primecloud/certs/origin.key"
		if _, err := os.Stat(certPath); err == nil {
			sb.WriteString(fmt.Sprintf("    tls %s %s\n", certPath, keyPath))
		} else {
			sb.WriteString("    tls internal\n")
		}
	} else {
		sb.WriteString(fmt.Sprintf("http://%s {\n", domain))
	}

	sb.WriteString(fmt.Sprintf("    reverse_proxy %s {\n", upstream))
	sb.WriteString("        header_up Host {host}\n")
	sb.WriteString("        header_up X-Real-IP {remote_host}\n")

	for k, v := range route.Headers {
		sb.WriteString(fmt.Sprintf("        header_up %s %q\n", k, v))
	}

	if route.HealthCheckPath != "" {
		sb.WriteString(fmt.Sprintf("        health_path %s\n", route.HealthCheckPath))
		sb.WriteString("        health_interval 5s\n")
		sb.WriteString("        health_timeout 2s\n")
	}

	sb.WriteString("    }\n")
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
	cleanDomain := strings.TrimSpace(route.Domain)
	cleanDomain = strings.TrimPrefix(cleanDomain, "http://")
	cleanDomain = strings.TrimPrefix(cleanDomain, "https://")
	cleanDomain = strings.TrimSuffix(cleanDomain, "/")
	if cleanDomain == "" {
		return fmt.Errorf("domain cannot be empty")
	}
	if !validDomainRegex.MatchString(cleanDomain) && cleanDomain != "localhost" && !strings.HasSuffix(cleanDomain, ".local") {
		return fmt.Errorf("invalid domain format: %q", route.Domain)
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

	targetFile := filepath.Join(m.configDir, fmt.Sprintf("%s.caddy", cleanDomain))
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

// TCPRouteConfig defines routing rules for a TCP external gateway.
type TCPRouteConfig struct {
	ID          string `json:"id"`
	Port        int    `json:"port"`
	ContainerIP string `json:"container_ip"`
	TargetPort  int    `json:"target_port"`
}

// GenerateTCPSnippet renders a Caddyfile snippet for a TCP proxy.
func GenerateTCPSnippet(route *TCPRouteConfig) (string, error) {
	if route == nil {
		return "", fmt.Errorf("route config cannot be nil")
	}
	if route.Port <= 0 || route.TargetPort <= 0 {
		return "", fmt.Errorf("invalid ports")
	}
	if route.ContainerIP == "" {
		return "", fmt.Errorf("container IP cannot be empty")
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf(":%d {\n", route.Port))
	sb.WriteString(fmt.Sprintf("    reverse_proxy %s:%d\n", route.ContainerIP, route.TargetPort))
	sb.WriteString("}\n")

	return sb.String(), nil
}

// ConfigureTCPRoute validates and writes a Caddy route snippet and reloads.
func (m *Manager) ConfigureTCPRoute(ctx context.Context, route *TCPRouteConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if err := os.MkdirAll(m.configDir, 0755); err != nil {
		return fmt.Errorf("failed to create caddy config dir: %w", err)
	}

	snippet, err := GenerateTCPSnippet(route)
	if err != nil {
		return fmt.Errorf("failed to generate caddy snippet: %w", err)
	}

	targetFile := filepath.Join(m.configDir, fmt.Sprintf("tcp_%s.caddy", route.ID))
	tmpFile := targetFile + ".tmp"

	if err := os.WriteFile(tmpFile, []byte(snippet), 0644); err != nil {
		return fmt.Errorf("failed to write temporary caddy config: %w", err)
	}

	if err := os.Rename(tmpFile, targetFile); err != nil {
		_ = os.Remove(tmpFile)
		return fmt.Errorf("failed to commit caddy config file: %w", err)
	}

	m.logger.Info("caddy_tcp_route_configured", "id", route.ID, "port", route.Port, "upstream", route.ContainerIP, "file", targetFile)

	// Attempt reload
	if err := m.reloadInternal(ctx); err != nil {
		m.logger.Warn("caddy_reload_notice", "id", route.ID, "reason", err.Error())
	}

	return nil
}
