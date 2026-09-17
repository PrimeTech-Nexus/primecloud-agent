// Package caddy provides the reverse proxy and ingress driver for Caddy.
package caddy

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
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
		configDir = "/etc/caddy/conf.d"
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

// GenerateSnippet renders a Caddyfile configuration block for the route.
func GenerateSnippet(route *RouteConfig) (string, error) {
	if route == nil {
		return "", fmt.Errorf("route config cannot be nil")
	}
	if strings.TrimSpace(route.Domain) == "" {
		return "", fmt.Errorf("domain cannot be empty")
	}
	if strings.TrimSpace(route.Upstream) == "" {
		return "", fmt.Errorf("upstream cannot be empty")
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%s {\n", route.Domain))
	if !route.TLS {
		sb.WriteString("    tls off\n")
	}
	sb.WriteString(fmt.Sprintf("    reverse_proxy %s {\n", route.Upstream))
	sb.WriteString("        header_up Host {upstream_hostport}\n")
	sb.WriteString("        header_up X-Real-IP {remote_host}\n")
	sb.WriteString("        header_up X-Forwarded-For {remote_host}\n")
	sb.WriteString("        header_up X-Forwarded-Proto {scheme}\n")

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

	targetFile := filepath.Join(m.configDir, fmt.Sprintf("%s.caddy", route.Domain))
	tmpFile := targetFile + ".tmp"

	if err := os.WriteFile(tmpFile, []byte(snippet), 0644); err != nil {
		return fmt.Errorf("failed to write temporary caddy config: %w", err)
	}

	if err := os.Rename(tmpFile, targetFile); err != nil {
		_ = os.Remove(tmpFile)
		return fmt.Errorf("failed to commit caddy config file: %w", err)
	}

	m.logger.Info("caddy_route_configured", "domain", route.Domain, "upstream", route.Upstream, "file", targetFile)

	// Attempt reload (non-fatal if Caddy daemon is offline in dev)
	if err := m.reloadInternal(ctx); err != nil {
		m.logger.Warn("caddy_reload_notice", "domain", route.Domain, "reason", err.Error())
	}

	return nil
}
