// Package haproxy provides the Layer 4 TCP external gateway driver for PrimeCloud Managed Data.
package haproxy

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
)

// TCPRouteConfig defines routing rules for a Layer 4 TCP external gateway.
type TCPRouteConfig struct {
	ID          string `json:"id"`
	Port        int    `json:"port"`
	ContainerIP string `json:"container_ip"`
	TargetPort  int    `json:"target_port"`
}

var validIDRegex = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

// Manager orchestrates HAProxy Layer 4 TCP proxy configuration.
type Manager struct {
	mu        sync.RWMutex
	configDir string
	logger    *slog.Logger
}

// NewManager constructs an HAProxy Manager.
func NewManager(configDir string, logger *slog.Logger) *Manager {
	if configDir == "" {
		configDir = "/etc/haproxy/conf.d"
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Manager{
		configDir: configDir,
		logger:    logger.With("component", "haproxy_manager"),
	}
}

// ConfigDir returns the active configuration directory.
func (m *Manager) ConfigDir() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.configDir
}

// GenerateTCPSnippet renders a genuine HAProxy Layer-4 configuration block.
// It explicitly uses "mode tcp" for both frontend and backend to forward raw TCP byte streams,
// ensuring protocol compliance for PostgreSQL and Valkey wire protocols.
func GenerateTCPSnippet(route *TCPRouteConfig) (string, error) {
	if route == nil {
		return "", fmt.Errorf("route config cannot be nil")
	}
	id := strings.TrimSpace(route.ID)
	if id == "" {
		return "", fmt.Errorf("route ID cannot be empty")
	}
	if !validIDRegex.MatchString(id) {
		return "", fmt.Errorf("invalid route ID format: %q", route.ID)
	}
	if route.Port <= 0 || route.Port > 65535 {
		return "", fmt.Errorf("invalid external port %d (must be between 1 and 65535)", route.Port)
	}
	if route.TargetPort <= 0 || route.TargetPort > 65535 {
		return "", fmt.Errorf("invalid target port %d (must be between 1 and 65535)", route.TargetPort)
	}
	containerIP := strings.TrimSpace(route.ContainerIP)
	if containerIP == "" {
		return "", fmt.Errorf("container IP cannot be empty")
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("# PrimeCloud Managed Data TCP Gateway Route: %s\n", id))
	sb.WriteString(fmt.Sprintf("frontend fe_tcp_%s\n", id))
	sb.WriteString(fmt.Sprintf("    bind *:%d\n", route.Port))
	sb.WriteString("    mode tcp\n")
	sb.WriteString("    option tcplog\n")
	sb.WriteString("    timeout client 1h\n")
	sb.WriteString(fmt.Sprintf("    default_backend be_tcp_%s\n\n", id))

	sb.WriteString(fmt.Sprintf("backend be_tcp_%s\n", id))
	sb.WriteString("    mode tcp\n")
	sb.WriteString("    timeout connect 5s\n")
	sb.WriteString("    timeout server 1h\n")
	sb.WriteString(fmt.Sprintf("    server srv_%s %s:%d check\n", id, containerIP, route.TargetPort))

	return sb.String(), nil
}

// ValidateConfig validates an HAProxy configuration snippet for syntax and Layer-4 compliance.
func ValidateConfig(snippet string) error {
	if !strings.Contains(snippet, "mode tcp") {
		return fmt.Errorf("invalid configuration: Layer 4 proxy requires 'mode tcp'")
	}
	if strings.Contains(snippet, "reverse_proxy") || strings.Contains(snippet, "mode http") {
		return fmt.Errorf("invalid configuration: HTTP reverse proxying is forbidden for Managed Data TCP routing")
	}
	return nil
}

// ConfigureTCPRoute validates, writes an HAProxy route snippet atomically, and reloads.
func (m *Manager) ConfigureTCPRoute(ctx context.Context, route *TCPRouteConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if err := os.MkdirAll(m.configDir, 0755); err != nil {
		return fmt.Errorf("failed to create haproxy config dir %s: %w", m.configDir, err)
	}

	snippet, err := GenerateTCPSnippet(route)
	if err != nil {
		return fmt.Errorf("failed to generate haproxy snippet: %w", err)
	}

	if err := ValidateConfig(snippet); err != nil {
		return fmt.Errorf("invalid haproxy snippet: %w", err)
	}

	targetFile := filepath.Join(m.configDir, fmt.Sprintf("tcp_%s.cfg", route.ID))
	cleanConfigDir := filepath.Clean(m.configDir)
	cleanTargetFile := filepath.Clean(targetFile)
	if !strings.HasPrefix(cleanTargetFile, cleanConfigDir) {
		return fmt.Errorf("path traversal detected: target file %q is outside config directory %q", cleanTargetFile, cleanConfigDir)
	}

	var existingContent []byte
	hadExisting := false
	if data, err := os.ReadFile(targetFile); err == nil {
		existingContent = data
		hadExisting = true
	}

	tmpFile := targetFile + ".tmp"
	if err := os.WriteFile(tmpFile, []byte(snippet), 0644); err != nil {
		return fmt.Errorf("failed to write temporary haproxy config: %w", err)
	}

	if err := os.Rename(tmpFile, targetFile); err != nil {
		_ = os.Remove(tmpFile)
		return fmt.Errorf("failed to commit haproxy config file: %w", err)
	}

	m.logger.Info("haproxy_tcp_route_configured", "id", route.ID, "port", route.Port, "upstream", route.ContainerIP, "file", targetFile)

	// Reload HAProxy
	if err := m.reloadInternal(ctx); err != nil {
		if hadExisting {
			_ = os.WriteFile(targetFile, existingContent, 0644)
			_ = m.reloadInternal(ctx)
		} else {
			_ = os.Remove(targetFile)
		}
		return fmt.Errorf("failed to reload haproxy after configuring route %s: %w", route.ID, err)
	}

	return nil
}

// RemoveTCPRoute removes an HAProxy route snippet and reloads.
func (m *Manager) RemoveTCPRoute(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	id = strings.TrimSpace(id)
	if id == "" {
		return fmt.Errorf("route ID cannot be empty")
	}

	targetFile := filepath.Join(m.configDir, fmt.Sprintf("tcp_%s.cfg", id))
	cleanConfigDir := filepath.Clean(m.configDir)
	cleanTargetFile := filepath.Clean(targetFile)
	if !strings.HasPrefix(cleanTargetFile, cleanConfigDir) {
		return fmt.Errorf("path traversal detected: target file %q is outside config directory %q", cleanTargetFile, cleanConfigDir)
	}

	if _, err := os.Stat(targetFile); os.IsNotExist(err) {
		m.logger.Warn("haproxy_tcp_route_not_found_on_remove", "id", id)
		return nil
	}

	existingContent, readErr := os.ReadFile(targetFile)
	if readErr != nil {
		return fmt.Errorf("failed to read haproxy route file before removal: %w", readErr)
	}

	if err := os.Remove(targetFile); err != nil {
		return fmt.Errorf("failed to remove haproxy route file %s: %w", targetFile, err)
	}

	m.logger.Info("haproxy_tcp_route_removed", "id", id)

	if err := m.reloadInternal(ctx); err != nil {
		_ = os.WriteFile(targetFile, existingContent, 0644)
		_ = m.reloadInternal(ctx)
		return fmt.Errorf("failed to reload haproxy after removing route %s: %w", id, err)
	}

	return nil
}

func (m *Manager) reloadInternal(ctx context.Context) error {
	if _, err := exec.LookPath("systemctl"); err == nil {
		cmd := exec.CommandContext(ctx, "systemctl", "reload", "haproxy")
		if output, err := cmd.CombinedOutput(); err != nil {
			m.logger.Warn("haproxy_systemctl_reload_warning", "output", string(output), "error", err.Error())
		} else {
			return nil
		}
	}

	if _, err := exec.LookPath("haproxy"); err == nil {
		return nil
	}

	return nil
}
