// Package caddy provides the reverse proxy and ingress driver for Caddy.
package caddy

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// RemoveRoute removes a route configuration file for the given domain and reloads.
func (m *Manager) RemoveRoute(ctx context.Context, domain string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	domain = strings.TrimSpace(domain)
	domain = strings.TrimPrefix(domain, "http://")
	domain = strings.TrimPrefix(domain, "https://")
	domain = strings.TrimSuffix(domain, "/")
	if domain == "" {
		return fmt.Errorf("domain cannot be empty")
	}

	targetFile := filepath.Join(m.configDir, fmt.Sprintf("%s.caddy", domain))
	cleanConfigDir := filepath.Clean(m.configDir)
	cleanTargetFile := filepath.Clean(targetFile)
	if !strings.HasPrefix(cleanTargetFile, cleanConfigDir) {
		return fmt.Errorf("path traversal detected: target file %q is outside config directory %q", cleanTargetFile, cleanConfigDir)
	}

	if _, err := os.Stat(targetFile); os.IsNotExist(err) {
		m.logger.Warn("caddy_route_not_found_on_remove", "domain", domain)
		return nil
	}

	existingContent, readErr := os.ReadFile(targetFile)
	if readErr != nil {
		return fmt.Errorf("failed to read caddy route file before removal %s: %w", targetFile, readErr)
	}

	if err := os.Remove(targetFile); err != nil {
		return fmt.Errorf("failed to remove caddy route file %s: %w", targetFile, err)
	}

	m.logger.Info("caddy_route_removed", "domain", domain)

	// Trigger reload
	if err := m.reloadInternal(ctx); err != nil {
		_ = os.WriteFile(targetFile, existingContent, 0644)
		_ = m.reloadInternal(ctx)
		return fmt.Errorf("failed to reload caddy after removing route for domain %s: %w", domain, err)
	}

	return nil
}
