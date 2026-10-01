// Package caddy provides the reverse proxy and ingress driver for Caddy.
package caddy

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
)

// Reload triggers a dynamic reload of Caddy configurations.
func (m *Manager) Reload(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.reloadInternal(ctx)
}

func (m *Manager) reloadInternal(ctx context.Context) error {
	caddyConfigFile := "/etc/caddy/Caddyfile"

	// Strategy 1: CLI invocation (caddy reload --config /etc/caddy/Caddyfile)
	if caddyPath, err := exec.LookPath("caddy"); err == nil && caddyPath != "" {
		args := []string{"reload"}
		if _, statErr := os.Stat(caddyConfigFile); statErr == nil {
			args = append(args, "--config", caddyConfigFile)
		}
		if m.adminURL != "" {
			args = append(args, "--address", m.adminURL)
		}
		cmd := exec.CommandContext(ctx, caddyPath, args...)
		if out, err := cmd.CombinedOutput(); err == nil {
			m.logger.Info("caddy_reload_successful_via_cli", "config", caddyConfigFile)
			return nil
		} else {
			m.logger.Warn("caddy_cli_reload_failed", "error", err.Error(), "output", string(out))
		}
	}

	// Strategy 2: systemctl reload caddy
	if sysctlPath, err := exec.LookPath("systemctl"); err == nil && sysctlPath != "" {
		cmd := exec.CommandContext(ctx, sysctlPath, "reload", "caddy")
		if out, err := cmd.CombinedOutput(); err == nil {
			m.logger.Info("caddy_reload_successful_via_systemctl")
			return nil
		} else {
			m.logger.Debug("caddy_systemctl_reload_failed", "error", err.Error(), "output", string(out))
		}
	}

	// Strategy 3: Check if Caddy Admin API is responding or trigger reload via /load
	if m.adminURL != "" {
		reqPost, err := http.NewRequestWithContext(ctx, http.MethodPost, fmt.Sprintf("%s/load", m.adminURL), strings.NewReader("{}"))
		if err == nil {
			reqPost.Header.Set("Content-Type", "application/json")
			resp, getErr := m.httpClient.Do(reqPost)
			if getErr == nil {
				defer resp.Body.Close()
				if resp.StatusCode >= 200 && resp.StatusCode < 300 {
					m.logger.Info("caddy_admin_api_responsive", "admin_url", m.adminURL)
					return nil
				}
			}
		}

		reqGet, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%s/config/", m.adminURL), nil)
		if err == nil {
			resp, getErr := m.httpClient.Do(reqGet)
			if getErr == nil {
				defer resp.Body.Close()
				if resp.StatusCode >= 200 && resp.StatusCode < 300 {
					m.logger.Info("caddy_admin_api_responsive", "admin_url", m.adminURL)
					return nil
				}
			}
		}
	}

	return fmt.Errorf("caddy reload failed: neither caddy CLI nor systemctl succeeded and admin API unreachable at %s", m.adminURL)
}
