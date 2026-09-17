// Package caddy provides the reverse proxy and ingress driver for Caddy.
package caddy

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"os/exec"
)

// Reload triggers a dynamic reload of Caddy configurations.
func (m *Manager) Reload(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.reloadInternal(ctx)
}

func (m *Manager) reloadInternal(ctx context.Context) error {
	// Strategy 1: Caddy HTTP Admin API (/load)
	url := fmt.Sprintf("%s/load", m.adminURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewBuffer([]byte("{}")))
	if err == nil {
		req.Header.Set("Content-Type", "application/json")
		resp, postErr := m.httpClient.Do(req)
		if postErr == nil {
			defer resp.Body.Close()
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				m.logger.Info("caddy_reload_successful_via_api", "admin_url", m.adminURL)
				return nil
			}
		}
	}

	// Strategy 2: CLI invocation (caddy reload)
	if caddyPath, err := exec.LookPath("caddy"); err == nil && caddyPath != "" {
		cmd := exec.CommandContext(ctx, caddyPath, "reload", "--address", m.adminURL)
		if out, err := cmd.CombinedOutput(); err == nil {
			m.logger.Info("caddy_reload_successful_via_cli")
			return nil
		} else {
			m.logger.Debug("caddy_cli_reload_failed", "error", err.Error(), "output", string(out))
		}
	}

	return fmt.Errorf("caddy admin API unreachable at %s", m.adminURL)
}
