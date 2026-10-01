// Package caddy provides the reverse proxy and ingress driver for Caddy.
package caddy

import (
	"fmt"
	"os/exec"
	"strings"
)

// ValidateConfig validates Caddy configuration syntax.
func ValidateConfig(content string) error {
	trimmed := strings.TrimSpace(content)
	if trimmed == "" {
		return fmt.Errorf("caddy config content is empty")
	}

	// 1. Check brace matching
	openBraces := 0
	for _, ch := range trimmed {
		if ch == '{' {
			openBraces++
		} else if ch == '}' {
			openBraces--
			if openBraces < 0 {
				return fmt.Errorf("mismatched closing brace '}' in caddy config")
			}
		}
	}
	if openBraces != 0 {
		return fmt.Errorf("unclosed brace '{' in caddy config (unclosed count: %d)", openBraces)
	}

	// 2. Check for required reverse_proxy directive
	if !strings.Contains(trimmed, "reverse_proxy") {
		return fmt.Errorf("caddy route config missing reverse_proxy directive")
	}

	// 3. Optional: if caddy CLI binary exists on PATH, run formal syntax validation
	if caddyPath, err := exec.LookPath("caddy"); err == nil && caddyPath != "" {
		cmd := exec.Command(caddyPath, "validate", "--adapter", "caddyfile", "--config", "-")
		cmd.Stdin = strings.NewReader(trimmed)
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("caddy validate failed: %s (%w)", string(out), err)
		}
	}

	return nil
}
