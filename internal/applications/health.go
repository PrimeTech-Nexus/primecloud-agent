// Package applications manages customer application lifecycle, deployment, health verification, and secrets injection.
package applications

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/primecloud/primecloud-agent/internal/logs"
	"github.com/primecloud/primecloud-agent/internal/runtime"
)

var secretRedactionPattern = regexp.MustCompile(`(?i)(password|secret|token|api_key|access_token|refresh_token|client_secret)\s*[:=]\s*[^\s"']+`)

// SanitizeCrashLogs scrubs secret patterns and bounds output to 4096 bytes.
func SanitizeCrashLogs(raw string) string {
	scrubbed := secretRedactionPattern.ReplaceAllString(raw, "$1=***REDACTED***")
	if len(scrubbed) > 4096 {
		scrubbed = scrubbed[len(scrubbed)-4096:]
	}
	return scrubbed
}

// extractContainerCrashLogs fetches the last log lines from an exited container for diagnostics.
func extractContainerCrashLogs(ctx context.Context, rt runtime.ContainerRuntime, containerID string) string {
	if rt == nil {
		return ""
	}
	reader, err := rt.GetContainerLogs(ctx, containerID)
	if err != nil || reader == nil {
		return ""
	}
	defer reader.Close()

	items, err := logs.DemuxDockerLogStream(reader, "stdout")
	if err != nil || len(items) == 0 {
		return ""
	}

	var lines []string
	start := 0
	if len(items) > 50 {
		start = len(items) - 50
	}
	for i := start; i < len(items); i++ {
		msg := strings.TrimSpace(items[i].Message)
		if msg != "" {
			lines = append(lines, msg)
		}
	}
	if len(lines) == 0 {
		return ""
	}
	return SanitizeCrashLogs(strings.Join(lines, "\n"))
}

// WaitForContainerReady polls container status until it is running and healthy or timeout occurs.
func WaitForContainerReady(ctx context.Context, rt runtime.ContainerRuntime, containerID string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		inspect, err := rt.InspectContainer(ctx, containerID)
		if err == nil && inspect != nil {
			if inspect.Running {
				// If container defines Docker healthcheck, wait until HEALTHY
				if inspect.Health != "" {
					if inspect.Health == "healthy" {
						return nil
					}
					if inspect.Health == "unhealthy" {
						return fmt.Errorf("container reported unhealthy status")
					}
				} else {
					// Running without specific healthcheck
					return nil
				}
			} else if inspect.State == "exited" || inspect.State == "dead" {
				crashLogs := extractContainerCrashLogs(ctx, rt, containerID)
				if crashLogs != "" {
					return fmt.Errorf("container exited prematurely with code %d:\n%s", inspect.ExitCode, crashLogs)
				}
				return fmt.Errorf("container exited prematurely with code %d", inspect.ExitCode)
			}
		}

		time.Sleep(500 * time.Millisecond)
	}

	return fmt.Errorf("timeout waiting for container %s to become ready", containerID)
}

// ProbeHTTP executes an HTTP GET probe against the container's exposed port.
func ProbeHTTP(ctx context.Context, url string, expectedStatus int) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false, err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	if expectedStatus == 0 {
		return resp.StatusCode >= 200 && resp.StatusCode < 400, nil
	}

	return resp.StatusCode == expectedStatus, nil
}
