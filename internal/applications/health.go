// Package applications manages customer application lifecycle, deployment, health verification, and secrets injection.
package applications

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/primecloud/primecloud-agent/internal/runtime"
)

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
		expectedStatus = http.StatusOK
	}

	return resp.StatusCode == expectedStatus, nil
}
