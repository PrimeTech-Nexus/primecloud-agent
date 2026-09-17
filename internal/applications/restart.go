// Package applications manages customer application lifecycle, deployment, health verification, and secrets injection.
package applications

import (
	"context"
	"fmt"
	"time"

	"github.com/primecloud/primecloud-agent/internal/runtime"
)

// RestartApplication gracefully stops a container and restarts it.
func RestartApplication(ctx context.Context, rt runtime.ContainerRuntime, containerID string, timeoutSec int) error {
	if rt == nil {
		return fmt.Errorf("container runtime cannot be nil")
	}

	if timeoutSec <= 0 {
		timeoutSec = 10
	}

	// 1. Stop container gracefully
	if err := rt.StopContainer(ctx, containerID, &timeoutSec); err != nil {
		return fmt.Errorf("failed to stop container %s during restart: %w", containerID, err)
	}

	// 2. Start container
	if err := rt.StartContainer(ctx, containerID); err != nil {
		return fmt.Errorf("failed to start container %s during restart: %w", containerID, err)
	}

	// 3. Wait for ready
	if err := WaitForContainerReady(ctx, rt, containerID, 15*time.Second); err != nil {
		return fmt.Errorf("container %s did not become ready after restart: %w", containerID, err)
	}

	return nil
}
