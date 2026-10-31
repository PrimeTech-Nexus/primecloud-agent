// Package applications manages customer application lifecycle, deployment, health verification, and secrets injection.
package applications

import (
	"context"
	"fmt"
	"time"

	"github.com/primecloud/primecloud-agent/internal/runtime"
)

// StopApplication gracefully stops an application container preserving volumes and state.
func StopApplication(ctx context.Context, rt runtime.ContainerRuntime, containerID string, timeoutSec int) error {
	if rt == nil {
		return fmt.Errorf("container runtime cannot be nil")
	}

	if timeoutSec <= 0 {
		timeoutSec = 10
	}

	if err := rt.StopContainer(ctx, containerID, &timeoutSec); err != nil {
		return fmt.Errorf("failed to stop container %s gracefully: %w", containerID, err)
	}

	return nil
}

// StartApplication starts a stopped application container and waits for ready status.
func StartApplication(ctx context.Context, rt runtime.ContainerRuntime, containerID string) error {
	if rt == nil {
		return fmt.Errorf("container runtime cannot be nil")
	}

	if err := rt.StartContainer(ctx, containerID); err != nil {
		return fmt.Errorf("failed to start container %s: %w", containerID, err)
	}

	// Wait for ready
	if err := WaitForContainerReady(ctx, rt, containerID, 15*time.Second); err != nil {
		return fmt.Errorf("container %s did not become ready after start: %w", containerID, err)
	}

	return nil
}
