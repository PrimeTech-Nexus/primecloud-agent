// Package applications manages customer application lifecycle, deployment, health verification, and secrets injection.
package applications

import (
	"context"
	"fmt"

	"github.com/primecloud/primecloud-agent/internal/runtime"
)

// RemoveApplication stops and removes a container.
func RemoveApplication(ctx context.Context, rt runtime.ContainerRuntime, containerID string, force bool) error {
	if rt == nil {
		return fmt.Errorf("container runtime cannot be nil")
	}

	timeout := 5
	_ = rt.StopContainer(ctx, containerID, &timeout)

	if err := rt.RemoveContainer(ctx, containerID, force); err != nil {
		return fmt.Errorf("failed to remove container %s: %w", containerID, err)
	}

	return nil
}
