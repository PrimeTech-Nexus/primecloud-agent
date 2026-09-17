// Package postgres provides the authoritative PostgreSQL driver for provisioning, credentials, lifecycle, backup, and restore.
package postgres

import (
	"context"
	"fmt"

	"github.com/primecloud/primecloud-agent/internal/runtime"
)

// LifecycleManager controls container state transitions for PostgreSQL instances.
type LifecycleManager struct {
	rt runtime.ContainerRuntime
}

// NewLifecycleManager constructs a LifecycleManager.
func NewLifecycleManager(rt runtime.ContainerRuntime) *LifecycleManager {
	return &LifecycleManager{rt: rt}
}

// Start boots the PostgreSQL container.
func (lm *LifecycleManager) Start(ctx context.Context, containerID string) error {
	if lm.rt == nil {
		return fmt.Errorf("container runtime is nil")
	}
	return lm.rt.StartContainer(ctx, containerID)
}

// Stop halts the PostgreSQL container with graceful shutdown timeout.
func (lm *LifecycleManager) Stop(ctx context.Context, containerID string, timeoutSec int) error {
	if lm.rt == nil {
		return fmt.Errorf("container runtime is nil")
	}
	return lm.rt.StopContainer(ctx, containerID, &timeoutSec)
}

// Restart performs graceful stop followed by start.
func (lm *LifecycleManager) Restart(ctx context.Context, containerID string, timeoutSec int) error {
	if lm.rt == nil {
		return fmt.Errorf("container runtime is nil")
	}
	if err := lm.rt.StopContainer(ctx, containerID, &timeoutSec); err != nil {
		return fmt.Errorf("failed to stop postgres container: %w", err)
	}
	if err := lm.rt.StartContainer(ctx, containerID); err != nil {
		return fmt.Errorf("failed to start postgres container: %w", err)
	}
	return nil
}

// Remove deletes the PostgreSQL container and clean up associated resources.
func (lm *LifecycleManager) Remove(ctx context.Context, containerID string) error {
	if lm.rt == nil {
		return fmt.Errorf("container runtime is nil")
	}
	timeout := 5
	_ = lm.rt.StopContainer(ctx, containerID, &timeout)
	return lm.rt.RemoveContainer(ctx, containerID, true)
}
