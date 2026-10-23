// Package mysql provides the authoritative MySQL driver for provisioning, credentials, lifecycle, backup, and restore.
package mysql

import (
	"context"
	"fmt"
	"strings"

	"github.com/primecloud/primecloud-agent/internal/runtime"
)

// LifecycleManager controls container state transitions for MySQL instances.
type LifecycleManager struct {
	rt runtime.ContainerRuntime
}

// NewLifecycleManager constructs a LifecycleManager.
func NewLifecycleManager(rt runtime.ContainerRuntime) *LifecycleManager {
	return &LifecycleManager{rt: rt}
}

// Start boots the MySQL container.
func (lm *LifecycleManager) Start(ctx context.Context, containerID string) error {
	if lm.rt == nil {
		return fmt.Errorf("container runtime is nil")
	}
	return lm.rt.StartContainer(ctx, containerID)
}

// Stop halts the MySQL container with graceful shutdown timeout.
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
		return fmt.Errorf("failed to stop mysql container: %w", err)
	}
	if err := lm.rt.StartContainer(ctx, containerID); err != nil {
		return fmt.Errorf("failed to start mysql container: %w", err)
	}
	return nil
}

// Remove deletes the MySQL container and cleans up associated runtime state.
func (lm *LifecycleManager) Remove(ctx context.Context, containerID string) error {
	if lm.rt == nil {
		return fmt.Errorf("container runtime is nil")
	}
	timeout := 5
	_ = lm.rt.StopContainer(ctx, containerID, &timeout)
	err := lm.rt.RemoveContainer(ctx, containerID, true)
	if err != nil && (strings.Contains(err.Error(), "No such container") || strings.Contains(err.Error(), "not found") || strings.Contains(err.Error(), "404")) {
		return nil
	}
	return err
}
