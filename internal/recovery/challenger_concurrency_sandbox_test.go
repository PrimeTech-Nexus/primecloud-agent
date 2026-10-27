package recovery_test

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/primecloud/primecloud-agent/internal/postgres"
	"github.com/primecloud/primecloud-agent/internal/recovery"
	"github.com/primecloud/primecloud-agent/internal/runtime"
)

// challengerTrackingRuntime records every container runtime interaction with thread safety.
type challengerTrackingRuntime struct {
	mu             sync.Mutex
	containers     map[string]*runtime.ContainerInspect
	createdConfigs []*runtime.ContainerConfig
	startedIDs     []string
	stoppedIDs     []string
	inspectedIDs   []string
	removedIDs     []string
	execCalls      []struct {
		ContainerID string
		Cmd         []string
	}
}

func newChallengerTrackingRuntime() *challengerTrackingRuntime {
	return &challengerTrackingRuntime{
		containers: make(map[string]*runtime.ContainerInspect),
	}
}

func (c *challengerTrackingRuntime) PullImage(ctx context.Context, ref string) error { return nil }
func (c *challengerTrackingRuntime) PullImageWithAuth(ctx context.Context, ref, auth string) error {
	return nil
}

func (c *challengerTrackingRuntime) CreateContainer(ctx context.Context, cfg *runtime.ContainerConfig, l *runtime.ResourceLimits, p *runtime.HardenedIsolationProfile) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.containers[cfg.Name]; exists {
		return "", fmt.Errorf("CONFLICT: container name %q is already in use by container %q", cfg.Name, cfg.Name)
	}
	c.createdConfigs = append(c.createdConfigs, cfg)
	c.containers[cfg.Name] = &runtime.ContainerInspect{
		ID:      cfg.Name,
		Name:    cfg.Name,
		Running: false,
		State:   "created",
	}
	return cfg.Name, nil
}

func (c *challengerTrackingRuntime) StartContainer(ctx context.Context, id string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.startedIDs = append(c.startedIDs, id)
	if ci, ok := c.containers[id]; ok {
		ci.Running = true
		ci.State = "running"
		return nil
	}
	c.containers[id] = &runtime.ContainerInspect{
		ID:      id,
		Name:    id,
		Running: true,
		State:   "running",
	}
	return nil
}

func (c *challengerTrackingRuntime) StopContainer(ctx context.Context, id string, timeout *int) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.stoppedIDs = append(c.stoppedIDs, id)
	if ci, ok := c.containers[id]; ok {
		ci.Running = false
		ci.State = "stopped"
	}
	return nil
}

func (c *challengerTrackingRuntime) RemoveContainer(ctx context.Context, id string, force bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.removedIDs = append(c.removedIDs, id)
	delete(c.containers, id)
	return nil
}

func (c *challengerTrackingRuntime) InspectContainer(ctx context.Context, id string) (*runtime.ContainerInspect, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.inspectedIDs = append(c.inspectedIDs, id)
	if ci, ok := c.containers[id]; ok {
		return ci, nil
	}
	return nil, fmt.Errorf("CONTAINER_NOT_FOUND: container %s does not exist", id)
}

func (c *challengerTrackingRuntime) ListContainers(ctx context.Context, all bool) ([]runtime.ContainerSummary, error) {
	return nil, nil
}
func (c *challengerTrackingRuntime) GetContainerLogs(ctx context.Context, containerID string) (io.ReadCloser, error) {
	return nil, nil
}
func (c *challengerTrackingRuntime) GetContainerStats(ctx context.Context, containerID string) (io.ReadCloser, error) {
	return nil, nil
}
func (c *challengerTrackingRuntime) Ping(ctx context.Context) error { return nil }
func (c *challengerTrackingRuntime) Close() error                   { return nil }

func (c *challengerTrackingRuntime) ExecContainer(ctx context.Context, containerID string, cmd []string, env []string, stdin io.Reader) ([]byte, []byte, int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.execCalls = append(c.execCalls, struct {
		ContainerID string
		Cmd         []string
	}{
		ContainerID: containerID,
		Cmd:         cmd,
	})

	cmdStr := strings.Join(cmd, " ")
	if strings.Contains(cmdStr, "pg_isready") {
		return []byte("accepting connections"), nil, 0, nil
	}
	if strings.Contains(cmdStr, "SELECT 1;") {
		return []byte("1"), nil, 0, nil
	}
	return []byte("ok"), nil, 0, nil
}

// =============================================================================
// Challenge 1: Source Container & Volumes Are 100% Untouched During NEW_INSTANCE
// =============================================================================

func TestChallenger_SandboxIsolation_SourceContainerAndVolumesUntouched(t *testing.T) {
	ctx := context.Background()
	rt := newChallengerTrackingRuntime()

	tmpDir := t.TempDir()
	dumpPath := filepath.Join(tmpDir, "challenge_test.dump")
	_ = os.WriteFile(dumpPath, []byte("PGDMP\x01\x02\x03challenge postgres dump content"), 0600)

	sourceResID := "db-source-production-99"
	sourceContainer := fmt.Sprintf("pc-pg-%s", sourceResID)
	sandboxTarget := "pc_drill_tgt_challenger_001"

	// Live source container active in runtime
	rt.containers[sourceContainer] = &runtime.ContainerInspect{
		ID:      sourceContainer,
		Name:    sourceContainer,
		Running: true,
		State:   "running",
	}

	// Execute restore targeting isolated sandbox
	err := postgres.RestorePostgresWithVault(ctx, rt, nil, "default", sourceResID, dumpPath, sandboxTarget)
	if err != nil {
		t.Fatalf("unexpected RestorePostgresWithVault error: %v", err)
	}

	// 1. Strict assertion: source container was NEVER inspected
	for _, id := range rt.inspectedIDs {
		if id == sourceContainer {
			t.Fatalf("ADVERSARIAL CHALLENGE FAILED (AC-1.2): source container %s was inspected!", sourceContainer)
		}
	}

	// 2. Strict assertion: source container was NEVER started, stopped, or removed
	for _, id := range rt.startedIDs {
		if id == sourceContainer {
			t.Fatalf("ADVERSARIAL CHALLENGE FAILED (AC-1.2): source container %s was started!", sourceContainer)
		}
	}
	for _, id := range rt.stoppedIDs {
		if id == sourceContainer {
			t.Fatalf("ADVERSARIAL CHALLENGE FAILED (AC-1.2): source container %s was stopped!", sourceContainer)
		}
	}
	for _, id := range rt.removedIDs {
		if id == sourceContainer {
			t.Fatalf("ADVERSARIAL CHALLENGE FAILED (AC-1.2): source container %s was removed!", sourceContainer)
		}
	}

	// 3. Strict assertion: source container had ZERO commands executed against it
	for _, call := range rt.execCalls {
		if call.ContainerID == sourceContainer {
			t.Fatalf("ADVERSARIAL CHALLENGE FAILED (AC-1.2): command executed on source container %s: %+v", sourceContainer, call.Cmd)
		}
	}

	// 4. Strict assertion: sandbox volume bind does NOT mount or touch source directory
	var sandboxConfig *runtime.ContainerConfig
	for _, cfg := range rt.createdConfigs {
		if cfg.Name == sandboxTarget {
			sandboxConfig = cfg
			break
		}
	}
	if sandboxConfig == nil {
		t.Fatalf("sandbox container config not found for %s", sandboxTarget)
	}
	for _, b := range sandboxConfig.Binds {
		if strings.Contains(b, sourceResID) || strings.Contains(b, sourceContainer) {
			t.Fatalf("ADVERSARIAL CHALLENGE FAILED (AC-1.2): sandbox volume bind contains source reference: %s", b)
		}
		if !strings.Contains(b, "primecloud-drill-pg") {
			t.Fatalf("expected sandbox volume bind in primecloud-drill-pg, got %s", b)
		}
	}
}

// =============================================================================
// Challenge 2: Sandbox Target Identity Divergence & Fail-Closed Validation
// =============================================================================

func TestChallenger_SandboxTargetIdentity_StrictInequalityAndFailClosed(t *testing.T) {
	sourceResID := "source-prod-007"

	adversarialCases := []struct {
		name      string
		cfg       recovery.RestoreSafetyConfig
		expectErr bool
		errSubstr string
	}{
		{
			name: "Attempt source resource ID as target container in NEW_INSTANCE",
			cfg: recovery.RestoreSafetyConfig{
				TargetMode:      "NEW_INSTANCE",
				TargetContainer: sourceResID,
				ResourceID:      sourceResID,
			},
			expectErr: true,
			errSubstr: "TARGET_CONTAINER_INVALID",
		},
		{
			name: "Attempt pc-pg-<source> as target container in NEW_INSTANCE",
			cfg: recovery.RestoreSafetyConfig{
				TargetMode:      "NEW_INSTANCE",
				TargetContainer: fmt.Sprintf("pc-pg-%s", sourceResID),
				ResourceID:      sourceResID,
			},
			expectErr: true,
			errSubstr: "TARGET_CONTAINER_INVALID",
		},
		{
			name: "Attempt pc-my-<source> as target container in NEW_INSTANCE",
			cfg: recovery.RestoreSafetyConfig{
				TargetMode:      "NEW_INSTANCE",
				TargetContainer: fmt.Sprintf("pc-my-%s", sourceResID),
				ResourceID:      sourceResID,
			},
			expectErr: true,
			errSubstr: "TARGET_CONTAINER_INVALID",
		},
		{
			name: "Attempt pc-mg-<source> as target container in NEW_INSTANCE",
			cfg: recovery.RestoreSafetyConfig{
				TargetMode:      "NEW_INSTANCE",
				TargetContainer: fmt.Sprintf("pc-mg-%s", sourceResID),
				ResourceID:      sourceResID,
			},
			expectErr: true,
			errSubstr: "TARGET_CONTAINER_INVALID",
		},
		{
			name: "Attempt pc-vk-<source> as target container in NEW_INSTANCE",
			cfg: recovery.RestoreSafetyConfig{
				TargetMode:      "NEW_INSTANCE",
				TargetContainer: fmt.Sprintf("pc-vk-%s", sourceResID),
				ResourceID:      sourceResID,
			},
			expectErr: true,
			errSubstr: "TARGET_CONTAINER_INVALID",
		},
		{
			name: "Empty target container in NEW_INSTANCE",
			cfg: recovery.RestoreSafetyConfig{
				TargetMode:      "NEW_INSTANCE",
				TargetContainer: "",
				ResourceID:      sourceResID,
			},
			expectErr: true,
			errSubstr: "TARGET_CONTAINER_REQUIRED",
		},
		{
			name: "Whitespace target container in NEW_INSTANCE",
			cfg: recovery.RestoreSafetyConfig{
				TargetMode:      "NEW_INSTANCE",
				TargetContainer: "   \t  ",
				ResourceID:      sourceResID,
			},
			expectErr: true,
			errSubstr: "TARGET_CONTAINER_REQUIRED",
		},
		{
			name: "Valid distinct sandbox container succeeds",
			cfg: recovery.RestoreSafetyConfig{
				TargetMode:      "NEW_INSTANCE",
				TargetContainer: "pc_drill_tgt_sandbox_uuid_123",
				ResourceID:      sourceResID,
			},
			expectErr: false,
		},
	}

	for _, tc := range adversarialCases {
		t.Run(tc.name, func(t *testing.T) {
			err := recovery.ValidateRestoreSafety(tc.cfg)
			if tc.expectErr {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tc.errSubstr)
				}
				if !strings.Contains(err.Error(), tc.errSubstr) {
					t.Fatalf("expected error containing %q, got: %v", tc.errSubstr, err)
				}
			} else {
				if err != nil {
					t.Fatalf("expected success, got error: %v", err)
				}
			}
		})
	}
}

// =============================================================================
// Challenge 3: Idempotent Retry & Duplicate Container Safety (AC-1.11)
// =============================================================================

func TestChallenger_IdempotentRetry_DuplicateContainerDoesNotCrash(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	dumpPath := filepath.Join(tmpDir, "retry_challenge.dump")
	_ = os.WriteFile(dumpPath, []byte("PGDMP\x01\x02\x03challenge retry data"), 0600)

	sourceResID := "source-retry-55"
	sandboxTarget := "pc_drill_tgt_retry_002"

	t.Run("Retry when container already exists and is stopped", func(t *testing.T) {
		rt := newChallengerTrackingRuntime()
		// Pre-populate container as existed (e.g. from failed attempt 1)
		rt.containers[sandboxTarget] = &runtime.ContainerInspect{
			ID:      sandboxTarget,
			Name:    sandboxTarget,
			Running: false,
			State:   "exited",
		}

		err := postgres.RestorePostgresWithVault(ctx, rt, nil, "default", sourceResID, dumpPath, sandboxTarget)
		if err != nil {
			t.Fatalf("retry failed: %v", err)
		}

		// Must NOT call CreateContainer because it would fail with Docker conflict error!
		if len(rt.createdConfigs) != 0 {
			t.Fatalf("ADVERSARIAL CHALLENGE FAILED: CreateContainer called on existing container (%d configs)", len(rt.createdConfigs))
		}

		// Must call StartContainer to revive it
		var started bool
		for _, sID := range rt.startedIDs {
			if sID == sandboxTarget {
				started = true
				break
			}
		}
		if !started {
			t.Fatalf("expected sandbox container %s to be started on retry", sandboxTarget)
		}
	})

	t.Run("Retry when container already exists and is running", func(t *testing.T) {
		rt := newChallengerTrackingRuntime()
		// Pre-populate container as ALREADY RUNNING
		rt.containers[sandboxTarget] = &runtime.ContainerInspect{
			ID:      sandboxTarget,
			Name:    sandboxTarget,
			Running: true,
			State:   "running",
		}

		err := postgres.RestorePostgresWithVault(ctx, rt, nil, "default", sourceResID, dumpPath, sandboxTarget)
		if err != nil {
			t.Fatalf("retry on running container failed: %v", err)
		}

		// Must NOT call CreateContainer
		if len(rt.createdConfigs) != 0 {
			t.Fatalf("ADVERSARIAL CHALLENGE FAILED: CreateContainer called on running container")
		}
	})
}
