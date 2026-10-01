// Package valkey provides the authoritative Valkey/Redis driver for provisioning, credentials, lifecycle, backup, and restore.
package valkey

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/primecloud/primecloud-agent/internal/runtime"
	"github.com/primecloud/primecloud-agent/internal/vault"
)

// RestoreValkey restores a Valkey instance state from a backup RDB artifact.
func RestoreValkey(ctx context.Context, rt runtime.ContainerRuntime, resourceID, artifactPath string) error {
	return RestoreValkeyWithVault(ctx, rt, nil, "", "default", resourceID, artifactPath)
}

// RestoreValkeyWithVault restores a Valkey instance from an RDB artifact, cleanly replacing state and verifying recovery.
func RestoreValkeyWithVault(ctx context.Context, rt runtime.ContainerRuntime, vClient *vault.Client, baseResDir, projectID, resourceID, artifactPath string) error {
	if artifactPath == "" {
		return fmt.Errorf("artifact path cannot be empty")
	}

	fi, err := os.Stat(artifactPath)
	if err != nil {
		return fmt.Errorf("failed to locate backup artifact at %s: %w", artifactPath, err)
	}
	if fi.Size() == 0 {
		return fmt.Errorf("backup artifact at %s is empty", artifactPath)
	}

	data, err := os.ReadFile(artifactPath)
	if err != nil {
		return fmt.Errorf("failed to read backup artifact: %w", err)
	}

	// Verify RDB header magic number
	if !bytes.HasPrefix(data, []byte("REDIS")) {
		return fmt.Errorf("invalid valkey rdb artifact format: missing REDIS header")
	}

	containerName := fmt.Sprintf("pc-vk-%s", resourceID)

	// If runtime is available and container exists, execute live RDB restore
	if rt != nil {
		inspect, err := rt.InspectContainer(ctx, containerName)
		if err == nil && inspect != nil {
			authToken, _ := resolveValkeyAuthToken(ctx, vClient, projectID, resourceID)

			// 1. Safely stop Valkey container so persistence is quiescent
			timeout := 5
			if inspect.Running {
				if stopErr := rt.StopContainer(ctx, containerName, &timeout); stopErr != nil {
					return fmt.Errorf("failed stopping valkey container %s before restore: %w", containerName, stopErr)
				}
			}

			// 2. Replace dump.rdb in host volume directory
			if baseResDir != "" {
				volumeDir := filepath.Join(baseResDir, "valkey", resourceID)
				_ = os.MkdirAll(volumeDir, 0700)

				targetRdb := filepath.Join(volumeDir, "dump.rdb")
				if wErr := os.WriteFile(targetRdb, data, 0600); wErr != nil {
					return fmt.Errorf("failed writing restored dump.rdb to %s: %w", targetRdb, wErr)
				}

				// Purge stale AOF files so Valkey prioritizes restored RDB
				_ = os.Remove(filepath.Join(volumeDir, "appendonly.aof"))
				_ = os.RemoveAll(filepath.Join(volumeDir, "appendonlydir"))
			}

			// 3. Start Valkey container
			if startErr := rt.StartContainer(ctx, containerName); startErr != nil {
				return fmt.Errorf("failed starting valkey container %s after restore: %w", containerName, startErr)
			}

			// 4. Wait for PING -> PONG to verify service recovery
			ready := false
			deadline := time.Now().Add(20 * time.Second)

			for time.Now().Before(deadline) {
				pingCmd := []string{"valkey-cli"}
				if authToken != "" {
					pingCmd = append(pingCmd, "-a", authToken)
				}
				pingCmd = append(pingCmd, "ping")

				pStdout, _, pCode, pErr := rt.ExecContainer(ctx, containerName, pingCmd, nil, nil)
				if pErr == nil && pCode == 0 && strings.Contains(strings.ToUpper(string(pStdout)), "PONG") {
					ready = true
					break
				}

				// Try redis-cli fallback
				pingCmd[0] = "redis-cli"
				pStdout, _, pCode, pErr = rt.ExecContainer(ctx, containerName, pingCmd, nil, nil)
				if pErr == nil && pCode == 0 && strings.Contains(strings.ToUpper(string(pStdout)), "PONG") {
					ready = true
					break
				}

				time.Sleep(200 * time.Millisecond)
			}

			if !ready {
				return fmt.Errorf("valkey container %s did not respond to PING after restore", containerName)
			}
		}
	}

	return nil
}
