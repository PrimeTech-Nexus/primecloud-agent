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

// BackupResult describes a generated Valkey backup artifact.
type BackupResult struct {
	BackupID     string    `json:"backup_id"`
	ResourceID   string    `json:"resource_id"`
	ArtifactPath string    `json:"artifact_path"`
	SizeBytes    int64     `json:"size_bytes"`
	CreatedAt    time.Time `json:"created_at"`
}

// resolveValkeyAuthToken fetches auth token from Vault or inspects container arguments.
func resolveValkeyAuthToken(ctx context.Context, vClient *vault.Client, projectID, resourceID string) (string, error) {
	if projectID == "" {
		projectID = "default"
	}

	if vClient != nil {
		tenantPath := fmt.Sprintf("secret/data/primecloud/tenants/%s/keyvalue/%s", projectID, resourceID)
		secret, err := vClient.ReadSecret(ctx, tenantPath)
		if err == nil && secret != nil {
			if token, ok := secret["auth_token"].(string); ok && token != "" {
				return token, nil
			}
			if pw, ok := secret["password"].(string); ok && pw != "" {
				return pw, nil
			}
		}

		compatPath := fmt.Sprintf("primecloud/resources/valkey/%s", resourceID)
		secret, err = vClient.ReadSecret(ctx, compatPath)
		if err == nil && secret != nil {
			if token, ok := secret["auth_token"].(string); ok && token != "" {
				return token, nil
			}
			if pw, ok := secret["password"].(string); ok && pw != "" {
				return pw, nil
			}
		}
	}

	return "", nil
}

// BackupValkey triggers an RDB snapshot and writes the backup artifact.
func BackupValkey(ctx context.Context, rt runtime.ContainerRuntime, resourceID, backupDir string) (*BackupResult, error) {
	return BackupValkeyWithVault(ctx, rt, nil, "", "default", resourceID, backupDir)
}

// BackupValkeyWithVault triggers a real BGSAVE, waits for persistence completion, extracts the RDB, and writes the artifact.
func BackupValkeyWithVault(ctx context.Context, rt runtime.ContainerRuntime, vClient *vault.Client, baseResDir, projectID, resourceID, backupDir string) (*BackupResult, error) {
	if resourceID == "" {
		return nil, fmt.Errorf("resource_id cannot be empty for backup")
	}

	if backupDir == "" {
		backupDir = filepath.Join(os.TempDir(), "primecloud-backups", "valkey", resourceID)
	}
	if err := os.MkdirAll(backupDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create backup directory: %w", err)
	}

	backupID := fmt.Sprintf("vk-bk-%d", time.Now().UnixNano())
	artifactFile := filepath.Join(backupDir, fmt.Sprintf("%s.rdb", backupID))

	containerName := fmt.Sprintf("pc-vk-%s", resourceID)
	authToken, _ := resolveValkeyAuthToken(ctx, vClient, projectID, resourceID)

	var rdbBytes []byte

	// 1. If runtime is available, check for a running Valkey container
	if rt != nil {
		inspect, err := rt.InspectContainer(ctx, containerName)
		if err == nil && inspect != nil && inspect.Running {
			// Trigger BGSAVE
			bgsaveCmd := []string{"valkey-cli"}
			if authToken != "" {
				bgsaveCmd = append(bgsaveCmd, "-a", authToken)
			}
			bgsaveCmd = append(bgsaveCmd, "BGSAVE")

			stdout, stderr, exitCode, execErr := rt.ExecContainer(ctx, containerName, bgsaveCmd, nil, nil)
			outStr := string(stdout) + string(stderr)
			if execErr != nil && !strings.Contains(outStr, "Background saving already in progress") {
				// Try redis-cli fallback
				bgsaveCmd[0] = "redis-cli"
				stdout, stderr, exitCode, execErr = rt.ExecContainer(ctx, containerName, bgsaveCmd, nil, nil)
				outStr = string(stdout) + string(stderr)
			}

			if execErr != nil && !strings.Contains(outStr, "Background saving already in progress") {
				return nil, fmt.Errorf("failed executing BGSAVE on %s: %w (%s)", containerName, execErr, outStr)
			}
			if exitCode != 0 && !strings.Contains(outStr, "Background saving already in progress") {
				return nil, fmt.Errorf("BGSAVE failed with code %d: %s", exitCode, outStr)
			}

			// 2. Poll until persistence completes
			pollDeadline := time.Now().Add(30 * time.Second)
			saved := false

			for time.Now().Before(pollDeadline) {
				infoCmd := []string{bgsaveCmd[0]}
				if authToken != "" {
					infoCmd = append(infoCmd, "-a", authToken)
				}
				infoCmd = append(infoCmd, "INFO", "persistence")

				iStdout, _, _, iErr := rt.ExecContainer(ctx, containerName, infoCmd, nil, nil)
				if iErr == nil {
					infoStr := string(iStdout)
					if strings.Contains(infoStr, "rdb_bgsave_in_progress:0") {
						if strings.Contains(infoStr, "rdb_last_bgsave_status:ok") {
							saved = true
							break
						}
					}
				}
				time.Sleep(200 * time.Millisecond)
			}

			if !saved {
				return nil, fmt.Errorf("timed out waiting for Valkey BGSAVE to complete on %s", containerName)
			}

			// 3. Extract dump.rdb
			// Check host volume path first if available
			if baseResDir != "" {
				hostRdbPath := filepath.Join(baseResDir, "valkey", resourceID, "dump.rdb")
				if data, rErr := os.ReadFile(hostRdbPath); rErr == nil && len(data) > 0 {
					rdbBytes = data
				}
			}

			// If host path wasn't read, read directly from container /data/dump.rdb
			if len(rdbBytes) == 0 {
				catCmd := []string{"cat", "/data/dump.rdb"}
				cStdout, cStderr, cCode, cErr := rt.ExecContainer(ctx, containerName, catCmd, nil, nil)
				if cErr == nil && cCode == 0 && len(cStdout) > 0 {
					rdbBytes = cStdout
				} else {
					return nil, fmt.Errorf("failed reading RDB from /data/dump.rdb: %w (stderr: %s)", cErr, string(cStderr))
				}
			}
		}
	}

	if len(rdbBytes) == 0 {
		return nil, fmt.Errorf("failed to extract RDB from container or host volume")
	}

	// Verify RDB header magic number
	if !bytes.HasPrefix(rdbBytes, []byte("REDIS")) {
		return nil, fmt.Errorf("extracted Valkey artifact does not have valid REDIS header")
	}

	if err := os.WriteFile(artifactFile, rdbBytes, 0600); err != nil {
		return nil, fmt.Errorf("failed writing valkey rdb file: %w", err)
	}

	fi, err := os.Stat(artifactFile)
	if err != nil {
		return nil, err
	}

	return &BackupResult{
		BackupID:     backupID,
		ResourceID:   resourceID,
		ArtifactPath: artifactFile,
		SizeBytes:    fi.Size(),
		CreatedAt:    time.Now().UTC(),
	}, nil
}
