// Package valkey provides the authoritative Valkey/Redis driver for provisioning, credentials, lifecycle, backup, and restore.
package valkey

import (
	"bytes"
	"context"
	"fmt"
	"io"
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

	var hostRdbPath string

	// 1. If runtime is available, check for a running Valkey container and trigger BGSAVE
	if rt != nil {
		inspect, err := rt.InspectContainer(ctx, containerName)
		if err != nil {
			return nil, fmt.Errorf("failed inspecting valkey container %s: %w", containerName, err)
		}
		if inspect == nil || !inspect.Running {
			return nil, fmt.Errorf("valkey container %s is not running", containerName)
		}

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
	}

	// 3. Locate dump.rdb from host volume (eliminating in-memory cat buffer)
	searchDirs := []string{}
	if baseResDir != "" {
		searchDirs = append(searchDirs, baseResDir)
	}
	searchDirs = append(searchDirs, "/opt/primecloud/resources", filepath.Join(os.TempDir(), "primecloud-resources"))
	for _, dir := range searchDirs {
		candidate := filepath.Join(dir, "valkey", resourceID, "dump.rdb")
		if fi, err := os.Stat(candidate); err == nil && fi.Size() > 0 {
			hostRdbPath = candidate
			break
		}
	}

	if hostRdbPath == "" {
		return nil, fmt.Errorf("failed to extract RDB: no snapshot found on host volume for %s", resourceID)
	}

	// Verify RDB header magic number by reading only the first 5 bytes
	srcFile, err := os.Open(hostRdbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open extracted RDB file: %w", err)
	}
	defer srcFile.Close()

	header := make([]byte, 5)
	if _, err := io.ReadFull(srcFile, header); err != nil || !bytes.Equal(header, []byte("REDIS")) {
		return nil, fmt.Errorf("extracted Valkey artifact does not have valid REDIS header")
	}

	// Rewind to beginning for full streaming copy
	if _, err := srcFile.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("failed seeking RDB stream: %w", err)
	}

	// Stream directly to artifactFile via io.Copy
	dstFile, err := os.OpenFile(artifactFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return nil, fmt.Errorf("failed creating valkey rdb artifact file: %w", err)
	}
	defer dstFile.Close()

	copiedBytes, err := io.Copy(dstFile, srcFile)
	if err != nil {
		return nil, fmt.Errorf("failed streaming valkey rdb snapshot: %w", err)
	}
	_ = copiedBytes

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
