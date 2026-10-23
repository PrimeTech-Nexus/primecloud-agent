// Package postgres provides the authoritative PostgreSQL driver for provisioning, credentials, lifecycle, backup, and restore.
package postgres

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/primecloud/primecloud-agent/internal/runtime"
	"github.com/primecloud/primecloud-agent/internal/vault"
)

// RestoreDatabase restores a PostgreSQL database instance from a backup artifact (alias for RestorePostgres).
func RestoreDatabase(ctx context.Context, rt runtime.ContainerRuntime, resourceID, artifactPath string) error {
	return RestorePostgres(ctx, rt, resourceID, artifactPath)
}

// RestorePostgres restores a PostgreSQL database instance from a backup artifact.
func RestorePostgres(ctx context.Context, rt runtime.ContainerRuntime, resourceID, artifactPath string) error {
	return RestorePostgresWithVault(ctx, rt, nil, "default", resourceID, artifactPath)
}

// RestorePostgresWithVault restores a PostgreSQL instance from an artifact using pg_restore / psql and verifies database health.
func RestorePostgresWithVault(ctx context.Context, rt runtime.ContainerRuntime, vClient *vault.Client, projectID, resourceID, artifactPath string) error {
	if artifactPath == "" {
		return fmt.Errorf("artifact path cannot be empty")
	}
	if resourceID == "" {
		return fmt.Errorf("resource_id cannot be empty")
	}
	if rt == nil {
		return fmt.Errorf("CONTAINER_NOT_FOUND: container runtime is nil")
	}

	fi, err := os.Stat(artifactPath)
	if err != nil {
		return fmt.Errorf("failed to locate backup artifact at %s: %w", artifactPath, err)
	}
	if fi.Size() == 0 {
		return fmt.Errorf("backup artifact at %s is empty", artifactPath)
	}

	// Read first 512 bytes for header identification instead of reading entire artifact into memory
	headerFile, err := os.Open(artifactPath)
	if err != nil {
		return fmt.Errorf("failed to open backup artifact: %w", err)
	}
	header := make([]byte, 512)
	n, err := io.ReadFull(headerFile, header)
	headerFile.Close()
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return fmt.Errorf("failed to read backup artifact header: %w", err)
	}
	if n < 10 {
		return fmt.Errorf("invalid backup artifact format: payload is too small (%d bytes)", n)
	}
	header = header[:n]

	containerName := fmt.Sprintf("pc-pg-%s", resourceID)

	// Verify target container exists and is running; eliminate silent success
	inspect, err := rt.InspectContainer(ctx, containerName)
	if err != nil || inspect == nil {
		// Attempt to start if container exists but inspect failed, or fail closed
		startErr := rt.StartContainer(ctx, containerName)
		if startErr != nil {
			return fmt.Errorf("CONTAINER_NOT_FOUND: target postgres container %s not found: %w", containerName, err)
		}
		inspect, err = rt.InspectContainer(ctx, containerName)
		if err != nil || inspect == nil || !inspect.Running {
			return fmt.Errorf("CONTAINER_NOT_FOUND: target postgres container %s not found or failed to run: %v", containerName, err)
		}
	} else if !inspect.Running {
		// Container exists but is stopped; start it
		if startErr := rt.StartContainer(ctx, containerName); startErr != nil {
			return fmt.Errorf("CONTAINER_STOPPED: target postgres container %s is stopped and failed to start: %w", containerName, startErr)
		}
		inspect, err = rt.InspectContainer(ctx, containerName)
		if err != nil || inspect == nil || !inspect.Running {
			return fmt.Errorf("CONTAINER_STOPPED: target postgres container %s is not running after start attempt", containerName)
		}
	}

	creds, credErr := resolvePostgresCredentials(ctx, vClient, projectID, resourceID)
	if credErr != nil {
		return fmt.Errorf("failed to resolve postgres credentials: %w", credErr)
	}

	env := []string{
		fmt.Sprintf("PGPASSWORD=%s", creds.Password),
	}

	// Open file reader for stdin streaming
	fileReader, err := os.Open(artifactPath)
	if err != nil {
		return fmt.Errorf("failed opening artifact file for restore: %w", err)
	}
	defer fileReader.Close()

	var cmd []string
	if bytes.HasPrefix(header, []byte("PGDMP")) || (len(header) >= 262 && string(header[257:262]) == "ustar") {
		// PostgreSQL custom dump format or tar archive -> use pg_restore
		cmd = []string{
			"pg_restore",
			"-U", creds.Username,
			"-d", creds.Database,
			"--clean",
			"--if-exists",
		}
	} else {
		// SQL plaintext script -> use psql
		cmd = []string{
			"psql",
			"-U", creds.Username,
			"-d", creds.Database,
		}
	}

	_, stderr, exitCode, execErr := rt.ExecContainer(ctx, containerName, cmd, env, fileReader)
	if execErr != nil {
		return fmt.Errorf("failed executing database restore on %s: %w (stderr: %s)", containerName, execErr, string(stderr))
	}
	// In pg_restore, exit code 0 is clean success; exit code 1 indicates non-fatal warnings
	if exitCode > 1 {
		return fmt.Errorf("database restore command exited with error code %d: %s", exitCode, strings.TrimSpace(string(stderr)))
	}

	// Post-restore verification query: confirm database is responding and queryable
	verifyCmd := []string{
		"psql",
		"-U", creds.Username,
		"-d", creds.Database,
		"-c", "SELECT 1;",
	}
	_, vStderr, vCode, vErr := rt.ExecContainer(ctx, containerName, verifyCmd, env, nil)
	if vErr != nil || vCode != 0 {
		return fmt.Errorf("restore verification failed on %s (exit %d): %s", containerName, vCode, strings.TrimSpace(string(vStderr)))
	}

	return nil
}
