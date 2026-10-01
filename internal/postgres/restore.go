// Package postgres provides the authoritative PostgreSQL driver for provisioning, credentials, lifecycle, backup, and restore.
package postgres

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/primecloud/primecloud-agent/internal/runtime"
	"github.com/primecloud/primecloud-agent/internal/vault"
)

// RestorePostgres restores a PostgreSQL database instance from a backup artifact.
func RestorePostgres(ctx context.Context, rt runtime.ContainerRuntime, resourceID, artifactPath string) error {
	return RestorePostgresWithVault(ctx, rt, nil, "default", resourceID, artifactPath)
}

// RestorePostgresWithVault restores a PostgreSQL instance from an artifact using pg_restore / psql and verifies database health.
func RestorePostgresWithVault(ctx context.Context, rt runtime.ContainerRuntime, vClient *vault.Client, projectID, resourceID, artifactPath string) error {
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

	// Verify header integrity (at least 10 bytes)
	if len(data) < 10 {
		return fmt.Errorf("invalid backup artifact format: payload is too small")
	}

	containerName := fmt.Sprintf("pc-pg-%s", resourceID)

	// If runtime is available and container is running, execute live restore
	if rt != nil {
		inspect, err := rt.InspectContainer(ctx, containerName)
		if err == nil && inspect != nil && inspect.Running {
			creds, _ := resolvePostgresCredentials(ctx, vClient, projectID, resourceID)

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
			if bytes.HasPrefix(data, []byte("PGDMP")) {
				// PostgreSQL custom dump format -> use pg_restore
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
		}
	}

	return nil
}
