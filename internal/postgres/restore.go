// Package postgres provides the authoritative PostgreSQL driver for provisioning, credentials, lifecycle, backup, and restore.
package postgres

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

// RestoreDatabase restores a PostgreSQL database instance from a backup artifact (alias for RestorePostgres).
func RestoreDatabase(ctx context.Context, rt runtime.ContainerRuntime, resourceID, artifactPath string, targetOpts ...string) error {
	return RestorePostgres(ctx, rt, resourceID, artifactPath, targetOpts...)
}

// RestorePostgres restores a PostgreSQL database instance from a backup artifact.
func RestorePostgres(ctx context.Context, rt runtime.ContainerRuntime, resourceID, artifactPath string, targetOpts ...string) error {
	return RestorePostgresWithVault(ctx, rt, nil, "default", resourceID, artifactPath, targetOpts...)
}

// RestorePostgresWithVault restores a PostgreSQL instance from an artifact using pg_restore / psql and verifies database health.
// If targetContainerName is provided, it is targeted instead of the default pc-pg-<resourceID>.
// If targetContainerName is a sandbox/drill container (e.g. pc_drill_tgt_*), it is provisioned if not existing.
func RestorePostgresWithVault(ctx context.Context, rt runtime.ContainerRuntime, vClient *vault.Client, projectID, resourceID, artifactPath string, targetOpts ...string) error {
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

	targetContainerName := ""
	if len(targetOpts) > 0 && targetOpts[0] != "" {
		targetContainerName = targetOpts[0]
	}
	if targetContainerName == "" {
		targetContainerName = fmt.Sprintf("pc-pg-%s", resourceID)
	}
	containerName := targetContainerName

	creds, credErr := resolvePostgresCredentials(ctx, vClient, projectID, resourceID)
	if credErr != nil {
		return fmt.Errorf("failed to resolve postgres credentials: %w", credErr)
	}

	isSandbox := strings.HasPrefix(containerName, "pc_drill_tgt_") || strings.Contains(containerName, "drill") || strings.Contains(containerName, "sandbox")

	if isSandbox {
		inspect, err := rt.InspectContainer(ctx, containerName)
		if err != nil || inspect == nil {
			// Sandbox container does not exist in runtime: provision an isolated PostgreSQL sandbox container
			tempVolDir := filepath.Join(os.TempDir(), "primecloud-drill-pg", containerName)
			if mkErr := os.MkdirAll(tempVolDir, 0700); mkErr != nil {
				return fmt.Errorf("failed to create postgres sandbox volume directory: %w", mkErr)
			}

			cfg := &runtime.ContainerConfig{
				Name:  containerName,
				Image: "postgres:16-alpine",
				Env: map[string]string{
					"POSTGRES_USER":     creds.Username,
					"POSTGRES_PASSWORD": creds.Password,
					"POSTGRES_DB":       creds.Database,
					"PGDATA":            "/var/lib/postgresql/data/pgdata",
				},
				Binds: []string{
					fmt.Sprintf("%s:/var/lib/postgresql/data:rw", tempVolDir),
				},
				HealthCheckCmd: []string{
					"CMD-SHELL",
					fmt.Sprintf("pg_isready -U %s -d %s", creds.Username, creds.Database),
				},
				HealthInterval: 2 * time.Second,
				HealthTimeout:  2 * time.Second,
				HealthRetries:  5,
				Labels: map[string]string{
					"primecloud.resource_id": resourceID,
					"primecloud.drill":       "true",
					"primecloud.managed":     "true",
				},
				WorkloadType: runtime.WorkloadTypeManagedPostgres,
			}
			limits := runtime.DefaultResourceLimits()
			profile := runtime.DefaultHardenedProfile()
			profile.User = "999:999"

			cid, cErr := rt.CreateContainer(ctx, cfg, limits, profile)
			if cErr != nil {
				return fmt.Errorf("failed to create isolated postgres sandbox container %s: %w", containerName, cErr)
			}
			if sErr := rt.StartContainer(ctx, cid); sErr != nil {
				_ = rt.RemoveContainer(ctx, cid, true)
				return fmt.Errorf("failed to start isolated postgres sandbox container %s: %w", containerName, sErr)
			}
		} else if !inspect.Running {
			// Container exists from prior attempt / retry: start it idempotently (AC-1.11)
			if startErr := rt.StartContainer(ctx, containerName); startErr != nil {
				return fmt.Errorf("CONTAINER_STOPPED: sandbox postgres container %s is stopped and failed to start: %w", containerName, startErr)
			}
		}

		// Wait for readiness (pg_isready)
		ready := false
		deadline := time.Now().Add(30 * time.Second)
		for time.Now().Before(deadline) {
			chkCmd := []string{"pg_isready", "-U", creds.Username, "-d", creds.Database}
			_, _, code, chkErr := rt.ExecContainer(ctx, containerName, chkCmd, nil, nil)
			if chkErr == nil && code == 0 {
				ready = true
				break
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(300 * time.Millisecond):
			}
		}
		if !ready {
			return fmt.Errorf("SANDBOX_READINESS_TIMEOUT: isolated postgres sandbox container %s failed pg_isready health check", containerName)
		}
	} else {
		// Non-sandbox container (e.g. in-place overwrite): verify target container exists and is running
		inspect, err := rt.InspectContainer(ctx, containerName)
		if err != nil || inspect == nil {
			startErr := rt.StartContainer(ctx, containerName)
			if startErr != nil {
				return fmt.Errorf("CONTAINER_NOT_FOUND: target postgres container %s not found: %w", containerName, err)
			}
			inspect, err = rt.InspectContainer(ctx, containerName)
			if err != nil || inspect == nil || !inspect.Running {
				return fmt.Errorf("CONTAINER_NOT_FOUND: target postgres container %s not found or failed to run: %v", containerName, err)
			}
		} else if !inspect.Running {
			if startErr := rt.StartContainer(ctx, containerName); startErr != nil {
				return fmt.Errorf("CONTAINER_STOPPED: target postgres container %s is stopped and failed to start: %w", containerName, startErr)
			}
			inspect, err = rt.InspectContainer(ctx, containerName)
			if err != nil || inspect == nil || !inspect.Running {
				return fmt.Errorf("CONTAINER_STOPPED: target postgres container %s is not running after start attempt", containerName)
			}
		}
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
