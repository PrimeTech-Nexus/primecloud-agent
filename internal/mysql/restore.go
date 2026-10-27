// Package mysql provides the authoritative MySQL driver for provisioning, credentials, lifecycle, backup, and restore.
package mysql

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/primecloud/primecloud-agent/internal/runtime"
	"github.com/primecloud/primecloud-agent/internal/vault"
)

// RestoreMySQL restores a MySQL database instance from a backup artifact.
func RestoreMySQL(ctx context.Context, rt runtime.ContainerRuntime, resourceID, artifactPath string, targetOpts ...string) error {
	return RestoreMySQLWithVault(ctx, rt, nil, "default", resourceID, artifactPath, targetOpts...)
}

// RestoreMySQLWithVault restores a MySQL instance from an artifact using mysql stdin streaming and verifies database health.
func RestoreMySQLWithVault(ctx context.Context, rt runtime.ContainerRuntime, vClient *vault.Client, projectID, resourceID, artifactPath string, targetOpts ...string) error {
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

	containerName := fmt.Sprintf("pc-my-%s", resourceID)
	if len(targetOpts) > 0 && targetOpts[0] != "" {
		containerName = targetOpts[0]
	}

	inspect, err := rt.InspectContainer(ctx, containerName)
	if err != nil || inspect == nil {
		startErr := rt.StartContainer(ctx, containerName)
		if startErr != nil {
			return fmt.Errorf("CONTAINER_NOT_FOUND: target mysql container %s not found: %w", containerName, err)
		}
		inspect, err = rt.InspectContainer(ctx, containerName)
		if err != nil || inspect == nil || !inspect.Running {
			return fmt.Errorf("CONTAINER_NOT_FOUND: target mysql container %s not found or failed to run: %v", containerName, err)
		}
	} else if !inspect.Running {
		if startErr := rt.StartContainer(ctx, containerName); startErr != nil {
			return fmt.Errorf("CONTAINER_STOPPED: target mysql container %s is stopped and failed to start: %w", containerName, startErr)
		}
		inspect, err = rt.InspectContainer(ctx, containerName)
		if err != nil || inspect == nil || !inspect.Running {
			return fmt.Errorf("CONTAINER_STOPPED: target mysql container %s is not running after start attempt", containerName)
		}
	}

	creds, credErr := resolveMySQLCredentials(ctx, vClient, projectID, resourceID)
	if credErr != nil {
		return fmt.Errorf("failed to resolve mysql credentials: %w", credErr)
	}

	authUser := creds.Username
	authPass := creds.Password
	if creds.RootPassword != "" {
		authUser = "root"
		authPass = creds.RootPassword
	}

	env := []string{
		fmt.Sprintf("MYSQL_PWD=%s", authPass),
	}

	fileReader, err := os.Open(artifactPath)
	if err != nil {
		return fmt.Errorf("failed opening artifact file for restore: %w", err)
	}
	defer fileReader.Close()

	cmd := []string{
		"mysql",
		"-h", "127.0.0.1",
		"-u", authUser,
		creds.Database,
	}

	_, stderr, exitCode, execErr := rt.ExecContainer(ctx, containerName, cmd, env, fileReader)
	if execErr != nil {
		return fmt.Errorf("failed executing mysql restore on %s: %w (stderr: %s)", containerName, execErr, string(stderr))
	}
	if exitCode != 0 {
		return fmt.Errorf("mysql restore command exited with error code %d: %s", exitCode, strings.TrimSpace(string(stderr)))
	}

	// Post-restore verification query: confirm database is responding and queryable
	verifyCmd := []string{
		"mysql",
		"-h", "127.0.0.1",
		"-u", authUser,
		"-e", "SELECT 1;",
		creds.Database,
	}
	_, vStderr, vCode, vErr := rt.ExecContainer(ctx, containerName, verifyCmd, env, nil)
	if vErr != nil || vCode != 0 {
		return fmt.Errorf("restore verification failed on %s (exit %d): %s", containerName, vCode, strings.TrimSpace(string(vStderr)))
	}

	return nil
}
