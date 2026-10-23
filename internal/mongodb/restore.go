// Package mongodb provides the authoritative MongoDB driver for provisioning, rs0 replica set bootstrap, credentials, lifecycle, backup, and restore.
package mongodb

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/primecloud/primecloud-agent/internal/runtime"
	"github.com/primecloud/primecloud-agent/internal/vault"
)

// RestoreMongoDB restores a MongoDB database instance from a backup artifact.
func RestoreMongoDB(ctx context.Context, rt runtime.ContainerRuntime, resourceID, artifactPath string) error {
	return RestoreMongoDBWithVault(ctx, rt, nil, "default", resourceID, artifactPath)
}

// RestoreMongoDBWithVault restores a MongoDB instance from a compressed archive using mongorestore --archive --gzip --drop and verifies database health.
func RestoreMongoDBWithVault(ctx context.Context, rt runtime.ContainerRuntime, vClient *vault.Client, projectID, resourceID, artifactPath string) error {
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

	containerName := fmt.Sprintf("pc-mg-%s", resourceID)

	inspect, err := rt.InspectContainer(ctx, containerName)
	if err != nil || inspect == nil {
		startErr := rt.StartContainer(ctx, containerName)
		if startErr != nil {
			return fmt.Errorf("CONTAINER_NOT_FOUND: target mongodb container %s not found: %w", containerName, err)
		}
		inspect, err = rt.InspectContainer(ctx, containerName)
		if err != nil || inspect == nil || !inspect.Running {
			return fmt.Errorf("CONTAINER_NOT_FOUND: target mongodb container %s not found or failed to run: %v", containerName, err)
		}
	} else if !inspect.Running {
		if startErr := rt.StartContainer(ctx, containerName); startErr != nil {
			return fmt.Errorf("CONTAINER_STOPPED: target mongodb container %s is stopped and failed to start: %w", containerName, startErr)
		}
		inspect, err = rt.InspectContainer(ctx, containerName)
		if err != nil || inspect == nil || !inspect.Running {
			return fmt.Errorf("CONTAINER_STOPPED: target mongodb container %s is not running after start attempt", containerName)
		}
	}

	creds, credErr := resolveMongoDBCredentials(ctx, vClient, projectID, resourceID)
	if credErr != nil {
		return fmt.Errorf("failed to resolve mongodb credentials: %w", credErr)
	}

	authUser := creds.Username
	authPass := creds.Password
	authDB := creds.Database
	if creds.AdminPassword != "" {
		authUser = creds.AdminUsername
		authPass = creds.AdminPassword
		authDB = "admin"
	}

	fileReader, err := os.Open(artifactPath)
	if err != nil {
		return fmt.Errorf("failed opening artifact file for restore: %w", err)
	}
	defer fileReader.Close()

	cmd := []string{
		"mongorestore",
		"--host", "127.0.0.1",
		"--port", "27017",
		"--username", authUser,
		"--password", authPass,
		"--authenticationDatabase", authDB,
		"--archive",
		"--gzip",
		"--drop",
	}

	_, stderr, exitCode, execErr := rt.ExecContainer(ctx, containerName, cmd, nil, fileReader)
	if execErr != nil {
		return fmt.Errorf("failed executing mongorestore on %s: %w (stderr: %s)", containerName, execErr, string(stderr))
	}
	if exitCode != 0 {
		return fmt.Errorf("mongorestore command exited with error code %d: %s", exitCode, strings.TrimSpace(string(stderr)))
	}

	// Post-restore verification query: confirm database is responding and queryable
	verifyCmd := []string{
		"mongosh",
		"--quiet",
		"-u", authUser,
		"-p", authPass,
		"--authenticationDatabase", authDB,
		"--eval", "db.adminCommand({ ping: 1 }).ok",
	}
	_, vStderr, vCode, vErr := rt.ExecContainer(ctx, containerName, verifyCmd, nil, nil)
	if vErr != nil || vCode != 0 {
		return fmt.Errorf("restore verification failed on %s (exit %d): %s", containerName, vCode, strings.TrimSpace(string(vStderr)))
	}

	return nil
}
