// Package mysql provides the authoritative MySQL driver for provisioning, credentials, lifecycle, backup, and restore.
package mysql

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/primecloud/primecloud-agent/internal/runtime"
	"github.com/primecloud/primecloud-agent/internal/vault"
)

// BackupResult describes a generated MySQL backup artifact.
type BackupResult struct {
	BackupID     string    `json:"backup_id"`
	ResourceID   string    `json:"resource_id"`
	ArtifactPath string    `json:"artifact_path"`
	SizeBytes    int64     `json:"size_bytes"`
	CreatedAt    time.Time `json:"created_at"`
}

// resolveMySQLCredentials fetches credentials from Vault or derives defaults from resourceID.
func resolveMySQLCredentials(ctx context.Context, vClient *vault.Client, projectID, resourceID string) (*Credentials, error) {
	if projectID == "" {
		projectID = "default"
	}

	if vClient != nil {
		tenantPath := fmt.Sprintf("secret/data/primecloud/tenants/%s/mysql/%s", projectID, resourceID)
		secret, err := vClient.ReadSecret(ctx, tenantPath)
		if err == nil && secret != nil {
			user, _ := secret["username"].(string)
			pw, _ := secret["password"].(string)
			db, _ := secret["database"].(string)
			rootPw, _ := secret["root_password"].(string)
			if user != "" && pw != "" && db != "" {
				return &Credentials{
					Username:     user,
					Password:     pw,
					Database:     db,
					RootPassword: rootPw,
					Port:         DefaultPort,
				}, nil
			}
		}

		// Fallback to legacy path
		compatPath := fmt.Sprintf("primecloud/resources/mysql/%s", resourceID)
		secret, err = vClient.ReadSecret(ctx, compatPath)
		if err == nil && secret != nil {
			user, _ := secret["username"].(string)
			pw, _ := secret["password"].(string)
			db, _ := secret["database"].(string)
			rootPw, _ := secret["root_password"].(string)
			if user != "" && pw != "" && db != "" {
				return &Credentials{
					Username:     user,
					Password:     pw,
					Database:     db,
					RootPassword: rootPw,
					Port:         DefaultPort,
				}, nil
			}
		}
	}

	sanitizedID := stringsFilterAlpha(resourceID)
	if len(sanitizedID) > 8 {
		sanitizedID = sanitizedID[:8]
	}
	return &Credentials{
		Username:     fmt.Sprintf("pc_user_%s", sanitizedID),
		Password:     "password",
		Database:     fmt.Sprintf("pc_db_%s", sanitizedID),
		RootPassword: "root_password",
		Port:         DefaultPort,
	}, nil
}

// BackupMySQL creates a logical backup dump from the running MySQL instance.
func BackupMySQL(ctx context.Context, rt runtime.ContainerRuntime, resourceID, backupDir string) (*BackupResult, error) {
	return BackupMySQLWithVault(ctx, rt, nil, "default", resourceID, backupDir)
}

// BackupMySQLWithVault creates an authoritative mysqldump --single-transaction backup using Vault credentials and container execution.
func BackupMySQLWithVault(ctx context.Context, rt runtime.ContainerRuntime, vClient *vault.Client, projectID, resourceID, backupDir string) (*BackupResult, error) {
	if resourceID == "" {
		return nil, fmt.Errorf("resource_id cannot be empty for backup")
	}

	if backupDir == "" {
		backupDir = filepath.Join(os.TempDir(), "primecloud-backups", "mysql", resourceID)
	}
	if err := os.MkdirAll(backupDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create backup directory %s: %w", backupDir, err)
	}

	backupID := fmt.Sprintf("my-bk-%d", time.Now().UnixNano())
	artifactFile := filepath.Join(backupDir, fmt.Sprintf("%s.sql", backupID))

	containerName := fmt.Sprintf("pc-my-%s", resourceID)
	creds, _ := resolveMySQLCredentials(ctx, vClient, projectID, resourceID)

	if rt == nil {
		return nil, fmt.Errorf("container runtime is nil: cannot backup mysql container %s", containerName)
	}

	inspect, err := rt.InspectContainer(ctx, containerName)
	if err != nil {
		return nil, fmt.Errorf("failed inspecting mysql container %s: %w", containerName, err)
	}
	if inspect == nil || !inspect.Running {
		return nil, fmt.Errorf("mysql container %s is not running", containerName)
	}

	authUser := creds.Username
	authPass := creds.Password
	if creds.RootPassword != "" {
		authUser = "root"
		authPass = creds.RootPassword
	}

	cmd := []string{
		"mysqldump",
		"-h", "127.0.0.1",
		"-u", authUser,
		"--single-transaction",
		"--quick",
		"--routines",
		"--triggers",
		creds.Database,
	}
	env := []string{
		fmt.Sprintf("MYSQL_PWD=%s", authPass),
	}

	stdout, stderr, exitCode, execErr := rt.ExecContainer(ctx, containerName, cmd, env, nil)
	if execErr != nil {
		return nil, fmt.Errorf("failed executing mysqldump on %s: %w (stderr: %s)", containerName, execErr, string(stderr))
	}
	if exitCode != 0 {
		return nil, fmt.Errorf("mysqldump exited with code %d: %s", exitCode, strings.TrimSpace(string(stderr)))
	}
	if len(stdout) == 0 {
		return nil, fmt.Errorf("mysqldump produced empty output: %s", strings.TrimSpace(string(stderr)))
	}

	if err := os.WriteFile(artifactFile, stdout, 0600); err != nil {
		return nil, fmt.Errorf("failed to write mysql backup dump file %s: %w", artifactFile, err)
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
