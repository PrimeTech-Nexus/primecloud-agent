// Package mongodb provides the authoritative MongoDB driver for provisioning, rs0 replica set bootstrap, credentials, lifecycle, backup, and restore.
package mongodb

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

// BackupResult describes a generated MongoDB backup artifact.
type BackupResult struct {
	BackupID     string    `json:"backup_id"`
	ResourceID   string    `json:"resource_id"`
	ArtifactPath string    `json:"artifact_path"`
	SizeBytes    int64     `json:"size_bytes"`
	CreatedAt    time.Time `json:"created_at"`
}

// resolveMongoDBCredentials fetches credentials from Vault or derives defaults from resourceID.
func resolveMongoDBCredentials(ctx context.Context, vClient *vault.Client, projectID, resourceID string) (*Credentials, error) {
	if projectID == "" {
		projectID = "default"
	}

	if vClient != nil {
		tenantPath := fmt.Sprintf("secret/data/primecloud/tenants/%s/mongodb/%s", projectID, resourceID)
		secret, err := vClient.ReadSecret(ctx, tenantPath)
		if err == nil && secret != nil {
			user, _ := secret["username"].(string)
			pw, _ := secret["password"].(string)
			db, _ := secret["database"].(string)
			adminUser, _ := secret["admin_username"].(string)
			adminPw, _ := secret["admin_password"].(string)
			if adminPw == "" {
				adminPw, _ = secret["root_password"].(string)
			}
			if adminUser == "" {
				adminUser = "admin"
			}
			if user != "" && pw != "" && db != "" {
				return &Credentials{
					Username:      user,
					Password:      pw,
					Database:      db,
					AdminUsername: adminUser,
					AdminPassword: adminPw,
					ReplicaSet:    DefaultReplicaSet,
					Port:          DefaultPort,
				}, nil
			}
		}

		// Fallback to legacy path
		compatPath := fmt.Sprintf("primecloud/resources/mongodb/%s", resourceID)
		secret, err = vClient.ReadSecret(ctx, compatPath)
		if err == nil && secret != nil {
			user, _ := secret["username"].(string)
			pw, _ := secret["password"].(string)
			db, _ := secret["database"].(string)
			adminUser, _ := secret["admin_username"].(string)
			adminPw, _ := secret["admin_password"].(string)
			if adminPw == "" {
				adminPw, _ = secret["root_password"].(string)
			}
			if adminUser == "" {
				adminUser = "admin"
			}
			if user != "" && pw != "" && db != "" {
				return &Credentials{
					Username:      user,
					Password:      pw,
					Database:      db,
					AdminUsername: adminUser,
					AdminPassword: adminPw,
					ReplicaSet:    DefaultReplicaSet,
					Port:          DefaultPort,
				}, nil
			}
		}
	}

	sanitizedID := stringsFilterAlpha(resourceID)
	if len(sanitizedID) > 8 {
		sanitizedID = sanitizedID[:8]
	}
	return &Credentials{
		Username:      fmt.Sprintf("pc_user_%s", sanitizedID),
		Password:      "password",
		Database:      fmt.Sprintf("pc_db_%s", sanitizedID),
		AdminUsername: "admin",
		AdminPassword: "admin_password",
		ReplicaSet:    DefaultReplicaSet,
		Port:          DefaultPort,
	}, nil
}

// BackupMongoDB creates an archive backup dump from the running MongoDB instance.
func BackupMongoDB(ctx context.Context, rt runtime.ContainerRuntime, resourceID, backupDir string) (*BackupResult, error) {
	return BackupMongoDBWithVault(ctx, rt, nil, "default", resourceID, backupDir)
}

// BackupMongoDBWithVault creates an authoritative mongodump --archive --gzip backup using Vault credentials and container execution.
func BackupMongoDBWithVault(ctx context.Context, rt runtime.ContainerRuntime, vClient *vault.Client, projectID, resourceID, backupDir string) (*BackupResult, error) {
	if resourceID == "" {
		return nil, fmt.Errorf("resource_id cannot be empty for backup")
	}

	if backupDir == "" {
		backupDir = filepath.Join(os.TempDir(), "primecloud-backups", "mongodb", resourceID)
	}
	if err := os.MkdirAll(backupDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create backup directory %s: %w", backupDir, err)
	}

	backupID := fmt.Sprintf("mg-bk-%d", time.Now().UnixNano())
	artifactFile := filepath.Join(backupDir, fmt.Sprintf("%s.archive.gz", backupID))

	containerName := fmt.Sprintf("pc-mg-%s", resourceID)
	creds, _ := resolveMongoDBCredentials(ctx, vClient, projectID, resourceID)

	if rt == nil {
		return nil, fmt.Errorf("container runtime is nil: cannot backup mongodb container %s", containerName)
	}

	inspect, err := rt.InspectContainer(ctx, containerName)
	if err != nil {
		return nil, fmt.Errorf("failed inspecting mongodb container %s: %w", containerName, err)
	}
	if inspect == nil || !inspect.Running {
		return nil, fmt.Errorf("mongodb container %s is not running", containerName)
	}

	authUser := creds.Username
	authPass := creds.Password
	authDB := creds.Database
	if creds.AdminPassword != "" {
		authUser = creds.AdminUsername
		authPass = creds.AdminPassword
		authDB = "admin"
	}

	cmd := []string{
		"mongodump",
		"--host", "127.0.0.1",
		"--port", "27017",
		"--username", authUser,
		"--password", authPass,
		"--authenticationDatabase", authDB,
		"--db", creds.Database,
		"--archive",
		"--gzip",
	}

	stdout, stderr, exitCode, execErr := rt.ExecContainer(ctx, containerName, cmd, nil, nil)
	if execErr != nil {
		return nil, fmt.Errorf("failed executing mongodump on %s: %w (stderr: %s)", containerName, execErr, string(stderr))
	}
	if exitCode != 0 {
		return nil, fmt.Errorf("mongodump exited with code %d: %s", exitCode, strings.TrimSpace(string(stderr)))
	}
	if len(stdout) == 0 {
		return nil, fmt.Errorf("mongodump produced empty output: %s", strings.TrimSpace(string(stderr)))
	}

	if err := os.WriteFile(artifactFile, stdout, 0600); err != nil {
		return nil, fmt.Errorf("failed to write mongodb backup archive file %s: %w", artifactFile, err)
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
