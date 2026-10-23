// Package postgres provides the authoritative PostgreSQL driver for provisioning, credentials, lifecycle, backup, and restore.
package postgres

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

// BackupResult describes a generated PostgreSQL backup artifact.
type BackupResult struct {
	BackupID     string    `json:"backup_id"`
	ResourceID   string    `json:"resource_id"`
	ArtifactPath string    `json:"artifact_path"`
	SizeBytes    int64     `json:"size_bytes"`
	CreatedAt    time.Time `json:"created_at"`
}

// resolvePostgresCredentials fetches credentials from Vault or derives defaults from resourceID.
func resolvePostgresCredentials(ctx context.Context, vClient *vault.Client, projectID, resourceID string) (*Credentials, error) {
	if projectID == "" {
		projectID = "default"
	}

	if vClient != nil {
		tenantPath := fmt.Sprintf("secret/data/primecloud/tenants/%s/postgres/%s", projectID, resourceID)
		secret, err := vClient.ReadSecret(ctx, tenantPath)
		if err == nil && secret != nil {
			user, _ := secret["username"].(string)
			pw, _ := secret["password"].(string)
			db, _ := secret["database"].(string)
			if user != "" && pw != "" && db != "" {
				return &Credentials{
					Username: user,
					Password: pw,
					Database: db,
					Port:     5432,
				}, nil
			}
		}

		// Fallback to legacy path
		compatPath := fmt.Sprintf("primecloud/resources/postgres/%s", resourceID)
		secret, err = vClient.ReadSecret(ctx, compatPath)
		if err == nil && secret != nil {
			user, _ := secret["username"].(string)
			pw, _ := secret["password"].(string)
			db, _ := secret["database"].(string)
			if user != "" && pw != "" && db != "" {
				return &Credentials{
					Username: user,
					Password: pw,
					Database: db,
					Port:     5432,
				}, nil
			}
		}
	}

	// Default convention matching GenerateCredentials
	sanitizedID := stringsFilterAlpha(resourceID)
	if len(sanitizedID) > 8 {
		sanitizedID = sanitizedID[:8]
	}
	return &Credentials{
		Username: fmt.Sprintf("pc_user_%s", sanitizedID),
		Password: "password",
		Database: fmt.Sprintf("pc_db_%s", sanitizedID),
		Port:     5432,
	}, nil
}

// BackupPostgres creates a backup dump from the running PostgreSQL instance.
func BackupPostgres(ctx context.Context, rt runtime.ContainerRuntime, resourceID, backupDir string) (*BackupResult, error) {
	return BackupPostgresWithVault(ctx, rt, nil, "default", resourceID, backupDir)
}

// BackupPostgresWithVault creates an authoritative pg_dump backup using Vault credentials and container execution.
func BackupPostgresWithVault(ctx context.Context, rt runtime.ContainerRuntime, vClient *vault.Client, projectID, resourceID, backupDir string) (*BackupResult, error) {
	if resourceID == "" {
		return nil, fmt.Errorf("resource_id cannot be empty for backup")
	}

	if backupDir == "" {
		backupDir = filepath.Join(os.TempDir(), "primecloud-backups", "postgres", resourceID)
	}
	if err := os.MkdirAll(backupDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create backup directory %s: %w", backupDir, err)
	}

	backupID := fmt.Sprintf("pg-bk-%d", time.Now().UnixNano())
	artifactFile := filepath.Join(backupDir, fmt.Sprintf("%s.dump", backupID))

	containerName := fmt.Sprintf("pc-pg-%s", resourceID)
	creds, _ := resolvePostgresCredentials(ctx, vClient, projectID, resourceID)

	// 1. Check container runtime and inspect running PostgreSQL container
	if rt == nil {
		return nil, fmt.Errorf("container runtime is nil: cannot backup postgres container %s", containerName)
	}

	inspect, err := rt.InspectContainer(ctx, containerName)
	if err != nil {
		return nil, fmt.Errorf("failed inspecting postgres container %s: %w", containerName, err)
	}
	if inspect == nil || !inspect.Running {
		return nil, fmt.Errorf("postgres container %s is not running", containerName)
	}

	cmd := []string{
		"pg_dump",
		"-U", creds.Username,
		"-d", creds.Database,
		"-Fc", // Custom format: compressed archive with TOC
	}
	env := []string{
		fmt.Sprintf("PGPASSWORD=%s", creds.Password),
	}

	// 2. Stream pg_dump directly to artifactFile with bounded memory
	dstFile, err := os.OpenFile(artifactFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return nil, fmt.Errorf("failed to create backup dump file %s: %w", artifactFile, err)
	}
	defer dstFile.Close()

	var stderrBuf bytes.Buffer
	var exitCode int
	var execErr error

	if streamer, ok := rt.(runtime.StreamingContainerRuntime); ok {
		exitCode, execErr = streamer.ExecContainerStream(ctx, containerName, cmd, env, nil, dstFile, &stderrBuf)
	} else {
		var stdout []byte
		var stderr []byte
		stdout, stderr, exitCode, execErr = rt.ExecContainer(ctx, containerName, cmd, env, nil)
		if len(stdout) > 0 {
			_, _ = dstFile.Write(stdout)
		}
		stderrBuf.Write(stderr)
	}

	if execErr != nil {
		_ = os.Remove(artifactFile)
		return nil, fmt.Errorf("failed executing pg_dump on %s: %w (stderr: %s)", containerName, execErr, stderrBuf.String())
	}
	if exitCode != 0 {
		_ = os.Remove(artifactFile)
		return nil, fmt.Errorf("pg_dump exited with code %d: %s", exitCode, strings.TrimSpace(stderrBuf.String()))
	}

	_ = dstFile.Sync()
	fi, err := dstFile.Stat()
	if err != nil {
		_ = os.Remove(artifactFile)
		return nil, err
	}
	if fi.Size() == 0 {
		_ = os.Remove(artifactFile)
		return nil, fmt.Errorf("pg_dump produced empty output: %s", strings.TrimSpace(stderrBuf.String()))
	}



	return &BackupResult{
		BackupID:     backupID,
		ResourceID:   resourceID,
		ArtifactPath: artifactFile,
		SizeBytes:    fi.Size(),
		CreatedAt:    time.Now().UTC(),
	}, nil
}
