// Package postgres provides the authoritative PostgreSQL driver for provisioning, credentials, lifecycle, backup, and restore.
package postgres

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/primecloud/primecloud-agent/internal/applications"
	"github.com/primecloud/primecloud-agent/internal/runtime"
	"github.com/primecloud/primecloud-agent/internal/vault"
)

// Credentials holds generated PostgreSQL connection and auth properties.
type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Database string `json:"database"`
	Port     int    `json:"port"`
}

// ProvisionResult contains details of the provisioned PostgreSQL instance.
type ProvisionResult struct {
	ResourceID     string       `json:"resource_id"`
	ContainerID    string       `json:"container_id"`
	Endpoint       string       `json:"endpoint"`
	VaultSecretRef string       `json:"vault_secret_ref"`
	VolumePath     string       `json:"volume_path"`
	Credentials    *Credentials `json:"-"` // Redacted from JSON output
}

// Provisioner orchestrates PostgreSQL provisioning on compute nodes.
type Provisioner struct {
	rt          runtime.ContainerRuntime
	vaultClient *vault.Client
	baseResDir  string
	logger      *slog.Logger
}

// NewProvisioner constructs a Provisioner instance.
func NewProvisioner(rt runtime.ContainerRuntime, vaultClient *vault.Client, baseResDir string, logger *slog.Logger) *Provisioner {
	if baseResDir == "" {
		baseResDir = "/opt/primecloud/resources"
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Provisioner{
		rt:          rt,
		vaultClient: vaultClient,
		baseResDir:  baseResDir,
		logger:      logger.With("component", "postgres_provisioner"),
	}
}

// GenerateCredentials produces cryptographically secure credentials.
func GenerateCredentials(resourceID string) (*Credentials, error) {
	pwBytes := make([]byte, 16)
	if _, err := rand.Read(pwBytes); err != nil {
		return nil, fmt.Errorf("failed to generate random password: %w", err)
	}

	sanitizedID := stringsFilterAlpha(resourceID)
	if len(sanitizedID) > 8 {
		sanitizedID = sanitizedID[:8]
	}

	return &Credentials{
		Username: fmt.Sprintf("pc_user_%s", sanitizedID),
		Password: hex.EncodeToString(pwBytes),
		Database: fmt.Sprintf("pc_db_%s", sanitizedID),
		Port:     5432,
	}, nil
}

// Provision prepares storage, generates credentials, writes them to Vault, and starts the container.
func (p *Provisioner) Provision(ctx context.Context, resourceID, image string, hostPort string) (*ProvisionResult, error) {
	return p.ProvisionWithProject(ctx, "default", resourceID, image, hostPort)
}

// ProvisionWithProject prepares storage, generates credentials, writes them to Vault under the tenant path, and starts the container.
func (p *Provisioner) ProvisionWithProject(ctx context.Context, projectID, resourceID, image, hostPort string) (*ProvisionResult, error) {
	if resourceID == "" {
		return nil, fmt.Errorf("resource_id cannot be empty")
	}
	if projectID == "" {
		projectID = "default"
	}
	if image == "" {
		image = "postgres:16-alpine"
	}

	p.logger.Info("provisioning_postgres_starting", "project_id", projectID, "resource_id", resourceID, "image", image)

	// 1. Create Volume Directory
	volumePath := filepath.Join(p.baseResDir, "postgres", resourceID)
	if err := os.MkdirAll(volumePath, 0700); err != nil {
		return nil, fmt.Errorf("failed to create postgres volume directory %s: %w", volumePath, err)
	}

	// 2. Generate Credentials
	creds, err := GenerateCredentials(resourceID)
	if err != nil {
		return nil, err
	}

	host := fmt.Sprintf("pc-pg-%s", resourceID)
	url := fmt.Sprintf("postgresql://%s:%s@%s:%d/%s", creds.Username, creds.Password, host, creds.Port, creds.Database)

	// 3. Store Credentials in Vault
	tenantVaultRef := fmt.Sprintf("secret/data/primecloud/tenants/%s/postgres/%s", projectID, resourceID)
	compatVaultRef := fmt.Sprintf("primecloud/resources/postgres/%s", resourceID)
	if p.vaultClient != nil {
		secretData := map[string]interface{}{
			"username": creds.Username,
			"password": creds.Password,
			"database": creds.Database,
			"host":     host,
			"port":     creds.Port,
			"url":      url,
		}
		if err := p.vaultClient.WriteSecret(ctx, tenantVaultRef, secretData); err != nil {
			return nil, fmt.Errorf("failed to store postgres credentials in vault (%s): %w", tenantVaultRef, err)
		}
		p.logger.Info("postgres_credentials_stored_in_vault", "vault_ref", tenantVaultRef)

		// Dual-write legacy compatibility path
		if err := p.vaultClient.WriteSecret(ctx, compatVaultRef, secretData); err != nil {
			p.logger.Warn("postgres_credentials_compat_vault_write_failed", "vault_ref", compatVaultRef, "error", err)
		}
	}

	// 4. Container Configuration
	containerName := fmt.Sprintf("pc-pg-%s", resourceID)
	cfg := &runtime.ContainerConfig{
		Name:  containerName,
		Image: image,
		Env: map[string]string{
			"POSTGRES_USER":     creds.Username,
			"POSTGRES_PASSWORD": creds.Password,
			"POSTGRES_DB":       creds.Database,
			"PGDATA":            "/var/lib/postgresql/data/pgdata",
		},
		Binds: []string{
			fmt.Sprintf("%s:/var/lib/postgresql/data:rw", volumePath),
		},
		HealthCheckCmd: []string{
			"CMD-SHELL",
			fmt.Sprintf("pg_isready -U %s -d %s", creds.Username, creds.Database),
		},
		HealthInterval: 3 * time.Second,
		HealthTimeout:  2 * time.Second,
		HealthRetries:  5,
	}

	if hostPort != "" {
		cfg.Ports = map[string]string{
			"5432": hostPort,
		}
	}

	limits := runtime.DefaultResourceLimits()
	profile := runtime.DefaultHardenedProfile()
	// Postgres requires postgres user inside container
	profile.User = "999:999"

	var containerID string
	if p.rt != nil {
		cid, err := p.rt.CreateContainer(ctx, cfg, limits, profile)
		if err != nil {
			return nil, fmt.Errorf("failed to create postgres container: %w", err)
		}
		containerID = cid

		if err := p.rt.StartContainer(ctx, containerID); err != nil {
			_ = p.rt.RemoveContainer(ctx, containerID, true)
			return nil, fmt.Errorf("failed to start postgres container: %w", err)
		}

		// Wait for pg_isready
		if err := applications.WaitForContainerReady(ctx, p.rt, containerID, 30*time.Second); err != nil {
			return nil, fmt.Errorf("postgres container failed health check: %w", err)
		}
	}

	result := &ProvisionResult{
		ResourceID:     resourceID,
		ContainerID:    containerID,
		Endpoint:       fmt.Sprintf("%s:5432", host),
		VaultSecretRef: tenantVaultRef,
		VolumePath:     volumePath,
		Credentials:    creds,
	}

	p.logger.Info("provisioning_postgres_completed", "resource_id", resourceID, "endpoint", result.Endpoint)
	return result, nil
}

func stringsFilterAlpha(s string) string {
	var out []rune
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			out = append(out, r)
		}
	}
	return string(out)
}
