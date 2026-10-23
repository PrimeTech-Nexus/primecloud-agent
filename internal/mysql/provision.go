// Package mysql provides the authoritative MySQL driver for provisioning, credentials, lifecycle, backup, and restore.
package mysql

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"
	"time"

	"github.com/primecloud/primecloud-agent/internal/applications"
	"github.com/primecloud/primecloud-agent/internal/network"
	"github.com/primecloud/primecloud-agent/internal/runtime"
	"github.com/primecloud/primecloud-agent/internal/vault"
)

const (
	// DefaultPort is the canonical internal MySQL port.
	DefaultPort = 3306
	// DefaultImage is the default version-pinned official MySQL image.
	DefaultImage = "mysql:8.0"
)

// Credentials holds generated MySQL connection and auth properties.
// Separates administrative root credentials from tenant user credentials.
type Credentials struct {
	Username     string `json:"username"`
	Password     string `json:"password"`
	Database     string `json:"database"`
	RootPassword string `json:"root_password"`
	Port         int    `json:"port"`
}

// ProvisionResult contains details of the provisioned MySQL instance.
type ProvisionResult struct {
	ResourceID     string       `json:"resource_id"`
	ContainerID    string       `json:"container_id"`
	Endpoint       string       `json:"endpoint"`
	VaultSecretRef string       `json:"vault_secret_ref"`
	VolumePath     string       `json:"volume_path"`
	Credentials    *Credentials `json:"-"` // Redacted from JSON output
}

// Provisioner orchestrates MySQL provisioning on compute nodes.
type Provisioner struct {
	rt          runtime.ContainerRuntime
	vaultClient *vault.Client
	baseResDir  string
	netMgr      *network.Manager
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
		logger:      logger.With("component", "mysql_provisioner"),
	}
}

// SetNetworkManager sets the ManagedDataNetworkManager for network attachment.
func (p *Provisioner) SetNetworkManager(mgr *network.Manager) {
	p.netMgr = mgr
}

// ResolvePinnedImage maps a version or image string to a version-pinned official MySQL image ("mysql:8.0" or "mysql:8.4").
func ResolvePinnedImage(versionOrImage string) (string, error) {
	trimmed := strings.TrimSpace(strings.ToLower(versionOrImage))
	if trimmed == "" || trimmed == "8.0" || trimmed == "mysql:8.0" {
		return "mysql:8.0", nil
	}
	if trimmed == "8.4" || trimmed == "mysql:8.4" {
		return "mysql:8.4", nil
	}
	if strings.HasPrefix(trimmed, "8.0.") || strings.HasPrefix(trimmed, "mysql:8.0.") {
		return "mysql:8.0", nil
	}
	if strings.HasPrefix(trimmed, "8.4.") || strings.HasPrefix(trimmed, "mysql:8.4.") {
		return "mysql:8.4", nil
	}
	return "", fmt.Errorf("UNSUPPORTED_MYSQL_VERSION: unsupported MySQL version or image %q (allowed: 8.0, 8.4)", versionOrImage)
}

// GenerateCredentials produces cryptographically secure root and non-root tenant credentials.
func GenerateCredentials(resourceID string) (*Credentials, error) {
	pwBytes := make([]byte, 16)
	if _, err := rand.Read(pwBytes); err != nil {
		return nil, fmt.Errorf("failed to generate random tenant password: %w", err)
	}
	rootBytes := make([]byte, 16)
	if _, err := rand.Read(rootBytes); err != nil {
		return nil, fmt.Errorf("failed to generate random root password: %w", err)
	}

	sanitizedID := stringsFilterAlpha(resourceID)
	if len(sanitizedID) > 8 {
		sanitizedID = sanitizedID[:8]
	}

	return &Credentials{
		Username:     fmt.Sprintf("pc_user_%s", sanitizedID),
		Password:     hex.EncodeToString(pwBytes),
		Database:     fmt.Sprintf("pc_db_%s", sanitizedID),
		RootPassword: hex.EncodeToString(rootBytes),
		Port:         DefaultPort,
	}, nil
}

// Provision prepares storage, generates credentials, writes them to Vault, and starts the container.
func (p *Provisioner) Provision(ctx context.Context, resourceID, image string, hostPort string) (*ProvisionResult, error) {
	return p.ProvisionWithProject(ctx, "default", "", resourceID, image, hostPort)
}

// ProvisionWithProject prepares storage, generates credentials, writes them to Vault under the tenant path, and starts the container.
func (p *Provisioner) ProvisionWithProject(ctx context.Context, projectID, environmentID, resourceID, image, hostPort string) (*ProvisionResult, error) {
	if resourceID == "" {
		return nil, fmt.Errorf("resource_id cannot be empty")
	}
	if projectID == "" {
		projectID = "default"
	}

	pinnedImage, err := ResolvePinnedImage(image)
	if err != nil {
		return nil, err
	}

	p.logger.Info("provisioning_mysql_starting", "project_id", projectID, "resource_id", resourceID, "image", pinnedImage)

	// 1. Create Volume Directory with correct permissions for mysql (UID 999:999)
	volumePath := filepath.Join(p.baseResDir, "mysql", resourceID)
	if err := ensureMySQLDataDir(volumePath); err != nil {
		return nil, fmt.Errorf("failed to create mysql volume directory %s: %w", volumePath, err)
	}

	// 2. Generate Credentials
	creds, err := GenerateCredentials(resourceID)
	if err != nil {
		return nil, err
	}

	legacyHost := fmt.Sprintf("pc-my-%s", resourceID)
	internalHost := fmt.Sprintf("mysql-%s.internal.primecloud", resourceID)

	urlHost := internalHost
	if environmentID == "" {
		urlHost = legacyHost
	}
	url := fmt.Sprintf("mysql://%s:%s@%s:%d/%s", creds.Username, creds.Password, urlHost, creds.Port, creds.Database)

	// 3. Store Credentials in Vault
	tenantVaultRef := fmt.Sprintf("secret/data/primecloud/tenants/%s/mysql/%s", projectID, resourceID)
	compatVaultRef := fmt.Sprintf("primecloud/resources/mysql/%s", resourceID)
	if p.vaultClient != nil {
		secretData := map[string]interface{}{
			"username":      creds.Username,
			"password":      creds.Password,
			"database":      creds.Database,
			"root_password": creds.RootPassword,
			"host":          legacyHost,
			"port":          creds.Port,
			"url":           url,
		}
		if err := p.vaultClient.WriteSecret(ctx, tenantVaultRef, secretData); err != nil {
			return nil, fmt.Errorf("failed to store mysql credentials in vault (%s): %w", tenantVaultRef, err)
		}
		p.logger.Info("mysql_credentials_stored_in_vault", "vault_ref", tenantVaultRef)

		if err := p.vaultClient.WriteSecret(ctx, compatVaultRef, secretData); err != nil {
			p.logger.Warn("mysql_credentials_compat_vault_write_failed", "vault_ref", compatVaultRef, "error", err)
		}
	}

	// 4. Container Configuration
	containerName := fmt.Sprintf("pc-my-%s", resourceID)
	cfg := &runtime.ContainerConfig{
		Name:  containerName,
		Image: pinnedImage,
		Command: []string{
			"--character-set-server=utf8mb4",
			"--collation-server=utf8mb4_unicode_ci",
		},
		Env: map[string]string{
			"MYSQL_ROOT_PASSWORD": creds.RootPassword,
			"MYSQL_DATABASE":      creds.Database,
			"MYSQL_USER":          creds.Username,
			"MYSQL_PASSWORD":      creds.Password,
		},
		Binds: []string{
			fmt.Sprintf("%s:/var/lib/mysql:rw", volumePath),
		},
		HealthCheckCmd: []string{
			"CMD-SHELL",
			fmt.Sprintf("MYSQL_PWD=%s mysqladmin ping -h 127.0.0.1 -u %s", creds.Password, creds.Username),
		},
		HealthInterval: 3 * time.Second,
		HealthTimeout:  2 * time.Second,
		HealthRetries:  10,
		Labels: map[string]string{
			"primecloud.resource_id": resourceID,
			"primecloud.engine":      "mysql",
			"primecloud.managed":     "true",
		},
		WorkloadType: runtime.WorkloadTypeManagedMySQL,
	}

	if hostPort != "" {
		cfg.Ports = map[string]string{
			"3306": hostPort,
		}
	}

	limits := runtime.DefaultResourceLimits()
	profile := runtime.DefaultHardenedProfile()
	profile.User = "999:999"

	var containerID string
	if p.rt != nil {
		cid, err := p.rt.CreateContainer(ctx, cfg, limits, profile)
		if err != nil {
			return nil, fmt.Errorf("failed to create mysql container: %w", err)
		}
		containerID = cid

		if err := p.rt.StartContainer(ctx, containerID); err != nil {
			_ = p.rt.RemoveContainer(ctx, containerID, true)
			return nil, fmt.Errorf("failed to start mysql container: %w", err)
		}

		// Wait for mysqladmin ping health check
		if err := applications.WaitForContainerReady(ctx, p.rt, containerID, 60*time.Second); err != nil {
			return nil, fmt.Errorf("mysql container failed health check: %w", err)
		}

		// Attach container to pc-net-<environmentID>
		if p.netMgr != nil && environmentID != "" {
			aliases := network.FormatMySQLAliases(resourceID)
			if err := p.netMgr.AttachContainerToEnvironmentNetwork(ctx, environmentID, containerID, aliases); err != nil {
				p.logger.Warn("mysql_network_attach_failed",
					"resource_id", resourceID,
					"environment_id", environmentID,
					"container_id", containerID,
					"error", err,
				)
			} else {
				p.logger.Info("mysql_network_attached",
					"resource_id", resourceID,
					"environment_id", environmentID,
					"network", "pc-net-"+environmentID,
					"aliases", aliases,
				)
			}
		}
	}

	result := &ProvisionResult{
		ResourceID:     resourceID,
		ContainerID:    containerID,
		Endpoint:       fmt.Sprintf("%s:3306", legacyHost),
		VaultSecretRef: tenantVaultRef,
		VolumePath:     volumePath,
		Credentials:    creds,
	}

	p.logger.Info("provisioning_mysql_completed", "resource_id", resourceID, "endpoint", result.Endpoint)
	return result, nil
}

// SetHostPort reconfigures the MySQL container with a new published host port while preserving the persistent data volume.
func (p *Provisioner) SetHostPort(ctx context.Context, projectID, environmentID, resourceID string, hostPort string) error {
	if resourceID == "" {
		return fmt.Errorf("resource_id cannot be empty")
	}
	if projectID == "" {
		projectID = "default"
	}

	containerName := fmt.Sprintf("pc-my-%s", resourceID)
	volumePath := filepath.Join(p.baseResDir, "mysql", resourceID)

	image := DefaultImage
	var creds *Credentials
	if p.vaultClient != nil {
		if c, err := resolveMySQLCredentials(ctx, p.vaultClient, projectID, resourceID); err == nil && c != nil {
			creds = c
		}
	}
	if creds == nil {
		if p.rt != nil {
			if insp, err := p.rt.InspectContainer(ctx, containerName); err == nil && insp != nil && insp.Image != "" {
				image = insp.Image
			}
		}
		sanitizedID := stringsFilterAlpha(resourceID)
		if len(sanitizedID) > 8 {
			sanitizedID = sanitizedID[:8]
		}
		creds = &Credentials{
			Username: fmt.Sprintf("pc_user_%s", sanitizedID),
			Database: fmt.Sprintf("pc_db_%s", sanitizedID),
			Port:     DefaultPort,
		}
	}

	cfg := &runtime.ContainerConfig{
		Name:  containerName,
		Image: image,
		Command: []string{
			"--character-set-server=utf8mb4",
			"--collation-server=utf8mb4_unicode_ci",
		},
		Env: map[string]string{
			"MYSQL_ROOT_PASSWORD": creds.RootPassword,
			"MYSQL_DATABASE":      creds.Database,
			"MYSQL_USER":          creds.Username,
			"MYSQL_PASSWORD":      creds.Password,
		},
		Binds: []string{
			fmt.Sprintf("%s:/var/lib/mysql:rw", volumePath),
		},
		HealthCheckCmd: []string{
			"CMD-SHELL",
			fmt.Sprintf("MYSQL_PWD=%s mysqladmin ping -h 127.0.0.1 -u %s", creds.Password, creds.Username),
		},
		HealthInterval: 3 * time.Second,
		HealthTimeout:  2 * time.Second,
		HealthRetries:  10,
		Labels: map[string]string{
			"primecloud.resource_id": resourceID,
			"primecloud.engine":      "mysql",
			"primecloud.managed":     "true",
		},
		WorkloadType: runtime.WorkloadTypeManagedMySQL,
	}

	if hostPort != "" {
		cfg.Ports = map[string]string{
			"3306": hostPort,
		}
	}

	limits := runtime.DefaultResourceLimits()
	profile := runtime.DefaultHardenedProfile()
	profile.User = "999:999"

	if p.rt == nil {
		return fmt.Errorf("container runtime is nil")
	}

	timeout := 10
	_ = p.rt.StopContainer(ctx, containerName, &timeout)
	_ = p.rt.RemoveContainer(ctx, containerName, true)

	cid, err := p.rt.CreateContainer(ctx, cfg, limits, profile)
	if err != nil {
		return fmt.Errorf("failed to recreate mysql container: %w", err)
	}
	if err := p.rt.StartContainer(ctx, cid); err != nil {
		return fmt.Errorf("failed to start recreated mysql container: %w", err)
	}
	if err := applications.WaitForContainerReady(ctx, p.rt, cid, 60*time.Second); err != nil {
		return fmt.Errorf("recreated mysql container failed health check: %w", err)
	}

	if p.netMgr != nil && environmentID != "" {
		aliases := network.FormatMySQLAliases(resourceID)
		_ = p.netMgr.AttachContainerToEnvironmentNetwork(ctx, environmentID, cid, aliases)
	}

	return nil
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
