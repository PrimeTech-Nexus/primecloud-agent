// Package valkey provides the authoritative Valkey/Redis driver for provisioning, credentials, lifecycle, backup, and restore.
package valkey

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
	"github.com/primecloud/primecloud-agent/internal/network"
	"github.com/primecloud/primecloud-agent/internal/runtime"
	"github.com/primecloud/primecloud-agent/internal/vault"
)

// Credentials holds generated Valkey auth token and port details.
type Credentials struct {
	AuthToken string `json:"auth_token"`
	Port      int    `json:"port"`
}

// ProvisionResult contains details of the provisioned Valkey instance.
type ProvisionResult struct {
	ResourceID     string       `json:"resource_id"`
	ContainerID    string       `json:"container_id"`
	Endpoint       string       `json:"endpoint"`
	VaultSecretRef string       `json:"vault_secret_ref"`
	VolumePath     string       `json:"volume_path"`
	Credentials    *Credentials `json:"-"` // Redacted from JSON
}

// Provisioner orchestrates Valkey provisioning on compute nodes.
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
		logger:      logger.With("component", "valkey_provisioner"),
	}
}

// SetNetworkManager sets the ManagedDataNetworkManager for network attachment.
func (p *Provisioner) SetNetworkManager(mgr *network.Manager) {
	p.netMgr = mgr
}

// GenerateCredentials generates a random auth token.
func GenerateCredentials() (*Credentials, error) {
	bytes := make([]byte, 24)
	if _, err := rand.Read(bytes); err != nil {
		return nil, fmt.Errorf("failed to generate random token: %w", err)
	}
	return &Credentials{
		AuthToken: hex.EncodeToString(bytes),
		Port:      6379,
	}, nil
}

// Provision sets up storage, credentials in Vault, and starts the Valkey container.
func (p *Provisioner) Provision(ctx context.Context, resourceID, image string, hostPort string) (*ProvisionResult, error) {
	return p.ProvisionWithProject(ctx, "default", "", resourceID, image, hostPort)
}

// ProvisionWithProject sets up storage, credentials in Vault under the tenant path, and starts the Valkey container.
// environmentID is the PrimeCloud environment UUID used to attach the container to the managed-data network.
// Pass an empty string if no environment network attachment is required (e.g., tests without Docker).
func (p *Provisioner) ProvisionWithProject(ctx context.Context, projectID, environmentID, resourceID, image, hostPort string) (*ProvisionResult, error) {
	if resourceID == "" {
		return nil, fmt.Errorf("resource_id cannot be empty")
	}
	if projectID == "" {
		projectID = "default"
	}
	if image == "" {
		image = "valkey/valkey:7.2-alpine"
	}

	p.logger.Info("provisioning_valkey_starting", "project_id", projectID, "resource_id", resourceID, "image", image)

	// 1. Create Volume Directory
	volumePath := filepath.Join(p.baseResDir, "valkey", resourceID)
	if err := os.MkdirAll(volumePath, 0700); err != nil {
		return nil, fmt.Errorf("failed to create valkey volume directory: %w", err)
	}

	// 2. Generate Credentials
	creds, err := GenerateCredentials()
	if err != nil {
		return nil, err
	}

	// Legacy host label (kept for backward compat in Vault and existing connection-string consumers)
	legacyHost := fmt.Sprintf("pc-vk-%s", resourceID)
	// Internal DNS hostname used inside pc-net-<environmentID> for container-to-container resolution
	internalHost := fmt.Sprintf("valkey-%s.internal.primecloud", resourceID)

	// Build the authoritative connection URL using the internal DNS hostname so that
	// applications consuming this secret resolve correctly inside the managed-data network.
	// When environmentID is empty (e.g. legacy or test path) fall back to the legacy host.
	urlHost := internalHost
	if environmentID == "" {
		urlHost = legacyHost
	}
	url := fmt.Sprintf("redis://default:%s@%s:%d", creds.AuthToken, urlHost, creds.Port)

	// 3. Store Credentials in Vault
	tenantVaultRef := fmt.Sprintf("secret/data/primecloud/tenants/%s/keyvalue/%s", projectID, resourceID)
	redisCompatVaultRef := fmt.Sprintf("secret/data/primecloud/tenants/%s/redis/%s", projectID, resourceID)
	compatVaultRef := fmt.Sprintf("primecloud/resources/valkey/%s", resourceID)
	if p.vaultClient != nil {
		secretData := map[string]interface{}{
			"username":   "default",
			"password":   creds.AuthToken,
			"auth_token": creds.AuthToken,
			"host":       legacyHost, // Legacy host preserved for compat; use url for connection
			"port":       creds.Port,
			"url":        url,
		}
		if err := p.vaultClient.WriteSecret(ctx, tenantVaultRef, secretData); err != nil {
			return nil, fmt.Errorf("failed to store valkey credentials in vault (%s): %w", tenantVaultRef, err)
		}
		p.logger.Info("valkey_credentials_stored_in_vault", "vault_ref", tenantVaultRef)

		// Dual-write redis compatibility path for tenants
		if err := p.vaultClient.WriteSecret(ctx, redisCompatVaultRef, secretData); err != nil {
			p.logger.Warn("valkey_credentials_redis_compat_vault_write_failed", "vault_ref", redisCompatVaultRef, "error", err)
		}
		// Dual-write legacy compatibility path
		if err := p.vaultClient.WriteSecret(ctx, compatVaultRef, secretData); err != nil {
			p.logger.Warn("valkey_credentials_compat_vault_write_failed", "vault_ref", compatVaultRef, "error", err)
		}
	}

	// 4. Container Configuration
	containerName := fmt.Sprintf("pc-vk-%s", resourceID)
	cfg := &runtime.ContainerConfig{
		Name:  containerName,
		Image: image,
		Command: []string{
			"valkey-server",
			"--requirepass", creds.AuthToken,
			"--appendonly", "yes",
			"--dir", "/data",
		},
		Binds: []string{
			fmt.Sprintf("%s:/data:rw", volumePath),
		},
		HealthCheckCmd: []string{
			"CMD", "valkey-cli", "-a", creds.AuthToken, "ping",
		},
		HealthInterval: 3 * time.Second,
		HealthTimeout:  2 * time.Second,
		HealthRetries:  5,
		Labels: map[string]string{
			"primecloud.resource_id": resourceID,
			"primecloud.managed":     "true",
		},
		WorkloadType: runtime.WorkloadTypeManagedValkey,
	}

	if hostPort != "" {
		cfg.Ports = map[string]string{
			"6379": hostPort,
		}
	}

	limits := runtime.DefaultResourceLimits()
	profile := runtime.DefaultHardenedProfile()
	profile.User = "999:999"

	var containerID string
	if p.rt != nil {
		cid, err := p.rt.CreateContainer(ctx, cfg, limits, profile)
		if err != nil {
			return nil, fmt.Errorf("failed to create valkey container: %w", err)
		}
		containerID = cid

		if err := p.rt.StartContainer(ctx, containerID); err != nil {
			_ = p.rt.RemoveContainer(ctx, containerID, true)
			return nil, fmt.Errorf("failed to start valkey container: %w", err)
		}

		if err := applications.WaitForContainerReady(ctx, p.rt, containerID, 20*time.Second); err != nil {
			return nil, fmt.Errorf("valkey container failed health check: %w", err)
		}

		// Attach container to the managed-data network (pc-net-<environmentID>) so that
		// application containers in the same environment can resolve via internal DNS.
		if p.netMgr != nil && environmentID != "" {
			aliases := network.FormatValkeyAliases(resourceID)
			if err := p.netMgr.AttachContainerToEnvironmentNetwork(ctx, environmentID, containerID, aliases); err != nil {
				p.logger.Warn("valkey_network_attach_failed",
					"resource_id", resourceID,
					"environment_id", environmentID,
					"container_id", containerID,
					"error", err,
				)
				// Non-fatal: container is up and serving; network attachment will be retried
				// by reconcile_managed_data_network.
			} else {
				p.logger.Info("valkey_network_attached",
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
		Endpoint:       fmt.Sprintf("%s:6379", legacyHost),
		VaultSecretRef: tenantVaultRef,
		VolumePath:     volumePath,
		Credentials:    creds,
	}

	p.logger.Info("provisioning_valkey_completed", "resource_id", resourceID, "endpoint", result.Endpoint)
	return result, nil
}
