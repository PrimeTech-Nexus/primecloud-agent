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
	if resourceID == "" {
		return nil, fmt.Errorf("resource_id cannot be empty")
	}
	if image == "" {
		image = "valkey/valkey:7.2-alpine"
	}

	p.logger.Info("provisioning_valkey_starting", "resource_id", resourceID, "image", image)

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

	// 3. Store Credentials in Vault
	vaultRef := fmt.Sprintf("primecloud/resources/valkey/%s", resourceID)
	if p.vaultClient != nil {
		secretData := map[string]interface{}{
			"auth_token": creds.AuthToken,
			"port":       creds.Port,
		}
		if err := p.vaultClient.WriteSecret(ctx, vaultRef, secretData); err != nil {
			return nil, fmt.Errorf("failed to store valkey credentials in vault: %w", err)
		}
		p.logger.Info("valkey_credentials_stored_in_vault", "vault_ref", vaultRef)
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
	}

	result := &ProvisionResult{
		ResourceID:     resourceID,
		ContainerID:    containerID,
		Endpoint:       fmt.Sprintf("%s:6379", containerName),
		VaultSecretRef: vaultRef,
		VolumePath:     volumePath,
		Credentials:    creds,
	}

	p.logger.Info("provisioning_valkey_completed", "resource_id", resourceID, "endpoint", result.Endpoint)
	return result, nil
}
