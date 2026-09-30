// Package applications manages customer application lifecycle, deployment, health verification, and secrets injection.
package applications

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/primecloud/primecloud-agent/internal/runtime"
	"github.com/primecloud/primecloud-agent/internal/vault"
)

// DeployPayload defines the JSON payload schema for deploy_application operations.
type DeployPayload struct {
	Image            string                  `json:"image"`
	ImageDigest      string                  `json:"image_digest"`
	Env              map[string]string       `json:"env"`
	SecretRefs       map[string]string       `json:"secret_refs"` // ENV_VAR_NAME -> "path/in/vault#key"
	Ports            map[string]string       `json:"ports"`
	Command          []string                `json:"command"`
	HealthCheckCmd   []string                `json:"health_check_cmd"`
	HealthTimeoutSec int                     `json:"health_timeout_sec"`
	Limits           *runtime.ResourceLimits `json:"limits"`
}

// Deployer orchestrates deployment, secret resolution, and container execution.
type Deployer struct {
	rt          runtime.ContainerRuntime
	vaultClient *vault.Client
	logger      *slog.Logger
}

// NewDeployer constructs a Deployer instance.
func NewDeployer(rt runtime.ContainerRuntime, vaultClient *vault.Client, logger *slog.Logger) *Deployer {
	if logger == nil {
		logger = slog.Default()
	}
	return &Deployer{
		rt:          rt,
		vaultClient: vaultClient,
		logger:      logger.With("component", "application_deployer"),
	}
}

// Deploy executes the deploy_application operation workflow.
func (d *Deployer) Deploy(
	ctx context.Context,
	projectID, environmentID, appID, instanceID string,
	payloadJSON string,
) (string, error) {
	var payload DeployPayload
	if err := json.Unmarshal([]byte(payloadJSON), &payload); err != nil {
		return "", fmt.Errorf("failed to parse deploy payload: %w", err)
	}

	// Canonical image resolution
	imageToPull := strings.TrimSpace(payload.Image)
	if strings.HasPrefix(imageToPull, "sha256:") {
		imageToPull = ""
	}

	if imageToPull == "" {
		trimmedDigest := strings.TrimSpace(payload.ImageDigest)
		if trimmedDigest != "" && !strings.HasPrefix(trimmedDigest, "sha256:") {
			imageToPull = trimmedDigest
		}
	}

	if imageToPull == "" {
		return "", fmt.Errorf("invalid image reference: bare sha256 digest is not pullable; canonical registry reference required")
	}

	imageToRun := imageToPull

	d.logger.Info("application_deploy_starting",
		"project_id", projectID,
		"application_id", appID,
		"instance_id", instanceID,
		"image", imageToRun,
	)

	// 1. Resolve Vault secrets and inject into environment
	finalEnv := make(map[string]string)
	for k, v := range payload.Env {
		finalEnv[k] = v
	}

	if d.vaultClient != nil && len(payload.SecretRefs) > 0 {
		for envVar, ref := range payload.SecretRefs {
			val, err := d.resolveSecret(ctx, ref)
			if err != nil {
				return "", fmt.Errorf("failed to resolve secret for %s (%s): %w", envVar, ref, err)
			}
			finalEnv[envVar] = val
		}
	}

	if d.rt == nil {
		return "", fmt.Errorf("container runtime is not configured")
	}

	// 2. Pull container image before creation
	d.logger.Info("docker_image_pulling", "image", imageToPull)
	authStr := d.resolveGHCRAuth(ctx)
	if err := d.rt.PullImageWithAuth(ctx, imageToPull, authStr); err != nil {
		d.logger.Error("docker_image_pull_failed", "image", imageToPull, "error", err)
		return "", fmt.Errorf("failed to pull docker image %s: %w", imageToPull, err)
	}
	d.logger.Info("docker_image_pulled", "image", imageToPull)

	// 3. Prepare container config
	containerName := fmt.Sprintf("pc-app-%s-%s", appID, instanceID)
	if instanceID == "" {
		containerName = fmt.Sprintf("pc-app-%s", appID)
	}

	cfg := &runtime.ContainerConfig{
		Name:           containerName,
		Image:          imageToRun,
		ImageDigest:    payload.ImageDigest,
		Command:        payload.Command,
		Env:            finalEnv,
		Ports:          payload.Ports,
		HealthCheckCmd: payload.HealthCheckCmd,
		ProjectID:      projectID,
		EnvironmentID:  environmentID,
		ApplicationID:  appID,
		InstanceID:     instanceID,
	}

	limits := payload.Limits
	if limits == nil {
		limits = runtime.DefaultResourceLimits()
	}

	profile := runtime.DefaultHardenedProfile()

	// 4. Create Container
	containerID, err := d.rt.CreateContainer(ctx, cfg, limits, profile)
	if err != nil {
		return "", fmt.Errorf("failed to create application container: %w", err)
	}

	// 4. Start Container
	if err := d.rt.StartContainer(ctx, containerID); err != nil {
		_ = d.rt.RemoveContainer(ctx, containerID, true)
		return "", fmt.Errorf("failed to start application container: %w", err)
	}

	// 5. Health check poll
	waitTimeout := 15 * time.Second
	if payload.HealthTimeoutSec > 0 {
		waitTimeout = time.Duration(payload.HealthTimeoutSec) * time.Second
	}

	if err := WaitForContainerReady(ctx, d.rt, containerID, waitTimeout); err != nil {
		d.logger.Warn("application_healthcheck_failed", "container_id", containerID, "error", err)
		// We do not silently drop; report error
		return containerID, fmt.Errorf("container started but failed health check: %w", err)
	}

	d.logger.Info("application_deploy_succeeded", "container_id", containerID)
	return containerID, nil
}

func (d *Deployer) resolveSecret(ctx context.Context, ref string) (string, error) {
	// Format: "secret/path#key" or "path#key"
	parts := strings.Split(ref, "#")
	if len(parts) != 2 {
		return "", fmt.Errorf("invalid secret reference format %s (expected 'path#key')", ref)
	}

	path := parts[0]
	key := parts[1]

	data, err := d.vaultClient.ReadSecret(ctx, path)
	if err != nil {
		return "", fmt.Errorf("vault read error at %s: %w", path, err)
	}
	if data == nil {
		return "", fmt.Errorf("secret not found in vault at %s", path)
	}

	val, exists := data[key]
	if !exists {
		return "", fmt.Errorf("key %s not found in vault secret at %s", key, path)
	}

	return fmt.Sprintf("%v", val), nil
}

func (d *Deployer) resolveGHCRAuth(ctx context.Context) string {
	// 1. Check environment variables, node credentials, or docker config
	if auth := runtime.GetGHCRAuth(); auth != "" {
		return auth
	}

	// 2. Fallback to HashiCorp Vault at primecloud/github/ghcr
	if d.vaultClient != nil {
		data, err := d.vaultClient.ReadSecret(ctx, "primecloud/github/ghcr")
		if err == nil && data != nil {
			u, _ := data["username"].(string)
			p, _ := data["token"].(string)
			if p == "" {
				p, _ = data["password"].(string)
			}
			if p != "" {
				return runtime.EncodeGHCRAuth(u, p)
			}
		}
	}
	return ""
}
