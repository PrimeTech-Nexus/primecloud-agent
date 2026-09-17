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
	ImageDigest      string                  `json:"image_digest"`
	Image            string                  `json:"image"`
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

	imageToRun := payload.ImageDigest
	if imageToRun == "" {
		imageToRun = payload.Image
	}
	if imageToRun == "" {
		return "", fmt.Errorf("either image_digest or image must be provided")
	}

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

	// 2. Prepare container config
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

	if d.rt == nil {
		return "", fmt.Errorf("container runtime is not configured")
	}

	// 3. Create Container
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
