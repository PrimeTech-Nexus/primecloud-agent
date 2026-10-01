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
	ImageReference   string                  `json:"image_reference"`
	ImageDigest      string                  `json:"image_digest"`
	Env              map[string]string       `json:"env"`
	EnvVars          map[string]string       `json:"env_vars"` // Backwards-compatible combined environment map
	SecretRefs       map[string]string       `json:"secret_refs"` // ENV_VAR_NAME -> "path/in/vault#key"
	Port             interface{}             `json:"port"`
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
		ref := strings.TrimSpace(payload.ImageReference)
		if ref != "" && !strings.HasPrefix(ref, "sha256:") {
			imageToPull = ref
		}
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

	// 1. Resolve environment variables and Vault secrets
	finalEnv := make(map[string]string)

	// Populate from normal env map
	for k, v := range payload.Env {
		finalEnv[k] = v
	}

	// Populate from backwards-compatible env_vars map if not already present
	for k, v := range payload.EnvVars {
		if _, exists := finalEnv[k]; !exists {
			finalEnv[k] = v
		}
	}

	// Consolidate secret references: from secret_refs map and any embedded "vault:" prefixes
	secretRefs := make(map[string]string)
	for k, ref := range payload.SecretRefs {
		secretRefs[k] = ref
	}
	for k, v := range finalEnv {
		if strings.HasPrefix(v, "vault:") {
			secretRefs[k] = strings.TrimPrefix(v, "vault:")
			delete(finalEnv, k) // Remove placeholder so raw vault: URI is never passed to container
		}
	}

	// Safe diagnostics (keys and counts only - NEVER plaintext secret values)
	envKeyList := make([]string, 0, len(finalEnv))
	for k := range finalEnv {
		envKeyList = append(envKeyList, k)
	}
	secretKeyList := make([]string, 0, len(secretRefs))
	for k := range secretRefs {
		secretKeyList = append(secretKeyList, k)
	}
	d.logger.Info("environment_handoff_received",
		"normal_env_count", len(finalEnv),
		"normal_env_keys", envKeyList,
		"secret_ref_count", len(secretRefs),
		"secret_ref_keys", secretKeyList,
	)

	// Resolve Vault secrets (fail-closed if secrets required but client unconfigured or project_id missing)
	if len(secretRefs) > 0 {
		if strings.TrimSpace(projectID) == "" {
			return "", fmt.Errorf("cannot resolve %d secret reference(s): project_id is required but missing from deployment envelope", len(secretRefs))
		}
		if d.vaultClient == nil {
			return "", fmt.Errorf("cannot resolve %d secret reference(s): vault client is not configured on agent", len(secretRefs))
		}
		for envVar, ref := range secretRefs {
			val, err := d.resolveSecret(ctx, envVar, ref)
			if err != nil {
				return "", fmt.Errorf("failed to resolve secret for %s (%s): %w", envVar, ref, err)
			}
			finalEnv[envVar] = val
		}
	}

	finalKeyList := make([]string, 0, len(finalEnv))
	for k := range finalEnv {
		finalKeyList = append(finalKeyList, k)
	}
	d.logger.Info("environment_resolution_completed",
		"total_env_count", len(finalEnv),
		"total_env_keys", finalKeyList,
	)

	if d.rt == nil {
		return "", fmt.Errorf("container runtime is not configured")
	}

	// 2. Pull container image before creation
	d.logger.Info("docker_image_pulling", "image", imageToPull)
	authStr := d.resolveGHCRAuth(ctx)
	if authStr != "" {
		d.logger.Info("registry_auth_resolved", "registry", "ghcr.io")
	} else {
		d.logger.Warn("registry_auth_unresolved", "registry", "ghcr.io")
	}
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

	portsMap := make(map[string]string)
	for k, v := range payload.Ports {
		portsMap[k] = v
	}
	if len(portsMap) == 0 && payload.Port != nil {
		var pNum int
		if p, ok := payload.Port.(float64); ok && p > 0 {
			pNum = int(p)
		} else if p, ok := payload.Port.(int); ok && p > 0 {
			pNum = p
		}
		if pNum > 0 {
			portsMap[fmt.Sprintf("%d/tcp", pNum)] = ""
		}
	}

	cfg := &runtime.ContainerConfig{
		Name:           containerName,
		Image:          imageToRun,
		ImageDigest:    payload.ImageDigest,
		Command:        payload.Command,
		Env:            finalEnv,
		Ports:          portsMap,
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

func (d *Deployer) resolveSecret(ctx context.Context, envVar, ref string) (string, error) {
	// Strip optional "vault:" scheme prefix
	cleanRef := strings.TrimPrefix(ref, "vault:")

	var path, key string
	if strings.Contains(cleanRef, "#") {
		parts := strings.SplitN(cleanRef, "#", 2)
		path = parts[0]
		key = parts[1]
	} else {
		path = cleanRef
		if envVar == "DATABASE_URL" || envVar == "REDIS_URL" {
			key = "url"
		} else {
			key = envVar
		}
	}

	if key == "" {
		if envVar == "DATABASE_URL" || envVar == "REDIS_URL" {
			key = "url"
		} else {
			key = envVar
		}
	}

	if path == "" {
		return "", fmt.Errorf("secret reference path is empty for variable %s", envVar)
	}

	data, err := d.readSecretWithFallback(ctx, path)
	if err != nil {
		return "", fmt.Errorf("vault read error at %s: %w", path, err)
	}
	if data == nil {
		return "", fmt.Errorf("secret not found in vault at %s", path)
	}

	// HashiCorp Vault KV v2 wraps secret data under "data"
	if nested, ok := data["data"].(map[string]interface{}); ok {
		data = nested
	}

	val, exists := data[key]
	if !exists {
		// Synthesize URL if "url" was requested (or envVar is DATABASE_URL/REDIS_URL) and component fields exist
		if key == "url" || envVar == "DATABASE_URL" || envVar == "REDIS_URL" {
			if synthURL, ok := synthesizeURL(data, path); ok {
				return synthURL, nil
			}
		}
		if key == "password" {
			if tok, ok := data["auth_token"]; ok {
				return fmt.Sprintf("%v", tok), nil
			}
		}
		if key == "auth_token" {
			if pass, ok := data["password"]; ok {
				return fmt.Sprintf("%v", pass), nil
			}
		}
		return "", fmt.Errorf("key %s not found in vault secret at %s", key, path)
	}

	return fmt.Sprintf("%v", val), nil
}

func (d *Deployer) readSecretWithFallback(ctx context.Context, path string) (map[string]interface{}, error) {
	if strings.Contains(path, "tenants//") || strings.Contains(path, "/tenants//") {
		return nil, fmt.Errorf("invalid tenant vault path with empty tenant ID: %s", path)
	}
	pathsToTry := []string{path}

	// Cross-mount variations
	if strings.Contains(path, "/keyvalue/") {
		pathsToTry = append(pathsToTry, strings.Replace(path, "/keyvalue/", "/redis/", 1))
	}
	if strings.Contains(path, "/redis/") {
		pathsToTry = append(pathsToTry, strings.Replace(path, "/redis/", "/keyvalue/", 1))
	}

	if strings.HasPrefix(path, "secret/data/") {
		// Preserve KV v2 API semantics when resolving across secret/ and primecloud/ mounts
		// 1. primecloud/data/primecloud/... (if saved with subpath "primecloud/tenants/...")
		pathsToTry = append(pathsToTry, strings.Replace(path, "secret/data/", "primecloud/data/", 1))
		// 2. primecloud/data/... (if saved with subpath "tenants/...")
		if strings.HasPrefix(path, "secret/data/primecloud/") {
			pathsToTry = append(pathsToTry, strings.Replace(path, "secret/data/primecloud/", "primecloud/data/", 1))
		}
	} else if strings.HasPrefix(path, "secret/") {
		pathsToTry = append(pathsToTry, strings.Replace(path, "secret/", "secret/data/", 1))
		pathsToTry = append(pathsToTry, strings.Replace(path, "secret/", "primecloud/data/", 1))
	} else if strings.HasPrefix(path, "primecloud/data/") {
		pathsToTry = append(pathsToTry, strings.Replace(path, "primecloud/data/", "secret/data/", 1))
		pathsToTry = append(pathsToTry, strings.Replace(path, "primecloud/data/", "secret/data/primecloud/", 1))
	} else if strings.HasPrefix(path, "primecloud/tenants/") {
		pathsToTry = append(pathsToTry, "secret/data/"+path)
		pathsToTry = append(pathsToTry, "primecloud/data/"+strings.TrimPrefix(path, "primecloud/"))
	}

	// Legacy driver paths fallback (only if NOT an explicit tenant path)
	if !strings.Contains(path, "/tenants/") {
		parts := strings.Split(path, "/")
		if len(parts) >= 2 {
			resID := parts[len(parts)-1]
			resType := parts[len(parts)-2]
			if resType == "postgres" {
				pathsToTry = append(pathsToTry, fmt.Sprintf("primecloud/resources/postgres/%s", resID))
			} else if resType == "keyvalue" || resType == "redis" || resType == "valkey" {
				pathsToTry = append(pathsToTry, fmt.Sprintf("primecloud/resources/valkey/%s", resID))
			}
		}
	}

	for _, p := range pathsToTry {
		data, err := d.vaultClient.ReadSecret(ctx, p)
		if err == nil && data != nil && len(data) > 0 {
			return data, nil
		}
	}

	return d.vaultClient.ReadSecret(ctx, path)
}

func synthesizeURL(data map[string]interface{}, path string) (string, bool) {
	// 1. PostgreSQL check
	if db, ok := data["database"]; ok {
		u := "postgres"
		if userVal, ok := data["username"]; ok && userVal != "" {
			u = fmt.Sprintf("%v", userVal)
		}
		p := ""
		if passVal, ok := data["password"]; ok {
			p = fmt.Sprintf("%v", passVal)
		}
		host := "localhost"
		if hostVal, ok := data["host"]; ok && hostVal != "" {
			host = fmt.Sprintf("%v", hostVal)
		}
		port := 5432
		if portVal, ok := data["port"]; ok {
			switch pv := portVal.(type) {
			case int:
				port = pv
			case float64:
				port = int(pv)
			default:
				fmt.Sscanf(fmt.Sprintf("%v", portVal), "%d", &port)
			}
		}
		return fmt.Sprintf("postgresql://%s:%s@%s:%d/%v", u, p, host, port, db), true
	}

	// 2. Redis / Valkey check
	tok := ""
	if tokVal, ok := data["auth_token"]; ok {
		tok = fmt.Sprintf("%v", tokVal)
	} else if passVal, ok := data["password"]; ok {
		tok = fmt.Sprintf("%v", passVal)
	}

	if tok != "" || strings.Contains(path, "redis") || strings.Contains(path, "keyvalue") || strings.Contains(path, "valkey") {
		host := "localhost"
		if hostVal, ok := data["host"]; ok && hostVal != "" {
			host = fmt.Sprintf("%v", hostVal)
		}
		port := 6379
		if portVal, ok := data["port"]; ok {
			switch pv := portVal.(type) {
			case int:
				port = pv
			case float64:
				port = int(pv)
			default:
				fmt.Sscanf(fmt.Sprintf("%v", portVal), "%d", &port)
			}
		}
		return fmt.Sprintf("redis://default:%s@%s:%d", tok, host, port), true
	}

	return "", false
}

func (d *Deployer) resolveGHCRAuth(ctx context.Context) string {
	// 1. Check environment variables, node credentials, or docker config
	if auth := runtime.GetGHCRAuth(); auth != "" {
		return auth
	}

	// 2. Fallback to HashiCorp Vault KV v2 (primecloud/data/github/ghcr) with legacy fallback
	if d.vaultClient != nil {
		data, err := d.vaultClient.ReadSecret(ctx, "primecloud/data/github/ghcr")
		if err != nil || data == nil {
			data, err = d.vaultClient.ReadSecret(ctx, "primecloud/github/ghcr")
		}
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
