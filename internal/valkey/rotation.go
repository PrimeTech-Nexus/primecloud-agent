package valkey

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/primecloud/primecloud-agent/internal/runtime"
	"github.com/primecloud/primecloud-agent/internal/vault"
)

// RotationResult describes the outcome of a Valkey credential rotation.
// Secrets are never included in JSON output.
type RotationResult struct {
	ResourceID     string `json:"resource_id"`
	ProjectID      string `json:"project_id"`
	VaultSecretRef string `json:"vault_secret_ref"`
	ContainerID    string `json:"container_id,omitempty"`
	Synchronized   bool   `json:"synchronized"`
}

// Rotator orchestrates zero-downtime Valkey credential rotation.
type Rotator struct {
	rt          runtime.ContainerRuntime
	vaultClient *vault.Client
	logger      *slog.Logger
}

// NewRotator constructs a Valkey Rotator.
func NewRotator(rt runtime.ContainerRuntime, vaultClient *vault.Client, logger *slog.Logger) *Rotator {
	if logger == nil {
		logger = slog.Default()
	}
	return &Rotator{
		rt:          rt,
		vaultClient: vaultClient,
		logger:      logger.With("component", "valkey_rotator"),
	}
}

// Rotate updates the Valkey service live with CONFIG SET requirepass and
// CONFIG REWRITE (via authenticated valkey-cli/redis-cli with old token),
// then commits the new token to Vault and dual-writes legacy paths.
//
// If the container is not running, the new token is still persisted to Vault
// and will be applied on next start via the --requirepass argument.
func (r *Rotator) Rotate(ctx context.Context, projectID, environmentID, resourceID string) (*RotationResult, error) {
	if resourceID == "" {
		return nil, fmt.Errorf("resource_id cannot be empty for valkey rotation")
	}
	if projectID == "" {
		projectID = "default"
	}

	r.logger.Info("valkey_credential_rotation_started",
		"project_id", projectID,
		"resource_id", resourceID,
	)

	// 1. Read existing credential metadata (auth_token) from Vault.
	oldCreds, err := ReadCredentials(ctx, r.vaultClient, projectID, resourceID)
	if err != nil {
		r.logger.Error("valkey_credential_rotation_failed",
			"stage", "read_existing",
			"resource_id", resourceID,
			"error", err,
		)
		return nil, fmt.Errorf("failed to read existing valkey credentials: %w", err)
	}

	// 2. Generate a new 256-bit auth token.
	newToken, err := generateToken()
	if err != nil {
		return nil, fmt.Errorf("failed generating new valkey token: %w", err)
	}

	newCreds := &Credentials{
		AuthToken: newToken,
		Port:      oldCreds.Port,
	}

	// 3. Synchronize the live Valkey service via CONFIG SET requirepass.
	containerName := LegacyHost(resourceID)
	synchronized := false

	if r.rt != nil {
		inspect, err := r.rt.InspectContainer(ctx, containerName)
		if err == nil && inspect != nil && inspect.Running {
			// Try valkey-cli first, then redis-cli. Pass old credentials to authenticate.
			cliBins := []string{"valkey-cli", "redis-cli"}
			var lastErr error
			var syncSuccess bool

			for _, bin := range cliBins {
				// Step 3a: Update in-memory password live
				setCmd := []string{bin}
				if oldCreds.AuthToken != "" {
					setCmd = append(setCmd, "-a", oldCreds.AuthToken)
				}
				setCmd = append(setCmd, "CONFIG", "SET", "requirepass", newCreds.AuthToken)

				stdout, stderr, exitCode, execErr := r.rt.ExecContainer(ctx, containerName, setCmd, nil, nil)
				if execErr != nil {
					lastErr = fmt.Errorf("%s exec failed: %w", bin, execErr)
					continue
				}
				if exitCode != 0 {
					lastErr = fmt.Errorf("%s CONFIG SET failed with exit code %d: %s",
						bin, exitCode, strings.TrimSpace(string(stderr)))
					continue
				}
				if !strings.Contains(strings.ToUpper(string(stdout)), "OK") {
					lastErr = fmt.Errorf("%s CONFIG SET unexpected output: %s", bin, strings.TrimSpace(string(stdout)))
					continue
				}

				// Step 3b: Persist config to disk if supported by container configuration
				rewriteCmd := []string{bin, "-a", newCreds.AuthToken, "CONFIG", "REWRITE"}
				_, _, _, _ = r.rt.ExecContainer(ctx, containerName, rewriteCmd, nil, nil)

				// Step 3c: Verify new token responds to PING
				pingCmd := []string{bin, "-a", newCreds.AuthToken, "ping"}
				pStdout, _, pCode, pErr := r.rt.ExecContainer(ctx, containerName, pingCmd, nil, nil)
				if pErr == nil && pCode == 0 && strings.Contains(strings.ToUpper(string(pStdout)), "PONG") {
					syncSuccess = true
					break
				}
			}

			if !syncSuccess && lastErr != nil {
				r.logger.Error("valkey_credential_rotation_failed",
					"stage", "service_sync",
					"resource_id", resourceID,
					"error", lastErr,
				)
				return nil, fmt.Errorf("failed to synchronize live valkey credentials: %w", lastErr)
			}

			synchronized = syncSuccess
			r.logger.Info("valkey_service_credential_synchronized",
				"resource_id", resourceID,
				"container", containerName,
			)
		}
	}

	// 4. Update Vault with the new credentials.
	urlHost := InternalHost(resourceID)
	if environmentID == "" {
		urlHost = LegacyHost(resourceID)
	}

	data := secretData(newCreds, resourceID, urlHost)
	tenantPath := VaultPath(projectID, resourceID)
	if r.vaultClient != nil {
		if err := r.vaultClient.WriteSecret(ctx, tenantPath, data); err != nil {
			r.logger.Error("valkey_credential_rotation_failed",
				"stage", "vault_write",
				"resource_id", resourceID,
				"error", err,
			)
			return nil, fmt.Errorf("failed persisting rotated valkey credentials to vault (%s): %w", tenantPath, err)
		}
		r.logger.Info("valkey_rotated_credentials_stored_in_vault", "vault_ref", tenantPath)

		// Dual-write redis compatibility path
		redisCompatPath := fmt.Sprintf("secret/data/primecloud/tenants/%s/redis/%s", projectID, resourceID)
		if err := r.vaultClient.WriteSecret(ctx, redisCompatPath, data); err != nil {
			r.logger.Warn("valkey_rotated_credentials_redis_compat_vault_write_failed",
				"vault_ref", redisCompatPath,
				"error", err,
			)
		}

		// Dual-write legacy compatibility path
		compatPath := fmt.Sprintf("primecloud/resources/valkey/%s", resourceID)
		if err := r.vaultClient.WriteSecret(ctx, compatPath, data); err != nil {
			r.logger.Warn("valkey_rotated_credentials_compat_vault_write_failed",
				"vault_ref", compatPath,
				"error", err,
			)
		}
	}

	r.logger.Info("valkey_credential_rotation_completed",
		"project_id", projectID,
		"resource_id", resourceID,
		"synchronized", synchronized,
	)

	return &RotationResult{
		ResourceID:     resourceID,
		ProjectID:      projectID,
		VaultSecretRef: tenantPath,
		ContainerID:    containerName,
		Synchronized:   synchronized,
	}, nil
}
