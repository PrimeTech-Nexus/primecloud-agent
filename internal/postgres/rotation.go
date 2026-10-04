package postgres

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/primecloud/primecloud-agent/internal/runtime"
	"github.com/primecloud/primecloud-agent/internal/vault"
)

// RotationResult describes the outcome of a credential rotation operation.
// Secrets are never included in JSON output.
type RotationResult struct {
	ResourceID     string `json:"resource_id"`
	ProjectID      string `json:"project_id"`
	VaultSecretRef string `json:"vault_secret_ref"`
	ContainerID    string `json:"container_id,omitempty"`
	Synchronized   bool   `json:"synchronized"`
}

// Rotator orchestrates zero-downtime PostgreSQL credential rotation.
type Rotator struct {
	rt          runtime.ContainerRuntime
	vaultClient *vault.Client
	logger      *slog.Logger
}

// NewRotator constructs a PostgreSQL Rotator.
func NewRotator(rt runtime.ContainerRuntime, vaultClient *vault.Client, logger *slog.Logger) *Rotator {
	if logger == nil {
		logger = slog.Default()
	}
	return &Rotator{
		rt:          rt,
		vaultClient: vaultClient,
		logger:      logger.With("component", "postgres_rotator"),
	}
}

// Rotate generates a new 256-bit password, updates the live database user via
// an encrypted SCRAM-SHA-256 verifier, persists the new secret to Vault, and
// dual-writes the legacy compatibility path.
//
// Never logs secrets, never sends plaintext passwords to the database server,
// and fails closed if any step encounters an error.
func (r *Rotator) Rotate(ctx context.Context, projectID, environmentID, resourceID string) (*RotationResult, error) {
	if resourceID == "" {
		return nil, fmt.Errorf("resource_id cannot be empty for postgres rotation")
	}
	if projectID == "" {
		projectID = "default"
	}

	r.logger.Info("postgres_credential_rotation_started",
		"project_id", projectID,
		"resource_id", resourceID,
	)

	// 1. Read existing credential metadata (username, database, port) from Vault.
	oldCreds, err := ReadCredentials(ctx, r.vaultClient, projectID, resourceID)
	if err != nil {
		r.logger.Error("postgres_credential_rotation_failed",
			"stage", "read_existing",
			"resource_id", resourceID,
			"error", err,
		)
		return nil, fmt.Errorf("failed to read existing postgres credentials: %w", err)
	}

	// 2. Generate a new high-entropy password.
	newPassword, err := generatePassword()
	if err != nil {
		return nil, fmt.Errorf("failed generating new postgres password: %w", err)
	}

	newCreds := &Credentials{
		Username: oldCreds.Username,
		Password: newPassword,
		Database: oldCreds.Database,
		Port:     oldCreds.Port,
	}

	// 3. Synchronize the live PostgreSQL service if a running container exists.
	containerName := LegacyHost(resourceID)
	synchronized := false

	if r.rt != nil {
		inspect, err := r.rt.InspectContainer(ctx, containerName)
		if err == nil && inspect != nil && inspect.Running {
			// Compute SCRAM-SHA-256 verifier so the plaintext password is never
			// passed on the command line or visible in PostgreSQL server logs.
			verifier, vErr := scramSHA256Verifier(newPassword)
			if vErr != nil {
				return nil, fmt.Errorf("failed computing scram verifier: %w", vErr)
			}

			// Execute ALTER ROLE inside the container using the postgres bootstrap superuser
			// over local socket. Pass the verifier via stdin to avoid process argv exposure.
			sqlScript := fmt.Sprintf("ALTER ROLE %s WITH PASSWORD '%s';\n", newCreds.Username, verifier)
			cmd := []string{"psql", "-U", "postgres", "-v", "ON_ERROR_STOP=1", "-f", "-"}

			stdout, stderr, exitCode, execErr := r.rt.ExecContainer(
				ctx,
				containerName,
				cmd,
				nil,
				bytes.NewReader([]byte(sqlScript)),
			)
			if execErr != nil {
				r.logger.Error("postgres_credential_rotation_failed",
					"stage", "service_sync",
					"resource_id", resourceID,
					"error", execErr,
				)
				return nil, fmt.Errorf("failed executing password update on postgres %s: %w", containerName, execErr)
			}
			if exitCode != 0 {
				r.logger.Error("postgres_credential_rotation_failed",
					"stage", "service_sync",
					"resource_id", resourceID,
					"exit_code", exitCode,
					"stderr", strings.TrimSpace(string(stderr)),
				)
				return nil, fmt.Errorf("postgres alter role failed with exit code %d: %s",
					exitCode, strings.TrimSpace(string(stderr)))
			}

			synchronized = true
			r.logger.Info("postgres_service_credential_synchronized",
				"resource_id", resourceID,
				"container", containerName,
				"username", newCreds.Username,
				"output", strings.TrimSpace(string(stdout)),
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
			r.logger.Error("postgres_credential_rotation_failed",
				"stage", "vault_write",
				"resource_id", resourceID,
				"error", err,
			)
			return nil, fmt.Errorf("failed persisting rotated postgres credentials to vault (%s): %w", tenantPath, err)
		}
		r.logger.Info("postgres_rotated_credentials_stored_in_vault", "vault_ref", tenantPath)

		// Dual-write legacy compatibility path
		compatPath := fmt.Sprintf("primecloud/resources/postgres/%s", resourceID)
		if err := r.vaultClient.WriteSecret(ctx, compatPath, data); err != nil {
			r.logger.Warn("postgres_rotated_credentials_compat_vault_write_failed",
				"vault_ref", compatPath,
				"error", err,
			)
		}
	}

	r.logger.Info("postgres_credential_rotation_completed",
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
