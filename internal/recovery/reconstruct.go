// Package recovery coordinates artifact decryption, integrity verification, and workload state reconstruction.
package recovery

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/primecloud/primecloud-agent/internal/backup"
	"github.com/primecloud/primecloud-agent/internal/postgres"
	agentruntime "github.com/primecloud/primecloud-agent/internal/runtime"
	"github.com/primecloud/primecloud-agent/internal/valkey"
	"github.com/primecloud/primecloud-agent/internal/vault"
)

// Reconstructor orchestrates decryption and restoration of backup artifacts.
type Reconstructor struct {
	rt     agentruntime.ContainerRuntime
	logger *slog.Logger
}

// NewReconstructor constructs a Reconstructor.
func NewReconstructor(rt agentruntime.ContainerRuntime, logger *slog.Logger) *Reconstructor {
	if logger == nil {
		logger = slog.Default()
	}
	return &Reconstructor{
		rt:     rt,
		logger: logger.With("component", "reconstructor"),
	}
}

// ReconstructArtifact decrypts the encrypted backup file and verifies its checksum against the manifest.
func (r *Reconstructor) ReconstructArtifact(ctx context.Context, encryptedPath, manifestPath string, encKey []byte, outputDir string) (string, *backup.Manifest, error) {
	manifest, err := backup.LoadManifest(manifestPath)
	if err != nil {
		return "", nil, fmt.Errorf("failed to load manifest: %w", err)
	}

	ciphertext, err := os.ReadFile(encryptedPath)
	if err != nil {
		return "", nil, fmt.Errorf("failed to read encrypted backup file: %w", err)
	}

	plaintext, err := backup.DecryptAESGCM(encKey, ciphertext)
	if err != nil {
		return "", nil, fmt.Errorf("failed to decrypt backup artifact: %w", err)
	}

	if err := os.MkdirAll(outputDir, 0700); err != nil {
		return "", nil, fmt.Errorf("failed to create output directory: %w", err)
	}

	ext := ".dump"
	if manifest.ResourceType == "valkey" {
		ext = ".rdb"
	}
	restoredPath := filepath.Join(outputDir, fmt.Sprintf("%s%s", manifest.ResourceID, ext))

	if err := os.WriteFile(restoredPath, plaintext, 0600); err != nil {
		return "", nil, fmt.Errorf("failed to write decrypted artifact: %w", err)
	}

	// Immediate post-decryption integrity verification
	if err := manifest.VerifyIntegrity(restoredPath); err != nil {
		_ = os.Remove(restoredPath)
		return "", nil, fmt.Errorf("post-decryption integrity verification failed: %w", err)
	}

	r.logger.Info("artifact_reconstructed_successfully", "resource_id", manifest.ResourceID, "path", restoredPath)
	return restoredPath, manifest, nil
}

// RestoreToWorkload applies the reconstructed artifact to the corresponding database/service.
func (r *Reconstructor) RestoreToWorkload(ctx context.Context, manifest *backup.Manifest, artifactPath string) error {
	r.logger.Info("restoring_to_workload", "resource_id", manifest.ResourceID, "type", manifest.ResourceType)

	switch manifest.ResourceType {
	case "postgres":
		return postgres.RestorePostgres(ctx, r.rt, manifest.ResourceID, artifactPath)
	case "valkey", "keyvalue":
		return valkey.RestoreValkey(ctx, r.rt, manifest.ResourceID, artifactPath)
	default:
		r.logger.Info("generic_workload_restored", "resource_id", manifest.ResourceID)
		return nil
	}
}

// RestoreToWorkloadWithVault applies the reconstructed artifact to the database/service using Vault credentials and configuration.
func (r *Reconstructor) RestoreToWorkloadWithVault(ctx context.Context, manifest *backup.Manifest, artifactPath string, vClient *vault.Client, baseResDir, projectID string) error {
	r.logger.Info("restoring_to_workload", "resource_id", manifest.ResourceID, "type", manifest.ResourceType)

	switch manifest.ResourceType {
	case "postgres":
		return postgres.RestorePostgresWithVault(ctx, r.rt, vClient, projectID, manifest.ResourceID, artifactPath)
	case "valkey", "keyvalue":
		return valkey.RestoreValkeyWithVault(ctx, r.rt, vClient, baseResDir, projectID, manifest.ResourceID, artifactPath)
	default:
		r.logger.Info("generic_workload_restored", "resource_id", manifest.ResourceID)
		return nil
	}
}

