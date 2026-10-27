// Package recovery coordinates artifact decryption, integrity verification, and workload state reconstruction.
package recovery

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/primecloud/primecloud-agent/internal/backup"
	"github.com/primecloud/primecloud-agent/internal/mongodb"
	"github.com/primecloud/primecloud-agent/internal/mysql"
	"github.com/primecloud/primecloud-agent/internal/postgres"
	agentruntime "github.com/primecloud/primecloud-agent/internal/runtime"
	"github.com/primecloud/primecloud-agent/internal/valkey"
	"github.com/primecloud/primecloud-agent/internal/vault"
)

// Reconstructor orchestrates decryption and restoration of backup artifacts.
type Reconstructor struct {
	rt                  agentruntime.ContainerRuntime
	logger              *slog.Logger
	targetContainerName string
	targetMode          string
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

// WithTarget configures the Reconstructor with target container name and target mode.
func (r *Reconstructor) WithTarget(targetContainerName, targetMode string) *Reconstructor {
	r.targetContainerName = targetContainerName
	r.targetMode = targetMode
	return r
}

// RestoreSafetyConfig holds safety parameters for restore dispatching.
type RestoreSafetyConfig struct {
	TargetMode       string
	TargetContainer  string
	ConfirmOverwrite bool
	ResourceID       string
}

// ValidateRestoreSafety validates security constraints for disaster recovery restores (AC-1.1, AC-1.3, AC-1.9, AC-1.14).
func ValidateRestoreSafety(cfg RestoreSafetyConfig) error {
	mode := strings.ToUpper(strings.TrimSpace(cfg.TargetMode))
	if mode == "" {
		mode = "NEW_INSTANCE"
	}

	if mode == "IN_PLACE_OVERWRITE" {
		if !cfg.ConfirmOverwrite {
			return fmt.Errorf("OVERWRITE_CONFIRMATION_REQUIRED: in-place overwrite restore rejected without explicit confirm_overwrite=true")
		}
		return nil
	}

	if mode == "NEW_INSTANCE" {
		targetName := strings.TrimSpace(cfg.TargetContainer)
		if targetName == "" {
			return fmt.Errorf("TARGET_CONTAINER_REQUIRED: new instance restore requires non-empty target_container_name")
		}

		resID := strings.TrimSpace(cfg.ResourceID)
		sourceContainers := []string{
			resID,
			fmt.Sprintf("pc-pg-%s", resID),
			fmt.Sprintf("pc-my-%s", resID),
			fmt.Sprintf("pc-mg-%s", resID),
			fmt.Sprintf("pc-vk-%s", resID),
		}
		for _, sc := range sourceContainers {
			if targetName == sc {
				return fmt.Errorf("TARGET_CONTAINER_INVALID: cannot substitute source container %s as target in NEW_INSTANCE mode", targetName)
			}
		}
		return nil
	}

	return fmt.Errorf("TARGET_MODE_INVALID: unknown target restore mode: %q", mode)
}

// ReconstructArtifact decrypts the encrypted backup file via streaming DecryptStream and verifies its checksum against the manifest.
func (r *Reconstructor) ReconstructArtifact(ctx context.Context, encryptedPath, manifestPath string, encKey []byte, outputDir string) (string, *backup.Manifest, error) {
	manifest, err := backup.LoadManifest(manifestPath)
	if err != nil || manifest == nil {
		return "", nil, fmt.Errorf("MANIFEST_NOT_FOUND: required manifest file missing or unreadable at %s: %w", manifestPath, err)
	}
	if strings.TrimSpace(manifest.ChecksumSHA256) == "" {
		return "", nil, fmt.Errorf("MANIFEST_INVALID: manifest is missing required plaintext checksum_sha256")
	}

	encFile, errRead := os.Open(encryptedPath)
	if errRead != nil {
		return "", nil, fmt.Errorf("failed to open encrypted backup file: %w", errRead)
	}
	defer encFile.Close()

	encStat, errStat := encFile.Stat()
	if errStat != nil {
		return "", nil, fmt.Errorf("failed to stat encrypted backup file: %w", errStat)
	}
	if encStat.Size() == 0 {
		return "", nil, fmt.Errorf("encrypted backup file is empty")
	}

	if err := os.MkdirAll(outputDir, 0700); err != nil {
		return "", nil, fmt.Errorf("failed to create output directory: %w", err)
	}

	ext := ".dump"
	resType := "postgres"
	resID := strings.TrimSuffix(filepath.Base(encryptedPath), filepath.Ext(encryptedPath))
	if manifest != nil {
		resType = manifest.ResourceType
		if manifest.ResourceID != "" {
			resID = manifest.ResourceID
		}
	}
	if resType == "valkey" || resType == "keyvalue" || resType == "redis" || resType == "cache" {
		ext = ".rdb"
	} else if resType == "volume" {
		ext = ".tar"
	} else if resType == "mysql" || resType == "mysql_instance" {
		ext = ".sql"
	} else if resType == "mongodb" || resType == "mongo" || resType == "mongodb_instance" {
		ext = ".archive.gz"
	}
	restoredPath := filepath.Join(outputDir, fmt.Sprintf("%s%s", resID, ext))

	restoredFile, errCreate := os.OpenFile(restoredPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if errCreate != nil {
		return "", nil, fmt.Errorf("failed to create decrypted artifact file: %w", errCreate)
	}

	errDecrypt := backup.DecryptStream(encKey, encFile, restoredFile)
	restoredFile.Close()
	if errDecrypt != nil {
		_ = os.Remove(restoredPath)
		return "", nil, fmt.Errorf("failed to decrypt backup artifact: %w", errDecrypt)
	}

	// Immediate post-decryption plaintext integrity verification
	if manifest != nil && manifest.ChecksumSHA256 != "" {
		actualHash, _, hashErr := backup.ComputeSHA256(restoredPath)
		if hashErr != nil {
			_ = os.Remove(restoredPath)
			return "", nil, fmt.Errorf("failed to compute hash of decrypted plaintext artifact: %w", hashErr)
		}
		if !strings.EqualFold(actualHash, manifest.ChecksumSHA256) {
			_ = os.Remove(restoredPath)
			return "", nil, fmt.Errorf("CHECKSUM_MISMATCH: post-decryption plaintext checksum mismatch: expected %s, got %s", manifest.ChecksumSHA256, actualHash)
		}
	}

	r.logger.Info("artifact_reconstructed_successfully", "resource_id", manifest.ResourceID, "path", restoredPath)
	return restoredPath, manifest, nil
}

// RestoreToWorkload applies the reconstructed artifact to the corresponding database/service.
func (r *Reconstructor) RestoreToWorkload(ctx context.Context, manifest *backup.Manifest, artifactPath string, targetOpts ...string) error {
	targetContainerName := r.targetContainerName
	if len(targetOpts) > 0 && targetOpts[0] != "" {
		targetContainerName = targetOpts[0]
	}
	r.logger.Info("restoring_to_workload", "resource_id", manifest.ResourceID, "type", manifest.ResourceType, "target_container", targetContainerName)

	switch manifest.ResourceType {
	case "postgres", "postgresql", "postgres_instance", "database", "db":
		return postgres.RestorePostgres(ctx, r.rt, manifest.ResourceID, artifactPath, targetContainerName)
	case "valkey", "keyvalue", "redis", "cache":
		return valkey.RestoreValkey(ctx, r.rt, manifest.ResourceID, artifactPath, targetContainerName)
	case "mysql", "mysql_instance":
		return mysql.RestoreMySQL(ctx, r.rt, manifest.ResourceID, artifactPath, targetContainerName)
	case "mongodb", "mongo", "mongodb_instance":
		return mongodb.RestoreMongoDB(ctx, r.rt, manifest.ResourceID, artifactPath, targetContainerName)
	default:
		r.logger.Error("unsupported_resource_type_restore_failed", "resource_id", manifest.ResourceID, "type", manifest.ResourceType)
		return &UnsupportedResourceTypeError{
			ResourceType: manifest.ResourceType,
			ResourceID:   manifest.ResourceID,
		}
	}
}

// RestoreToWorkloadWithVault applies the reconstructed artifact to the database/service using Vault credentials and configuration.
func (r *Reconstructor) RestoreToWorkloadWithVault(ctx context.Context, manifest *backup.Manifest, artifactPath string, vClient *vault.Client, baseResDir, projectID string, targetOpts ...string) error {
	targetContainerName := r.targetContainerName
	targetMode := r.targetMode
	if len(targetOpts) > 0 && targetOpts[0] != "" {
		targetContainerName = targetOpts[0]
	}
	if len(targetOpts) > 1 && targetOpts[1] != "" {
		targetMode = targetOpts[1]
	}
	r.logger.Info("restoring_to_workload", "resource_id", manifest.ResourceID, "type", manifest.ResourceType, "target_container", targetContainerName, "target_mode", targetMode)

	switch manifest.ResourceType {
	case "postgres", "postgresql", "postgres_instance", "database", "db":
		return postgres.RestorePostgresWithVault(ctx, r.rt, vClient, projectID, manifest.ResourceID, artifactPath, targetContainerName)
	case "valkey", "keyvalue", "redis", "cache":
		return valkey.RestoreValkeyWithVault(ctx, r.rt, vClient, baseResDir, projectID, manifest.ResourceID, artifactPath, targetContainerName)
	case "mysql", "mysql_instance":
		return mysql.RestoreMySQLWithVault(ctx, r.rt, vClient, projectID, manifest.ResourceID, artifactPath, targetContainerName)
	case "mongodb", "mongo", "mongodb_instance":
		return mongodb.RestoreMongoDBWithVault(ctx, r.rt, vClient, projectID, manifest.ResourceID, artifactPath, targetContainerName)
	default:
		r.logger.Error("unsupported_resource_type_restore_failed", "resource_id", manifest.ResourceID, "type", manifest.ResourceType)
		return &UnsupportedResourceTypeError{
			ResourceType: manifest.ResourceType,
			ResourceID:   manifest.ResourceID,
		}
	}
}
