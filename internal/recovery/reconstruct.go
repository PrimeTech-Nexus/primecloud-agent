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
func (r *Reconstructor) RestoreToWorkload(ctx context.Context, manifest *backup.Manifest, artifactPath string) error {
	r.logger.Info("restoring_to_workload", "resource_id", manifest.ResourceID, "type", manifest.ResourceType)

	switch manifest.ResourceType {
	case "postgres", "postgresql", "postgres_instance", "database", "db":
		return postgres.RestorePostgres(ctx, r.rt, manifest.ResourceID, artifactPath)
	case "valkey", "keyvalue", "redis", "cache":
		return valkey.RestoreValkey(ctx, r.rt, manifest.ResourceID, artifactPath)
	case "mysql", "mysql_instance":
		return mysql.RestoreMySQL(ctx, r.rt, manifest.ResourceID, artifactPath)
	case "mongodb", "mongo", "mongodb_instance":
		return mongodb.RestoreMongoDB(ctx, r.rt, manifest.ResourceID, artifactPath)
	default:
		r.logger.Error("unsupported_resource_type_restore_failed", "resource_id", manifest.ResourceID, "type", manifest.ResourceType)
		return &UnsupportedResourceTypeError{
			ResourceType: manifest.ResourceType,
			ResourceID:   manifest.ResourceID,
		}
	}
}

// RestoreToWorkloadWithVault applies the reconstructed artifact to the database/service using Vault credentials and configuration.
func (r *Reconstructor) RestoreToWorkloadWithVault(ctx context.Context, manifest *backup.Manifest, artifactPath string, vClient *vault.Client, baseResDir, projectID string) error {
	r.logger.Info("restoring_to_workload", "resource_id", manifest.ResourceID, "type", manifest.ResourceType)

	switch manifest.ResourceType {
	case "postgres", "postgresql", "postgres_instance", "database", "db":
		return postgres.RestorePostgresWithVault(ctx, r.rt, vClient, projectID, manifest.ResourceID, artifactPath)
	case "valkey", "keyvalue", "redis", "cache":
		return valkey.RestoreValkeyWithVault(ctx, r.rt, vClient, baseResDir, projectID, manifest.ResourceID, artifactPath)
	case "mysql", "mysql_instance":
		return mysql.RestoreMySQLWithVault(ctx, r.rt, vClient, projectID, manifest.ResourceID, artifactPath)
	case "mongodb", "mongo", "mongodb_instance":
		return mongodb.RestoreMongoDBWithVault(ctx, r.rt, vClient, projectID, manifest.ResourceID, artifactPath)
	default:
		r.logger.Error("unsupported_resource_type_restore_failed", "resource_id", manifest.ResourceID, "type", manifest.ResourceType)
		return &UnsupportedResourceTypeError{
			ResourceType: manifest.ResourceType,
			ResourceID:   manifest.ResourceID,
		}
	}
}
