// Package backup orchestrates node-level backup artifact packaging, encryption, manifests, and secure upload.
package backup

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/primecloud/primecloud-agent/internal/vault"
)

// toVaultPaths resolves both the KV-v2 API path and the logical KV-v1 path.
func toVaultPaths(keyRefOrResourceID string) (kv2Path string, logicalPath string) {
	cleaned := strings.TrimPrefix(keyRefOrResourceID, "/")
	if strings.HasPrefix(cleaned, "primecloud/data/backup-keys/") {
		kv2Path = cleaned
		logicalPath = "primecloud/backup-keys/" + strings.TrimPrefix(cleaned, "primecloud/data/backup-keys/")
		return kv2Path, logicalPath
	}
	if strings.HasPrefix(cleaned, "primecloud/backup-keys/") {
		logicalPath = cleaned
		kv2Path = "primecloud/data/backup-keys/" + strings.TrimPrefix(cleaned, "primecloud/backup-keys/")
		return kv2Path, logicalPath
	}
	logicalPath = fmt.Sprintf("primecloud/backup-keys/%s", cleaned)
	kv2Path = fmt.Sprintf("primecloud/data/backup-keys/%s", cleaned)
	return kv2Path, logicalPath
}

// GetOrCreateBackupKey retrieves a resource encryption key from Vault KV or generates a new 32-byte key.
// It fails closed if Vault is unavailable, unsealed, or unauthenticated; it never falls back to an ephemeral key.
func GetOrCreateBackupKey(ctx context.Context, vClient *vault.Client, resourceID string) ([]byte, error) {
	if resourceID == "" {
		return nil, fmt.Errorf("resource_id cannot be empty")
	}

	if vClient == nil {
		return nil, fmt.Errorf("%w: vault service is unavailable", vault.ErrVaultUnavailable)
	}

	if healthy, err := vClient.IsHealthy(ctx); err != nil || !healthy {
		return nil, fmt.Errorf("%w: vault service is unavailable or sealed: %v", vault.ErrVaultUnavailable, err)
	}

	if err := vClient.EnsureAuthenticated(ctx); err != nil {
		return nil, fmt.Errorf("%w: %v", vault.ErrUnauthenticated, err)
	}

	kv2Path, logicalPath := toVaultPaths(resourceID)

	// Attempt read from KV-v2 path first, then fallback to logical path (KV-v1)
	secretData, err := vClient.ReadSecret(ctx, kv2Path)
	if err != nil || secretData == nil {
		if sV1, errV1 := vClient.ReadSecret(ctx, logicalPath); errV1 == nil && sV1 != nil {
			secretData = sV1
		}
	}

	if secretData != nil && secretData["key"] != nil {
		if keyHex, ok := secretData["key"].(string); ok && keyHex != "" {
			keyBytes, decErr := hex.DecodeString(keyHex)
			if decErr == nil && len(keyBytes) == 32 {
				return keyBytes, nil
			}
			if decErr != nil || len(keyBytes) != 32 {
				return nil, fmt.Errorf("corrupted backup encryption key in vault at %s: invalid hex or length", logicalPath)
			}
		}
	}

	// Generate high-entropy 256-bit AES key
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("failed to generate random encryption key: %w", err)
	}

	payload := map[string]interface{}{
		"key":        hex.EncodeToString(key),
		"algorithm":  "AES-256-GCM",
		"created_at": time.Now().UTC().Format(time.RFC3339),
	}

	// Attempt write to KV-v2 path; fallback to logical path if KV-v1
	writeErr := vClient.WriteSecret(ctx, kv2Path, payload)
	if writeErr != nil {
		writeErr = vClient.WriteSecret(ctx, logicalPath, payload)
	}
	if writeErr != nil {
		return nil, fmt.Errorf("failed to store backup encryption key in vault: %w", writeErr)
	}

	return key, nil
}

// GetBackupKey retrieves an existing backup encryption key from Vault KV in read-only mode for decryption/restore.
// It fails closed if Vault is unavailable, sealed, unauthenticated, or if the key does not exist.
// It never generates replacement keys or writes to Vault during restore.
func GetBackupKey(ctx context.Context, vClient *vault.Client, keyRefOrResourceID string) ([]byte, error) {
	if keyRefOrResourceID == "" {
		return nil, fmt.Errorf("key reference or resource_id cannot be empty")
	}

	if vClient == nil {
		return nil, fmt.Errorf("%w: vault service is unavailable", vault.ErrVaultUnavailable)
	}

	if healthy, err := vClient.IsHealthy(ctx); err != nil || !healthy {
		return nil, fmt.Errorf("%w: vault service is unavailable or sealed: %v", vault.ErrVaultUnavailable, err)
	}

	if err := vClient.EnsureAuthenticated(ctx); err != nil {
		return nil, fmt.Errorf("%w: %v", vault.ErrUnauthenticated, err)
	}

	kv2Path, logicalPath := toVaultPaths(keyRefOrResourceID)

	// Attempt read from KV-v2 path first, then fallback to logical path
	secretData, err := vClient.ReadSecret(ctx, kv2Path)
	if err != nil || secretData == nil {
		if sV1, errV1 := vClient.ReadSecret(ctx, logicalPath); errV1 == nil && sV1 != nil {
			secretData = sV1
		}
	}

	if secretData == nil || secretData["key"] == nil {
		return nil, fmt.Errorf("backup encryption key not found in vault at %s", logicalPath)
	}

	keyHex, ok := secretData["key"].(string)
	if !ok || keyHex == "" {
		return nil, fmt.Errorf("backup encryption key not found in vault at %s", logicalPath)
	}

	keyBytes, decErr := hex.DecodeString(keyHex)
	if decErr != nil || len(keyBytes) != 32 {
		return nil, fmt.Errorf("backup encryption key not found in vault at %s", logicalPath)
	}

	return keyBytes, nil
}
