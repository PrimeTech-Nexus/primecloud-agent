// Package backup orchestrates node-level backup artifact packaging, encryption, manifests, and secure upload.
package backup

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/primecloud/primecloud-agent/internal/vault"
)

// GetOrCreateBackupKey retrieves a resource encryption key from Vault KV or generates a new 32-byte key.
func GetOrCreateBackupKey(ctx context.Context, vClient *vault.Client, resourceID string) ([]byte, error) {
	if resourceID == "" {
		return nil, fmt.Errorf("resource_id cannot be empty")
	}

	vaultPath := fmt.Sprintf("primecloud/backup-keys/%s", resourceID)

	if vClient != nil {
		secretData, err := vClient.ReadSecret(ctx, vaultPath)
		if err == nil && secretData != nil && secretData["key"] != nil {
			if keyHex, ok := secretData["key"].(string); ok {
				keyBytes, decErr := hex.DecodeString(keyHex)
				if decErr == nil && len(keyBytes) == 32 {
					return keyBytes, nil
				}
			}
		}
	}

	// Generate high-entropy 256-bit AES key
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("failed to generate random encryption key: %w", err)
	}

	if vClient != nil {
		err := vClient.WriteSecret(ctx, vaultPath, map[string]interface{}{
			"key":        hex.EncodeToString(key),
			"algorithm":  "AES-256-GCM",
			"created_at": time.Now().UTC().Format(time.RFC3339),
		})
		if err != nil {
			return nil, fmt.Errorf("failed to store backup encryption key in vault: %w", err)
		}
	}

	return key, nil
}
