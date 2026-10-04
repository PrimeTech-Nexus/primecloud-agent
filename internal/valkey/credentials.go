package valkey

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/primecloud/primecloud-agent/internal/vault"
)

// Canonical Managed Data credential contract for Valkey / Key-Value.
//
// Vault is the single source of truth. The canonical path is:
//
//	secret/data/primecloud/tenants/{project_id}/keyvalue/{resource_id}
//
// No other Vault path holds Valkey credentials.

const (
	// DefaultPort is the Valkey/Redis port inside the managed-data network.
	DefaultPort = 6379
	// tokenEntropyBytes yields 256 bits of entropy (64 hex chars).
	tokenEntropyBytes = 32
)

// ErrCredentialsNotFound is returned when no credential secret exists for a resource.
var ErrCredentialsNotFound = errors.New("valkey credentials not found in vault")

// ErrCredentialsMalformed is returned when the stored secret is missing required fields.
var ErrCredentialsMalformed = errors.New("valkey credentials in vault are malformed")

// VaultPath returns the canonical Vault KV v2 path for a Valkey resource.
func VaultPath(projectID, resourceID string) string {
	return fmt.Sprintf("secret/data/primecloud/tenants/%s/keyvalue/%s", projectID, resourceID)
}

// InternalHost returns the canonical Phase 2 internal DNS hostname.
func InternalHost(resourceID string) string {
	return fmt.Sprintf("valkey-%s.internal.primecloud", resourceID)
}

// LegacyHost returns the legacy container-name host label.
func LegacyHost(resourceID string) string {
	return fmt.Sprintf("pc-vk-%s", resourceID)
}

// ConnectionURL builds the REDIS_URL. The result contains the auth token and
// must never be logged or returned outside the authorized credential contract.
func ConnectionURL(creds *Credentials, host string) string {
	return fmt.Sprintf("redis://default:%s@%s:%d/0", creds.AuthToken, host, creds.Port)
}

// generateToken returns a cryptographically random 256-bit hex auth token.
func generateToken() (string, error) {
	b := make([]byte, tokenEntropyBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate random token: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// secretData renders the canonical Vault payload. host is the legacy label kept
// for backward compatibility; url carries the authoritative connection host.
func secretData(creds *Credentials, resourceID, urlHost string) map[string]interface{} {
	return map[string]interface{}{
		"username":   "default",
		"password":   creds.AuthToken,
		"auth_token": creds.AuthToken,
		"host":       LegacyHost(resourceID),
		"port":       creds.Port,
		"url":        ConnectionURL(creds, urlHost),
	}
}

// ReadCredentials reads the canonical credential secret. It fails closed: no
// defaults, no fallbacks, no synthesized values.
func ReadCredentials(ctx context.Context, vClient *vault.Client, projectID, resourceID string) (*Credentials, error) {
	if vClient == nil {
		return nil, fmt.Errorf("vault client is not configured")
	}
	if projectID == "" || resourceID == "" {
		return nil, fmt.Errorf("project_id and resource_id are required to resolve valkey credentials")
	}
	secret, err := vClient.ReadSecret(ctx, VaultPath(projectID, resourceID))
	if err != nil {
		return nil, fmt.Errorf("vault read failed for valkey resource %s: %w", resourceID, err)
	}
	if secret == nil {
		return nil, ErrCredentialsNotFound
	}
	token, _ := secret["auth_token"].(string)
	if token == "" {
		token, _ = secret["password"].(string)
	}
	if token == "" {
		return nil, ErrCredentialsMalformed
	}
	port := DefaultPort
	switch p := secret["port"].(type) {
	case float64:
		port = int(p)
	case int:
		port = p
	}
	return &Credentials{AuthToken: token, Port: port}, nil
}
