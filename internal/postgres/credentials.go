package postgres

import (
	"context"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/primecloud/primecloud-agent/internal/vault"
)

// Canonical Managed Data credential contract for PostgreSQL.
//
// Vault is the single source of truth. The canonical path is:
//
//	secret/data/primecloud/tenants/{project_id}/postgres/{resource_id}
//
// No other Vault path holds PostgreSQL credentials.

const (
	// DefaultPort is the PostgreSQL port inside the managed-data network.
	DefaultPort = 5432
	// passwordEntropyBytes yields 256 bits of entropy (64 hex chars).
	passwordEntropyBytes = 32
	// scramIterations matches the PostgreSQL server default for SCRAM-SHA-256.
	scramIterations = 4096
)

// ErrCredentialsNotFound is returned when no credential secret exists for a resource.
var ErrCredentialsNotFound = errors.New("postgres credentials not found in vault")

// ErrCredentialsMalformed is returned when the stored secret is missing required fields.
var ErrCredentialsMalformed = errors.New("postgres credentials in vault are malformed")

// VaultPath returns the canonical Vault KV v2 path for a PostgreSQL resource.
func VaultPath(projectID, resourceID string) string {
	return fmt.Sprintf("secret/data/primecloud/tenants/%s/postgres/%s", projectID, resourceID)
}

// InternalHost returns the canonical Phase 2 internal DNS hostname.
func InternalHost(resourceID string) string {
	return fmt.Sprintf("postgres-%s.internal.primecloud", resourceID)
}

// LegacyHost returns the legacy container-name host label.
func LegacyHost(resourceID string) string {
	return fmt.Sprintf("pc-pg-%s", resourceID)
}

// ConnectionURL builds the DATABASE_URL. The result contains the password and
// must never be logged or returned outside the authorized credential contract.
func ConnectionURL(creds *Credentials, host string) string {
	return fmt.Sprintf("postgresql://%s:%s@%s:%d/%s", creds.Username, creds.Password, host, creds.Port, creds.Database)
}

// generatePassword returns a cryptographically random hex password.
func generatePassword() (string, error) {
	b := make([]byte, passwordEntropyBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate random password: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// secretData renders the canonical Vault payload. host is the legacy label kept
// for backward compatibility; url carries the authoritative connection host.
func secretData(creds *Credentials, resourceID, urlHost string) map[string]interface{} {
	return map[string]interface{}{
		"username": creds.Username,
		"password": creds.Password,
		"database": creds.Database,
		"host":     LegacyHost(resourceID),
		"port":     creds.Port,
		"url":      ConnectionURL(creds, urlHost),
	}
}

// ReadCredentials reads the canonical credential secret. It fails closed: no
// defaults, no fallbacks, no synthesized values.
func ReadCredentials(ctx context.Context, vClient *vault.Client, projectID, resourceID string) (*Credentials, error) {
	if vClient == nil {
		return nil, fmt.Errorf("vault client is not configured")
	}
	if projectID == "" || resourceID == "" {
		return nil, fmt.Errorf("project_id and resource_id are required to resolve postgres credentials")
	}
	secret, err := vClient.ReadSecret(ctx, VaultPath(projectID, resourceID))
	if err != nil {
		return nil, fmt.Errorf("vault read failed for postgres resource %s: %w", resourceID, err)
	}
	if secret == nil {
		return nil, ErrCredentialsNotFound
	}
	user, _ := secret["username"].(string)
	pw, _ := secret["password"].(string)
	db, _ := secret["database"].(string)
	if user == "" || pw == "" || db == "" {
		return nil, ErrCredentialsMalformed
	}
	port := DefaultPort
	switch p := secret["port"].(type) {
	case float64:
		port = int(p)
	case int:
		port = p
	}
	return &Credentials{Username: user, Password: pw, Database: db, Port: port}, nil
}

// scramSHA256Verifier computes a PostgreSQL SCRAM-SHA-256 password verifier.
//
// Sending the verifier (instead of the plaintext) in ALTER ROLE guarantees the
// plaintext password never reaches the database server, its statement logs, or
// error logs. Format (RFC 5803 / PostgreSQL):
//
//	SCRAM-SHA-256$<iterations>:<salt>$<StoredKey>:<ServerKey>
func scramSHA256Verifier(password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("failed to generate scram salt: %w", err)
	}
	return scramSHA256VerifierWithSalt(password, salt, scramIterations)
}

func scramSHA256VerifierWithSalt(password string, salt []byte, iterations int) (string, error) {
	salted, err := pbkdf2.Key(sha256.New, password, salt, iterations, sha256.Size)
	if err != nil {
		return "", fmt.Errorf("pbkdf2 derivation failed: %w", err)
	}
	clientKey := hmacSHA256(salted, []byte("Client Key"))
	storedKey := sha256.Sum256(clientKey)
	serverKey := hmacSHA256(salted, []byte("Server Key"))
	enc := base64.StdEncoding
	return fmt.Sprintf("SCRAM-SHA-256$%d:%s$%s:%s",
		iterations, enc.EncodeToString(salt), enc.EncodeToString(storedKey[:]), enc.EncodeToString(serverKey)), nil
}

func hmacSHA256(key, msg []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(msg)
	return m.Sum(nil)
}
