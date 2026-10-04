package postgres

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVaultPath(t *testing.T) {
	projectID := "proj-123"
	resourceID := "res-456"
	expected := "secret/data/primecloud/tenants/proj-123/postgres/res-456"
	if got := VaultPath(projectID, resourceID); got != expected {
		t.Fatalf("expected vault path %s, got %s", expected, got)
	}
}

func TestInternalHost(t *testing.T) {
	resourceID := "res-789"
	expected := "postgres-res-789.internal.primecloud"
	if got := InternalHost(resourceID); got != expected {
		t.Fatalf("expected internal host %s, got %s", expected, got)
	}
}

func TestGeneratePassword(t *testing.T) {
	p1, err := generatePassword()
	if err != nil {
		t.Fatalf("failed to generate password: %v", err)
	}
	if len(p1) != 64 { // 32 bytes hex encoded = 64 chars = 256 bits
		t.Fatalf("expected 64 hex characters (256 bits), got %d chars", len(p1))
	}
	p2, err := generatePassword()
	if err != nil {
		t.Fatalf("failed to generate second password: %v", err)
	}
	if p1 == p2 {
		t.Fatalf("passwords should be cryptographically unique")
	}
}

func TestScramSHA256Verifier(t *testing.T) {
	password := "test-password-12345"
	verifier, err := scramSHA256Verifier(password)
	if err != nil {
		t.Fatalf("failed to compute scram verifier: %v", err)
	}
	// SCRAM verifier format: SCRAM-SHA-256$<iterations>:<salt>$<storedkey>:<serverkey>
	if !strings.HasPrefix(verifier, "SCRAM-SHA-256$4096:") {
		t.Fatalf("expected SCRAM-SHA-256$4096 prefix, got %s", verifier)
	}
	parts := strings.Split(verifier, "$")
	if len(parts) != 3 {
		t.Fatalf("expected 3 parts separated by $, got %d", len(parts))
	}
}

func TestReadCredentialsNilClientFailsClosed(t *testing.T) {
	ctx := context.Background()
	_, err := ReadCredentials(ctx, nil, "proj-1", "res-1")
	if err == nil {
		t.Fatal("expected error with nil vault client, got nil")
	}
}

func TestReadCredentialsEmptyIDsFailsClosed(t *testing.T) {
	ctx := context.Background()
	_, err := ReadCredentials(ctx, nil, "", "")
	if err == nil {
		t.Fatal("expected error with empty IDs, got nil")
	}
}

func TestEnsurePostgresDataDir(t *testing.T) {
	tempDir := t.TempDir()
	volumePath := filepath.Join(tempDir, "postgres", "test-res-123")

	if err := ensurePostgresDataDir(volumePath); err != nil {
		t.Fatalf("ensurePostgresDataDir failed: %v", err)
	}

	// Verify volumePath exists
	info, err := os.Stat(volumePath)
	if err != nil {
		t.Fatalf("volume directory not created: %v", err)
	}
	if !info.IsDir() {
		t.Fatalf("volume path is not a directory")
	}

	// Verify pgdata subdirectory exists
	pgdata := filepath.Join(volumePath, "pgdata")
	pgInfo, err := os.Stat(pgdata)
	if err != nil {
		t.Fatalf("pgdata directory not created: %v", err)
	}
	if !pgInfo.IsDir() {
		t.Fatalf("pgdata path is not a directory")
	}
}

