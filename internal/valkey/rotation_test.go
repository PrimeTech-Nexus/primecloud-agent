package valkey

import (
	"context"
	"testing"
)

func TestVaultPath(t *testing.T) {
	projectID := "proj-kv-1"
	resourceID := "res-kv-2"
	expected := "secret/data/primecloud/tenants/proj-kv-1/keyvalue/res-kv-2"
	if got := VaultPath(projectID, resourceID); got != expected {
		t.Fatalf("expected vault path %s, got %s", expected, got)
	}
}

func TestInternalHost(t *testing.T) {
	resourceID := "res-kv-3"
	expected := "valkey-res-kv-3.internal.primecloud"
	if got := InternalHost(resourceID); got != expected {
		t.Fatalf("expected internal host %s, got %s", expected, got)
	}
}

func TestGenerateToken(t *testing.T) {
	t1, err := generateToken()
	if err != nil {
		t.Fatalf("failed to generate token: %v", err)
	}
	if len(t1) != 64 { // 32 bytes hex encoded = 64 chars = 256 bits
		t.Fatalf("expected 64 hex characters (256 bits), got %d chars", len(t1))
	}
	t2, err := generateToken()
	if err != nil {
		t.Fatalf("failed to generate second token: %v", err)
	}
	if t1 == t2 {
		t.Fatalf("tokens should be cryptographically unique")
	}
}

func TestConnectionURL(t *testing.T) {
	creds := &Credentials{
		AuthToken: "test-auth-token-12345",
		Port:      6379,
	}
	host := "valkey-test.internal.primecloud"
	expected := "redis://default:test-auth-token-12345@valkey-test.internal.primecloud:6379/0"
	if got := ConnectionURL(creds, host); got != expected {
		t.Fatalf("expected connection URL %s, got %s", expected, got)
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
