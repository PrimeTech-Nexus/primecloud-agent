package backup

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/primecloud/primecloud-agent/internal/vault"
)

func TestGetOrCreateBackupKey_NilClient_FailsClosed(t *testing.T) {
	ctx := context.Background()
	_, err := GetOrCreateBackupKey(ctx, nil, "res-1234")
	if err == nil {
		t.Fatal("expected error with nil vault client, got nil")
	}
	if !errors.Is(err, vault.ErrVaultUnavailable) {
		t.Fatalf("expected ErrVaultUnavailable, got %v", err)
	}
}

func TestGetOrCreateBackupKey_EmptyResourceID_FailsClosed(t *testing.T) {
	ctx := context.Background()
	cfg := vault.Config{
		Address: "http://127.0.0.1:8200",
		Token:   "test-token",
	}
	client, err := vault.NewClient(cfg)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	_, err = GetOrCreateBackupKey(ctx, client, "")
	if err == nil {
		t.Fatal("expected error with empty resourceID, got nil")
	}
}

func TestGetOrCreateBackupKey_UnreachableVault_FailsClosed(t *testing.T) {
	ctx := context.Background()
	// Deliberately unreachable port
	cfg := vault.Config{
		Address: "http://127.0.0.1:59999",
		Token:   "test-token",
	}
	client, err := vault.NewClient(cfg)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	_, err = GetOrCreateBackupKey(ctx, client, "res-test-unreachable")
	if err == nil {
		t.Fatal("expected error with unreachable vault, got nil")
	}
	if !errors.Is(err, vault.ErrVaultUnavailable) {
		t.Fatalf("expected ErrVaultUnavailable, got %v", err)
	}
}

func TestGetOrCreateBackupKey_ExistingKey_ReturnsKey(t *testing.T) {
	ctx := context.Background()
	expectedKey := make([]byte, 32)
	for i := range expectedKey {
		expectedKey[i] = byte(i + 1)
	}
	expectedHex := hex.EncodeToString(expectedKey)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/sys/health" {
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"initialized": true, "sealed": false})
			return
		}

		// Read secret
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"key": expectedHex,
			},
		})
	}))
	defer server.Close()

	client, err := vault.NewClient(vault.Config{
		Address: server.URL,
		Token:   "test-token",
	})
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	key, err := GetOrCreateBackupKey(ctx, client, "res-existing")
	if err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}
	if hex.EncodeToString(key) != expectedHex {
		t.Fatalf("expected key %s, got %s", expectedHex, hex.EncodeToString(key))
	}
}

func TestGetOrCreateBackupKey_CorruptKey_FailsClosed(t *testing.T) {
	ctx := context.Background()
	// Key that is not 32 bytes (only 8 bytes)
	badHex := hex.EncodeToString([]byte("shortkey"))

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/sys/health" {
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"initialized": true, "sealed": false})
			return
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"key": badHex,
			},
		})
	}))
	defer server.Close()

	client, err := vault.NewClient(vault.Config{
		Address: server.URL,
		Token:   "test-token",
	})
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	_, err = GetOrCreateBackupKey(ctx, client, "res-corrupt")
	if err == nil {
		t.Fatal("expected error on corrupt key, got nil")
	}
}

func TestGetOrCreateBackupKey_NewKeyGenerationAndWrite(t *testing.T) {
	ctx := context.Background()
	var writtenKeyHex string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/sys/health" {
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"initialized": true, "sealed": false})
			return
		}

		if r.Method == http.MethodGet {
			// Secret not found
			w.WriteHeader(http.StatusNotFound)
			return
		}

		if r.Method == http.MethodPut || r.Method == http.MethodPost {
			var body map[string]interface{}
			_ = json.NewDecoder(r.Body).Decode(&body)
			if nested, ok := body["data"].(map[string]interface{}); ok {
				if k, ok := nested["key"].(string); ok {
					writtenKeyHex = k
				}
			} else if k, ok := body["key"].(string); ok {
				writtenKeyHex = k
			}
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"data": map[string]interface{}{"version": 1}})
			return
		}
	}))
	defer server.Close()

	client, err := vault.NewClient(vault.Config{
		Address: server.URL,
		Token:   "test-token",
	})
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	key, err := GetOrCreateBackupKey(ctx, client, "res-brand-new")
	if err != nil {
		t.Fatalf("expected key creation success, got error: %v", err)
	}
	if len(key) != 32 {
		t.Fatalf("expected 32-byte key, got length %d", len(key))
	}
	if hex.EncodeToString(key) != writtenKeyHex {
		t.Fatalf("key returned %x does not match key written to vault %s", key, writtenKeyHex)
	}
}

func TestGetOrCreateBackupKey_WriteFailure_FailsClosed(t *testing.T) {
	ctx := context.Background()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/sys/health" {
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"initialized": true, "sealed": false})
			return
		}

		if r.Method == http.MethodGet {
			// Secret not found
			w.WriteHeader(http.StatusNotFound)
			return
		}

		// Write fails with 500 Internal Server Error
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"errors": []string{"storage backend error"}})
	}))
	defer server.Close()

	client, err := vault.NewClient(vault.Config{
		Address: server.URL,
		Token:   "test-token",
	})
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	_, err = GetOrCreateBackupKey(ctx, client, "res-fail-write")
	if err == nil {
		t.Fatal("expected error when vault write fails, got nil")
	}
}
