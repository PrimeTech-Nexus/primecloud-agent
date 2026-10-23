package backup_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	vaultapi "github.com/hashicorp/vault/api"
	"github.com/primecloud/primecloud-agent/internal/backup"
	"github.com/primecloud/primecloud-agent/internal/vault"
	"github.com/primecloud/primecloud-agent/tests/testenv"
)

func setupTestVault(t *testing.T) *vault.Client {
	t.Helper()
	vClient, _ := testenv.EnsureVaultDev(t)
	raw := vClient.RawClient()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	mounts, err := raw.Sys().ListMountsWithContext(ctx)
	if err == nil {
		if _, ok := mounts["primecloud/"]; ok {
			return vClient
		}
	}
	_ = raw.Sys().MountWithContext(ctx, "primecloud", &vaultapi.MountInput{
		Type: "kv",
	})
	return vClient
}

func TestBackup_EncryptionAndManifest(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	tempDir := t.TempDir()
	sourceDir := filepath.Join(tempDir, "source")
	targetDir := filepath.Join(tempDir, "target")
	_ = os.MkdirAll(sourceDir, 0700)
	_ = os.MkdirAll(targetDir, 0700)

	// 1. Create a dummy artifact (e.g. simulated database dump)
	artifactPath := filepath.Join(sourceDir, "test-database.dump")
	rawContent := []byte("PostgreSQL database dump sample data -- version 16.1")
	if err := os.WriteFile(artifactPath, rawContent, 0600); err != nil {
		t.Fatalf("Failed to create test artifact: %v", err)
	}

	// 2. Generate 32-byte encryption key
	encKey := make([]byte, 32)
	if _, err := rand.Read(encKey); err != nil {
		t.Fatalf("Failed to generate encryption key: %v", err)
	}

	// 3. Test AES-GCM Direct Round Trip
	ciphertext, err := backup.EncryptAESGCM(encKey, rawContent)
	if err != nil {
		t.Fatalf("EncryptAESGCM failed: %v", err)
	}
	decrypted, err := backup.DecryptAESGCM(encKey, ciphertext)
	if err != nil {
		t.Fatalf("DecryptAESGCM failed: %v", err)
	}
	if string(decrypted) != string(rawContent) {
		t.Errorf("Decrypted content mismatch: got %s, want %s", string(decrypted), string(rawContent))
	}

	// 4. Test Packaging & Upload
	uploader := backup.NewUploader(nil)
	manifest, encFile, err := uploader.PackageAndUpload(ctx, "bk-12345", "res-pg-1", "postgres", "node-1", artifactPath, encKey, targetDir)
	if err != nil {
		t.Fatalf("PackageAndUpload failed: %v", err)
	}

	if manifest.OriginalSizeBytes != int64(len(rawContent)) {
		t.Errorf("Manifest size mismatch: got %d, want %d", manifest.OriginalSizeBytes, len(rawContent))
	}
	if manifest.EncryptedSizeBytes <= 0 {
		t.Error("Encrypted size is zero or negative")
	}

	// 5. Test Manifest Save & Load
	manifestPath := filepath.Join(targetDir, "bk-12345.manifest.json")
	loadedManifest, err := backup.LoadManifest(manifestPath)
	if err != nil {
		t.Fatalf("LoadManifest failed: %v", err)
	}
	if loadedManifest.ChecksumSHA256 != manifest.ChecksumSHA256 {
		t.Errorf("Loaded manifest checksum mismatch: got %s, want %s", loadedManifest.ChecksumSHA256, manifest.ChecksumSHA256)
	}

	// 6. Test Integrity Verification
	if err := loadedManifest.VerifyIntegrity(artifactPath); err != nil {
		t.Fatalf("VerifyIntegrity failed on original file: %v", err)
	}

	// Corrupt file and verify detection
	corruptPath := filepath.Join(sourceDir, "corrupted.dump")
	_ = os.WriteFile(corruptPath, []byte("tampered content"), 0600)
	if err := loadedManifest.VerifyIntegrity(corruptPath); err == nil {
		t.Error("Expected VerifyIntegrity to fail on tampered content")
	}

	// 7. Decrypt the staged encrypted file
	encData, err := os.ReadFile(encFile)
	if err != nil {
		t.Fatalf("Failed to read encrypted file: %v", err)
	}
	recovered, err := backup.DecryptAESGCM(encKey, encData)
	if err != nil {
		t.Fatalf("Failed to decrypt staged encrypted file: %v", err)
	}
	if string(recovered) != string(rawContent) {
		t.Errorf("Recovered content mismatch: got %s, want %s", string(recovered), string(rawContent))
	}
}

func TestBackup_VaultManagedKey(t *testing.T) {
	vClient := setupTestVault(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resID := "res-test-vault-key-1"
	key1, err := backup.GetOrCreateBackupKey(ctx, vClient, resID)
	if err != nil {
		t.Fatalf("GetOrCreateBackupKey failed: %v", err)
	}
	if len(key1) != 32 {
		t.Fatalf("Expected 32-byte key, got %d", len(key1))
	}

	// Fetch again via GetOrCreateBackupKey -> should be identical (persistent in Vault)
	key2, err := backup.GetOrCreateBackupKey(ctx, vClient, resID)
	if err != nil {
		t.Fatalf("GetOrCreateBackupKey second call failed: %v", err)
	}
	if !bytes.Equal(key1, key2) {
		t.Error("Expected identical key retrieved from Vault KV on second GetOrCreate call")
	}

	// Fetch via read-only GetBackupKey -> should be identical
	keyRestore, err := backup.GetBackupKey(ctx, vClient, resID)
	if err != nil {
		t.Fatalf("GetBackupKey failed: %v", err)
	}
	if !bytes.Equal(key1, keyRestore) {
		t.Error("Expected GetBackupKey to match key created by GetOrCreateBackupKey")
	}

	// Fetch via full path reference -> should be identical
	keyFullPath, err := backup.GetBackupKey(ctx, vClient, "primecloud/backup-keys/"+resID)
	if err != nil {
		t.Fatalf("GetBackupKey with full path failed: %v", err)
	}
	if !bytes.Equal(key1, keyFullPath) {
		t.Error("Expected GetBackupKey with full path to match original key")
	}
}

func TestBackup_VaultKey_FailClosed_NilClient(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// 1. GetOrCreateBackupKey with nil client must fail closed
	key, err := backup.GetOrCreateBackupKey(ctx, nil, "res-nil-client")
	if err == nil {
		t.Fatal("Expected error with nil vault client in GetOrCreateBackupKey, got nil error")
	}
	if key != nil {
		t.Errorf("Expected nil key on failure, got %d bytes", len(key))
	}
	if !errors.Is(err, vault.ErrVaultUnavailable) {
		t.Errorf("Expected error to wrap vault.ErrVaultUnavailable, got %v", err)
	}
	if !strings.Contains(err.Error(), "vault service is unavailable") {
		t.Errorf("Expected error to contain 'vault service is unavailable', got %v", err)
	}

	// 2. GetBackupKey with nil client must fail closed
	restoreKey, err := backup.GetBackupKey(ctx, nil, "res-nil-client")
	if err == nil {
		t.Fatal("Expected error with nil vault client in GetBackupKey, got nil error")
	}
	if restoreKey != nil {
		t.Errorf("Expected nil key on failure, got %d bytes", len(restoreKey))
	}
	if !errors.Is(err, vault.ErrVaultUnavailable) {
		t.Errorf("Expected error to wrap vault.ErrVaultUnavailable, got %v", err)
	}
	if !strings.Contains(err.Error(), "vault service is unavailable") {
		t.Errorf("Expected error to contain 'vault service is unavailable', got %v", err)
	}
}

func TestBackup_VaultKey_EmptyResourceID(t *testing.T) {
	vClient := setupTestVault(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// GetOrCreateBackupKey with empty resourceID
	key, err := backup.GetOrCreateBackupKey(ctx, vClient, "")
	if err == nil {
		t.Fatal("Expected error for empty resourceID in GetOrCreateBackupKey")
	}
	if key != nil {
		t.Errorf("Expected nil key, got %v", key)
	}

	// GetBackupKey with empty keyRef
	key, err = backup.GetBackupKey(ctx, vClient, "")
	if err == nil {
		t.Fatal("Expected error for empty keyRefOrResourceID in GetBackupKey")
	}
	if key != nil {
		t.Errorf("Expected nil key, got %v", key)
	}
}

func TestBackup_VaultKey_RestoreReadOnly_MissingKey(t *testing.T) {
	vClient := setupTestVault(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	nonExistentResID := "res-definitely-does-not-exist-xyz987"
	key, err := backup.GetBackupKey(ctx, vClient, nonExistentResID)
	if err == nil {
		t.Fatal("Expected GetBackupKey to fail for non-existent key, got nil error")
	}
	if key != nil {
		t.Errorf("Expected nil key, got %v", key)
	}
	expectedMsg := "backup encryption key not found in vault at primecloud/backup-keys/" + nonExistentResID
	if !strings.Contains(err.Error(), expectedMsg) {
		t.Errorf("Expected error to contain %q, got %v", expectedMsg, err)
	}

	// Verify that GetBackupKey did NOT create the secret in Vault (must remain read-only)
	secretData, _ := vClient.ReadSecret(ctx, "primecloud/data/backup-keys/"+nonExistentResID)
	if secretData != nil && secretData["key"] != nil {
		t.Fatal("GetBackupKey must NOT write or generate keys on restore")
	}
	secretDataV1, _ := vClient.ReadSecret(ctx, "primecloud/backup-keys/"+nonExistentResID)
	if secretDataV1 != nil && secretDataV1["key"] != nil {
		t.Fatal("GetBackupKey must NOT write or generate keys on restore")
	}
}

func TestBackup_VaultKey_RoundTripDecryption(t *testing.T) {
	vClient := setupTestVault(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resID := "res-roundtrip-test-42"
	backupKey, err := backup.GetOrCreateBackupKey(ctx, vClient, resID)
	if err != nil {
		t.Fatalf("GetOrCreateBackupKey failed: %v", err)
	}

	payload := []byte("Sensitive database snapshot payload with critical rows")
	ciphertext, err := backup.EncryptAESGCM(backupKey, payload)
	if err != nil {
		t.Fatalf("EncryptAESGCM failed: %v", err)
	}

	// Retrieve key via read-only restore function
	restoreKey, err := backup.GetBackupKey(ctx, vClient, resID)
	if err != nil {
		t.Fatalf("GetBackupKey failed: %v", err)
	}

	plaintext, err := backup.DecryptAESGCM(restoreKey, ciphertext)
	if err != nil {
		t.Fatalf("DecryptAESGCM failed: %v", err)
	}

	if !bytes.Equal(plaintext, payload) {
		t.Errorf("Decrypted payload mismatch: got %s, want %s", string(plaintext), string(payload))
	}
}

func TestBackup_VaultKey_CorruptedKeyDetection(t *testing.T) {
	vClient := setupTestVault(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resID := "res-corrupted-key-test"
	vaultPath := "primecloud/data/backup-keys/" + resID

	// Write invalid/corrupted key (e.g. truncated key: 8 bytes instead of 32)
	err := vClient.WriteSecret(ctx, vaultPath, map[string]interface{}{
		"key":        "deadbeef01020304", // 8 bytes only
		"algorithm":  "AES-256-GCM",
		"created_at": time.Now().UTC().Format(time.RFC3339),
	})
	if err != nil {
		vaultPath = "primecloud/backup-keys/" + resID
		err = vClient.WriteSecret(ctx, vaultPath, map[string]interface{}{
			"key":        "deadbeef01020304",
			"algorithm":  "AES-256-GCM",
			"created_at": time.Now().UTC().Format(time.RFC3339),
		})
	}
	if err != nil {
		t.Fatalf("Failed to write corrupted key for test: %v", err)
	}

	// GetBackupKey must reject corrupted key
	key, err := backup.GetBackupKey(ctx, vClient, resID)
	if err == nil {
		t.Fatal("Expected GetBackupKey to fail on corrupted key, got nil error")
	}
	if key != nil {
		t.Errorf("Expected nil key on corruption, got %v", key)
	}

	// GetOrCreateBackupKey must also reject corrupted key rather than returning it
	key2, err := backup.GetOrCreateBackupKey(ctx, vClient, resID)
	if err == nil {
		t.Fatal("Expected GetOrCreateBackupKey to fail on corrupted key, got nil error")
	}
	if key2 != nil {
		t.Errorf("Expected nil key on corruption, got %v", key2)
	}
}

func TestBackup_VaultKey_FailClosed_Unauthenticated(t *testing.T) {
	vClient := setupTestVault(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Create unauthenticated client pointing to valid vault dev server
	unauthClient, err := vault.NewClient(vault.Config{
		Address: vClient.RawClient().Address(),
		Token:   "", // empty token and no AppRole credentials
	})
	if err != nil {
		t.Fatalf("Failed to create unauthenticated vault client: %v", err)
	}

	// 1. GetOrCreateBackupKey must fail closed without token
	key, err := backup.GetOrCreateBackupKey(ctx, unauthClient, "res-unauth-test")
	if err == nil {
		t.Fatal("Expected error with unauthenticated vault client in GetOrCreateBackupKey, got nil error")
	}
	if key != nil {
		t.Errorf("Expected nil key, got %v", key)
	}
	if !errors.Is(err, vault.ErrUnauthenticated) {
		t.Errorf("Expected error to wrap vault.ErrUnauthenticated, got %v", err)
	}

	// 2. GetBackupKey must fail closed without token
	restoreKey, err := backup.GetBackupKey(ctx, unauthClient, "res-unauth-test")
	if err == nil {
		t.Fatal("Expected error with unauthenticated vault client in GetBackupKey, got nil error")
	}
	if restoreKey != nil {
		t.Errorf("Expected nil key, got %v", restoreKey)
	}
	if !errors.Is(err, vault.ErrUnauthenticated) {
		t.Errorf("Expected error to wrap vault.ErrUnauthenticated, got %v", err)
	}
}

func TestBackup_VaultKey_FailClosed_UnreachableVault(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	badClient, err := vault.NewClient(vault.Config{
		Address: "http://127.0.0.1:1",
		Timeout: 500 * time.Millisecond,
		Token:   "dummy-token",
	})
	if err != nil {
		t.Fatalf("Failed to create vault client: %v", err)
	}

	key, err := backup.GetOrCreateBackupKey(ctx, badClient, "res-bad-vault")
	if err == nil {
		t.Fatal("Expected error with unreachable vault in GetOrCreateBackupKey, got nil error")
	}
	if key != nil {
		t.Errorf("Expected nil key, got %v", key)
	}
	if !errors.Is(err, vault.ErrVaultUnavailable) {
		t.Errorf("Expected error to wrap vault.ErrVaultUnavailable, got %v", err)
	}
	if !strings.Contains(err.Error(), "vault service is unavailable") {
		t.Errorf("Expected error message to contain 'vault service is unavailable', got %v", err)
	}

	restoreKey, err := backup.GetBackupKey(ctx, badClient, "res-bad-vault")
	if err == nil {
		t.Fatal("Expected error with unreachable vault in GetBackupKey, got nil error")
	}
	if restoreKey != nil {
		t.Errorf("Expected nil key, got %v", restoreKey)
	}
	if !errors.Is(err, vault.ErrVaultUnavailable) {
		t.Errorf("Expected error to wrap vault.ErrVaultUnavailable, got %v", err)
	}
	if !strings.Contains(err.Error(), "vault service is unavailable") {
		t.Errorf("Expected error message to contain 'vault service is unavailable', got %v", err)
	}
}


