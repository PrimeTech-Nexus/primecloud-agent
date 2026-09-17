package backup_test

import (
	"context"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/primecloud/primecloud-agent/internal/backup"
	"github.com/primecloud/primecloud-agent/tests/testenv"
)

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
	vClient, _ := testenv.EnsureVaultDev(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	key1, err := backup.GetOrCreateBackupKey(ctx, vClient, "res-test-vault-key-1")
	if err != nil {
		t.Fatalf("GetOrCreateBackupKey failed: %v", err)
	}
	if len(key1) != 32 {
		t.Fatalf("Expected 32-byte key, got %d", len(key1))
	}

	// Fetch again -> should be identical (persistent in Vault)
	key2, err := backup.GetOrCreateBackupKey(ctx, vClient, "res-test-vault-key-1")
	if err != nil {
		t.Fatalf("GetOrCreateBackupKey second call failed: %v", err)
	}
	if string(key1) != string(key2) {
		t.Error("Expected identical key retrieved from Vault KV")
	}
}
