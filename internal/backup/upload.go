// Package backup orchestrates node-level backup artifact packaging, encryption, manifests, and secure upload.
package backup

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
)

// EncryptAESGCM encrypts plaintext using standard authenticated AES-256-GCM.
func EncryptAESGCM(key, plaintext []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("AES-256 requires 32-byte key, got %d bytes", len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Ciphertext contains nonce + sealed data + tag
	sealed := gcm.Seal(nonce, nonce, plaintext, nil)
	return sealed, nil
}

// DecryptAESGCM decrypts AES-GCM ciphertext using the provided 32-byte key.
func DecryptAESGCM(key, ciphertext []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("AES-256 requires 32-byte key, got %d bytes", len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, actualCiphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, actualCiphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt ciphertext: %w", err)
	}

	return plaintext, nil
}

// Uploader coordinates local artifact packaging, AES-256-GCM encryption, and staging/upload.
type Uploader struct {
	logger *slog.Logger
}

// NewUploader constructs an Uploader instance.
func NewUploader(logger *slog.Logger) *Uploader {
	if logger == nil {
		logger = slog.Default()
	}
	return &Uploader{logger: logger.With("component", "backup_uploader")}
}

// PackageAndUpload encrypts the local artifact, creates an integrity manifest, and stores it in destination.
func (u *Uploader) PackageAndUpload(ctx context.Context, backupID, resourceID, resourceType, nodeID, artifactPath string, encKey []byte, targetDir string) (*Manifest, string, error) {
	u.logger.Info("packaging_backup_starting", "backup_id", backupID, "resource_id", resourceID)

	data, err := os.ReadFile(artifactPath)
	if err != nil {
		return nil, "", fmt.Errorf("failed to read artifact for upload: %w", err)
	}

	encrypted, err := EncryptAESGCM(encKey, data)
	if err != nil {
		return nil, "", fmt.Errorf("failed to encrypt artifact: %w", err)
	}

	manifest, err := CreateManifest(backupID, resourceID, resourceType, nodeID, artifactPath, encrypted)
	if err != nil {
		return nil, "", fmt.Errorf("failed to create manifest: %w", err)
	}

	if err := os.MkdirAll(targetDir, 0700); err != nil {
		return nil, "", fmt.Errorf("failed to create target upload directory: %w", err)
	}

	encFile := filepath.Join(targetDir, fmt.Sprintf("%s.enc", backupID))
	if err := os.WriteFile(encFile, encrypted, 0600); err != nil {
		return nil, "", fmt.Errorf("failed to write encrypted backup: %w", err)
	}

	manifestFile := filepath.Join(targetDir, fmt.Sprintf("%s.manifest.json", backupID))
	if err := SaveManifest(manifest, manifestFile); err != nil {
		_ = os.Remove(encFile)
		return nil, "", fmt.Errorf("failed to write backup manifest: %w", err)
	}

	u.logger.Info("packaging_backup_completed", "backup_id", backupID, "encrypted_file", encFile, "manifest_file", manifestFile)
	return manifest, encFile, nil
}
