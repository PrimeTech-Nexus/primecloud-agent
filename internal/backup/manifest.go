// Package backup orchestrates node-level backup artifact packaging, encryption, manifests, and secure upload.
package backup

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"
)

// Manifest defines the authoritative integrity, encryption, and provenance record for a backup.
type Manifest struct {
	BackupID           string            `json:"backup_id"`
	ResourceID         string            `json:"resource_id"`
	ResourceType       string            `json:"resource_type"`
	Algorithm          string            `json:"algorithm"`
	ChecksumSHA256     string            `json:"checksum_sha256"`
	OriginalSizeBytes  int64             `json:"original_size_bytes"`
	EncryptedSizeBytes int64             `json:"encrypted_size_bytes"`
	CreatedAt          time.Time         `json:"created_at"`
	NodeID             string            `json:"node_id"`
	Metadata           map[string]string `json:"metadata,omitempty"`
}

// ComputeSHA256 calculates the hex SHA-256 digest of a file on disk.
func ComputeSHA256(filePath string) (string, int64, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", 0, fmt.Errorf("failed to open file for hashing: %w", err)
	}
	defer file.Close()

	hasher := sha256.New()
	size, err := io.Copy(hasher, file)
	if err != nil {
		return "", 0, fmt.Errorf("failed to compute hash: %w", err)
	}

	return hex.EncodeToString(hasher.Sum(nil)), size, nil
}

// CreateManifest computes hashes and constructs a Manifest for an encrypted artifact.
func CreateManifest(backupID, resourceID, resourceType, nodeID, origPath string, encryptedBytes []byte) (*Manifest, error) {
	hash, origSize, err := ComputeSHA256(origPath)
	if err != nil {
		return nil, err
	}

	return &Manifest{
		BackupID:           backupID,
		ResourceID:         resourceID,
		ResourceType:       resourceType,
		Algorithm:          "AES-256-GCM",
		ChecksumSHA256:     hash,
		OriginalSizeBytes:  origSize,
		EncryptedSizeBytes: int64(len(encryptedBytes)),
		CreatedAt:          time.Now(),
		NodeID:             nodeID,
		Metadata:           make(map[string]string),
	}, nil
}

// SaveManifest writes the manifest JSON to disk.
func SaveManifest(m *Manifest, filePath string) error {
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal manifest: %w", err)
	}
	return os.WriteFile(filePath, data, 0644)
}

// LoadManifest reads and parses a manifest JSON from disk.
func LoadManifest(filePath string) (*Manifest, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read manifest file: %w", err)
	}
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("failed to unmarshal manifest: %w", err)
	}
	return &m, nil
}

// VerifyIntegrity confirms that a decrypted artifact matches the original manifest checksum and size.
func (m *Manifest) VerifyIntegrity(filePath string) error {
	hash, size, err := ComputeSHA256(filePath)
	if err != nil {
		return fmt.Errorf("failed to verify integrity: %w", err)
	}

	if size != m.OriginalSizeBytes {
		return fmt.Errorf("size mismatch: manifest=%d, actual=%d", m.OriginalSizeBytes, size)
	}

	if hash != m.ChecksumSHA256 {
		return fmt.Errorf("checksum mismatch: manifest=%s, actual=%s", m.ChecksumSHA256, hash)
	}

	return nil
}
