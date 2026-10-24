// Package backup orchestrates node-level backup artifact packaging, encryption, manifests, and secure upload.
package backup

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// ChunkSize defines the 4MB bounded memory chunk size for AES-256-GCM streaming encryption.
const ChunkSize = 4 * 1024 * 1024

// EncryptStream encrypts r in 4MB chunks using AES-256-GCM framing:
// [4-byte big-endian payload length][12-byte nonce][ciphertext][16-byte tag]
// mirroring primecloud-control-plane/services/backup/encryption.py:115-178.
// It computes running SHA-256 of plaintext and returns:
// plainSHA256, origSize, encSize, err.
func EncryptStream(key []byte, r io.Reader, w io.Writer) (string, int64, int64, error) {
	if len(key) != 32 {
		return "", 0, 0, fmt.Errorf("AES-256 requires 32-byte key, got %d bytes", len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", 0, 0, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", 0, 0, fmt.Errorf("failed to create GCM: %w", err)
	}

	plainHasher := sha256.New()
	buf := make([]byte, ChunkSize)
	var origSize int64
	var encSize int64

	var lenBuf [4]byte

	for {
		n, rErr := io.ReadFull(r, buf)
		if n > 0 {
			origSize += int64(n)
			plainHasher.Write(buf[:n])

			nonce := make([]byte, gcm.NonceSize())
			if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
				return "", 0, 0, fmt.Errorf("failed to generate random nonce: %w", err)
			}

			// gcm.Seal appends ciphertext + 16-byte tag to dst (nonce)
			chunkPayload := gcm.Seal(nonce, nonce, buf[:n], nil)
			payloadLen := uint32(len(chunkPayload))

			binary.BigEndian.PutUint32(lenBuf[:], payloadLen)
			if _, err := w.Write(lenBuf[:]); err != nil {
				return "", 0, 0, fmt.Errorf("failed writing chunk length: %w", err)
			}
			if _, err := w.Write(chunkPayload); err != nil {
				return "", 0, 0, fmt.Errorf("failed writing chunk payload: %w", err)
			}

			encSize += int64(4 + payloadLen)
		}

		if rErr == io.EOF || rErr == io.ErrUnexpectedEOF {
			break
		}
		if rErr != nil {
			return "", 0, 0, fmt.Errorf("failed reading stream for encryption: %w", rErr)
		}
	}

	plainSHA256 := hex.EncodeToString(plainHasher.Sum(nil))
	return plainSHA256, origSize, encSize, nil
}

// DecryptStream streamingly decrypts an AES-256-GCM encrypted stream from r to w.
// It supports 4MB chunked framing as well as unchunked legacy fallback.
func DecryptStream(key []byte, r io.Reader, w io.Writer) error {
	if len(key) != 32 {
		return fmt.Errorf("AES-256 requires 32-byte key, got %d bytes", len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("failed to create GCM: %w", err)
	}

	rs, isSeeker := r.(io.ReadSeeker)
	if !isSeeker {
		allBytes, err := io.ReadAll(r)
		if err != nil {
			return fmt.Errorf("failed reading stream for decryption: %w", err)
		}
		rs = bytes.NewReader(allBytes)
	}

	// 1. Try chunked framing
	var lenBuf [4]byte
	n, err := io.ReadFull(rs, lenBuf[:])
	if err == io.EOF {
		return nil // Empty file
	}

	if n == 4 {
		firstLen := binary.BigEndian.Uint32(lenBuf[:])
		// Minimum chunk payload: 12 (nonce) + 16 (tag) = 28 bytes
		if firstLen >= 28 {
			chunkPayload := make([]byte, firstLen)
			if _, err := io.ReadFull(rs, chunkPayload); err == nil {
				nonce := chunkPayload[:12]
				rawCiphertext := chunkPayload[12:]
				plaintext, decErr := gcm.Open(nil, nonce, rawCiphertext, nil)
				if decErr == nil {
					if _, err := w.Write(plaintext); err != nil {
						return fmt.Errorf("failed writing decrypted chunk: %w", err)
					}

					// Successfully verified first chunk framing. Continue reading all remaining chunks.
					for {
						n, err := io.ReadFull(rs, lenBuf[:])
						if err == io.EOF {
							return nil
						}
						if err != nil {
							return fmt.Errorf("unexpected EOF reading chunk length header: %w", err)
						}
						if n < 4 {
							return fmt.Errorf("corrupt chunk length header")
						}
						chunkLen := binary.BigEndian.Uint32(lenBuf[:])
						if chunkLen < 28 {
							return fmt.Errorf("corrupt chunk: length %d less than 28 bytes", chunkLen)
						}
						payload := make([]byte, chunkLen)
						if _, err := io.ReadFull(rs, payload); err != nil {
							return fmt.Errorf("unexpected EOF reading chunk payload: %w", err)
						}
						cNonce := payload[:12]
						cCipher := payload[12:]
						cPlain, cErr := gcm.Open(nil, cNonce, cCipher, nil)
						if cErr != nil {
							return fmt.Errorf("failed decrypting chunk: %w", cErr)
						}
						if _, err := w.Write(cPlain); err != nil {
							return fmt.Errorf("failed writing decrypted chunk: %w", err)
						}
					}
				}
			}
		}
	}

	// 2. Fallback for unchunked legacy payload (12-byte nonce + ciphertext + 16-byte tag)
	if _, err := rs.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("failed seeking stream for legacy decryption fallback: %w", err)
	}

	nonceSize := gcm.NonceSize()
	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(rs, nonce); err != nil {
		return fmt.Errorf("ciphertext too short: %w", err)
	}

	rawCiphertext, err := io.ReadAll(rs)
	if err != nil {
		return fmt.Errorf("failed reading legacy ciphertext: %w", err)
	}

	plaintext, err := gcm.Open(nil, nonce, rawCiphertext, nil)
	if err != nil {
		return fmt.Errorf("failed to decrypt ciphertext: %w", err)
	}

	if _, err := w.Write(plaintext); err != nil {
		return fmt.Errorf("failed writing legacy decrypted plaintext: %w", err)
	}

	return nil
}

// EncryptAESGCM encrypts plaintext using standard authenticated AES-256-GCM (legacy slice helper).
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
	var buf bytes.Buffer
	reader := bytes.NewReader(ciphertext)
	if err := DecryptStream(key, reader, &buf); err == nil {
		return buf.Bytes(), nil
	}

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

// PackageAndUpload streamingly encrypts the local artifact via io.Pipe in 4MB chunks,
// creates an integrity manifest, and stores the encrypted backup in targetDir.
func (u *Uploader) PackageAndUpload(ctx context.Context, backupID, resourceID, resourceType, nodeID, artifactPath string, encKey []byte, targetDir string) (*Manifest, string, error) {
	u.logger.Info("packaging_backup_starting", "backup_id", backupID, "resource_id", resourceID)

	srcFile, err := os.Open(artifactPath)
	if err != nil {
		return nil, "", fmt.Errorf("failed to read artifact for upload: %w", err)
	}
	defer srcFile.Close()

	if err := os.MkdirAll(targetDir, 0700); err != nil {
		return nil, "", fmt.Errorf("failed to create target upload directory: %w", err)
	}

	encFile := filepath.Join(targetDir, fmt.Sprintf("%s.enc", backupID))
	dstFile, err := os.OpenFile(encFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return nil, "", fmt.Errorf("failed to create encrypted backup: %w", err)
	}
	defer dstFile.Close()

	// Use io.Pipe for streaming encryption
	pr, pw := io.Pipe()

	var plainSHA256 string
	var origSize int64
	var encErr error

	go func() {
		defer pw.Close()
		plainSHA256, origSize, _, encErr = EncryptStream(encKey, srcFile, pw)
		if encErr != nil {
			_ = pw.CloseWithError(encErr)
		}
	}()

	encSize, copyErr := io.Copy(dstFile, pr)
	if copyErr != nil {
		_ = os.Remove(encFile)
		return nil, "", fmt.Errorf("failed writing encrypted backup stream: %w", copyErr)
	}
	if encErr != nil {
		_ = os.Remove(encFile)
		return nil, "", fmt.Errorf("failed encrypting artifact stream: %w", encErr)
	}

	manifest := &Manifest{
		BackupID:           backupID,
		ResourceID:         resourceID,
		ResourceType:       resourceType,
		Algorithm:          "AES-256-GCM",
		ChecksumSHA256:     plainSHA256,
		OriginalSizeBytes:  origSize,
		EncryptedSizeBytes: encSize,
		CreatedAt:          time.Now(),
		NodeID:             nodeID,
		Metadata:           make(map[string]string),
	}

	manifestFile := filepath.Join(targetDir, fmt.Sprintf("%s.manifest.json", backupID))
	if err := SaveManifest(manifest, manifestFile); err != nil {
		_ = os.Remove(encFile)
		return nil, "", fmt.Errorf("failed to write backup manifest: %w", err)
	}

	u.logger.Info("packaging_backup_completed", "backup_id", backupID, "encrypted_file", encFile, "manifest_file", manifestFile)
	return manifest, encFile, nil
}

// UploadToURL streams the artifact at artifactPath to uploadURL using an HTTP PUT request.
// It verifies the file exists and is non-empty, sets Content-Length, streams the body
// without buffering in memory, and verifies a 2xx HTTP response status.
func (u *Uploader) UploadToURL(ctx context.Context, uploadURL, artifactPath string) error {
	if uploadURL == "" {
		return fmt.Errorf("upload URL cannot be empty")
	}
	if artifactPath == "" {
		return fmt.Errorf("artifact path cannot be empty")
	}

	info, err := os.Stat(artifactPath)
	if err != nil {
		return fmt.Errorf("failed to stat artifact file for upload: %w", err)
	}
	if info.IsDir() {
		return fmt.Errorf("artifact path %s is a directory, not a file", artifactPath)
	}
	fileSize := info.Size()
	if fileSize == 0 {
		return fmt.Errorf("cannot upload empty artifact file: %s", artifactPath)
	}

	f, err := os.Open(artifactPath)
	if err != nil {
		return fmt.Errorf("failed to open artifact file for upload: %w", err)
	}
	defer f.Close()

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, uploadURL, f)
	if err != nil {
		return fmt.Errorf("failed to create HTTP PUT request: %w", err)
	}

	req.ContentLength = fileSize
	req.Header.Set("Content-Type", "application/octet-stream")

	client := &http.Client{
		Timeout: 30 * time.Minute,
	}

	u.logger.Info("uploading_artifact_to_url", "url", uploadURL, "artifact", artifactPath, "size_bytes", fileSize)

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("streaming upload PUT request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		bodySnippet, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("upload failed with HTTP status %d: %s", resp.StatusCode, string(bodySnippet))
	}

	u.logger.Info("upload_to_url_completed", "url", uploadURL, "artifact", artifactPath, "size_bytes", fileSize)
	return nil
}

// UploadToURL streams the artifact at artifactPath to uploadURL using a default Uploader.
func UploadToURL(ctx context.Context, uploadURL, artifactPath string) error {
	return NewUploader(nil).UploadToURL(ctx, uploadURL, artifactPath)
}

// DownloadFromURL streams the remote artifact from downloadURL to targetFilePath using bounded memory.
func (u *Uploader) DownloadFromURL(ctx context.Context, downloadURL, targetFilePath string) error {
	if downloadURL == "" {
		return fmt.Errorf("download URL cannot be empty")
	}
	if targetFilePath == "" {
		return fmt.Errorf("target file path cannot be empty")
	}

	if err := os.MkdirAll(filepath.Dir(targetFilePath), 0700); err != nil {
		return fmt.Errorf("failed creating parent directory for download: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, downloadURL, nil)
	if err != nil {
		return fmt.Errorf("failed creating download GET request: %w", err)
	}

	client := &http.Client{
		Timeout: 30 * time.Minute,
	}

	u.logger.Info("downloading_artifact_from_url", "url", downloadURL, "target", targetFilePath)

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("streaming download GET request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		bodySnippet, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("download failed with HTTP status %d: %s", resp.StatusCode, string(bodySnippet))
	}

	dstFile, err := os.OpenFile(targetFilePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed creating target file %s: %w", targetFilePath, err)
	}
	defer dstFile.Close()

	buf := make([]byte, 64*1024)
	copied, err := io.CopyBuffer(dstFile, resp.Body, buf)
	if err != nil {
		_ = os.Remove(targetFilePath)
		return fmt.Errorf("failed streaming download body: %w", err)
	}

	u.logger.Info("download_from_url_completed", "url", downloadURL, "target", targetFilePath, "size_bytes", copied)
	return nil
}

// DownloadFromURL streams the remote artifact from downloadURL to targetFilePath using a default Uploader.
func DownloadFromURL(ctx context.Context, downloadURL, targetFilePath string) error {
	return NewUploader(nil).DownloadFromURL(ctx, downloadURL, targetFilePath)
}
