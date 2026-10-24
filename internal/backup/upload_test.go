package backup_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/primecloud/primecloud-agent/internal/backup"
	"github.com/primecloud/primecloud-agent/internal/recovery"
)

func TestEncryptStream_RoundTripSmall(t *testing.T) {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		t.Fatalf("Failed generating key: %v", err)
	}

	plaintext := []byte("The quick brown fox jumps over the lazy dog. PrimeCloud streaming backup pipeline.")
	var encBuf bytes.Buffer

	plainHash, origSize, encSize, err := backup.EncryptStream(key, bytes.NewReader(plaintext), &encBuf)
	if err != nil {
		t.Fatalf("EncryptStream failed: %v", err)
	}

	if origSize != int64(len(plaintext)) {
		t.Errorf("Expected origSize %d, got %d", len(plaintext), origSize)
	}
	if encSize != int64(encBuf.Len()) {
		t.Errorf("Expected encSize %d, got %d", encBuf.Len(), encSize)
	}
	if plainHash == "" {
		t.Error("Expected non-empty plainHash")
	}

	// Verify framing: first 4 bytes are big-endian uint32 payload length
	encBytes := encBuf.Bytes()
	if len(encBytes) < 4+12+16 {
		t.Fatalf("Encrypted bytes too short: %d", len(encBytes))
	}
	payloadLen := binary.BigEndian.Uint32(encBytes[:4])
	if int(payloadLen) != len(encBytes)-4 {
		t.Errorf("Payload length header mismatch: got %d, want %d", payloadLen, len(encBytes)-4)
	}

	// Decrypt
	var decBuf bytes.Buffer
	if err := backup.DecryptStream(key, bytes.NewReader(encBytes), &decBuf); err != nil {
		t.Fatalf("DecryptStream failed: %v", err)
	}

	if !bytes.Equal(decBuf.Bytes(), plaintext) {
		t.Errorf("Decrypted plaintext mismatch: got %q, want %q", decBuf.String(), string(plaintext))
	}
}

func TestEncryptStream_MultiChunk(t *testing.T) {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		t.Fatalf("Failed generating key: %v", err)
	}

	// 9MB payload exercises 2 full 4MB chunks + 1 partial 1MB chunk
	totalSize := 9 * 1024 * 1024
	largePlaintext := make([]byte, totalSize)
	for i := range largePlaintext {
		largePlaintext[i] = byte(i % 251)
	}

	tempDir := t.TempDir()
	srcPath := filepath.Join(tempDir, "large_plain.bin")
	encPath := filepath.Join(tempDir, "large_enc.bin")
	decPath := filepath.Join(tempDir, "large_dec.bin")

	if err := os.WriteFile(srcPath, largePlaintext, 0600); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	srcFile, err := os.Open(srcPath)
	if err != nil {
		t.Fatalf("Failed to open source file: %v", err)
	}
	defer srcFile.Close()

	encFile, err := os.OpenFile(encPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		t.Fatalf("Failed to create encrypted file: %v", err)
	}

	plainHash, origSize, encSize, err := backup.EncryptStream(key, srcFile, encFile)
	encFile.Close()
	if err != nil {
		t.Fatalf("EncryptStream failed: %v", err)
	}

	if origSize != int64(totalSize) {
		t.Errorf("Expected origSize %d, got %d", totalSize, origSize)
	}
	if encSize <= origSize {
		t.Errorf("Expected encrypted size to be greater than plaintext size, got %d vs %d", encSize, origSize)
	}

	// Decrypt streamingly
	readEnc, err := os.Open(encPath)
	if err != nil {
		t.Fatalf("Failed to open enc file: %v", err)
	}
	defer readEnc.Close()

	decFile, err := os.OpenFile(decPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		t.Fatalf("Failed to create dec file: %v", err)
	}

	if err := backup.DecryptStream(key, readEnc, decFile); err != nil {
		decFile.Close()
		t.Fatalf("DecryptStream failed on multi-chunk: %v", err)
	}
	decFile.Close()

	// Verify decrypted content hash
	decHash, decSize, err := backup.ComputeSHA256(decPath)
	if err != nil {
		t.Fatalf("ComputeSHA256 failed: %v", err)
	}
	if decSize != int64(totalSize) {
		t.Errorf("Decrypted size mismatch: got %d, want %d", decSize, totalSize)
	}
	if decHash != plainHash {
		t.Errorf("SHA-256 hash mismatch: got %s, want %s", decHash, plainHash)
	}
}

func TestDecryptStream_LegacyUnchunkedFallback(t *testing.T) {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		t.Fatalf("Failed generating key: %v", err)
	}

	plaintext := []byte("Legacy unchunked artifact payload without 4-byte framing headers.")

	// Encrypt using legacy EncryptAESGCM (no 4-byte length prefix)
	legacyCiphertext, err := backup.EncryptAESGCM(key, plaintext)
	if err != nil {
		t.Fatalf("EncryptAESGCM failed: %v", err)
	}

	// Decrypt using DecryptStream (should auto-detect and fallback to legacy)
	var decBuf bytes.Buffer
	if err := backup.DecryptStream(key, bytes.NewReader(legacyCiphertext), &decBuf); err != nil {
		t.Fatalf("DecryptStream failed to fallback to legacy: %v", err)
	}

	if !bytes.Equal(decBuf.Bytes(), plaintext) {
		t.Errorf("Decrypted text mismatch: got %q, want %q", decBuf.String(), string(plaintext))
	}
}

func TestPackageAndUpload_StreamingPipeline(t *testing.T) {
	ctx := context.Background()
	tempDir := t.TempDir()
	sourceDir := filepath.Join(tempDir, "src")
	targetDir := filepath.Join(tempDir, "target")
	_ = os.MkdirAll(sourceDir, 0700)
	_ = os.MkdirAll(targetDir, 0700)

	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		t.Fatalf("Failed generating key: %v", err)
	}

	artifactData := []byte("-- PostgreSQL genuine dump --\nCREATE TABLE users (id int);\nINSERT INTO users VALUES (1);\n")
	artifactPath := filepath.Join(sourceDir, "test.dump")
	if err := os.WriteFile(artifactPath, artifactData, 0600); err != nil {
		t.Fatalf("Failed writing artifact: %v", err)
	}

	uploader := backup.NewUploader(nil)
	manifest, encPath, err := uploader.PackageAndUpload(ctx, "bk-pipe-1", "res-pipe-1", "postgres", "node-pipe", artifactPath, key, targetDir)
	if err != nil {
		t.Fatalf("PackageAndUpload failed: %v", err)
	}

	if manifest.OriginalSizeBytes != int64(len(artifactData)) {
		t.Errorf("Manifest OriginalSizeBytes mismatch: got %d, want %d", manifest.OriginalSizeBytes, len(artifactData))
	}
	if manifest.EncryptedSizeBytes == 0 {
		t.Error("Manifest EncryptedSizeBytes is 0")
	}

	// Reconstruct artifact
	restoreDir := filepath.Join(tempDir, "restore")
	manifestPath := filepath.Join(targetDir, "bk-pipe-1.manifest.json")
	reconstructor := recovery.NewReconstructor(nil, nil)
	restoredPath, restoredManifest, err := reconstructor.ReconstructArtifact(ctx, encPath, manifestPath, key, restoreDir)
	if err != nil {
		t.Fatalf("ReconstructArtifact failed: %v", err)
	}

	verifier := recovery.NewVerifier(nil)
	if err := verifier.VerifyIntegrity(manifest, restoredPath); err != nil {
		t.Fatalf("VerifyIntegrity failed: %v", err)
	}
	if err := verifier.VerifyFormat("postgres", restoredPath); err != nil {
		t.Fatalf("VerifyFormat failed: %v", err)
	}

	restoredContent, err := os.ReadFile(restoredPath)
	if err != nil {
		t.Fatalf("Failed reading restored file: %v", err)
	}
	if !bytes.Equal(restoredContent, artifactData) {
		t.Errorf("Restored data mismatch: got %q, want %q", string(restoredContent), string(artifactData))
	}

	if restoredManifest.ResourceID != "res-pipe-1" {
		t.Errorf("Restored manifest ResourceID mismatch: got %s, want res-pipe-1", restoredManifest.ResourceID)
	}
}

func TestEncryptStream_InvalidKeyLengthFailsClosed(t *testing.T) {
	shortKey := []byte("short-key-16-bytes")
	_, _, _, err := backup.EncryptStream(shortKey, bytes.NewReader([]byte("test")), io.Discard)
	if err == nil {
		t.Error("Expected error for non-32 byte key")
	}

	err = backup.DecryptStream(shortKey, bytes.NewReader([]byte("test")), io.Discard)
	if err == nil {
		t.Error("Expected error for non-32 byte key in DecryptStream")
	}
}

func TestDecryptStream_CorruptDataFails(t *testing.T) {
	key := make([]byte, 32)
	_, _ = io.ReadFull(rand.Reader, key)

	corrupt := []byte("this is corrupt data not valid ciphertext")
	err := backup.DecryptStream(key, bytes.NewReader(corrupt), io.Discard)
	if err == nil {
		t.Error("Expected error decrypting corrupt data")
	}
}

func TestUploadToURL_Success(t *testing.T) {
	ctx := context.Background()
	payload := []byte("STREAMING_ENCRYPTED_BACKUP_PAYLOAD_CONTENT")

	var receivedBody []byte
	var receivedMethod string
	var receivedContentType string
	var receivedContentLength int64

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedMethod = r.Method
		receivedContentType = r.Header.Get("Content-Type")
		receivedContentLength = r.ContentLength
		var err error
		receivedBody, err = io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	tempFile := filepath.Join(t.TempDir(), "test_artifact.enc")
	if err := os.WriteFile(tempFile, payload, 0600); err != nil {
		t.Fatalf("Failed writing temp artifact: %v", err)
	}

	uploader := backup.NewUploader(nil)
	if err := uploader.UploadToURL(ctx, server.URL, tempFile); err != nil {
		t.Fatalf("UploadToURL failed: %v", err)
	}

	if receivedMethod != http.MethodPut {
		t.Errorf("Expected PUT method, got %s", receivedMethod)
	}
	if receivedContentType != "application/octet-stream" {
		t.Errorf("Expected Content-Type application/octet-stream, got %s", receivedContentType)
	}
	if receivedContentLength != int64(len(payload)) {
		t.Errorf("Expected Content-Length %d, got %d", len(payload), receivedContentLength)
	}
	if !bytes.Equal(receivedBody, payload) {
		t.Errorf("Received body mismatch: got %q, want %q", string(receivedBody), string(payload))
	}

	// Test package-level helper as well
	if err := backup.UploadToURL(ctx, server.URL, tempFile); err != nil {
		t.Fatalf("Package-level UploadToURL failed: %v", err)
	}
}

func TestUploadToURL_ServerError(t *testing.T) {
	ctx := context.Background()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal server error: S3 bucket full", http.StatusInternalServerError)
	}))
	defer server.Close()

	tempFile := filepath.Join(t.TempDir(), "test_artifact.enc")
	if err := os.WriteFile(tempFile, []byte("data"), 0600); err != nil {
		t.Fatalf("Failed writing temp artifact: %v", err)
	}

	uploader := backup.NewUploader(nil)
	err := uploader.UploadToURL(ctx, server.URL, tempFile)
	if err == nil {
		t.Fatal("Expected error on server 500 response, got nil")
	}
}

func TestUploadToURL_ValidationErrors(t *testing.T) {
	ctx := context.Background()
	uploader := backup.NewUploader(nil)

	// Empty URL
	if err := uploader.UploadToURL(ctx, "", "some/path"); err == nil {
		t.Error("Expected error for empty upload URL")
	}

	// Empty artifact path
	if err := uploader.UploadToURL(ctx, "http://localhost", ""); err == nil {
		t.Error("Expected error for empty artifact path")
	}

	// Nonexistent file
	if err := uploader.UploadToURL(ctx, "http://localhost", "nonexistent/file.bin"); err == nil {
		t.Error("Expected error for nonexistent file")
	}

	// Empty file (0 bytes)
	emptyFile := filepath.Join(t.TempDir(), "empty.bin")
	_ = os.WriteFile(emptyFile, []byte{}, 0600)
	if err := uploader.UploadToURL(ctx, "http://localhost", emptyFile); err == nil {
		t.Error("Expected error for empty 0-byte file")
	}
}

func TestDownloadFromURL_Success(t *testing.T) {
	payload := []byte("PRIMECLOUD_REMOTE_BACKUP_TEST_BYTES_FOR_RECOVERY")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "expected GET", http.StatusMethodNotAllowed)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(payload)
	}))
	defer server.Close()

	tmpDir := t.TempDir()
	targetFile := filepath.Join(tmpDir, "downloaded.enc")

	err := backup.DownloadFromURL(context.Background(), server.URL, targetFile)
	if err != nil {
		t.Fatalf("DownloadFromURL failed: %v", err)
	}

	downloaded, err := os.ReadFile(targetFile)
	if err != nil {
		t.Fatalf("failed reading downloaded file: %v", err)
	}

	if !bytes.Equal(downloaded, payload) {
		t.Fatalf("expected payload %s, got %s", string(payload), string(downloaded))
	}
}

func TestDownloadFromURL_NotFoundFailsClosed(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "Not Found", http.StatusNotFound)
	}))
	defer server.Close()

	tmpDir := t.TempDir()
	targetFile := filepath.Join(tmpDir, "downloaded.enc")

	err := backup.DownloadFromURL(context.Background(), server.URL, targetFile)
	if err == nil {
		t.Fatal("expected DownloadFromURL to fail on 404, got nil")
	}
}
