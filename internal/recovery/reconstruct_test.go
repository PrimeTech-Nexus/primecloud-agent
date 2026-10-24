package recovery_test

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/primecloud/primecloud-agent/internal/backup"
	"github.com/primecloud/primecloud-agent/internal/recovery"
)

func TestUnsupportedResourceTypeError_Formatting(t *testing.T) {
	err := &recovery.UnsupportedResourceTypeError{
		ResourceType: "cassandra",
		ResourceID:   "res-cas-1234",
	}

	expected := `unsupported resource type for disaster recovery restore: "cassandra" (resource_id: res-cas-1234)`
	if err.Error() != expected {
		t.Fatalf("expected error string %q, got %q", expected, err.Error())
	}
}

func TestRestoreToWorkload_FailsClosedOnUnsupportedType(t *testing.T) {
	reconstructor := recovery.NewReconstructor(nil, slog.Default())
	ctx := context.Background()

	manifest := &backup.Manifest{
		ResourceID:   "res-unknown-999",
		ResourceType: "unknown_engine",
	}

	err := reconstructor.RestoreToWorkload(ctx, manifest, "/tmp/fake.dump")
	if err == nil {
		t.Fatal("expected RestoreToWorkload to fail closed with error, got nil")
	}

	var typedErr *recovery.UnsupportedResourceTypeError
	if !errors.As(err, &typedErr) {
		t.Fatalf("expected *recovery.UnsupportedResourceTypeError, got %T: %v", err, err)
	}

	if typedErr.ResourceType != "unknown_engine" || typedErr.ResourceID != "res-unknown-999" {
		t.Fatalf("unexpected error payload: %+v", typedErr)
	}
}

func TestRestoreToWorkloadWithVault_FailsClosedOnUnsupportedType(t *testing.T) {
	reconstructor := recovery.NewReconstructor(nil, slog.Default())
	ctx := context.Background()

	manifest := &backup.Manifest{
		ResourceID:   "res-dynamo-000",
		ResourceType: "dynamodb",
	}

	err := reconstructor.RestoreToWorkloadWithVault(ctx, manifest, "/tmp/fake.dump", nil, "/tmp", "proj-123")
	if err == nil {
		t.Fatal("expected RestoreToWorkloadWithVault to fail closed with error, got nil")
	}

	var typedErr *recovery.UnsupportedResourceTypeError
	if !errors.As(err, &typedErr) {
		t.Fatalf("expected *recovery.UnsupportedResourceTypeError, got %T: %v", err, err)
	}

	if typedErr.ResourceType != "dynamodb" || typedErr.ResourceID != "res-dynamo-000" {
		t.Fatalf("unexpected error payload: %+v", typedErr)
	}
}

func TestReconstructArtifact_MissingManifestFailsClosed(t *testing.T) {
	reconstructor := recovery.NewReconstructor(nil, slog.Default())
	ctx := context.Background()

	// Create dummy encrypted file
	tmpDir := t.TempDir()
	encPath := filepath.Join(tmpDir, "test.enc")
	_ = os.WriteFile(encPath, []byte("dummy encrypted payload 1234567890"), 0600)

	nonExistentManifest := filepath.Join(tmpDir, "missing.manifest.json")
	key := make([]byte, 32)

	_, _, err := reconstructor.ReconstructArtifact(ctx, encPath, nonExistentManifest, key, tmpDir)
	if err == nil {
		t.Fatal("expected ReconstructArtifact to fail closed when manifest is missing, got nil")
	}

	if !strings.Contains(err.Error(), "MANIFEST_NOT_FOUND") {
		t.Fatalf("expected MANIFEST_NOT_FOUND error, got: %v", err)
	}
}

func TestReconstructArtifact_MissingChecksumFailsClosed(t *testing.T) {
	reconstructor := recovery.NewReconstructor(nil, slog.Default())
	ctx := context.Background()

	tmpDir := t.TempDir()
	encPath := filepath.Join(tmpDir, "test.enc")
	_ = os.WriteFile(encPath, []byte("dummy encrypted payload 1234567890"), 0600)

	// Manifest with empty checksum
	manifestPath := filepath.Join(tmpDir, "test.manifest.json")
	_ = os.WriteFile(manifestPath, []byte(`{"resource_id": "res-1", "resource_type": "postgres", "checksum_sha256": ""}`), 0600)
	key := make([]byte, 32)

	_, _, err := reconstructor.ReconstructArtifact(ctx, encPath, manifestPath, key, tmpDir)
	if err == nil {
		t.Fatal("expected ReconstructArtifact to fail closed when checksum is empty, got nil")
	}

	if !strings.Contains(err.Error(), "MANIFEST_INVALID") {
		t.Fatalf("expected MANIFEST_INVALID error, got: %v", err)
	}
}
