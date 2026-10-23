package recovery_test

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/primecloud/primecloud-agent/internal/backup"
	"github.com/primecloud/primecloud-agent/internal/recovery"
)

// TestAdversarial_DisasterRecoveryFailClosed stress-tests RestoreToWorkload and
// RestoreToWorkloadWithVault across arbitrary unsupported, malformed, and edge-case
// resource types to verify strict fail-closed security and typed error contracts.
func TestAdversarial_DisasterRecoveryFailClosed(t *testing.T) {
	reconstructor := recovery.NewReconstructor(nil, slog.Default())
	ctx := context.Background()

	unsupportedTypes := []string{
		"couchdb",
		"cassandra",
		"",
		"   ",
		"MYSQL",
		"MONGODB",
		"dynamodb",
		"sqlite",
		"neo4j",
		"elasticsearch",
		"kafka",
		"rabbitmq",
		"POSTGRES",
		"PostgreSQL",
		"VALKEY",
		"redis_cluster",
		"unknown-engine-type-999",
		"null",
		"undefined",
		"../../path/traversal",
		"select * from users",
	}

	testResourceIDs := []string{
		"res-standard-uuid-001",
		"",
		"res with spaces",
		"018f3a8b-1234-7000-8000-000000000001",
		"special!@#$%^&*()",
	}

	for _, resType := range unsupportedTypes {
		for _, resID := range testResourceIDs {
			t.Run("RestoreToWorkload_"+resType+"_"+resID, func(t *testing.T) {
				manifest := &backup.Manifest{
					ResourceID:   resID,
					ResourceType: resType,
				}

				// Test RestoreToWorkload
				err := reconstructor.RestoreToWorkload(ctx, manifest, "/tmp/mock_artifact.dump")
				if err == nil {
					t.Fatalf("CRITICAL SECURITY FLAW: RestoreToWorkload returned silent nil on unsupported type %q", resType)
				}

				var typedErr *recovery.UnsupportedResourceTypeError
				if !errors.As(err, &typedErr) {
					t.Fatalf("FAIL: expected *recovery.UnsupportedResourceTypeError, got %T (%v)", err, err)
				}

				if typedErr.ResourceType != resType {
					t.Fatalf("FAIL: expected typedErr.ResourceType %q, got %q", resType, typedErr.ResourceType)
				}
				if typedErr.ResourceID != resID {
					t.Fatalf("FAIL: expected typedErr.ResourceID %q, got %q", resID, typedErr.ResourceID)
				}

				errMsg := typedErr.Error()
				if errMsg == "" {
					t.Fatalf("FAIL: typedErr.Error() is empty for %q", resType)
				}
				if !strings.Contains(errMsg, resType) {
					t.Fatalf("FAIL: error string %q does not contain resource type %q", errMsg, resType)
				}
				if !strings.Contains(errMsg, resID) {
					t.Fatalf("FAIL: error string %q does not contain resource ID %q", errMsg, resID)
				}

				// Test RestoreToWorkloadWithVault
				errVault := reconstructor.RestoreToWorkloadWithVault(ctx, manifest, "/tmp/mock_artifact.dump", nil, "/tmp/base", "proj-test")
				if errVault == nil {
					t.Fatalf("CRITICAL SECURITY FLAW: RestoreToWorkloadWithVault returned silent nil on unsupported type %q", resType)
				}

				var typedErrVault *recovery.UnsupportedResourceTypeError
				if !errors.As(errVault, &typedErrVault) {
					t.Fatalf("FAIL: expected *recovery.UnsupportedResourceTypeError from RestoreToWorkloadWithVault, got %T (%v)", errVault, errVault)
				}

				if typedErrVault.ResourceType != resType || typedErrVault.ResourceID != resID {
					t.Fatalf("FAIL: mismatch in typed error payload from RestoreToWorkloadWithVault: %+v", typedErrVault)
				}
			})
		}
	}

	// Verify supported engines ("mysql", "mongodb") dispatch to engine handlers and fail closed when runtime is nil
	for _, supportedEngine := range []string{"mysql", "mongodb"} {
		t.Run("SupportedEngineDispatchesAndFailsClosedWithoutRuntime_"+supportedEngine, func(t *testing.T) {
			manifest := &backup.Manifest{
				ResourceID:   "res-valid-001",
				ResourceType: supportedEngine,
			}
			err := reconstructor.RestoreToWorkload(ctx, manifest, "/tmp/nonexistent")
			if err == nil {
				t.Fatalf("expected error when runtime is nil for %s", supportedEngine)
			}
			var typedErr *recovery.UnsupportedResourceTypeError
			if errors.As(err, &typedErr) {
				t.Fatalf("did not expect UnsupportedResourceTypeError for supported engine %s", supportedEngine)
			}
		})
	}
}
