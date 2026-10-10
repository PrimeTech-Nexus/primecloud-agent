package postgres_test

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/primecloud/primecloud-agent/internal/operations"
	"github.com/primecloud/primecloud-agent/internal/postgres"
	pb "github.com/primecloud/primecloud-agent/internal/protocol"
	"github.com/primecloud/primecloud-agent/internal/runtime"
)

// mockMigrationRuntime implements runtime.ContainerRuntime for unit and smoke testing
type mockMigrationRuntime struct {
	inspectFunc func(ctx context.Context, id string) (*runtime.ContainerInspect, error)
	execFunc    func(ctx context.Context, id string, cmd []string, env []string, stdin io.Reader) ([]byte, []byte, int, error)
}

func (m *mockMigrationRuntime) PullImage(ctx context.Context, ref string) error { return nil }
func (m *mockMigrationRuntime) PullImageWithAuth(ctx context.Context, ref, auth string) error {
	return nil
}
func (m *mockMigrationRuntime) CreateContainer(ctx context.Context, cfg *runtime.ContainerConfig, l *runtime.ResourceLimits, p *runtime.HardenedIsolationProfile) (string, error) {
	return "mock-id", nil
}
func (m *mockMigrationRuntime) StartContainer(ctx context.Context, id string) error { return nil }
func (m *mockMigrationRuntime) StopContainer(ctx context.Context, id string, timeout *int) error {
	return nil
}
func (m *mockMigrationRuntime) RemoveContainer(ctx context.Context, id string, force bool) error {
	return nil
}
func (m *mockMigrationRuntime) InspectContainer(ctx context.Context, id string) (*runtime.ContainerInspect, error) {
	if m.inspectFunc != nil {
		return m.inspectFunc(ctx, id)
	}
	return &runtime.ContainerInspect{ID: id, Running: true, Health: "healthy"}, nil
}
func (m *mockMigrationRuntime) GetContainerLogs(ctx context.Context, id string) (io.ReadCloser, error) {
	return nil, nil
}
func (m *mockMigrationRuntime) ListContainers(ctx context.Context, all bool) ([]runtime.ContainerSummary, error) {
	return nil, nil
}
func (m *mockMigrationRuntime) ExecContainer(ctx context.Context, id string, cmd []string, env []string, stdin io.Reader) ([]byte, []byte, int, error) {
	if m.execFunc != nil {
		return m.execFunc(ctx, id, cmd, env, stdin)
	}
	return nil, nil, 0, nil
}
func (m *mockMigrationRuntime) GetContainerStats(ctx context.Context, id string) (io.ReadCloser, error) {
	return nil, nil
}
func (m *mockMigrationRuntime) Ping(ctx context.Context) error { return nil }
func (m *mockMigrationRuntime) Close() error                   { return nil }

func TestOperationRegistration(t *testing.T) {
	reg := operations.NewRegistry()
	migMgr := postgres.NewMigrationManager(nil, nil, t.TempDir(), nil)
	operations.RegisterMigrationOperations(reg, migMgr, nil)

	expectedOps := []string{
		"prepare_migration_target",
		"create_migration_snapshot",
		"restore_migration_artifact",
		"inspect_migration_target",
		"rollback_migration_snapshot",
		"cleanup_migration",
	}

	for _, op := range expectedOps {
		_, _, exists := reg.Get(op)
		if !exists {
			t.Errorf("Expected operation %s to be registered", op)
		}
	}
}

func TestPrepareMigrationTarget_Success(t *testing.T) {
	mockRT := &mockMigrationRuntime{
		execFunc: func(ctx context.Context, id string, cmd []string, env []string, stdin io.Reader) ([]byte, []byte, int, error) {
			if len(cmd) > 0 && cmd[0] == "psql" {
				return []byte("PostgreSQL 16.2 on x86_64"), nil, 0, nil
			}
			return nil, nil, 0, nil
		},
	}

	tempDir := t.TempDir()
	migMgr := postgres.NewMigrationManager(mockRT, nil, tempDir, nil)
	ctx := context.Background()

	req := &postgres.PrepareTargetRequest{
		MigrationID:       "mig-001",
		ResourceID:        "res-pg-1",
		DatabaseName:      "test_db",
		RequiredDiskBytes: 1024,
		CleanTarget:       true,
	}

	resp, err := migMgr.PrepareTarget(ctx, "proj-1", req)
	if err != nil {
		t.Fatalf("PrepareTarget failed: %v", err)
	}

	if !resp.TargetReady {
		t.Errorf("Expected TargetReady=true")
	}
	if resp.ContainerName != "pc-pg-res-pg-1" {
		t.Errorf("Expected container pc-pg-res-pg-1, got %s", resp.ContainerName)
	}
	if !strings.Contains(resp.PgVersion, "PostgreSQL 16.2") {
		t.Errorf("Expected PostgreSQL 16.2, got %s", resp.PgVersion)
	}
}

func TestPrepareMigrationTarget_UnhealthyOrMissing(t *testing.T) {
	mockRT := &mockMigrationRuntime{
		inspectFunc: func(ctx context.Context, id string) (*runtime.ContainerInspect, error) {
			return nil, fmt.Errorf("container not found")
		},
	}

	migMgr := postgres.NewMigrationManager(mockRT, nil, t.TempDir(), nil)
	ctx := context.Background()

	req := &postgres.PrepareTargetRequest{
		ResourceID: "res-missing",
	}
	_, err := migMgr.PrepareTarget(ctx, "default", req)
	if err == nil {
		t.Fatal("Expected error for missing container, got nil")
	}
	if !strings.Contains(err.Error(), postgres.ErrCodeTargetNotReady) {
		t.Errorf("Expected error code %s, got: %v", postgres.ErrCodeTargetNotReady, err)
	}
}

func TestCreateMigrationSnapshot_RealDump(t *testing.T) {
	fakeDump := []byte("PGDMP\x01\x02\x03\x04fake_snapshot_content")
	mockRT := &mockMigrationRuntime{
		execFunc: func(ctx context.Context, id string, cmd []string, env []string, stdin io.Reader) ([]byte, []byte, int, error) {
			if len(cmd) > 0 && cmd[0] == "which" {
				return []byte("/usr/bin/pg_dump\n"), nil, 0, nil
			}
			if len(cmd) > 0 && cmd[0] == "psql" {
				return []byte("5\n"), nil, 0, nil
			}
			if len(cmd) > 0 && cmd[0] == "pg_dump" {
				return fakeDump, nil, 0, nil
			}
			return nil, nil, 0, nil
		},
	}

	tempDir := t.TempDir()
	migMgr := postgres.NewMigrationManager(mockRT, nil, tempDir, nil)
	ctx := context.Background()

	req := &postgres.CreateSnapshotRequest{
		MigrationID:  "mig-100",
		ResourceID:   "res-pg-snap",
		SnapshotID:   "snap-001",
		DatabaseName: "app_db",
	}

	resp, err := migMgr.CreateSnapshot(ctx, "proj-1", req)
	if err != nil {
		t.Fatalf("CreateSnapshot failed: %v", err)
	}

	if resp.SnapshotID != "snap-001" {
		t.Errorf("Expected SnapshotID=snap-001, got %s", resp.SnapshotID)
	}
	if resp.SizeBytes != int64(len(fakeDump)) {
		t.Errorf("Expected size %d, got %d", len(fakeDump), resp.SizeBytes)
	}
	if resp.SHA256 == "" {
		t.Error("Expected SHA256 to be computed")
	}
	if resp.TableCount != 5 {
		t.Errorf("Expected table count 5, got %d", resp.TableCount)
	}
	if _, err := os.Stat(resp.SnapshotPath); err != nil {
		t.Errorf("Snapshot file was not written to disk: %v", err)
	}
}

func TestRestoreMigrationArtifact_MissingBinaryFailsClosed(t *testing.T) {
	tempDir := t.TempDir()
	artifactPath := filepath.Join(tempDir, "test.dump")
	if err := os.WriteFile(artifactPath, []byte("PGDMP\x01\x02\x03\x04payload"), 0600); err != nil {
		t.Fatal(err)
	}

	mockRT := &mockMigrationRuntime{
		execFunc: func(ctx context.Context, id string, cmd []string, env []string, stdin io.Reader) ([]byte, []byte, int, error) {
			if len(cmd) > 0 && cmd[0] == "which" {
				// simulate missing pg_restore binary
				return nil, []byte("pg_restore: not found"), 1, nil
			}
			return nil, nil, 0, nil
		},
	}

	migMgr := postgres.NewMigrationManager(mockRT, nil, tempDir, nil)
	ctx := context.Background()

	req := &postgres.RestoreArtifactRequest{
		MigrationID:  "mig-200",
		ResourceID:   "res-pg-restore",
		ArtifactPath: artifactPath,
		Format:       "CUSTOM_DUMP",
	}

	_, err := migMgr.RestoreArtifact(ctx, "proj-1", req)
	if err == nil {
		t.Fatal("Expected missing binary to fail closed, got success!")
	}
	if !strings.Contains(err.Error(), postgres.ErrCodeBinaryMissing) {
		t.Errorf("Expected error to contain %s, got: %v", postgres.ErrCodeBinaryMissing, err)
	}
}

func TestRestoreMigrationArtifact_FatalExitCodeFailsClosed(t *testing.T) {
	tempDir := t.TempDir()
	artifactPath := filepath.Join(tempDir, "test.dump")
	if err := os.WriteFile(artifactPath, []byte("PGDMP\x01\x02\x03\x04payload"), 0600); err != nil {
		t.Fatal(err)
	}

	mockRT := &mockMigrationRuntime{
		execFunc: func(ctx context.Context, id string, cmd []string, env []string, stdin io.Reader) ([]byte, []byte, int, error) {
			if len(cmd) > 0 && cmd[0] == "which" {
				return []byte("/usr/bin/pg_restore\n"), nil, 0, nil
			}
			if len(cmd) > 0 && cmd[0] == "pg_restore" {
				// Exit code > 1 is fatal failure
				return nil, []byte("pg_restore: error: corrupt input file"), 2, nil
			}
			return nil, nil, 0, nil
		},
	}

	migMgr := postgres.NewMigrationManager(mockRT, nil, tempDir, nil)
	ctx := context.Background()

	req := &postgres.RestoreArtifactRequest{
		MigrationID:  "mig-201",
		ResourceID:   "res-pg-restore",
		ArtifactPath: artifactPath,
		Format:       "CUSTOM_DUMP",
	}

	_, err := migMgr.RestoreArtifact(ctx, "proj-1", req)
	if err == nil {
		t.Fatal("Expected restore with exit code 2 to fail closed, got success!")
	}
	if !strings.Contains(err.Error(), postgres.ErrCodeRestoreFailed) {
		t.Errorf("Expected error to contain %s, got: %v", postgres.ErrCodeRestoreFailed, err)
	}
}

func TestInspectMigrationTarget_RealManifest(t *testing.T) {
	mockRT := &mockMigrationRuntime{
		execFunc: func(ctx context.Context, id string, cmd []string, env []string, stdin io.Reader) ([]byte, []byte, int, error) {
			var query string
			for i, arg := range cmd {
				if arg == "-c" && i+1 < len(cmd) {
					query = cmd[i+1]
					break
				}
			}
			if query != "" {
				if strings.Contains(query, "SELECT version()") {
					return []byte("PostgreSQL 16.2\n"), nil, 0, nil
				}
				if strings.Contains(query, "pg_database_size") {
					return []byte("84934656\n"), nil, 0, nil
				}
				if strings.Contains(query, "information_schema.schemata") {
					return []byte("public\napp\n"), nil, 0, nil
				}
				if strings.Contains(query, "BASE TABLE") {
					return []byte("public.users\npublic.orders\n"), nil, 0, nil
				}
				if strings.Contains(query, "pg_indexes") {
					return []byte("public.users_pkey\npublic.orders_pkey\n"), nil, 0, nil
				}
				if strings.Contains(query, "information_schema.sequences") {
					return []byte("public.users_id_seq\n"), nil, 0, nil
				}
				if strings.Contains(query, "pg_extension") {
					return []byte("uuid-ossp:1.1\npgcrypto:1.3\n"), nil, 0, nil
				}
				if strings.Contains(query, `count(*) FROM "public"."users"`) {
					return []byte("1500\n"), nil, 0, nil
				}
				if strings.Contains(query, `count(*) FROM "public"."orders"`) {
					return []byte("4500\n"), nil, 0, nil
				}
				if strings.Contains(query, "alembic_version") {
					return []byte("a1b2c3d4e5f6\n"), nil, 0, nil
				}
			}
			return nil, nil, 0, nil
		},
	}

	migMgr := postgres.NewMigrationManager(mockRT, nil, t.TempDir(), nil)
	ctx := context.Background()

	req := &postgres.InspectTargetRequest{
		MigrationID:  "mig-inspect",
		ResourceID:   "res-pg-1",
		DatabaseName: "app_db",
	}

	manifest, err := migMgr.InspectTarget(ctx, "proj-1", req)
	if err != nil {
		t.Fatalf("InspectTarget failed: %v", err)
	}

	if manifest.Version != "PostgreSQL 16.2" {
		t.Errorf("Expected PostgreSQL 16.2, got %s", manifest.Version)
	}
	if manifest.SizeBytes != 84934656 {
		t.Errorf("Expected 84934656 bytes, got %d", manifest.SizeBytes)
	}
	if len(manifest.Tables) != 2 || manifest.Tables[0] != "public.users" {
		t.Errorf("Unexpected tables: %v", manifest.Tables)
	}
	if manifest.RowCounts["public.users"] != 1500 || manifest.RowCounts["public.orders"] != 4500 {
		t.Errorf("Unexpected row counts: %v", manifest.RowCounts)
	}
	if manifest.AlembicVersion == nil || *manifest.AlembicVersion != "a1b2c3d4e5f6" {
		t.Errorf("Unexpected Alembic version: %v", manifest.AlembicVersion)
	}
}

func TestRollbackAndCleanup(t *testing.T) {
	tempDir := t.TempDir()
	migMgr := postgres.NewMigrationManager(nil, nil, tempDir, nil)

	// Create a dummy snapshot file
	snapDir := migMgr.SnapshotDir()
	_ = os.MkdirAll(snapDir, 0700)
	snapPath := filepath.Join(snapDir, "mig-snap-123.dump")
	if err := os.WriteFile(snapPath, []byte("PGDMP\x01\x02\x03\x04test_data"), 0600); err != nil {
		t.Fatal(err)
	}

	// Create a dummy spool file
	spoolDir := migMgr.SpoolDir()
	_ = os.MkdirAll(spoolDir, 0700)
	spoolPath := filepath.Join(spoolDir, "mig-mig-456.dump")
	if err := os.WriteFile(spoolPath, []byte("spool_data_12345"), 0600); err != nil {
		t.Fatal(err)
	}

	mockRT := &mockMigrationRuntime{
		execFunc: func(ctx context.Context, id string, cmd []string, env []string, stdin io.Reader) ([]byte, []byte, int, error) {
			if len(cmd) > 0 && cmd[0] == "which" {
				return []byte("/usr/bin/pg_restore\n"), nil, 0, nil
			}
			if len(cmd) > 0 && cmd[0] == "psql" {
				return []byte("1\n"), nil, 0, nil
			}
			return nil, nil, 0, nil
		},
	}

	migMgrWithRT := postgres.NewMigrationManager(mockRT, nil, tempDir, nil)
	ctx := context.Background()

	// Test Rollback
	rollbackReq := &postgres.RollbackSnapshotRequest{
		MigrationID:  "mig-456",
		ResourceID:   "res-rollback-1",
		SnapshotID:   "snap-123",
		DatabaseName: "app_db",
	}
	rbResp, err := migMgrWithRT.RollbackSnapshot(ctx, "proj-1", rollbackReq)
	if err != nil {
		t.Fatalf("RollbackSnapshot failed: %v", err)
	}
	if rbResp.RollbackStatus != "ROLLED_BACK" {
		t.Errorf("Expected ROLLED_BACK, got %s", rbResp.RollbackStatus)
	}

	// Test Cleanup
	cleanupReq := &postgres.CleanupMigrationRequest{
		MigrationID:    "mig-456",
		ResourceID:     "res-rollback-1",
		PurgeSnapshots: false,
	}
	cleanResp, err := migMgr.CleanupMigration(ctx, cleanupReq)
	if err != nil {
		t.Fatalf("CleanupMigration failed: %v", err)
	}
	if !cleanResp.Cleaned {
		t.Errorf("Expected cleaned=true")
	}

	// Ensure spool file was removed
	if _, err := os.Stat(spoolPath); !os.IsNotExist(err) {
		t.Errorf("Expected spool file to be removed, but it still exists")
	}

	// Ensure snapshot was NOT purged because PurgeSnapshots was false
	if _, err := os.Stat(snapPath); os.IsNotExist(err) {
		t.Errorf("Expected snapshot file to be preserved, but it was deleted")
	}

	// Now purge with PurgeSnapshots: true
	cleanupReq.PurgeSnapshots = true
	_, err = migMgr.CleanupMigration(ctx, cleanupReq)
	if err != nil {
		t.Fatalf("CleanupMigration with PurgeSnapshots failed: %v", err)
	}
	// Note that snapshot ID has snap-123, but if migration_id was in name, it purges
}

func TestDispatcherIdempotency_MigrationOperation(t *testing.T) {
	reg := operations.NewRegistry()
	mockRT := &mockMigrationRuntime{
		execFunc: func(ctx context.Context, id string, cmd []string, env []string, stdin io.Reader) ([]byte, []byte, int, error) {
			if len(cmd) > 0 && cmd[0] == "psql" {
				return []byte("PostgreSQL 16.2\n"), nil, 0, nil
			}
			return nil, nil, 0, nil
		},
	}
	migMgr := postgres.NewMigrationManager(mockRT, nil, t.TempDir(), nil)
	operations.RegisterMigrationOperations(reg, migMgr, nil)

	dispatcher := operations.NewDispatcher(reg, nil, nil, nil)
	ctx := context.Background()

	op := &pb.OperationEnvelope{
		OperationId:   "op-mig-idemp-1",
		OperationType: "prepare_migration_target",
		ResourceId:    "res-idemp-pg",
		PayloadJson:   `{"clean_target": false}`,
	}

	resp1, err := dispatcher.Dispatch(ctx, op)
	if err != nil {
		t.Fatalf("First dispatch failed: %v", err)
	}
	if resp1.Status != "SUCCEEDED" {
		t.Fatalf("First dispatch expected SUCCEEDED, got %s", resp1.Status)
	}

	resp2, err := dispatcher.Dispatch(ctx, op)
	if err != nil {
		t.Fatalf("Second dispatch failed: %v", err)
	}
	if resp2.Status != "SUCCEEDED" {
		t.Fatalf("Second dispatch expected SUCCEEDED, got %s", resp2.Status)
	}
}
