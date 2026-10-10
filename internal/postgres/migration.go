// Package postgres provides the authoritative PostgreSQL driver for provisioning, credentials, lifecycle, backup, restore, and migrations.
package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/primecloud/primecloud-agent/internal/runtime"
	"github.com/primecloud/primecloud-agent/internal/vault"
)

// Standard error codes matching migration-contract-v1
const (
	ErrCodeTargetNotReady       = "TARGET_NOT_READY"
	ErrCodeContainerUnhealthy   = "CONTAINER_UNHEALTHY"
	ErrCodePostgresUnreachable  = "POSTGRES_UNREACHABLE"
	ErrCodeInsufficientDisk     = "INSUFFICIENT_DISK"
	ErrCodeSnapshotFailed       = "SNAPSHOT_FAILED"
	ErrCodeArtifactNotFound     = "ARTIFACT_NOT_FOUND"
	ErrCodeArtifactCorrupt      = "CORRUPT_ARTIFACT"
	ErrCodeRestoreFailed        = "RESTORE_FAILED"
	ErrCodeBinaryMissing        = "BINARY_MISSING"
	ErrCodeInspectionFailed     = "INSPECTION_FAILED"
	ErrCodeRollbackFailed       = "ROLLBACK_FAILED"
	ErrCodeCleanupFailed        = "CLEANUP_FAILED"
	ErrCodeInvalidPayload       = "INVALID_PAYLOAD_SCHEMA"
)

// PrepareTargetRequest defines request payload for prepare_migration_target.
type PrepareTargetRequest struct {
	MigrationID       string `json:"migration_id"`
	ResourceID        string `json:"resource_id"`
	DatabaseName      string `json:"database_name"`
	RequiredDiskBytes int64  `json:"required_disk_bytes"`
	CleanTarget       bool   `json:"clean_target"`
}

// PrepareTargetResponse defines response result for prepare_migration_target.
type PrepareTargetResponse struct {
	TargetReady        bool   `json:"target_ready"`
	ContainerName      string `json:"container_name"`
	AvailableDiskBytes int64  `json:"available_disk_bytes"`
	PgVersion          string `json:"pg_version"`
	CleanTargetApplied bool   `json:"clean_target_applied"`
}

// CreateSnapshotRequest defines request payload for create_migration_snapshot.
type CreateSnapshotRequest struct {
	MigrationID  string `json:"migration_id"`
	ResourceID   string `json:"resource_id"`
	SnapshotID   string `json:"snapshot_id"`
	DatabaseName string `json:"database_name"`
}

// CreateSnapshotResponse defines response result for create_migration_snapshot.
type CreateSnapshotResponse struct {
	SnapshotID   string `json:"snapshot_id"`
	SnapshotPath string `json:"snapshot_path"`
	SizeBytes    int64  `json:"size_bytes"`
	SHA256       string `json:"sha256"`
	TableCount   int    `json:"table_count"`
}

// RestoreArtifactRequest defines request payload for restore_migration_artifact.
type RestoreArtifactRequest struct {
	MigrationID  string `json:"migration_id"`
	ResourceID   string `json:"resource_id"`
	ArtifactPath string `json:"artifact_path"`
	Format       string `json:"format"`
	CleanTarget  bool   `json:"clean_target"`
	DatabaseName string `json:"database_name"`
}

// RestoreArtifactResponse defines response result for restore_migration_artifact.
type RestoreArtifactResponse struct {
	RestoreStatus string `json:"restore_status"`
	Command       string `json:"command"`
	ExitCode      int    `json:"exit_code"`
	WarningsCount int    `json:"warnings_count"`
	DurationMs    int64  `json:"duration_ms"`
}

// InspectTargetRequest defines request payload for inspect_migration_target.
type InspectTargetRequest struct {
	MigrationID  string `json:"migration_id"`
	ResourceID   string `json:"resource_id"`
	DatabaseName string `json:"database_name"`
}

// TargetManifest defines authoritative database catalog snapshot for inspect_migration_target.
type TargetManifest struct {
	Version        string            `json:"version"`
	DatabaseName   string            `json:"database_name"`
	SizeBytes      int64             `json:"size_bytes"`
	Schemas        []string          `json:"schemas"`
	Tables         []string          `json:"tables"`
	Indexes        []string          `json:"indexes"`
	Sequences      []string          `json:"sequences"`
	Extensions     map[string]string `json:"extensions"`
	RowCounts      map[string]int64  `json:"row_counts"`
	AlembicVersion *string           `json:"alembic_version"`
}

// RollbackSnapshotRequest defines request payload for rollback_migration_snapshot.
type RollbackSnapshotRequest struct {
	MigrationID  string `json:"migration_id"`
	ResourceID   string `json:"resource_id"`
	SnapshotID   string `json:"snapshot_id"`
	DatabaseName string `json:"database_name"`
}

// RollbackSnapshotResponse defines response result for rollback_migration_snapshot.
type RollbackSnapshotResponse struct {
	RollbackStatus     string `json:"rollback_status"`
	RestoredSnapshotID string `json:"restored_snapshot_id"`
	DurationMs         int64  `json:"duration_ms"`
}

// CleanupMigrationRequest defines request payload for cleanup_migration.
type CleanupMigrationRequest struct {
	MigrationID    string `json:"migration_id"`
	ResourceID     string `json:"resource_id"`
	PurgeSnapshots bool   `json:"purge_snapshots"`
}

// CleanupMigrationResponse defines response result for cleanup_migration.
type CleanupMigrationResponse struct {
	Cleaned    bool  `json:"cleaned"`
	BytesFreed int64 `json:"bytes_freed"`
}

// MigrationManager provides execution logic for node-local PostgreSQL migrations.
type MigrationManager struct {
	rt          runtime.ContainerRuntime
	vaultClient *vault.Client
	baseDir     string
	logger      *slog.Logger
}

// NewMigrationManager constructs a new MigrationManager.
func NewMigrationManager(rt runtime.ContainerRuntime, vaultClient *vault.Client, baseDir string, logger *slog.Logger) *MigrationManager {
	if baseDir == "" {
		baseDir = "/var/lib/primecloud"
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &MigrationManager{
		rt:          rt,
		vaultClient: vaultClient,
		baseDir:     baseDir,
		logger:      logger.With("component", "postgres_migration_manager"),
	}
}

// SpoolDir returns the directory path for spooling migration artifacts.
func (m *MigrationManager) SpoolDir() string {
	return filepath.Join(m.baseDir, "spool")
}

// SnapshotDir returns the directory path for pre-migration snapshots.
func (m *MigrationManager) SnapshotDir() string {
	return filepath.Join(m.baseDir, "snapshots")
}

// PrepareTarget verifies container existence, health, PostgreSQL connectivity, disk capacity, and version.
func (m *MigrationManager) PrepareTarget(ctx context.Context, projectID string, req *PrepareTargetRequest) (*PrepareTargetResponse, error) {
	if req.ResourceID == "" {
		return nil, errors.New("resource_id cannot be empty")
	}
	if m.rt == nil {
		return nil, errors.New("container runtime is not available")
	}

	containerName := fmt.Sprintf("pc-pg-%s", req.ResourceID)
	inspect, err := m.rt.InspectContainer(ctx, containerName)
	if err != nil {
		return nil, fmt.Errorf("%s: container %s does not exist or failed to inspect: %w", ErrCodeTargetNotReady, containerName, err)
	}
	if !inspect.Running {
		return nil, fmt.Errorf("%s: container %s is not running (state: %s)", ErrCodeTargetNotReady, containerName, inspect.State)
	}
	if inspect.Health != "" && inspect.Health != "healthy" && inspect.Health != "none" {
		return nil, fmt.Errorf("%s: container %s is in unhealthy state: %s", ErrCodeContainerUnhealthy, containerName, inspect.Health)
	}

	// Resolve target PostgreSQL credentials
	creds, err := resolvePostgresCredentials(ctx, m.vaultClient, projectID, req.ResourceID)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to resolve credentials: %w", ErrCodePostgresUnreachable, err)
	}
	dbName := creds.Database
	if req.DatabaseName != "" {
		dbName = req.DatabaseName
	}

	env := []string{fmt.Sprintf("PGPASSWORD=%s", creds.Password)}

	// Verify PostgreSQL reachability and extract version
	versionCmd := []string{"psql", "-U", creds.Username, "-d", dbName, "-t", "-A", "-c", "SELECT version();"}
	stdout, stderr, exitCode, err := m.rt.ExecContainer(ctx, containerName, versionCmd, env, nil)
	if err != nil || exitCode != 0 {
		return nil, fmt.Errorf("%s: postgresql unreachable in container %s (exit %d): %s (err: %v)", ErrCodePostgresUnreachable, containerName, exitCode, strings.TrimSpace(string(stderr)), err)
	}
	pgVersion := strings.TrimSpace(string(stdout))
	if pgVersion == "" {
		pgVersion = "PostgreSQL (unknown version)"
	}

	// Verify disk capacity on spool / snapshots volume
	availDisk, err := getAvailableDiskBytes(m.baseDir)
	if err != nil {
		// Try temp dir fallback for checking
		availDisk, _ = getAvailableDiskBytes(os.TempDir())
	}

	if req.RequiredDiskBytes > 0 && availDisk > 0 && availDisk < req.RequiredDiskBytes {
		return nil, fmt.Errorf("%s: available disk space (%d bytes) is less than required (%d bytes)", ErrCodeInsufficientDisk, availDisk, req.RequiredDiskBytes)
	}

	cleanApplied := false
	if req.CleanTarget {
		// According to Invariant 6: clean_target or DROP SCHEMA must NOT run until pre-migration snapshot has been recorded.
		// So prepare_migration_target validates readiness without prematurely dropping data.
		cleanApplied = false
	}

	return &PrepareTargetResponse{
		TargetReady:        true,
		ContainerName:      containerName,
		AvailableDiskBytes: availDisk,
		PgVersion:          pgVersion,
		CleanTargetApplied: cleanApplied,
	}, nil
}

// CreateSnapshot creates a real pre-migration logical PostgreSQL backup via pg_dump -Fc.
func (m *MigrationManager) CreateSnapshot(ctx context.Context, projectID string, req *CreateSnapshotRequest) (*CreateSnapshotResponse, error) {
	if req.ResourceID == "" {
		return nil, errors.New("resource_id cannot be empty")
	}
	if req.SnapshotID == "" {
		return nil, errors.New("snapshot_id cannot be empty")
	}
	if m.rt == nil {
		return nil, errors.New("container runtime is not available")
	}

	snapshotDir := m.SnapshotDir()
	if err := os.MkdirAll(snapshotDir, 0700); err != nil {
		return nil, fmt.Errorf("%s: failed to create snapshot directory: %w", ErrCodeSnapshotFailed, err)
	}

	containerName := fmt.Sprintf("pc-pg-%s", req.ResourceID)
	creds, err := resolvePostgresCredentials(ctx, m.vaultClient, projectID, req.ResourceID)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to resolve credentials: %w", ErrCodeSnapshotFailed, err)
	}
	dbName := creds.Database
	if req.DatabaseName != "" {
		dbName = req.DatabaseName
	}

	env := []string{fmt.Sprintf("PGPASSWORD=%s", creds.Password)}

	// Count existing non-system tables in database
	countCmd := []string{
		"psql", "-U", creds.Username, "-d", dbName, "-t", "-A", "-c",
		"SELECT count(*) FROM information_schema.tables WHERE table_schema NOT IN ('pg_catalog', 'information_schema');",
	}
	stdout, stderr, exitCode, err := m.rt.ExecContainer(ctx, containerName, countCmd, env, nil)
	tableCount := 0
	if err == nil && exitCode == 0 {
		tc, _ := strconv.Atoi(strings.TrimSpace(string(stdout)))
		tableCount = tc
	}

	// Verify pg_dump binary exists in container
	checkBinCmd := []string{"which", "pg_dump"}
	_, _, binExit, binErr := m.rt.ExecContainer(ctx, containerName, checkBinCmd, env, nil)
	if binErr != nil || binExit != 0 {
		return nil, fmt.Errorf("%s: pg_dump binary is missing inside container %s", ErrCodeBinaryMissing, containerName)
	}

	// Execute pg_dump -Fc
	dumpCmd := []string{
		"pg_dump",
		"-U", creds.Username,
		"-d", dbName,
		"-Fc",
	}

	stdout, stderr, exitCode, err = m.rt.ExecContainer(ctx, containerName, dumpCmd, env, nil)
	if err != nil {
		return nil, fmt.Errorf("%s: failed executing pg_dump on %s: %w (stderr: %s)", ErrCodeSnapshotFailed, containerName, err, string(stderr))
	}
	if exitCode != 0 {
		return nil, fmt.Errorf("%s: pg_dump exited with error code %d: %s", ErrCodeSnapshotFailed, exitCode, strings.TrimSpace(string(stderr)))
	}
	if len(stdout) == 0 {
		return nil, fmt.Errorf("%s: pg_dump produced empty snapshot output", ErrCodeSnapshotFailed)
	}

	snapshotFile := filepath.Join(snapshotDir, fmt.Sprintf("mig-%s.dump", req.SnapshotID))
	if err := os.WriteFile(snapshotFile, stdout, 0600); err != nil {
		return nil, fmt.Errorf("%s: failed writing snapshot file %s: %w", ErrCodeSnapshotFailed, snapshotFile, err)
	}

	h := sha256.New()
	h.Write(stdout)
	sha256Hex := hex.EncodeToString(h.Sum(nil))

	return &CreateSnapshotResponse{
		SnapshotID:   req.SnapshotID,
		SnapshotPath: snapshotFile,
		SizeBytes:    int64(len(stdout)),
		SHA256:       sha256Hex,
		TableCount:   tableCount,
	}, nil
}

// RestoreArtifact executes a real restore inside the target container using pg_restore or psql.
// Non-zero fatal execution errors MUST fail. Missing binaries MUST fail. No fake fallback.
func (m *MigrationManager) RestoreArtifact(ctx context.Context, projectID string, req *RestoreArtifactRequest) (*RestoreArtifactResponse, error) {
	startTime := time.Now()
	if req.ResourceID == "" {
		return nil, errors.New("resource_id cannot be empty")
	}
	if req.ArtifactPath == "" {
		return nil, errors.New("artifact_path cannot be empty")
	}
	if m.rt == nil {
		return nil, errors.New("container runtime is not available")
	}

	fi, err := os.Stat(req.ArtifactPath)
	if err != nil {
		return nil, fmt.Errorf("%s: artifact file %s not found: %w", ErrCodeArtifactNotFound, req.ArtifactPath, err)
	}
	if fi.Size() == 0 {
		return nil, fmt.Errorf("%s: artifact file %s is empty", ErrCodeArtifactCorrupt, req.ArtifactPath)
	}

	fileReader, err := os.Open(req.ArtifactPath)
	if err != nil {
		return nil, fmt.Errorf("failed opening artifact file %s: %w", req.ArtifactPath, err)
	}
	defer fileReader.Close()

	// Read first 512 bytes for format verification
	header := make([]byte, 512)
	n, _ := fileReader.Read(header)
	header = header[:n]
	_, _ = fileReader.Seek(0, io.SeekStart)

	containerName := fmt.Sprintf("pc-pg-%s", req.ResourceID)
	creds, err := resolvePostgresCredentials(ctx, m.vaultClient, projectID, req.ResourceID)
	if err != nil {
		return nil, fmt.Errorf("%s: failed resolving credentials: %w", ErrCodeRestoreFailed, err)
	}
	dbName := creds.Database
	if req.DatabaseName != "" {
		dbName = req.DatabaseName
	}
	env := []string{fmt.Sprintf("PGPASSWORD=%s", creds.Password)}

	// Determine tool to run: pg_restore or psql
	isCustomDump := strings.EqualFold(req.Format, "CUSTOM_DUMP") ||
		strings.EqualFold(req.Format, "TAR") ||
		bytes.HasPrefix(header, []byte("PGDMP")) ||
		(len(header) >= 262 && string(header[257:262]) == "ustar")

	var cmd []string
	var binaryName string

	if isCustomDump {
		binaryName = "pg_restore"
		cmd = []string{
			"pg_restore",
			"-U", creds.Username,
			"-d", dbName,
		}
		if req.CleanTarget {
			cmd = append(cmd, "--clean", "--if-exists")
		}
	} else {
		binaryName = "psql"
		cmd = []string{
			"psql",
			"-U", creds.Username,
			"-d", dbName,
		}
	}

	// Verify required binary exists in container. FAIL CLOSED if missing!
	whichCmd := []string{"which", binaryName}
	_, _, binCode, binErr := m.rt.ExecContainer(ctx, containerName, whichCmd, env, nil)
	if binErr != nil || binCode != 0 {
		return nil, fmt.Errorf("%s: required binary %s is missing in container %s", ErrCodeBinaryMissing, binaryName, containerName)
	}

	// Execute restore
	_, stderr, exitCode, execErr := m.rt.ExecContainer(ctx, containerName, cmd, env, fileReader)
	if execErr != nil {
		return nil, fmt.Errorf("%s: restore execution failed on %s: %w (stderr: %s)", ErrCodeRestoreFailed, containerName, execErr, string(stderr))
	}

	warningsCount := 0
	if binaryName == "pg_restore" {
		// pg_restore: 0 is clean success; 1 is warnings; >1 is fatal error
		if exitCode > 1 {
			return nil, fmt.Errorf("%s: pg_restore exited with error code %d: %s", ErrCodeRestoreFailed, exitCode, strings.TrimSpace(string(stderr)))
		}
		if exitCode == 1 {
			warningsCount = 1
			if len(stderr) > 0 {
				warningsCount = strings.Count(string(stderr), "\n") + 1
			}
		}
	} else {
		// psql: 0 is success; non-zero is failure
		if exitCode != 0 {
			return nil, fmt.Errorf("%s: psql exited with error code %d: %s", ErrCodeRestoreFailed, exitCode, strings.TrimSpace(string(stderr)))
		}
	}

	// Post-restore connectivity and query verification
	verifyCmd := []string{"psql", "-U", creds.Username, "-d", dbName, "-t", "-A", "-c", "SELECT 1;"}
	vOut, vStderr, vCode, vErr := m.rt.ExecContainer(ctx, containerName, verifyCmd, env, nil)
	if vErr != nil || vCode != 0 || strings.TrimSpace(string(vOut)) != "1" {
		return nil, fmt.Errorf("%s: post-restore database verification query failed (exit %d): %s", ErrCodeRestoreFailed, vCode, strings.TrimSpace(string(vStderr)))
	}

	duration := time.Since(startTime).Milliseconds()
	return &RestoreArtifactResponse{
		RestoreStatus: "SUCCEEDED",
		Command:       binaryName,
		ExitCode:      exitCode,
		WarningsCount: warningsCount,
		DurationMs:    duration,
	}, nil
}

// InspectTarget runs real PostgreSQL catalog queries against the container and returns the locked TargetManifest.
func (m *MigrationManager) InspectTarget(ctx context.Context, projectID string, req *InspectTargetRequest) (*TargetManifest, error) {
	if req.ResourceID == "" {
		return nil, errors.New("resource_id cannot be empty")
	}
	if m.rt == nil {
		return nil, errors.New("container runtime is not available")
	}

	containerName := fmt.Sprintf("pc-pg-%s", req.ResourceID)
	creds, err := resolvePostgresCredentials(ctx, m.vaultClient, projectID, req.ResourceID)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to resolve credentials: %w", ErrCodeInspectionFailed, err)
	}
	dbName := creds.Database
	if req.DatabaseName != "" {
		dbName = req.DatabaseName
	}
	env := []string{fmt.Sprintf("PGPASSWORD=%s", creds.Password)}

	// 1. Version
	verOut, _, code, err := m.rt.ExecContainer(ctx, containerName, []string{"psql", "-U", creds.Username, "-d", dbName, "-t", "-A", "-c", "SELECT version();"}, env, nil)
	if err != nil || code != 0 {
		return nil, fmt.Errorf("%s: failed querying version: %v", ErrCodeInspectionFailed, err)
	}
	version := strings.TrimSpace(string(verOut))

	// 2. Database Size
	sizeOut, _, code, err := m.rt.ExecContainer(ctx, containerName, []string{"psql", "-U", creds.Username, "-d", dbName, "-t", "-A", "-c", fmt.Sprintf("SELECT pg_database_size('%s');", dbName)}, env, nil)
	var sizeBytes int64
	if err == nil && code == 0 {
		sizeBytes, _ = strconv.ParseInt(strings.TrimSpace(string(sizeOut)), 10, 64)
	}

	// 3. Schemas (non-system schemas)
	schemaSQL := "SELECT schema_name FROM information_schema.schemata WHERE schema_name NOT IN ('pg_catalog', 'information_schema') AND schema_name NOT LIKE 'pg_toast%' AND schema_name NOT LIKE 'pg_temp%' ORDER BY schema_name;"
	schemaOut, _, code, err := m.rt.ExecContainer(ctx, containerName, []string{"psql", "-U", creds.Username, "-d", dbName, "-t", "-A", "-c", schemaSQL}, env, nil)
	if err != nil || code != 0 {
		return nil, fmt.Errorf("%s: failed querying schemas: %v", ErrCodeInspectionFailed, err)
	}
	schemas := splitLines(string(schemaOut))

	// 4. Tables
	tableSQL := "SELECT table_schema || '.' || table_name FROM information_schema.tables WHERE table_schema NOT IN ('pg_catalog', 'information_schema') AND table_type = 'BASE TABLE' ORDER BY 1;"
	tableOut, _, code, err := m.rt.ExecContainer(ctx, containerName, []string{"psql", "-U", creds.Username, "-d", dbName, "-t", "-A", "-c", tableSQL}, env, nil)
	if err != nil || code != 0 {
		return nil, fmt.Errorf("%s: failed querying tables: %v", ErrCodeInspectionFailed, err)
	}
	tables := splitLines(string(tableOut))

	// 5. Indexes
	indexSQL := "SELECT schemaname || '.' || indexname FROM pg_indexes WHERE schemaname NOT IN ('pg_catalog', 'information_schema') ORDER BY 1;"
	indexOut, _, code, err := m.rt.ExecContainer(ctx, containerName, []string{"psql", "-U", creds.Username, "-d", dbName, "-t", "-A", "-c", indexSQL}, env, nil)
	if err != nil || code != 0 {
		return nil, fmt.Errorf("%s: failed querying indexes: %v", ErrCodeInspectionFailed, err)
	}
	indexes := splitLines(string(indexOut))

	// 6. Sequences
	seqSQL := "SELECT sequence_schema || '.' || sequence_name FROM information_schema.sequences WHERE sequence_schema NOT IN ('pg_catalog', 'information_schema') ORDER BY 1;"
	seqOut, _, code, err := m.rt.ExecContainer(ctx, containerName, []string{"psql", "-U", creds.Username, "-d", dbName, "-t", "-A", "-c", seqSQL}, env, nil)
	if err != nil || code != 0 {
		return nil, fmt.Errorf("%s: failed querying sequences: %v", ErrCodeInspectionFailed, err)
	}
	sequences := splitLines(string(seqOut))

	// 7. Extensions
	extSQL := "SELECT extname || ':' || extversion FROM pg_extension WHERE extname != 'plpgsql' ORDER BY extname;"
	extOut, _, code, err := m.rt.ExecContainer(ctx, containerName, []string{"psql", "-U", creds.Username, "-d", dbName, "-t", "-A", "-c", extSQL}, env, nil)
	extensions := make(map[string]string)
	if err == nil && code == 0 {
		for _, line := range splitLines(string(extOut)) {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				extensions[parts[0]] = parts[1]
			}
		}
	}

	// 8. Row Counts for each table
	rowCounts := make(map[string]int64)
	for _, tbl := range tables {
		parts := strings.SplitN(tbl, ".", 2)
		if len(parts) != 2 {
			continue
		}
		rcSQL := fmt.Sprintf(`SELECT count(*) FROM "%s"."%s";`, parts[0], parts[1])
		rcOut, _, rCode, rErr := m.rt.ExecContainer(ctx, containerName, []string{"psql", "-U", creds.Username, "-d", dbName, "-t", "-A", "-c", rcSQL}, env, nil)
		if rErr == nil && rCode == 0 {
			count, _ := strconv.ParseInt(strings.TrimSpace(string(rcOut)), 10, 64)
			rowCounts[tbl] = count
		} else {
			rowCounts[tbl] = 0
		}
	}

	// 9. Alembic Version
	var alembicVersion *string
	alembicSQL := "SELECT version_num FROM alembic_version LIMIT 1;"
	avOut, _, avCode, avErr := m.rt.ExecContainer(ctx, containerName, []string{"psql", "-U", creds.Username, "-d", dbName, "-t", "-A", "-c", alembicSQL}, env, nil)
	if avErr == nil && avCode == 0 {
		v := strings.TrimSpace(string(avOut))
		if v != "" {
			alembicVersion = &v
		}
	}

	return &TargetManifest{
		Version:        version,
		DatabaseName:   dbName,
		SizeBytes:      sizeBytes,
		Schemas:        schemas,
		Tables:         tables,
		Indexes:        indexes,
		Sequences:      sequences,
		Extensions:     extensions,
		RowCounts:      rowCounts,
		AlembicVersion: alembicVersion,
	}, nil
}

// RollbackSnapshot restores the pre-migration snapshot into the target container.
func (m *MigrationManager) RollbackSnapshot(ctx context.Context, projectID string, req *RollbackSnapshotRequest) (*RollbackSnapshotResponse, error) {
	startTime := time.Now()
	if req.ResourceID == "" {
		return nil, errors.New("resource_id cannot be empty")
	}
	if req.SnapshotID == "" {
		return nil, errors.New("snapshot_id cannot be empty")
	}
	if m.rt == nil {
		return nil, errors.New("container runtime is not available")
	}

	snapshotFile := filepath.Join(m.SnapshotDir(), fmt.Sprintf("mig-%s.dump", req.SnapshotID))
	if _, err := os.Stat(snapshotFile); err != nil {
		return nil, fmt.Errorf("%s: snapshot file %s not found: %w", ErrCodeRollbackFailed, snapshotFile, err)
	}

	// Restore snapshot using RestoreArtifact with clean_target=true
	restoreReq := &RestoreArtifactRequest{
		MigrationID:  req.MigrationID,
		ResourceID:   req.ResourceID,
		ArtifactPath: snapshotFile,
		Format:       "CUSTOM_DUMP",
		CleanTarget:  true,
		DatabaseName: req.DatabaseName,
	}

	_, err := m.RestoreArtifact(ctx, projectID, restoreReq)
	if err != nil {
		return nil, fmt.Errorf("%s: rollback restore failed: %w", ErrCodeRollbackFailed, err)
	}

	duration := time.Since(startTime).Milliseconds()
	return &RollbackSnapshotResponse{
		RollbackStatus:     "ROLLED_BACK",
		RestoredSnapshotID: req.SnapshotID,
		DurationMs:         duration,
	}, nil
}

// CleanupMigration removes ephemeral migration spool files and optionally purge snapshots.
func (m *MigrationManager) CleanupMigration(ctx context.Context, req *CleanupMigrationRequest) (*CleanupMigrationResponse, error) {
	if req.MigrationID == "" && req.ResourceID == "" {
		return nil, errors.New("migration_id or resource_id is required")
	}

	var bytesFreed int64

	// 1. Spool files cleaning
	spoolDir := m.SpoolDir()
	if entries, err := os.ReadDir(spoolDir); err == nil {
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			name := e.Name()
			if (req.MigrationID != "" && strings.Contains(name, req.MigrationID)) ||
				(req.ResourceID != "" && strings.Contains(name, req.ResourceID)) {
				filePath := filepath.Join(spoolDir, name)
				if fi, err := e.Info(); err == nil {
					bytesFreed += fi.Size()
				}
				_ = os.Remove(filePath)
			}
		}
	}

	// 2. Snapshots purging if requested
	if req.PurgeSnapshots {
		snapDir := m.SnapshotDir()
		if entries, err := os.ReadDir(snapDir); err == nil {
			for _, e := range entries {
				if e.IsDir() {
					continue
				}
				name := e.Name()
				if (req.MigrationID != "" && strings.Contains(name, req.MigrationID)) ||
					(req.ResourceID != "" && strings.Contains(name, req.ResourceID)) {
					filePath := filepath.Join(snapDir, name)
					if fi, err := e.Info(); err == nil {
						bytesFreed += fi.Size()
					}
					_ = os.Remove(filePath)
				}
			}
		}
	}

	return &CleanupMigrationResponse{
		Cleaned:    true,
		BytesFreed: bytesFreed,
	}, nil
}

func splitLines(s string) []string {
	var lines []string
	for _, l := range strings.Split(s, "\n") {
		trimmed := strings.TrimSpace(l)
		if trimmed != "" {
			lines = append(lines, trimmed)
		}
	}
	return lines
}

