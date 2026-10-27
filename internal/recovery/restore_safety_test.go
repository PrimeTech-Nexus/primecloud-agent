package recovery_test

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/primecloud/primecloud-agent/internal/backup"
	"github.com/primecloud/primecloud-agent/internal/mongodb"
	"github.com/primecloud/primecloud-agent/internal/mysql"
	"github.com/primecloud/primecloud-agent/internal/postgres"
	"github.com/primecloud/primecloud-agent/internal/recovery"
	"github.com/primecloud/primecloud-agent/internal/runtime"
	"github.com/primecloud/primecloud-agent/internal/valkey"
)

// mockSafetyRuntime tracks container operations with thread safety.
type mockSafetyRuntime struct {
	mu             sync.Mutex
	containers     map[string]*runtime.ContainerInspect
	createdConfigs []*runtime.ContainerConfig
	startedIDs     []string
	stoppedIDs     []string
	execCalls      []execCallRecord
}

type execCallRecord struct {
	ContainerID string
	Cmd         []string
	Env         []string
	StdinData   []byte
}

func newMockSafetyRuntime() *mockSafetyRuntime {
	return &mockSafetyRuntime{
		containers: make(map[string]*runtime.ContainerInspect),
	}
}

func (m *mockSafetyRuntime) PullImage(ctx context.Context, ref string) error { return nil }
func (m *mockSafetyRuntime) PullImageWithAuth(ctx context.Context, ref, auth string) error {
	return nil
}

func (m *mockSafetyRuntime) CreateContainer(ctx context.Context, cfg *runtime.ContainerConfig, l *runtime.ResourceLimits, p *runtime.HardenedIsolationProfile) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.createdConfigs = append(m.createdConfigs, cfg)
	m.containers[cfg.Name] = &runtime.ContainerInspect{
		ID:      cfg.Name,
		Name:    cfg.Name,
		Running: false,
		State:   "created",
	}
	return cfg.Name, nil
}

func (m *mockSafetyRuntime) StartContainer(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.startedIDs = append(m.startedIDs, id)
	if c, ok := m.containers[id]; ok {
		c.Running = true
		c.State = "running"
	} else {
		m.containers[id] = &runtime.ContainerInspect{
			ID:      id,
			Name:    id,
			Running: true,
			State:   "running",
		}
	}
	return nil
}

func (m *mockSafetyRuntime) StopContainer(ctx context.Context, id string, timeout *int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stoppedIDs = append(m.stoppedIDs, id)
	if c, ok := m.containers[id]; ok {
		c.Running = false
		c.State = "stopped"
	}
	return nil
}

func (m *mockSafetyRuntime) RemoveContainer(ctx context.Context, id string, force bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.containers, id)
	return nil
}

func (m *mockSafetyRuntime) InspectContainer(ctx context.Context, id string) (*runtime.ContainerInspect, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if c, ok := m.containers[id]; ok {
		return c, nil
	}
	return nil, fmt.Errorf("CONTAINER_NOT_FOUND: no such container: %s", id)
}

func (m *mockSafetyRuntime) ListContainers(ctx context.Context, all bool) ([]runtime.ContainerSummary, error) {
	return nil, nil
}

func (m *mockSafetyRuntime) GetContainerLogs(ctx context.Context, containerID string) (io.ReadCloser, error) {
	return nil, nil
}

func (m *mockSafetyRuntime) GetContainerStats(ctx context.Context, containerID string) (io.ReadCloser, error) {
	return nil, nil
}

func (m *mockSafetyRuntime) Ping(ctx context.Context) error { return nil }
func (m *mockSafetyRuntime) Close() error                   { return nil }

func (m *mockSafetyRuntime) ExecContainer(ctx context.Context, containerID string, cmd []string, env []string, stdin io.Reader) ([]byte, []byte, int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	var stdinBuf []byte
	if stdin != nil {
		stdinBuf, _ = io.ReadAll(stdin)
	}

	m.execCalls = append(m.execCalls, execCallRecord{
		ContainerID: containerID,
		Cmd:         cmd,
		Env:         env,
		StdinData:   stdinBuf,
	})

	// Simulate successful verification responses
	cmdStr := strings.Join(cmd, " ")
	if strings.Contains(cmdStr, "pg_isready") {
		return []byte("accepting connections"), nil, 0, nil
	}
	if strings.Contains(cmdStr, "SELECT 1;") {
		return []byte("1"), nil, 0, nil
	}
	if strings.Contains(cmdStr, "ping: 1") {
		return []byte("1"), nil, 0, nil
	}
	if strings.Contains(cmdStr, "ping") || strings.Contains(cmdStr, "PING") {
		return []byte("PONG"), nil, 0, nil
	}

	return []byte("success"), nil, 0, nil
}

// 1. AC-1.9, AC-1.14: IN_PLACE_OVERWRITE fails closed without explicit confirm_overwrite=true
func TestRestoreSafety_InPlaceOverwrite_FailsClosedWithoutConfirmation(t *testing.T) {
	testCases := []struct {
		name             string
		targetMode       string
		confirmOverwrite bool
		resourceID       string
		wantErrContains  string
	}{
		{
			name:             "InPlaceOverwrite_WithoutConfirmation_FailsClosed",
			targetMode:       "IN_PLACE_OVERWRITE",
			confirmOverwrite: false,
			resourceID:       "res-pg-live-001",
			wantErrContains:  "OVERWRITE_CONFIRMATION_REQUIRED",
		},
		{
			name:             "InPlaceOverwrite_CaseInsensitive_WithoutConfirmation_FailsClosed",
			targetMode:       "in_place_overwrite",
			confirmOverwrite: false,
			resourceID:       "res-pg-live-002",
			wantErrContains:  "OVERWRITE_CONFIRMATION_REQUIRED",
		},
		{
			name:             "InPlaceOverwrite_WithConfirmation_Passes",
			targetMode:       "IN_PLACE_OVERWRITE",
			confirmOverwrite: true,
			resourceID:       "res-pg-live-003",
			wantErrContains:  "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := recovery.ValidateRestoreSafety(recovery.RestoreSafetyConfig{
				TargetMode:       tc.targetMode,
				TargetContainer:  "",
				ConfirmOverwrite: tc.confirmOverwrite,
				ResourceID:       tc.resourceID,
			})

			if tc.wantErrContains != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tc.wantErrContains)
				}
				if !strings.Contains(err.Error(), tc.wantErrContains) {
					t.Fatalf("expected error containing %q, got: %v", tc.wantErrContains, err)
				}
			} else {
				if err != nil {
					t.Fatalf("expected nil error, got: %v", err)
				}
			}
		})
	}
}

// 2. AC-1.1, AC-1.3, AC-1.5, AC-1.14: NEW_INSTANCE requires target_container_name and rejects source substitution
func TestRestoreSafety_NewInstance_TargetValidation(t *testing.T) {
	testCases := []struct {
		name             string
		targetMode       string
		targetContainer  string
		resourceID       string
		wantErrContains  string
	}{
		{
			name:            "NewInstance_EmptyTarget_FailsClosed",
			targetMode:      "NEW_INSTANCE",
			targetContainer: "",
			resourceID:      "res-pg-100",
			wantErrContains: "TARGET_CONTAINER_REQUIRED",
		},
		{
			name:            "NewInstance_WhitespaceTarget_FailsClosed",
			targetMode:      "NEW_INSTANCE",
			targetContainer: "   ",
			resourceID:      "res-pg-100",
			wantErrContains: "TARGET_CONTAINER_REQUIRED",
		},
		{
			name:            "NewInstance_SourceResourceIDAsTarget_FailsClosed",
			targetMode:      "NEW_INSTANCE",
			targetContainer: "res-pg-100",
			resourceID:      "res-pg-100",
			wantErrContains: "TARGET_CONTAINER_INVALID",
		},
		{
			name:            "NewInstance_SourcePostgresContainerAsTarget_FailsClosed",
			targetMode:      "NEW_INSTANCE",
			targetContainer: "pc-pg-res-pg-100",
			resourceID:      "res-pg-100",
			wantErrContains: "TARGET_CONTAINER_INVALID",
		},
		{
			name:            "NewInstance_SourceMySQLContainerAsTarget_FailsClosed",
			targetMode:      "NEW_INSTANCE",
			targetContainer: "pc-my-res-my-200",
			resourceID:      "res-my-200",
			wantErrContains: "TARGET_CONTAINER_INVALID",
		},
		{
			name:            "NewInstance_SourceMongoContainerAsTarget_FailsClosed",
			targetMode:      "NEW_INSTANCE",
			targetContainer: "pc-mg-res-mg-300",
			resourceID:      "res-mg-300",
			wantErrContains: "TARGET_CONTAINER_INVALID",
		},
		{
			name:            "NewInstance_SourceValkeyContainerAsTarget_FailsClosed",
			targetMode:      "NEW_INSTANCE",
			targetContainer: "pc-vk-res-vk-400",
			resourceID:      "res-vk-400",
			wantErrContains: "TARGET_CONTAINER_INVALID",
		},
		{
			name:            "NewInstance_ValidDistinctSandbox_Passes",
			targetMode:      "NEW_INSTANCE",
			targetContainer: "pc_drill_tgt_drill-999",
			resourceID:      "res-pg-100",
			wantErrContains: "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := recovery.ValidateRestoreSafety(recovery.RestoreSafetyConfig{
				TargetMode:       tc.targetMode,
				TargetContainer:  tc.targetContainer,
				ConfirmOverwrite: false,
				ResourceID:       tc.resourceID,
			})

			if tc.wantErrContains != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tc.wantErrContains)
				}
				if !strings.Contains(err.Error(), tc.wantErrContains) {
					t.Fatalf("expected error containing %q, got: %v", tc.wantErrContains, err)
				}
			} else {
				if err != nil {
					t.Fatalf("expected nil error, got: %v", err)
				}
			}
		})
	}
}

// 3. AC-1.1, AC-1.2, AC-1.3: Sandbox container provisioning in PostgreSQL keeps source container 100% untouched
func TestRestorePostgres_SandboxProvisioning_SourceUntouched(t *testing.T) {
	ctx := context.Background()
	rt := newMockSafetyRuntime()

	tmpDir := t.TempDir()
	dumpPath := filepath.Join(tmpDir, "test.dump")
	// Write dummy PostgreSQL custom dump header "PGDMP"
	_ = os.WriteFile(dumpPath, []byte("PGDMP\x01\x02\x03dummy postgres archive data"), 0600)

	sourceResID := "source-uuid-1111"
	sourceContainer := fmt.Sprintf("pc-pg-%s", sourceResID)
	sandboxTarget := "pc_drill_tgt_drill-7777"

	// Register source container as live in mock runtime
	rt.containers[sourceContainer] = &runtime.ContainerInspect{
		ID:      sourceContainer,
		Name:    sourceContainer,
		Running: true,
		State:   "running",
	}

	// Target sandbox container does NOT exist initially
	if _, err := rt.InspectContainer(ctx, sandboxTarget); err == nil {
		t.Fatalf("expected target sandbox %s to not exist initially", sandboxTarget)
	}

	// Execute restore targeting the isolated sandbox container
	err := postgres.RestorePostgresWithVault(ctx, rt, nil, "default", sourceResID, dumpPath, sandboxTarget)
	if err != nil {
		t.Fatalf("RestorePostgresWithVault failed: %v", err)
	}

	// 1. Verify isolated sandbox container was created with verified engine image
	if len(rt.createdConfigs) == 0 {
		t.Fatalf("expected sandbox container to be created in runtime")
	}
	var createdSandbox *runtime.ContainerConfig
	for _, cfg := range rt.createdConfigs {
		if cfg.Name == sandboxTarget {
			createdSandbox = cfg
			break
		}
	}
	if createdSandbox == nil {
		t.Fatalf("expected creation of container %s, got configs: %+v", sandboxTarget, rt.createdConfigs)
	}
	if createdSandbox.Image != "postgres:16-alpine" {
		t.Errorf("expected verified image postgres:16-alpine, got %s", createdSandbox.Image)
	}
	if createdSandbox.Labels["primecloud.drill"] != "true" {
		t.Errorf("expected primecloud.drill label to be true, got %v", createdSandbox.Labels)
	}

	// 2. Verify restore commands ran against the sandbox target
	var restoredOnTarget bool
	var verifiedOnTarget bool
	for _, call := range rt.execCalls {
		if call.ContainerID == sandboxTarget {
			cmdStr := strings.Join(call.Cmd, " ")
			if strings.Contains(cmdStr, "pg_restore") {
				restoredOnTarget = true
			}
			if strings.Contains(cmdStr, "SELECT 1;") {
				verifiedOnTarget = true
			}
		}
	}
	if !restoredOnTarget {
		t.Errorf("expected pg_restore to be executed on target container %s", sandboxTarget)
	}
	if !verifiedOnTarget {
		t.Errorf("expected SELECT 1; verification to be executed on target container %s", sandboxTarget)
	}

	// 3. CRITICAL SECURITY ASSERTION (AC-1.2): Source container remained 100% untouched!
	for _, call := range rt.execCalls {
		if call.ContainerID == sourceContainer {
			t.Fatalf("CRITICAL SECURITY VIOLATION: command was executed against source container %s: %+v", sourceContainer, call.Cmd)
		}
	}
	for _, sID := range rt.stoppedIDs {
		if sID == sourceContainer {
			t.Fatalf("CRITICAL SECURITY VIOLATION: source container %s was stopped during restore", sourceContainer)
		}
	}
}

// 4. AC-1.11: Retries and duplicate requests are safe and idempotent
func TestRestorePostgres_SandboxProvisioning_IdempotentRetry(t *testing.T) {
	ctx := context.Background()
	rt := newMockSafetyRuntime()

	tmpDir := t.TempDir()
	dumpPath := filepath.Join(tmpDir, "test.dump")
	_ = os.WriteFile(dumpPath, []byte("PGDMP\x01\x02\x03dummy postgres archive data"), 0600)

	sourceResID := "source-uuid-2222"
	sandboxTarget := "pc_drill_tgt_retry-8888"

	// Pre-populate container as ALREADY existing (e.g. from an earlier attempt / retry)
	rt.containers[sandboxTarget] = &runtime.ContainerInspect{
		ID:      sandboxTarget,
		Name:    sandboxTarget,
		Running: false, // stopped from prior run
		State:   "exited",
	}

	// Execute restore
	err := postgres.RestorePostgresWithVault(ctx, rt, nil, "default", sourceResID, dumpPath, sandboxTarget)
	if err != nil {
		t.Fatalf("RestorePostgresWithVault retry failed: %v", err)
	}

	// Assert: CreateContainer was NOT called because container already existed (AC-1.11)
	if len(rt.createdConfigs) != 0 {
		t.Fatalf("expected 0 CreateContainer calls on idempotent retry, got %d", len(rt.createdConfigs))
	}

	// Assert: Container was started and restored into idempotently
	var started bool
	for _, id := range rt.startedIDs {
		if id == sandboxTarget {
			started = true
			break
		}
	}
	if !started {
		t.Errorf("expected existing sandbox container %s to be started on retry", sandboxTarget)
	}
}

// 5. AC-1.15: MongoDB restore passes credentials via environment and NOT in command-line flags
func TestRestoreMongoDB_PasswordNotInCommandLineFlags(t *testing.T) {
	ctx := context.Background()
	rt := newMockSafetyRuntime()

	tmpDir := t.TempDir()
	archivePath := filepath.Join(tmpDir, "test.archive.gz")
	_ = os.WriteFile(archivePath, []byte("dummy mongodb archive gzip payload"), 0600)

	resID := "res-mongo-sec-01"
	targetContainer := "pc_drill_tgt_mongo_01"

	// Container exists and running
	rt.containers[targetContainer] = &runtime.ContainerInspect{
		ID:      targetContainer,
		Name:    targetContainer,
		Running: true,
		State:   "running",
	}

	err := mongodb.RestoreMongoDBWithVault(ctx, rt, nil, "default", resID, archivePath, targetContainer)
	if err != nil {
		t.Fatalf("RestoreMongoDBWithVault failed: %v", err)
	}

	if len(rt.execCalls) == 0 {
		t.Fatalf("expected exec calls on mongodb restore")
	}

	secretPassword := "password" // default derived password in resolveMongoDBCredentials

	for _, call := range rt.execCalls {
		if call.ContainerID != targetContainer {
			continue
		}

		// Verify cmd flags DO NOT contain the plaintext password
		for i, arg := range call.Cmd {
			if arg == "--password" && i+1 < len(call.Cmd) && call.Cmd[i+1] == secretPassword {
				t.Fatalf("SECURITY LEAK (AC-1.15): mongorestore command-line flag contains plaintext password: %+v", call.Cmd)
			}
			if arg == "-p" && i+1 < len(call.Cmd) && call.Cmd[i+1] == secretPassword {
				t.Fatalf("SECURITY LEAK (AC-1.15): mongosh command-line flag contains plaintext password: %+v", call.Cmd)
			}
		}

		// Verify environment variables carry MONGO_PASS
		var hasPasswordInEnv bool
		for _, envVar := range call.Env {
			if strings.HasPrefix(envVar, "MONGO_PASS=") {
				hasPasswordInEnv = true
				break
			}
		}
		if !hasPasswordInEnv {
			t.Errorf("expected MONGO_PASS in environment slice for call: %+v", call.Cmd)
		}
	}
}

// 6. AC-1.1, AC-1.3: MySQL restore targets explicit container
func TestRestoreMySQL_TargetsExplicitContainer(t *testing.T) {
	ctx := context.Background()
	rt := newMockSafetyRuntime()

	tmpDir := t.TempDir()
	sqlPath := filepath.Join(tmpDir, "test.sql")
	_ = os.WriteFile(sqlPath, []byte("CREATE TABLE t1 (id int);"), 0600)

	sourceResID := "my-source-res"
	targetContainer := "custom-my-target-container"

	rt.containers[targetContainer] = &runtime.ContainerInspect{
		ID:      targetContainer,
		Name:    targetContainer,
		Running: true,
		State:   "running",
	}

	err := mysql.RestoreMySQLWithVault(ctx, rt, nil, "default", sourceResID, sqlPath, targetContainer)
	if err != nil {
		t.Fatalf("RestoreMySQLWithVault failed: %v", err)
	}

	for _, call := range rt.execCalls {
		if call.ContainerID != targetContainer {
			t.Fatalf("expected all exec calls to target %s, got: %s", targetContainer, call.ContainerID)
		}
	}
}

// 7. AC-1.1, AC-1.3: Valkey restore targets explicit container
func TestRestoreValkey_TargetsExplicitContainer(t *testing.T) {
	ctx := context.Background()
	rt := newMockSafetyRuntime()

	tmpDir := t.TempDir()
	rdbPath := filepath.Join(tmpDir, "test.rdb")
	_ = os.WriteFile(rdbPath, []byte("REDIS0009\xffdummy_valkey_rdb_data"), 0600)

	sourceResID := "vk-source-res"
	targetContainer := "custom-vk-target-container"

	rt.containers[targetContainer] = &runtime.ContainerInspect{
		ID:      targetContainer,
		Name:    targetContainer,
		Running: true,
		State:   "running",
	}

	err := valkey.RestoreValkeyWithVault(ctx, rt, nil, tmpDir, "default", sourceResID, rdbPath, targetContainer)
	if err != nil {
		t.Fatalf("RestoreValkeyWithVault failed: %v", err)
	}

	for _, call := range rt.execCalls {
		if call.ContainerID != targetContainer {
			t.Fatalf("expected all exec calls to target %s, got: %s", targetContainer, call.ContainerID)
		}
	}
}

// 8. Reconstructor forwards target container and target mode end-to-end
func TestReconstructor_WithTarget_ForwardsToDriver(t *testing.T) {
	ctx := context.Background()
	rt := newMockSafetyRuntime()

	tmpDir := t.TempDir()
	dumpPath := filepath.Join(tmpDir, "artifact.dump")
	_ = os.WriteFile(dumpPath, []byte("PGDMP\x01\x02\x03dummy postgres archive data"), 0600)

	manifest := &backup.Manifest{
		ResourceID:     "res-pg-forward-1",
		ResourceType:   "postgres",
		ChecksumSHA256: "dummy-hash",
	}

	targetName := "pc_drill_tgt_e2e_forward"
	reconstructor := recovery.NewReconstructor(rt, nil).WithTarget(targetName, "NEW_INSTANCE")

	err := reconstructor.RestoreToWorkloadWithVault(ctx, manifest, dumpPath, nil, tmpDir, "default")
	if err != nil {
		t.Fatalf("RestoreToWorkloadWithVault failed: %v", err)
	}

	// Verify that targetName was used
	if len(rt.createdConfigs) == 0 || rt.createdConfigs[0].Name != targetName {
		t.Fatalf("expected reconstructor to forward target %s to postgres driver", targetName)
	}
}
