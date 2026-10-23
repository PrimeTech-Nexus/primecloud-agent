package mysql

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/primecloud/primecloud-agent/internal/runtime"
)

type mockMySQLRuntime struct {
	createdCfg    *runtime.ContainerConfig
	createdLimits *runtime.ResourceLimits
	createdProf   *runtime.HardenedIsolationProfile
	running       bool
	health        string
	execCmds      [][]string
	execEnv       [][]string
	execOut       []byte
	execCode      int
	execErr       error
}

func (m *mockMySQLRuntime) CreateContainer(ctx context.Context, cfg *runtime.ContainerConfig, limits *runtime.ResourceLimits, profile *runtime.HardenedIsolationProfile) (string, error) {
	m.createdCfg = cfg
	m.createdLimits = limits
	m.createdProf = profile
	return "cid-mysql-1", nil
}

func (m *mockMySQLRuntime) StartContainer(ctx context.Context, containerID string) error {
	m.running = true
	m.health = "healthy"
	return nil
}

func (m *mockMySQLRuntime) StopContainer(ctx context.Context, containerID string, timeoutSec *int) error {
	m.running = false
	return nil
}

func (m *mockMySQLRuntime) RemoveContainer(ctx context.Context, containerID string, force bool) error {
	m.running = false
	return nil
}

func (m *mockMySQLRuntime) InspectContainer(ctx context.Context, containerID string) (*runtime.ContainerInspect, error) {
	return &runtime.ContainerInspect{
		ID:      containerID,
		Name:    containerID,
		Running: m.running,
		State:   "running",
		Health:  m.health,
	}, nil
}

func (m *mockMySQLRuntime) PullImage(ctx context.Context, imageRef string) error { return nil }
func (m *mockMySQLRuntime) PullImageWithAuth(ctx context.Context, imageRef string, authBase64 string) error {
	return nil
}
func (m *mockMySQLRuntime) ListContainers(ctx context.Context, all bool) ([]runtime.ContainerSummary, error) {
	return nil, nil
}
func (m *mockMySQLRuntime) GetContainerLogs(ctx context.Context, containerID string) (io.ReadCloser, error) {
	return nil, nil
}
func (m *mockMySQLRuntime) GetContainerStats(ctx context.Context, containerID string) (io.ReadCloser, error) {
	return nil, nil
}
func (m *mockMySQLRuntime) Ping(ctx context.Context) error { return nil }
func (m *mockMySQLRuntime) Close() error                   { return nil }

func (m *mockMySQLRuntime) ExecContainer(ctx context.Context, containerID string, cmd []string, env []string, stdin io.Reader) ([]byte, []byte, int, error) {
	m.execCmds = append(m.execCmds, cmd)
	m.execEnv = append(m.execEnv, env)
	return m.execOut, nil, m.execCode, m.execErr
}

func (m *mockMySQLRuntime) ContainerLogs(ctx context.Context, containerID string, tail string) (io.ReadCloser, error) {
	return nil, nil
}

func TestResolvePinnedImage(t *testing.T) {
	img, err := ResolvePinnedImage("8.0")
	if err != nil || img != "mysql:8.0" {
		t.Fatalf("expected mysql:8.0, got %s, err %v", img, err)
	}
	img84, err := ResolvePinnedImage("8.4")
	if err != nil || img84 != "mysql:8.4" {
		t.Fatalf("expected mysql:8.4, got %s, err %v", img84, err)
	}
	_, errInvalid := ResolvePinnedImage("5.7")
	if errInvalid == nil {
		t.Fatalf("expected error for unsupported MySQL version 5.7")
	}
}

func TestGenerateCredentials(t *testing.T) {
	creds, err := GenerateCredentials("018f3a8b-1234-7000-8000-000000000001")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if creds.Port != 3306 {
		t.Fatalf("expected port 3306, got %d", creds.Port)
	}
	if creds.Username == "root" || creds.Password == creds.RootPassword {
		t.Fatalf("tenant user and root credentials must be distinct")
	}
	if len(creds.Password) < 32 || len(creds.RootPassword) < 32 {
		t.Fatalf("expected 32-char hex passwords")
	}
}

func TestProvisionAndBackupRestore(t *testing.T) {
	tmpDir := t.TempDir()
	rt := &mockMySQLRuntime{
		running: true,
		health:  "healthy",
		execOut: []byte("-- MySQL dump\nCREATE TABLE t1 (id INT);\n"),
	}
	prov := NewProvisioner(rt, nil, tmpDir, nil)
	ctx := context.Background()

	res, err := prov.ProvisionWithProject(ctx, "proj-1", "env-1", "res-mysql-1", "8.4", "33306")
	if err != nil {
		t.Fatalf("ProvisionWithProject failed: %v", err)
	}
	if res.ContainerID != "cid-mysql-1" {
		t.Fatalf("expected cid-mysql-1, got %s", res.ContainerID)
	}
	if rt.createdCfg.Image != "mysql:8.4" {
		t.Fatalf("expected mysql:8.4, got %s", rt.createdCfg.Image)
	}
	if rt.createdProf.User != "999:999" {
		t.Fatalf("expected UID 999:999, got %s", rt.createdProf.User)
	}

	// Backup
	bkDir := filepath.Join(tmpDir, "backups")
	bkRes, err := BackupMySQLWithVault(ctx, rt, nil, "proj-1", "res-mysql-1", bkDir)
	if err != nil {
		t.Fatalf("BackupMySQLWithVault failed: %v", err)
	}
	if bkRes.SizeBytes == 0 {
		t.Fatalf("expected non-zero backup size")
	}
	if len(rt.execCmds) == 0 || rt.execCmds[0][0] != "mysqldump" {
		t.Fatalf("expected mysqldump execution")
	}
	hasSingleTx := false
	for _, arg := range rt.execCmds[0] {
		if arg == "--single-transaction" {
			hasSingleTx = true
		}
	}
	if !hasSingleTx {
		t.Fatalf("expected --single-transaction in mysqldump args")
	}

	// Restore
	rt.execOut = []byte("1\n")
	if err := RestoreMySQLWithVault(ctx, rt, nil, "proj-1", "res-mysql-1", bkRes.ArtifactPath); err != nil {
		t.Fatalf("RestoreMySQLWithVault failed: %v", err)
	}

	// Lifecycle
	lm := NewLifecycleManager(rt)
	if err := lm.Stop(ctx, res.ContainerID, 5); err != nil || rt.running {
		t.Fatalf("Stop failed: %v", err)
	}
	if err := lm.Start(ctx, res.ContainerID); err != nil || !rt.running {
		t.Fatalf("Start failed: %v", err)
	}
	if err := lm.Restart(ctx, res.ContainerID, 5); err != nil || !rt.running {
		t.Fatalf("Restart failed: %v", err)
	}
	if err := lm.Remove(ctx, res.ContainerID); err != nil {
		t.Fatalf("Remove failed: %v", err)
	}

	// Fail-closed restore when artifact empty
	emptyFile := filepath.Join(tmpDir, "empty.sql")
	_ = os.WriteFile(emptyFile, nil, 0600)
	if err := RestoreMySQLWithVault(ctx, rt, nil, "proj-1", "res-mysql-1", emptyFile); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("expected fail-closed error on empty artifact, got %v", err)
	}
}
