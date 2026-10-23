package mongodb

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/primecloud/primecloud-agent/internal/runtime"
)

type mockMongoRuntime struct {
	createdCfg    *runtime.ContainerConfig
	createdLimits *runtime.ResourceLimits
	createdProf   *runtime.HardenedIsolationProfile
	running       bool
	health        string
	execCmds      [][]string
	execOut       []byte
	execCode      int
	execErr       error
}

func (m *mockMongoRuntime) CreateContainer(ctx context.Context, cfg *runtime.ContainerConfig, limits *runtime.ResourceLimits, profile *runtime.HardenedIsolationProfile) (string, error) {
	m.createdCfg = cfg
	m.createdLimits = limits
	m.createdProf = profile
	return "cid-mongo-1", nil
}

func (m *mockMongoRuntime) StartContainer(ctx context.Context, containerID string) error {
	m.running = true
	m.health = "healthy"
	return nil
}

func (m *mockMongoRuntime) StopContainer(ctx context.Context, containerID string, timeoutSec *int) error {
	m.running = false
	return nil
}

func (m *mockMongoRuntime) RemoveContainer(ctx context.Context, containerID string, force bool) error {
	m.running = false
	return nil
}

func (m *mockMongoRuntime) InspectContainer(ctx context.Context, containerID string) (*runtime.ContainerInspect, error) {
	return &runtime.ContainerInspect{
		ID:      containerID,
		Name:    containerID,
		Running: m.running,
		State:   "running",
		Health:  m.health,
	}, nil
}

func (m *mockMongoRuntime) PullImage(ctx context.Context, imageRef string) error { return nil }
func (m *mockMongoRuntime) PullImageWithAuth(ctx context.Context, imageRef string, authBase64 string) error {
	return nil
}
func (m *mockMongoRuntime) ListContainers(ctx context.Context, all bool) ([]runtime.ContainerSummary, error) {
	return nil, nil
}
func (m *mockMongoRuntime) GetContainerLogs(ctx context.Context, containerID string) (io.ReadCloser, error) {
	return nil, nil
}
func (m *mockMongoRuntime) GetContainerStats(ctx context.Context, containerID string) (io.ReadCloser, error) {
	return nil, nil
}
func (m *mockMongoRuntime) Ping(ctx context.Context) error { return nil }
func (m *mockMongoRuntime) Close() error                   { return nil }

func (m *mockMongoRuntime) ExecContainer(ctx context.Context, containerID string, cmd []string, env []string, stdin io.Reader) ([]byte, []byte, int, error) {
	m.execCmds = append(m.execCmds, cmd)
	return m.execOut, nil, m.execCode, m.execErr
}

func (m *mockMongoRuntime) ContainerLogs(ctx context.Context, containerID string, tail string) (io.ReadCloser, error) {
	return nil, nil
}

func TestResolvePinnedImage(t *testing.T) {
	img7, err := ResolvePinnedImage("7.0")
	if err != nil || img7 != "mongo:7.0" {
		t.Fatalf("expected mongo:7.0, got %s, err %v", img7, err)
	}
	img6, err := ResolvePinnedImage("6.0")
	if err != nil || img6 != "mongo:6.0" {
		t.Fatalf("expected mongo:6.0, got %s, err %v", img6, err)
	}
	_, errInvalid := ResolvePinnedImage("4.4")
	if errInvalid == nil {
		t.Fatalf("expected error for unsupported MongoDB version 4.4")
	}
}

func TestGenerateCredentials(t *testing.T) {
	creds, err := GenerateCredentials("018f3a8b-1234-7000-8000-000000000002")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if creds.Port != 27017 || creds.ReplicaSet != "rs0" {
		t.Fatalf("expected port 27017 and rs0, got %d %s", creds.Port, creds.ReplicaSet)
	}
	if creds.Username == creds.AdminUsername || creds.Password == creds.AdminPassword {
		t.Fatalf("tenant and admin credentials must be distinct")
	}
}

func TestProvisionReplicaSetAndBackupRestore(t *testing.T) {
	tmpDir := t.TempDir()
	rt := &mockMongoRuntime{
		running: true,
		health:  "healthy",
		execOut: []byte("OK\n"),
	}
	prov := NewProvisioner(rt, nil, tmpDir, nil)
	ctx := context.Background()

	res, err := prov.ProvisionWithProject(ctx, "proj-1", "env-1", "res-mongo-1", "7.0", "27018")
	if err != nil {
		t.Fatalf("ProvisionWithProject failed: %v", err)
	}
	if res.ReplicaSet != "rs0" {
		t.Fatalf("expected replica_set rs0, got %s", res.ReplicaSet)
	}
	if rt.createdCfg.Image != "mongo:7.0" {
		t.Fatalf("expected mongo:7.0, got %s", rt.createdCfg.Image)
	}
	if rt.createdProf.User != "999:999" {
		t.Fatalf("expected UID 999:999, got %s", rt.createdProf.User)
	}

	// Verify --replSet rs0 and --keyFile in command
	cmdStr := strings.Join(rt.createdCfg.Command, " ")
	if !strings.Contains(cmdStr, "--replSet rs0") || !strings.Contains(cmdStr, "--keyFile") {
		t.Fatalf("expected --replSet rs0 and --keyFile in command: %s", cmdStr)
	}

	// Verify bootstrap exec ran rs.initiate and createUser with readWrite/dbAdmin
	if len(rt.execCmds) == 0 {
		t.Fatalf("expected mongosh bootstrap exec")
	}
	bootstrapScript := strings.Join(rt.execCmds[0], " ")
	if !strings.Contains(bootstrapScript, "rs.initiate") || !strings.Contains(bootstrapScript, "readWrite") || !strings.Contains(bootstrapScript, "dbAdmin") {
		t.Fatalf("bootstrap script missing rs.initiate or scoped roles: %s", bootstrapScript)
	}

	// Backup
	rt.execCmds = nil
	rt.execOut = []byte("GZIPPED_ARCHIVE_DATA")
	bkDir := filepath.Join(tmpDir, "backups")
	bkRes, err := BackupMongoDBWithVault(ctx, rt, nil, "proj-1", "res-mongo-1", bkDir)
	if err != nil {
		t.Fatalf("BackupMongoDBWithVault failed: %v", err)
	}
	if bkRes.SizeBytes == 0 {
		t.Fatalf("expected non-zero backup size")
	}
	if len(rt.execCmds) == 0 || rt.execCmds[0][0] != "mongodump" {
		t.Fatalf("expected mongodump execution")
	}

	// Restore
	rt.execOut = []byte("1\n")
	if err := RestoreMongoDBWithVault(ctx, rt, nil, "proj-1", "res-mongo-1", bkRes.ArtifactPath); err != nil {
		t.Fatalf("RestoreMongoDBWithVault failed: %v", err)
	}

	// Fail-closed restore when artifact empty
	emptyFile := filepath.Join(tmpDir, "empty.archive.gz")
	_ = os.WriteFile(emptyFile, nil, 0600)
	if err := RestoreMongoDBWithVault(ctx, rt, nil, "proj-1", "res-mongo-1", emptyFile); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("expected fail-closed error on empty artifact, got %v", err)
	}
}
