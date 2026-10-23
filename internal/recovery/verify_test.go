package recovery_test

import (
	"context"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/primecloud/primecloud-agent/internal/recovery"
	"github.com/primecloud/primecloud-agent/internal/runtime"
)

type mockVerifyRuntime struct {
	inspectFunc func(ctx context.Context, id string) (*runtime.ContainerInspect, error)
	execFunc    func(ctx context.Context, id string, cmd []string, env []string, stdin io.Reader) ([]byte, []byte, int, error)
}

func (m *mockVerifyRuntime) PullImage(ctx context.Context, ref string) error { return nil }
func (m *mockVerifyRuntime) PullImageWithAuth(ctx context.Context, ref, auth string) error {
	return nil
}
func (m *mockVerifyRuntime) CreateContainer(ctx context.Context, cfg *runtime.ContainerConfig, l *runtime.ResourceLimits, p *runtime.HardenedIsolationProfile) (string, error) {
	return "mock-cid", nil
}
func (m *mockVerifyRuntime) StartContainer(ctx context.Context, id string) error { return nil }
func (m *mockVerifyRuntime) StopContainer(ctx context.Context, id string, timeout *int) error {
	return nil
}
func (m *mockVerifyRuntime) RemoveContainer(ctx context.Context, id string, force bool) error {
	return nil
}
func (m *mockVerifyRuntime) InspectContainer(ctx context.Context, id string) (*runtime.ContainerInspect, error) {
	if m.inspectFunc != nil {
		return m.inspectFunc(ctx, id)
	}
	return &runtime.ContainerInspect{ID: id, Running: true, Health: "healthy"}, nil
}
func (m *mockVerifyRuntime) GetContainerLogs(ctx context.Context, containerID string) (io.ReadCloser, error) {
	return nil, nil
}
func (m *mockVerifyRuntime) ListContainers(ctx context.Context, all bool) ([]runtime.ContainerSummary, error) {
	return nil, nil
}
func (m *mockVerifyRuntime) ExecContainer(ctx context.Context, containerID string, cmd []string, env []string, stdin io.Reader) ([]byte, []byte, int, error) {
	if m.execFunc != nil {
		return m.execFunc(ctx, containerID, cmd, env, stdin)
	}
	return nil, nil, 0, nil
}
func (m *mockVerifyRuntime) GetContainerStats(ctx context.Context, containerID string) (io.ReadCloser, error) {
	return nil, nil
}
func (m *mockVerifyRuntime) Ping(ctx context.Context) error { return nil }
func (m *mockVerifyRuntime) Close() error                   { return nil }

func TestVerifyServiceReady_FailsClosed(t *testing.T) {
	ctx := context.Background()

	// 1. Nil runtime fails closed
	nilVerifier := recovery.NewVerifier(nil)
	if err := nilVerifier.VerifyServiceReady(ctx, "c-1"); err == nil || !strings.Contains(err.Error(), "CONTAINER_RUNTIME_UNAVAILABLE") {
		t.Fatalf("expected CONTAINER_RUNTIME_UNAVAILABLE, got: %v", err)
	}

	// 2. Empty containerID fails closed
	rt := &mockVerifyRuntime{}
	v := recovery.NewVerifier(rt)
	if err := v.VerifyServiceReady(ctx, ""); err == nil || !strings.Contains(err.Error(), "INVALID_ARGUMENT") {
		t.Fatalf("expected INVALID_ARGUMENT, got: %v", err)
	}

	// 3. Container not found fails closed
	rt.inspectFunc = func(ctx context.Context, id string) (*runtime.ContainerInspect, error) {
		return nil, fmt.Errorf("no such container")
	}
	if err := v.VerifyServiceReady(ctx, "missing"); err == nil || !strings.Contains(err.Error(), "CONTAINER_NOT_FOUND") {
		t.Fatalf("expected CONTAINER_NOT_FOUND, got: %v", err)
	}

	// 4. Container stopped fails closed
	rt.inspectFunc = func(ctx context.Context, id string) (*runtime.ContainerInspect, error) {
		return &runtime.ContainerInspect{ID: id, Running: false, State: "exited"}, nil
	}
	if err := v.VerifyServiceReady(ctx, "stopped"); err == nil || !strings.Contains(err.Error(), "CONTAINER_NOT_RUNNING") {
		t.Fatalf("expected CONTAINER_NOT_RUNNING, got: %v", err)
	}

	// 5. Container unhealthy fails closed
	rt.inspectFunc = func(ctx context.Context, id string) (*runtime.ContainerInspect, error) {
		return &runtime.ContainerInspect{ID: id, Running: true, Health: "unhealthy"}, nil
	}
	if err := v.VerifyServiceReady(ctx, "unhealthy"); err == nil || !strings.Contains(err.Error(), "CONTAINER_UNHEALTHY") {
		t.Fatalf("expected CONTAINER_UNHEALTHY, got: %v", err)
	}

	// 6. Healthy container succeeds
	rt.inspectFunc = func(ctx context.Context, id string) (*runtime.ContainerInspect, error) {
		return &runtime.ContainerInspect{ID: id, Running: true, Health: "healthy"}, nil
	}
	if err := v.VerifyServiceReady(ctx, "running"); err != nil {
		t.Fatalf("expected nil error on healthy container, got: %v", err)
	}
}

func TestVerifyPostgres_AuthenticVerification(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// 1. Nil runtime fails closed
	nilVerifier := recovery.NewVerifier(nil)
	res, err := nilVerifier.VerifyPostgres(ctx, "pc-pg-1", "user", "db", 1)
	if err == nil || res.IsHealthy || res.ErrorCode != "RUNTIME_UNAVAILABLE" {
		t.Fatalf("expected RUNTIME_UNAVAILABLE on nil runtime, got res=%v, err=%v", res, err)
	}

	// 2. Stopped container fails closed
	rt := &mockVerifyRuntime{
		inspectFunc: func(ctx context.Context, id string) (*runtime.ContainerInspect, error) {
			return &runtime.ContainerInspect{ID: id, Running: false, State: "stopped"}, nil
		},
	}
	v := recovery.NewVerifier(rt)
	res, err = v.VerifyPostgres(ctx, "pc-pg-1", "user", "db", 1)
	if err == nil || res.IsHealthy || res.ErrorCode != "CONTAINER_NOT_RUNNING" {
		t.Fatalf("expected CONTAINER_NOT_RUNNING, got res=%v, err=%v", res, err)
	}

	// 3. pg_isready failure fails closed
	rt.inspectFunc = func(ctx context.Context, id string) (*runtime.ContainerInspect, error) {
		return &runtime.ContainerInspect{ID: id, Running: true}, nil
	}
	rt.execFunc = func(ctx context.Context, id string, cmd []string, env []string, stdin io.Reader) ([]byte, []byte, int, error) {
		if len(cmd) > 0 && cmd[0] == "pg_isready" {
			return nil, []byte("connection to server failed: Connection refused"), 2, fmt.Errorf("exit 2")
		}
		return nil, nil, 0, nil
	}
	res, err = v.VerifyPostgres(ctx, "pc-pg-1", "user", "db", 1)
	if err == nil || res.IsHealthy || res.ErrorCode != "CONNECTIVITY_FAILED" {
		t.Fatalf("expected CONNECTIVITY_FAILED on pg_isready failure, got res=%v, err=%v", res, err)
	}

	// 4. psql query SELECT 1 failure fails closed
	rt.execFunc = func(ctx context.Context, id string, cmd []string, env []string, stdin io.Reader) ([]byte, []byte, int, error) {
		if len(cmd) > 0 && cmd[0] == "pg_isready" {
			return []byte("accepting connections"), nil, 0, nil
		}
		last := cmd[len(cmd)-1]
		if last == "SELECT 1;" {
			return nil, []byte("FATAL: database db does not exist"), 1, fmt.Errorf("exit 1")
		}
		return nil, nil, 0, nil
	}
	res, err = v.VerifyPostgres(ctx, "pc-pg-1", "user", "db", 1)
	if err == nil || res.IsHealthy || res.ErrorCode != "QUERY_EXECUTION_FAILED" {
		t.Fatalf("expected QUERY_EXECUTION_FAILED on SELECT 1 failure, got res=%v, err=%v", res, err)
	}

	// 5. Schema table parity mismatch fails closed
	rt.execFunc = func(ctx context.Context, id string, cmd []string, env []string, stdin io.Reader) ([]byte, []byte, int, error) {
		if len(cmd) > 0 && cmd[0] == "pg_isready" {
			return []byte("accepting connections"), nil, 0, nil
		}
		last := cmd[len(cmd)-1]
		if last == "SELECT 1;" {
			return []byte("1\n"), nil, 0, nil
		}
		if strings.Contains(last, "information_schema.tables") {
			return []byte("0\n"), nil, 0, nil // 0 tables
		}
		return nil, nil, 0, nil
	}
	res, err = v.VerifyPostgres(ctx, "pc-pg-1", "user", "db", 3)
	if err == nil || res.IsHealthy || res.ErrorCode != "SCHEMA_PARITY_MISMATCH" {
		t.Fatalf("expected SCHEMA_PARITY_MISMATCH when 0 < 3 tables, got res=%v, err=%v", res, err)
	}

	// 6. Fully healthy Postgres verification succeeds
	rt.execFunc = func(ctx context.Context, id string, cmd []string, env []string, stdin io.Reader) ([]byte, []byte, int, error) {
		if len(cmd) > 0 && cmd[0] == "pg_isready" {
			return []byte("accepting connections"), nil, 0, nil
		}
		last := cmd[len(cmd)-1]
		if last == "SELECT 1;" {
			return []byte("1\n"), nil, 0, nil
		}
		if strings.Contains(last, "information_schema.tables") {
			return []byte("5\n"), nil, 0, nil // 5 tables
		}
		return nil, nil, 0, nil
	}
	res, err = v.VerifyPostgres(ctx, "pc-pg-1", "user", "db", 3)
	if err != nil || !res.IsHealthy || res.ErrorCode != "" {
		t.Fatalf("expected healthy postgres verification, got res=%v, err=%v", res, err)
	}
	if res.Details["table_count"] != 5 {
		t.Errorf("expected table_count 5, got %v", res.Details["table_count"])
	}
}

func TestVerifyValkey_AuthenticVerification(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// 1. Nil runtime fails closed
	nilVerifier := recovery.NewVerifier(nil)
	res, err := nilVerifier.VerifyValkey(ctx, "pc-valkey-1")
	if err == nil || res.IsHealthy || res.ErrorCode != "RUNTIME_UNAVAILABLE" {
		t.Fatalf("expected RUNTIME_UNAVAILABLE on nil runtime, got res=%v, err=%v", res, err)
	}

	// 2. Ping failure fails closed
	rt := &mockVerifyRuntime{
		inspectFunc: func(ctx context.Context, id string) (*runtime.ContainerInspect, error) {
			return &runtime.ContainerInspect{ID: id, Running: true}, nil
		},
		execFunc: func(ctx context.Context, id string, cmd []string, env []string, stdin io.Reader) ([]byte, []byte, int, error) {
			if len(cmd) > 1 && cmd[1] == "ping" {
				return nil, []byte("Could not connect to Redis at 127.0.0.1:6379: Connection refused"), 1, fmt.Errorf("exit 1")
			}
			return nil, nil, 0, nil
		},
	}
	v := recovery.NewVerifier(rt)
	res, err = v.VerifyValkey(ctx, "pc-valkey-1")
	if err == nil || res.IsHealthy || res.ErrorCode != "PING_FAILED" {
		t.Fatalf("expected PING_FAILED, got res=%v, err=%v", res, err)
	}

	// 3. Persistence error fails closed
	rt.execFunc = func(ctx context.Context, id string, cmd []string, env []string, stdin io.Reader) ([]byte, []byte, int, error) {
		if len(cmd) > 1 && cmd[1] == "ping" {
			return []byte("PONG\n"), nil, 0, nil
		}
		if len(cmd) > 2 && cmd[2] == "persistence" {
			return []byte("# Persistence\nrdb_last_bgsave_status:err\n"), nil, 0, nil
		}
		return nil, nil, 0, nil
	}
	res, err = v.VerifyValkey(ctx, "pc-valkey-1")
	if err == nil || res.IsHealthy || res.ErrorCode != "PERSISTENCE_CHECK_FAILED" {
		t.Fatalf("expected PERSISTENCE_CHECK_FAILED, got res=%v, err=%v", res, err)
	}

	// 4. Healthy Valkey ping and persistence succeeds
	rt.execFunc = func(ctx context.Context, id string, cmd []string, env []string, stdin io.Reader) ([]byte, []byte, int, error) {
		if len(cmd) > 1 && cmd[1] == "ping" {
			return []byte("PONG\n"), nil, 0, nil
		}
		if len(cmd) > 2 && cmd[2] == "persistence" {
			return []byte("# Persistence\nrdb_last_bgsave_status:ok\n"), nil, 0, nil
		}
		return nil, nil, 0, nil
	}
	res, err = v.VerifyValkey(ctx, "pc-valkey-1")
	if err != nil || !res.IsHealthy || res.ErrorCode != "" {
		t.Fatalf("expected healthy valkey verification, got res=%v, err=%v", res, err)
	}
	if res.Details["ping"] != "PONG" {
		t.Errorf("expected ping PONG, got %v", res.Details["ping"])
	}

	// 5. VerifyDatabase router works for both
	resDb, errDb := v.VerifyDatabase(ctx, "valkey", "pc-valkey-1", "", "", 0)
	if errDb != nil || !resDb.IsHealthy {
		t.Fatalf("expected VerifyDatabase(valkey) to succeed, got %v, err=%v", resDb, errDb)
	}
}
