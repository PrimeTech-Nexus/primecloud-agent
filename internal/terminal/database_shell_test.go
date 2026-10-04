package terminal

import (
	"context"
	"testing"
	"time"
)

func TestValidateCommand_SecurityBoundaries(t *testing.T) {
	// Allowed commands
	cmd, err := ValidateCommand("postgres", "psql")
	if err != nil || cmd != "psql" {
		t.Fatalf("expected psql to be allowed, got: %v (err: %v)", cmd, err)
	}

	cmd, err = ValidateCommand("keyvalue", "valkey-cli")
	if err != nil || cmd != "valkey-cli" {
		t.Fatalf("expected valkey-cli to be allowed, got: %v (err: %v)", cmd, err)
	}

	// Default fallback when empty
	cmd, err = ValidateCommand("postgres", "")
	if err != nil || cmd != "psql" {
		t.Fatalf("expected default psql, got: %v (err: %v)", cmd, err)
	}

	cmd, err = ValidateCommand("valkey", "")
	if err != nil || cmd != "valkey-cli" {
		t.Fatalf("expected default valkey-cli, got: %v (err: %v)", cmd, err)
	}

	// Forbidden commands MUST fail
	forbidden := []string{
		"bash", "sh", "ash", "zsh",
		"docker", "sudo", "ssh", "curl", "wget",
		"python", "nc",
	}

	for _, fc := range forbidden {
		_, err := ValidateCommand("postgres", fc)
		if err == nil {
			t.Fatalf("expected forbidden command '%s' to be rejected for postgres", fc)
		}
		_, err = ValidateCommand("keyvalue", fc)
		if err == nil {
			t.Fatalf("expected forbidden command '%s' to be rejected for keyvalue", fc)
		}
	}

	// Path traversal MUST fail
	traversals := []string{
		"/bin/sh", "/bin/bash", "./psql", "../valkey-cli", "C:\\Windows\\system32\\cmd.exe",
	}
	for _, path := range traversals {
		_, err := ValidateCommand("postgres", path)
		if err == nil {
			t.Fatalf("expected path '%s' to be rejected", path)
		}
	}

	// Mismatched engine MUST fail
	_, err = ValidateCommand("postgres", "valkey-cli")
	if err == nil {
		t.Fatalf("expected valkey-cli to be rejected for postgres")
	}
	_, err = ValidateCommand("keyvalue", "psql")
	if err == nil {
		t.Fatalf("expected psql to be rejected for keyvalue")
	}
}

func TestDatabaseShellManager_SessionLifecycle(t *testing.T) {
	mgr := NewDatabaseShellManager(nil, nil)
	ctx := context.Background()

	cfg := &SessionConfig{
		SessionID:    "test-sess-001",
		ResourceID:   "res-pg-001",
		ResourceType: "postgres",
		TenantID:     "tenant-acct-1",
		NodeID:       "node-001",
		Command:      "psql",
		Timeout:      1 * time.Second,
	}

	sess, err := mgr.CreateSession(ctx, cfg)
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	if sess.Status != StatusActive {
		t.Fatalf("expected status ACTIVE, got: %s", sess.Status)
	}

	// Read initial banner output
	out, err := mgr.ReadOutput(sess.SessionID, "tenant-acct-1")
	if err != nil {
		t.Fatalf("failed reading initial output: %v", err)
	}
	if len(out) == 0 {
		t.Fatalf("expected initial banner output")
	}

	// Write input
	inputPayload := []byte("SELECT 1;\n")
	err = mgr.WriteInput(sess.SessionID, "tenant-acct-1", inputPayload)
	if err != nil {
		t.Fatalf("failed writing input: %v", err)
	}

	// Read echo output
	out, err = mgr.ReadOutput(sess.SessionID, "tenant-acct-1")
	if err != nil {
		t.Fatalf("failed reading output after input: %v", err)
	}
	if string(out) != string(inputPayload) {
		t.Fatalf("expected output '%s', got '%s'", string(inputPayload), string(out))
	}

	// Tenant isolation: different tenant should be rejected
	err = mgr.WriteInput(sess.SessionID, "different-tenant", []byte("DROP TABLE users;"))
	if err != ErrUnauthorized {
		t.Fatalf("expected ErrUnauthorized for mismatched tenant, got: %v", err)
	}

	_, err = mgr.ReadOutput(sess.SessionID, "different-tenant")
	if err != ErrUnauthorized {
		t.Fatalf("expected ErrUnauthorized for mismatched tenant on read, got: %v", err)
	}

	err = mgr.CloseSession(sess.SessionID, "different-tenant")
	if err != ErrUnauthorized {
		t.Fatalf("expected ErrUnauthorized for mismatched tenant on close, got: %v", err)
	}

	// Close session with valid tenant
	err = mgr.CloseSession(sess.SessionID, "tenant-acct-1")
	if err != nil {
		t.Fatalf("failed closing session: %v", err)
	}

	// Subsequent input after close should fail
	err = mgr.WriteInput(sess.SessionID, "tenant-acct-1", []byte("SELECT 2;\n"))
	if err != ErrSessionClosed {
		t.Fatalf("expected ErrSessionClosed, got: %v", err)
	}
}

func TestDatabaseShellManager_SessionTimeout(t *testing.T) {
	mgr := NewDatabaseShellManager(nil, nil)
	ctx := context.Background()

	cfg := &SessionConfig{
		SessionID:    "test-sess-timeout",
		ResourceID:   "res-vk-001",
		ResourceType: "keyvalue",
		TenantID:     "tenant-acct-1",
		NodeID:       "node-001",
		Command:      "valkey-cli",
		Timeout:      50 * time.Millisecond,
	}

	sess, err := mgr.CreateSession(ctx, cfg)
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	// Wait for expiration
	time.Sleep(100 * time.Millisecond)

	// Writing input should fail with expiration
	err = mgr.WriteInput(sess.SessionID, "tenant-acct-1", []byte("PING\n"))
	if err != ErrSessionExpired {
		t.Fatalf("expected ErrSessionExpired, got: %v", err)
	}

	// Cleanup should catch any remaining
	cleaned := mgr.CleanupExpiredSessions()
	if cleaned < 0 {
		t.Fatalf("unexpected cleanup result: %d", cleaned)
	}
}
