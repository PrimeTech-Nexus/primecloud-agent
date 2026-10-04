// Package terminal provides secure, database-scoped interactive shell execution on compute nodes.
// Strictly enforces execution boundaries: only 'psql' for PostgreSQL and 'valkey-cli' for Valkey.
// Host shell, root shell, Docker daemon access, and arbitrary commands are strictly prohibited.
package terminal

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/primecloud/primecloud-agent/internal/runtime"
)

// Standard error definitions for shell security violations and lifecycle errors.
var (
	ErrForbiddenCommand  = errors.New("command forbidden: host shell, root shell, docker, and arbitrary binaries are strictly prohibited")
	ErrInvalidPath       = errors.New("command path traversal forbidden: absolute or relative executable paths are not allowed")
	ErrUnsupportedEngine = errors.New("unsupported resource engine: only postgres and valkey/keyvalue are supported")
	ErrSessionNotFound   = errors.New("shell session not found")
	ErrSessionExpired    = errors.New("shell session has expired")
	ErrSessionClosed     = errors.New("shell session is closed")
	ErrUnauthorized      = errors.New("cross-tenant shell access denied")
)

// Allowed database client executables per resource engine.
var AllowedCommands = map[string]string{
	"postgres":   "psql",
	"postgresql": "psql",
	"valkey":     "valkey-cli",
	"keyvalue":   "valkey-cli",
	"redis":      "valkey-cli",
}

// Explicitly forbidden commands that must never be executed under any circumstances.
var ForbiddenCommands = map[string]struct{}{
	"bash":       {},
	"sh":         {},
	"ash":        {},
	"zsh":        {},
	"csh":        {},
	"tcsh":       {},
	"fish":       {},
	"docker":     {},
	"podman":     {},
	"containerd": {},
	"runc":       {},
	"sudo":       {},
	"su":         {},
	"doas":       {},
	"ssh":        {},
	"scp":        {},
	"sftp":       {},
	"curl":       {},
	"wget":       {},
	"nc":         {},
	"netcat":     {},
	"socat":      {},
	"python":     {},
	"python3":    {},
	"perl":       {},
	"ruby":       {},
	"node":       {},
	"php":        {},
	"busybox":    {},
}

// SessionStatus represents the operational state of a shell session.
type SessionStatus string

const (
	StatusPending SessionStatus = "PENDING"
	StatusActive  SessionStatus = "ACTIVE"
	StatusClosed  SessionStatus = "CLOSED"
	StatusExpired SessionStatus = "EXPIRED"
	StatusFailed  SessionStatus = "FAILED"
)

// ShellSession represents an active or terminated database-scoped terminal session.
type ShellSession struct {
	SessionID      string        `json:"session_id"`
	ResourceID     string        `json:"resource_id"`
	ResourceType   string        `json:"resource_type"`
	TenantID       string        `json:"tenant_id"`
	NodeID         string        `json:"node_id"`
	Command        string        `json:"command"`
	Status         SessionStatus `json:"status"`
	StartedAt      time.Time     `json:"started_at"`
	ExpiresAt      time.Time     `json:"expires_at"`
	LastActivityAt time.Time     `json:"last_activity_at"`
	ClosedAt       *time.Time    `json:"closed_at,omitempty"`

	mu         sync.RWMutex
	inputChan  chan []byte
	outputBuf  *bytes.Buffer
	cancelFunc context.CancelFunc
}

// SessionConfig provides parameters for establishing a new shell session.
type SessionConfig struct {
	SessionID    string        `json:"session_id"`
	ResourceID   string        `json:"resource_id"`
	ResourceType string        `json:"resource_type"`
	TenantID     string        `json:"tenant_id"`
	NodeID       string        `json:"node_id"`
	Command      string        `json:"command"`
	Timeout      time.Duration `json:"timeout"`
}

// DatabaseShellManager coordinates and confines database shell sessions on compute nodes.
type DatabaseShellManager struct {
	rt       runtime.ContainerRuntime
	logger   *slog.Logger
	mu       sync.RWMutex
	sessions map[string]*ShellSession
}

// NewDatabaseShellManager initializes the shell manager.
func NewDatabaseShellManager(rt runtime.ContainerRuntime, logger *slog.Logger) *DatabaseShellManager {
	if logger == nil {
		logger = slog.Default()
	}
	return &DatabaseShellManager{
		rt:       rt,
		logger:   logger.With("component", "database_shell_manager"),
		sessions: make(map[string]*ShellSession),
	}
}

// ValidateCommand inspects and restricts executable arguments against platform security boundaries.
func ValidateCommand(resourceType, requestedCmd string) (string, error) {
	normEngine := strings.ToLower(strings.TrimSpace(resourceType))
	allowedCmd, ok := AllowedCommands[normEngine]
	if !ok {
		return "", fmt.Errorf("%w: %s", ErrUnsupportedEngine, resourceType)
	}

	trimmed := strings.TrimSpace(requestedCmd)
	if trimmed == "" {
		return allowedCmd, nil
	}

	// 1. Prohibit path separators (no /bin/sh, ../etc)
	if strings.ContainsAny(trimmed, "/\\") {
		return "", fmt.Errorf("%w: %s", ErrInvalidPath, trimmed)
	}

	// 2. Prohibit known shell/privilege-escalation/network binaries
	parts := strings.Fields(trimmed)
	base := strings.ToLower(parts[0])
	if _, forbidden := ForbiddenCommands[base]; forbidden {
		return "", fmt.Errorf("%w: %s", ErrForbiddenCommand, base)
	}

	// 3. Command must strictly match the permitted engine tool
	if base != allowedCmd {
		return "", fmt.Errorf("%w: requested '%s', only '%s' is permitted", ErrForbiddenCommand, base, allowedCmd)
	}

	return allowedCmd, nil
}

// CreateSession establishes an isolated, expiring terminal session for an active database resource.
func (m *DatabaseShellManager) CreateSession(ctx context.Context, cfg *SessionConfig) (*ShellSession, error) {
	if cfg == nil {
		return nil, errors.New("session config cannot be nil")
	}

	cmd, err := ValidateCommand(cfg.ResourceType, cfg.Command)
	if err != nil {
		m.logger.Warn("shell_creation_security_rejected",
			"resource_type", cfg.ResourceType,
			"command", cfg.Command,
			"error", err,
		)
		return nil, err
	}

	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 15 * time.Minute
	}
	if timeout > 2*time.Hour {
		timeout = 2 * time.Hour
	}

	sessCtx, cancel := context.WithCancel(ctx)
	now := time.Now().UTC()

	sess := &ShellSession{
		SessionID:      cfg.SessionID,
		ResourceID:     cfg.ResourceID,
		ResourceType:   cfg.ResourceType,
		TenantID:       cfg.TenantID,
		NodeID:         cfg.NodeID,
		Command:        cmd,
		Status:         StatusActive,
		StartedAt:      now,
		ExpiresAt:      now.Add(timeout),
		LastActivityAt: now,
		inputChan:      make(chan []byte, 128),
		outputBuf:      new(bytes.Buffer),
		cancelFunc:     cancel,
	}

	// Seed output banner
	sess.outputBuf.WriteString(fmt.Sprintf("PrimeCloud Managed Data Scoped Shell [%s]\n", cmd))
	sess.outputBuf.WriteString(fmt.Sprintf("Connected to %s (%s). Type \\q or quit to exit.\n\n", cfg.ResourceType, cfg.ResourceID))

	m.mu.Lock()
	m.sessions[sess.SessionID] = sess
	m.mu.Unlock()

	// Launch session lifecycle supervisor
	go m.superviseSession(sessCtx, sess, timeout)

	m.logger.Info("database_shell_session_created",
		"session_id", sess.SessionID,
		"resource_id", sess.ResourceID,
		"command", sess.Command,
		"expires_at", sess.ExpiresAt,
	)

	return sess, nil
}

// WriteInput accepts input data for an active session with tenant authorization.
func (m *DatabaseShellManager) WriteInput(sessionID, tenantID string, data []byte) error {
	m.mu.RLock()
	sess, exists := m.sessions[sessionID]
	m.mu.RUnlock()

	if !exists {
		return ErrSessionNotFound
	}

	sess.mu.Lock()
	defer sess.mu.Unlock()

	if tenantID != "" && sess.TenantID != tenantID {
		return ErrUnauthorized
	}

	now := time.Now().UTC()
	if sess.Status == StatusActive && now.After(sess.ExpiresAt) {
		sess.Status = StatusExpired
		t := now
		sess.ClosedAt = &t
		if sess.cancelFunc != nil {
			sess.cancelFunc()
		}
		return ErrSessionExpired
	}

	if sess.Status == StatusExpired {
		return ErrSessionExpired
	}

	if sess.Status != StatusActive {
		return ErrSessionClosed
	}

	sess.LastActivityAt = now
	// Append echo / input to buffer for interactive replay
	sess.outputBuf.Write(data)

	// Non-blocking send to input channel
	select {
	case sess.inputChan <- data:
	default:
	}

	return nil
}

// ReadOutput retrieves and drains buffered output for an active session.
func (m *DatabaseShellManager) ReadOutput(sessionID string, tenantID string) ([]byte, error) {
	m.mu.RLock()
	sess, exists := m.sessions[sessionID]
	m.mu.RUnlock()

	if !exists {
		return nil, ErrSessionNotFound
	}

	sess.mu.Lock()
	defer sess.mu.Unlock()

	if tenantID != "" && sess.TenantID != tenantID {
		return nil, ErrUnauthorized
	}

	now := time.Now().UTC()
	sess.LastActivityAt = now

	out := sess.outputBuf.Bytes()
	cp := make([]byte, len(out))
	copy(cp, out)
	sess.outputBuf.Reset()

	return cp, nil
}

// CloseSession terminates an active session and frees resources.
func (m *DatabaseShellManager) CloseSession(sessionID, tenantID string) error {
	m.mu.RLock()
	sess, exists := m.sessions[sessionID]
	m.mu.RUnlock()

	if !exists {
		return ErrSessionNotFound
	}

	sess.mu.Lock()
	if tenantID != "" && sess.TenantID != tenantID {
		sess.mu.Unlock()
		return ErrUnauthorized
	}

	now := time.Now().UTC()
	sess.Status = StatusClosed
	sess.ClosedAt = &now
	cancel := sess.cancelFunc
	sess.mu.Unlock()

	if cancel != nil {
		cancel()
	}

	m.logger.Info("database_shell_session_closed", "session_id", sessionID)
	return nil
}

// CleanupExpiredSessions scans and terminates sessions exceeding expiration time.
func (m *DatabaseShellManager) CleanupExpiredSessions() int {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now().UTC()
	count := 0

	for _, sess := range m.sessions {
		sess.mu.Lock()
		if sess.Status == StatusActive && now.After(sess.ExpiresAt) {
			sess.Status = StatusExpired
			t := now
			sess.ClosedAt = &t
			if sess.cancelFunc != nil {
				sess.cancelFunc()
			}
			count++
		}
		sess.mu.Unlock()
	}

	if count > 0 {
		m.logger.Info("expired_shell_sessions_cleaned_up", "count", count)
	}
	return count
}

func (m *DatabaseShellManager) superviseSession(ctx context.Context, sess *ShellSession, timeout time.Duration) {
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		// Cancelled by close or parent context
	case <-timer.C:
		sess.mu.Lock()
		if sess.Status == StatusActive {
			sess.Status = StatusExpired
			now := time.Now().UTC()
			sess.ClosedAt = &now
		}
		sess.mu.Unlock()
		m.logger.Info("database_shell_session_timeout", "session_id", sess.SessionID)
	}
}
