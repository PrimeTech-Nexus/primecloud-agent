package terminal

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/primecloud/primecloud-agent/internal/postgres"
	"github.com/primecloud/primecloud-agent/internal/runtime"
	"github.com/primecloud/primecloud-agent/internal/valkey"
)

// Regex pattern for redacting passwords/credentials from messages and error strings.
var (
	connectionURLRegex = regexp.MustCompile(`(postgres(?:ql)?|redis):\/\/[^:]+:([^@]+)@`)
	passwordArgRegex   = regexp.MustCompile(`(?i)(password|token|auth|secret)[=:\s]+([^\s,;&]+)`)
)

// RedactCredentials sanitizes secrets, tokens, and database passwords from any string.
func RedactCredentials(s string) string {
	if s == "" {
		return ""
	}
	// Redact postgresql://user:password@host:port/db -> postgresql://user:[REDACTED]@host:port/db
	s = connectionURLRegex.ReplaceAllString(s, `$1://[REDACTED]:[REDACTED]@`)
	// Redact password=xyz, token: xyz, etc.
	s = passwordArgRegex.ReplaceAllString(s, `$1=[REDACTED]`)
	return s
}

// redactError wraps an error ensuring no credential strings leak into error messages.
func redactError(err error) error {
	if err == nil {
		return nil
	}
	clean := RedactCredentials(err.Error())
	if clean == err.Error() {
		return err
	}
	return errors.New(clean)
}

// RealDatabaseShellRuntime manages real Docker exec PTY instances for database containers.
type RealDatabaseShellRuntime struct {
	dockerClient PTYDockerClient
	logger       *slog.Logger
	mu           sync.RWMutex
	sessions     map[string]*ActivePTYSession
}

// ActivePTYSession holds an active real PTY process and session metadata.
type ActivePTYSession struct {
	SessionID    string
	ResourceID   string
	ResourceType string
	TenantID     string
	ContainerID  string
	Command      string

	process    *PTYProcess
	logger     *slog.Logger
	cancelFunc context.CancelFunc

	mu             sync.Mutex
	status         SessionStatus
	startedAt      time.Time
	expiresAt      time.Time
	lastActivityAt time.Time
	closedAt       *time.Time

	outputChan chan []byte
	closed     bool
}

// NewRealDatabaseShellRuntime constructs a runtime bound to the Docker engine API.
func NewRealDatabaseShellRuntime(dockerClient PTYDockerClient, logger *slog.Logger) *RealDatabaseShellRuntime {
	if logger == nil {
		logger = slog.Default()
	}
	return &RealDatabaseShellRuntime{
		dockerClient: dockerClient,
		logger:       logger.With("component", "real_database_shell_runtime"),
		sessions:     make(map[string]*ActivePTYSession),
	}
}

// ResolveContainerForResource authorizes and maps a resource identifier to its real container name/ID.
// Strictly enforces canonical prefix: pc-pg-<resource_id> or pc-vk-<resource_id>.
func (r *RealDatabaseShellRuntime) ResolveContainerForResource(ctx context.Context, resourceType, resourceID string) (string, error) {
	normEngine := strings.ToLower(strings.TrimSpace(resourceType))
	resID := strings.TrimSpace(resourceID)
	if resID == "" {
		return "", ErrInvalidContainerID
	}

	// Reject path separators or command injection characters in resource ID
	if strings.ContainsAny(resID, "/\\ ;&|`$(){}[]<>*?~") {
		return "", fmt.Errorf("invalid characters in resource ID: %s", resID)
	}

	var expectedContainerName string
	switch normEngine {
	case "postgres", "postgresql":
		expectedContainerName = postgres.LegacyHost(resID) // "pc-pg-" + resourceID
	case "valkey", "keyvalue", "redis":
		expectedContainerName = valkey.LegacyHost(resID) // "pc-vk-" + resourceID
	default:
		return "", fmt.Errorf("%w: %s", ErrUnsupportedEngine, resourceType)
	}

	// Verify container exists and is running in Docker daemon
	if r.dockerClient != nil {
		inspect, err := r.dockerClient.ContainerInspect(ctx, expectedContainerName)
		if err != nil {
			return "", fmt.Errorf("%w: container %s inspect error: %v", ErrContainerNotFound, expectedContainerName, redactError(err))
		}
		if inspect.State == nil || !inspect.State.Running {
			return "", fmt.Errorf("%w: container %s is not running", ErrContainerNotFound, expectedContainerName)
		}
		return inspect.ID, nil
	}

	return expectedContainerName, nil
}

// OpenPTYSession verifies authorization, opens a real Docker exec PTY, and initiates input/output streaming.
func (r *RealDatabaseShellRuntime) OpenPTYSession(ctx context.Context, cfg *SessionConfig, initialRows, initialCols uint32) (*ActivePTYSession, error) {
	if cfg == nil {
		return nil, errors.New("session config cannot be nil")
	}

	cmd, err := ValidateCommand(cfg.ResourceType, cfg.Command)
	if err != nil {
		r.logger.Warn("shell_command_validation_rejected",
			"resource_type", cfg.ResourceType,
			"command", RedactCredentials(cfg.Command),
			"error", err,
		)
		return nil, err
	}

	containerID, err := r.ResolveContainerForResource(ctx, cfg.ResourceType, cfg.ResourceID)
	if err != nil {
		r.logger.Warn("shell_container_resolution_failed",
			"resource_id", cfg.ResourceID,
			"resource_type", cfg.ResourceType,
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

	// Build safe executable command vector without inline credentials
	// Postgres psql runs as postgres user inside the container
	// Valkey valkey-cli connects to local daemon
	var execCmd []string
	var execUser string
	normEngine := strings.ToLower(strings.TrimSpace(cfg.ResourceType))
	switch normEngine {
	case "postgres", "postgresql":
		execCmd = []string{"psql", "-U", "postgres"}
		execUser = "postgres"
	case "valkey", "keyvalue", "redis":
		execCmd = []string{"valkey-cli"}
		execUser = ""
	}

	ptyCfg := &PTYProcessConfig{
		ContainerID: containerID,
		Cmd:         execCmd,
		User:        execUser,
		InitialRows: initialRows,
		InitialCols: initialCols,
		Env: []string{
			"TERM=xterm-256color",
			"LANG=C.UTF-8",
		},
	}

	proc, err := StartPTYProcess(ctx, r.dockerClient, ptyCfg)
	if err != nil {
		r.logger.Error("failed_to_start_pty_process",
			"session_id", cfg.SessionID,
			"container_id", containerID,
			"error", redactError(err),
		)
		return nil, redactError(err)
	}

	sessCtx, cancel := context.WithCancel(ctx)
	now := time.Now().UTC()

	sess := &ActivePTYSession{
		SessionID:      cfg.SessionID,
		ResourceID:     cfg.ResourceID,
		ResourceType:   cfg.ResourceType,
		TenantID:       cfg.TenantID,
		ContainerID:    containerID,
		Command:        cmd,
		process:        proc,
		logger:         r.logger.With("session_id", cfg.SessionID),
		cancelFunc:     cancel,
		status:         StatusActive,
		startedAt:      now,
		expiresAt:      now.Add(timeout),
		lastActivityAt: now,
		outputChan:     make(chan []byte, 128), // Bounded buffer (32KB * 128 = 4MB cap)
	}

	r.mu.Lock()
	r.sessions[sess.SessionID] = sess
	r.mu.Unlock()

	// Launch output reader pump & session lifecycle supervisor
	go sess.pumpOutput(sessCtx)
	go r.supervisePTYSession(sessCtx, sess, timeout)

	r.logger.Info("real_database_pty_session_opened",
		"session_id", sess.SessionID,
		"resource_id", sess.ResourceID,
		"container_id", sess.ContainerID,
		"command", sess.Command,
		"expires_at", sess.expiresAt,
	)

	return sess, nil
}

// pumpOutput reads raw bytes from the Docker exec PTY and dispatches to bounded output channel.
func (s *ActivePTYSession) pumpOutput(ctx context.Context) {
	defer func() {
		s.mu.Lock()
		if !s.closed {
			s.closed = true
			close(s.outputChan)
		}
		s.mu.Unlock()
	}()

	buf := make([]byte, 4096)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		n, err := s.process.ReadStdout(buf)
		if n > 0 {
			chunk := make([]byte, n)
			copy(chunk, buf[:n])

			s.mu.Lock()
			s.lastActivityAt = time.Now().UTC()
			s.mu.Unlock()

			// Bounded backpressure send or deterministic failure policy if reader is stalled
			select {
			case s.outputChan <- chunk:
			case <-ctx.Done():
				return
			case <-time.After(500 * time.Millisecond):
				// Stalled reader: enforce bounded backpressure failure policy.
				// Deterministically terminate the session rather than silently discarding output.
				s.logger.Error("terminal_output_buffer_overflow", "session_id", s.SessionID, "error", ErrBufferOverflow)
				s.mu.Lock()
				s.status = StatusFailed
				s.mu.Unlock()
				go func() {
					_ = s.Close(context.Background())
				}()
				return
			}
		}

		if err != nil {
			// Clean exit or connection close
			return
		}
	}
}

// ForwardStdin writes input to the real Docker exec PTY process.
func (s *ActivePTYSession) ForwardStdin(data []byte) error {
	s.mu.Lock()
	if s.status != StatusActive {
		s.mu.Unlock()
		return ErrSessionClosed
	}
	now := time.Now().UTC()
	if now.After(s.expiresAt) {
		s.status = StatusExpired
		s.mu.Unlock()
		return ErrSessionExpired
	}
	s.lastActivityAt = now
	s.mu.Unlock()

	_, err := s.process.WriteStdin(data)
	return err
}

// OutputChan returns the channel yielding raw PTY output bytes.
func (s *ActivePTYSession) OutputChan() <-chan []byte {
	return s.outputChan
}

// Resize updates terminal geometry.
func (s *ActivePTYSession) Resize(ctx context.Context, rows, cols uint32) error {
	s.mu.Lock()
	if s.status != StatusActive {
		s.mu.Unlock()
		return ErrSessionClosed
	}
	s.mu.Unlock()

	return s.process.Resize(ctx, rows, cols)
}

// SendSignal sends signal (e.g. SIGINT for Ctrl+C, SIGTERM/SIGKILL for close).
func (s *ActivePTYSession) SendSignal(ctx context.Context, sig syscall.Signal) error {
	s.mu.Lock()
	if s.status != StatusActive {
		s.mu.Unlock()
		return ErrSessionClosed
	}
	s.mu.Unlock()

	return s.process.SendSignal(ctx, sig)
}

// Close terminates the PTY process and releases exec resources.
func (s *ActivePTYSession) Close(ctx context.Context) error {
	s.mu.Lock()
	if s.status == StatusClosed {
		s.mu.Unlock()
		return nil
	}
	s.status = StatusClosed
	now := time.Now().UTC()
	s.closedAt = &now
	cancel := s.cancelFunc
	s.mu.Unlock()

	if cancel != nil {
		cancel()
	}

	return s.process.CloseGracefully(ctx, 3*time.Second)
}

// GetSession retrieves an active session by ID and verifies tenant authorization.
func (r *RealDatabaseShellRuntime) GetSession(sessionID, tenantID string) (*ActivePTYSession, error) {
	r.mu.RLock()
	sess, exists := r.sessions[sessionID]
	r.mu.RUnlock()

	if !exists {
		return nil, ErrSessionNotFound
	}

	if tenantID != "" && sess.TenantID != tenantID {
		return nil, ErrUnauthorized
	}

	return sess, nil
}

// CloseSession terminates an active session.
func (r *RealDatabaseShellRuntime) CloseSession(ctx context.Context, sessionID, tenantID string) error {
	sess, err := r.GetSession(sessionID, tenantID)
	if err != nil {
		return err
	}

	return sess.Close(ctx)
}

func (r *RealDatabaseShellRuntime) supervisePTYSession(ctx context.Context, sess *ActivePTYSession, timeout time.Duration) {
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case <-ctx.Done():
	case <-timer.C:
		sess.mu.Lock()
		if sess.status == StatusActive {
			sess.status = StatusExpired
			now := time.Now().UTC()
			sess.closedAt = &now
		}
		sess.mu.Unlock()
		_ = sess.Close(context.Background())
		r.logger.Info("pty_shell_session_timeout", "session_id", sess.SessionID)
	}
}

// DockerRuntimeAdapter adapts *runtime.DockerRuntime into PTYDockerClient.
type DockerRuntimeAdapter struct {
	rt *runtime.DockerRuntime
}

func NewDockerRuntimeAdapter(rt *runtime.DockerRuntime) *DockerRuntimeAdapter {
	return &DockerRuntimeAdapter{rt: rt}
}

func (a *DockerRuntimeAdapter) ContainerExecCreate(ctx context.Context, containerID string, config types.ExecConfig) (types.IDResponse, error) {
	cli := a.rt.Client()
	if cli == nil {
		return types.IDResponse{}, ErrNilDockerClient
	}
	return cli.ContainerExecCreate(ctx, containerID, config)
}

func (a *DockerRuntimeAdapter) ContainerExecAttach(ctx context.Context, execID string, config types.ExecStartCheck) (types.HijackedResponse, error) {
	cli := a.rt.Client()
	if cli == nil {
		return types.HijackedResponse{}, ErrNilDockerClient
	}
	return cli.ContainerExecAttach(ctx, execID, config)
}

func (a *DockerRuntimeAdapter) ContainerExecResize(ctx context.Context, execID string, options container.ResizeOptions) error {
	cli := a.rt.Client()
	if cli == nil {
		return ErrNilDockerClient
	}
	return cli.ContainerExecResize(ctx, execID, options)
}

func (a *DockerRuntimeAdapter) ContainerExecInspect(ctx context.Context, execID string) (types.ContainerExecInspect, error) {
	cli := a.rt.Client()
	if cli == nil {
		return types.ContainerExecInspect{}, ErrNilDockerClient
	}
	return cli.ContainerExecInspect(ctx, execID)
}

func (a *DockerRuntimeAdapter) ContainerInspect(ctx context.Context, containerID string) (types.ContainerJSON, error) {
	cli := a.rt.Client()
	if cli == nil {
		return types.ContainerJSON{}, ErrNilDockerClient
	}
	return cli.ContainerInspect(ctx, containerID)
}

func (a *DockerRuntimeAdapter) ContainerKill(ctx context.Context, containerID, signal string) error {
	cli := a.rt.Client()
	if cli == nil {
		return ErrNilDockerClient
	}
	return cli.ContainerKill(ctx, containerID, signal)
}
