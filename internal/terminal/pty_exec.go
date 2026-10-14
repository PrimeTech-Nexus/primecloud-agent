package terminal

import (
	"context"
	"io"
	"net"
	"sync"
	"syscall"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
)

// PTYDockerClient abstracts the low-level Docker engine exec API operations
// required for interactive PTY shell streaming.
type PTYDockerClient interface {
	ContainerExecCreate(ctx context.Context, containerID string, config types.ExecConfig) (types.IDResponse, error)
	ContainerExecAttach(ctx context.Context, execID string, config types.ExecStartCheck) (types.HijackedResponse, error)
	ContainerExecResize(ctx context.Context, execID string, options container.ResizeOptions) error
	ContainerExecInspect(ctx context.Context, execID string) (types.ContainerExecInspect, error)
	ContainerInspect(ctx context.Context, containerID string) (types.ContainerJSON, error)
	ContainerKill(ctx context.Context, containerID, signal string) error
}

// PTYProcessConfig defines parameters for starting an interactive Docker exec PTY process.
type PTYProcessConfig struct {
	ContainerID string
	Cmd         []string
	Env         []string
	WorkingDir  string
	User        string
	InitialRows uint32
	InitialCols uint32
}

// PTYProcess represents an active interactive Docker exec process attached via PTY.
type PTYProcess struct {
	execID      string
	containerID string
	client      PTYDockerClient
	hijacked    types.HijackedResponse

	stdinWriter  io.WriteCloser
	stdoutReader io.Reader

	mu         sync.Mutex
	closed     bool
	closeOnce  sync.Once
	exitCode   int
	exitErr    error
	exitChan   chan struct{}
	cancelFunc context.CancelFunc
}

// StartPTYProcess initiates a real Docker exec session with PTY allocated and stream hijacked.
func StartPTYProcess(ctx context.Context, client PTYDockerClient, cfg *PTYProcessConfig) (*PTYProcess, error) {
	if client == nil {
		return nil, ErrNilDockerClient
	}
	if cfg == nil || cfg.ContainerID == "" {
		return nil, ErrInvalidContainerID
	}
	if len(cfg.Cmd) == 0 {
		return nil, ErrForbiddenCommand
	}

	rows := cfg.InitialRows
	cols := cfg.InitialCols
	if rows == 0 {
		rows = 24
	}
	if cols == 0 {
		cols = 80
	}

	execCfg := types.ExecConfig{
		AttachStdin:  true,
		AttachStdout: true,
		AttachStderr: true,
		Tty:          true,
		Cmd:          cfg.Cmd,
		Env:          cfg.Env,
		WorkingDir:   cfg.WorkingDir,
		User:         cfg.User,
		ConsoleSize:  &[2]uint{uint(rows), uint(cols)},
	}

	execCreateResp, err := client.ContainerExecCreate(ctx, cfg.ContainerID, execCfg)
	if err != nil {
		return nil, redactError(err)
	}

	startCheck := types.ExecStartCheck{
		Detach:      false,
		Tty:         true,
		ConsoleSize: &[2]uint{uint(rows), uint(cols)},
	}

	attachResp, err := client.ContainerExecAttach(ctx, execCreateResp.ID, startCheck)
	if err != nil {
		return nil, redactError(err)
	}

	procCtx, cancel := context.WithCancel(ctx)
	proc := &PTYProcess{
		execID:       execCreateResp.ID,
		containerID:  cfg.ContainerID,
		client:       client,
		hijacked:     attachResp,
		stdinWriter:  attachResp.Conn,
		stdoutReader: attachResp.Reader,
		exitCode:     -1,
		exitChan:     make(chan struct{}),
		cancelFunc:   cancel,
	}

	go proc.monitorProcess(procCtx)

	return proc, nil
}

// monitorProcess polls exec inspection to detect process exit and capture exit code.
func (p *PTYProcess) monitorProcess(ctx context.Context) {
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			p.reapExit(p.exitCode, ctx.Err())
			return
		case <-ticker.C:
			inspect, err := p.client.ContainerExecInspect(ctx, p.execID)
			if err != nil {
				// Container or daemon error
				p.reapExit(-1, redactError(err))
				return
			}
			if !inspect.Running {
				p.reapExit(inspect.ExitCode, nil)
				return
			}
		}
	}
}

func (p *PTYProcess) reapExit(code int, err error) {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return
	}
	p.exitCode = code
	p.exitErr = err
	p.mu.Unlock()

	p.closeOnce.Do(func() {
		p.hijacked.Close()
		close(p.exitChan)
	})
}

// WriteStdin writes raw bytes to the exec PTY stdin with deadline protection.
func (p *PTYProcess) WriteStdin(data []byte) (int, error) {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return 0, ErrSessionClosed
	}
	conn := p.hijacked.Conn
	p.mu.Unlock()

	if conn != nil {
		_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	}
	n, err := p.stdinWriter.Write(data)
	if err != nil {
		return n, redactError(err)
	}
	return n, nil
}

// ReadStdout reads raw bytes from the exec PTY output stream with deadline protection.
func (p *PTYProcess) ReadStdout(buf []byte) (int, error) {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return 0, io.EOF
	}
	conn := p.hijacked.Conn
	p.mu.Unlock()

	if conn != nil {
		_ = conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	}
	n, err := p.stdoutReader.Read(buf)
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return 0, ErrStreamTimeout
		}
		return n, redactError(err)
	}
	return n, nil
}

// Resize resizes the allocated exec PTY dimensions.
func (p *PTYProcess) Resize(ctx context.Context, rows, cols uint32) error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return ErrSessionClosed
	}
	execID := p.execID
	p.mu.Unlock()

	if rows == 0 {
		rows = 24
	}
	if cols == 0 {
		cols = 80
	}

	opts := container.ResizeOptions{
		Height: uint(rows),
		Width:  uint(cols),
	}
	if err := p.client.ContainerExecResize(ctx, execID, opts); err != nil {
		return redactError(err)
	}
	return nil
}

// SendSignal forwards an operating system signal to the PTY exec process or falls back to writing signal byte.
func (p *PTYProcess) SendSignal(ctx context.Context, sig syscall.Signal) error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return ErrSessionClosed
	}
	p.mu.Unlock()

	switch sig {
	case syscall.SIGINT:
		// Send ASCII ETX (\x03, Ctrl+C) to PTY stdin
		_, err := p.WriteStdin([]byte{0x03})
		return err
	case syscall.SIGTERM, syscall.SIGKILL:
		return p.CloseGracefully(ctx, 3*time.Second)
	default:
		return nil
	}
}

// CloseGracefully shuts down the PTY exec session safely without ever terminating
// the underlying database container. It closes stdin, sends an interrupt character,
// waits for clean exit up to gracePeriod, and closes the hijacked stream.
func (p *PTYProcess) CloseGracefully(ctx context.Context, gracePeriod time.Duration) error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil
	}
	p.closed = true
	p.mu.Unlock()

	if p.cancelFunc != nil {
		p.cancelFunc()
	}

	// 1. Close write half of the hijacked connection to signal EOF to the exec process
	_ = p.hijacked.CloseWrite()

	// 2. Wait up to gracePeriod for clean exit
	timer := time.NewTimer(gracePeriod)
	defer timer.Stop()

	select {
	case <-p.exitChan:
		// Clean exit occurred
	case <-timer.C:
		// Grace period expired: close hijacked connection to terminate PTY master stream.
		// CRITICAL SAFETY CHECK: Never call ContainerKill on the database container ID (p.containerID),
		// as doing so terminates the entire production database container!
	case <-ctx.Done():
		// Context cancelled
	}

	p.closeOnce.Do(func() {
		p.hijacked.Close()
		close(p.exitChan)
	})

	return nil
}

// Wait blocks until the process exits or context cancels, returning the process exit code.
func (p *PTYProcess) Wait(ctx context.Context) (int, error) {
	select {
	case <-p.exitChan:
		p.mu.Lock()
		defer p.mu.Unlock()
		return p.exitCode, p.exitErr
	case <-ctx.Done():
		return -1, ctx.Err()
	}
}
