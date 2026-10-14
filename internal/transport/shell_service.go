// Package transport provides mTLS configuration, gRPC client connections, and bidirectional shell streaming.
package transport

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"github.com/primecloud/primecloud-agent/internal/identity"
	pb "github.com/primecloud/primecloud-agent/internal/protocol"
	"github.com/primecloud/primecloud-agent/internal/terminal"
)

const (
	// MaxFrameSize limits client stdin / data frames to 32 KB as approved in contract.
	MaxFrameSize = 32 * 1024
	// InactivityTimeout cancels sessions if no input/resize occurs for 15 minutes.
	DefaultInactivityTimeout = 15 * time.Minute
	// MaxSessionLifetime enforces maximum stream duration (2 hours).
	MaxSessionLifetime = 2 * time.Hour
)

// PTYSessionRunner abstracts the runtime execution (real Docker PTY or test fake).
type PTYSessionRunner interface {
	ForwardStdin(data []byte) error
	OutputChan() <-chan []byte
	Resize(ctx context.Context, rows, cols uint32) error
	SendSignal(ctx context.Context, sig syscall.Signal) error
	Close(ctx context.Context) error
}

// ShellSessionFactory abstracts session creation for decoupling transport from Docker execution.
type ShellSessionFactory interface {
	CreateSession(ctx context.Context, req *pb.ShellInitRequest) (PTYSessionRunner, error)
}

// TicketValidator verifies ephemeral session tickets if ticket validation is required.
type TicketValidator interface {
	ValidateTicket(ctx context.Context, sessionID, ticket string) error
}

// ShellServerConfig holds configuration parameters for the bidirectional shell service.
type ShellServerConfig struct {
	Factory         ShellSessionFactory
	TicketValidator TicketValidator
	Logger          *slog.Logger
	AllowedNodeURI  string // Optional check for incoming peer SPIFFE URI
	ExpectedNodeID  string // e.g. pc-node-001
	RequireAuth     bool   // If true, peer identity / mTLS is strictly validated
	InactivityLimit time.Duration
	MaxLifetime     time.Duration
}

// DatabaseShellServer implements pb.ShellServiceServer for bidirectional interactive terminal streams.
type DatabaseShellServer struct {
	pb.UnimplementedShellServiceServer

	factory         ShellSessionFactory
	ticketValidator TicketValidator
	logger          *slog.Logger
	allowedNodeURI  string
	expectedNodeID  string
	requireAuth     bool
	inactivityLimit time.Duration
	maxLifetime     time.Duration

	mu             sync.RWMutex
	activeSessions map[string]bool
}

// NewDatabaseShellServer constructs a DatabaseShellServer.
func NewDatabaseShellServer(cfg ShellServerConfig) *DatabaseShellServer {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	inactivity := cfg.InactivityLimit
	if inactivity <= 0 {
		inactivity = DefaultInactivityTimeout
	}
	lifetime := cfg.MaxLifetime
	if lifetime <= 0 {
		lifetime = MaxSessionLifetime
	}

	return &DatabaseShellServer{
		factory:         cfg.Factory,
		ticketValidator: cfg.TicketValidator,
		logger:          logger.With("component", "shell_grpc_service"),
		allowedNodeURI:  cfg.AllowedNodeURI,
		expectedNodeID:  cfg.ExpectedNodeID,
		requireAuth:     cfg.RequireAuth,
		inactivityLimit: inactivity,
		maxLifetime:     lifetime,
		activeSessions:  make(map[string]bool),
	}
}

// StreamDatabaseShell handles the bidirectional gRPC streaming RPC for interactive terminal execution.
func (s *DatabaseShellServer) StreamDatabaseShell(stream grpc.BidiStreamingServer[pb.ShellClientMessage, pb.ShellServerMessage]) error {
	ctx := stream.Context()

	// 1. Peer Identity / Authentication Verification (if enabled)
	if s.requireAuth || s.allowedNodeURI != "" || s.expectedNodeID != "" {
		if err := s.verifyPeerIdentity(ctx); err != nil {
			s.logger.Warn("shell_stream_auth_rejected", "error", err)
			_ = stream.Send(&pb.ShellServerMessage{
				Payload: &pb.ShellServerMessage_Error{
					Error: &pb.ShellError{
						Code:    "AUTH_REJECTED",
						Message: "Mutual TLS peer authentication failed: " + err.Error(),
					},
				},
			})
			return status.Errorf(codes.Unauthenticated, "peer authentication failed: %v", err)
		}
	}

	// 2. Initial Message Handshake (Strict Ordering: FIRST message MUST be ShellInitRequest)
	firstMsg, err := stream.Recv()
	if err != nil {
		if errors.Is(err, io.EOF) {
			return nil
		}
		s.logger.Warn("shell_stream_recv_first_failed", "error", err)
		return status.Errorf(codes.InvalidArgument, "failed to receive initialization message: %v", err)
	}

	initReq := firstMsg.GetInit()
	if initReq == nil {
		s.logger.Warn("shell_stream_invalid_ordering_first_msg_not_init")
		_ = stream.Send(&pb.ShellServerMessage{
			Payload: &pb.ShellServerMessage_Error{
				Error: &pb.ShellError{
					Code:    "INVALID_ORDERING",
					Message: "First message on stream must be ShellInitRequest",
				},
			},
		})
		return status.Errorf(codes.FailedPrecondition, "first message must be ShellInitRequest")
	}

	// 3. Strict Validation of ShellInitRequest
	if err := s.validateInitRequest(initReq); err != nil {
		s.logger.Warn("shell_stream_init_validation_failed", "error", err)
		_ = stream.Send(&pb.ShellServerMessage{
			Payload: &pb.ShellServerMessage_Error{
				Error: &pb.ShellError{
					Code:    "INVALID_INIT",
					Message: err.Error(),
				},
			},
		})
		return status.Errorf(codes.InvalidArgument, "invalid ShellInitRequest: %v", err)
	}

	// 4. Validate Ticket if validator configured
	if s.ticketValidator != nil {
		if err := s.ticketValidator.ValidateTicket(ctx, initReq.SessionId, initReq.Ticket); err != nil {
			s.logger.Warn("shell_stream_ticket_validation_failed", "session_id", initReq.SessionId, "error", err)
			_ = stream.Send(&pb.ShellServerMessage{
				Payload: &pb.ShellServerMessage_Error{
					Error: &pb.ShellError{
						Code:    "INVALID_TICKET",
						Message: "Session ticket invalid or expired: " + err.Error(),
					},
				},
			})
			return status.Errorf(codes.PermissionDenied, "session ticket invalid: %v", err)
		}
	}

	// 5. Single Connection Guarantee (Prevent duplicate concurrent stream for same session)
	sessionID := initReq.SessionId
	s.mu.Lock()
	if s.activeSessions[sessionID] {
		s.mu.Unlock()
		s.logger.Warn("shell_stream_session_already_active", "session_id", sessionID)
		_ = stream.Send(&pb.ShellServerMessage{
			Payload: &pb.ShellServerMessage_Error{
				Error: &pb.ShellError{
					Code:    "SESSION_ACTIVE",
					Message: fmt.Sprintf("Shell session %s is already attached to an active stream", sessionID),
				},
			},
		})
		return status.Errorf(codes.AlreadyExists, "session %s already active", sessionID)
	}
	s.activeSessions[sessionID] = true
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		delete(s.activeSessions, sessionID)
		s.mu.Unlock()
	}()

	// 6. Create Session Runner via Factory
	if s.factory == nil {
		s.logger.Error("shell_factory_not_configured", "session_id", sessionID)
		_ = stream.Send(&pb.ShellServerMessage{
			Payload: &pb.ShellServerMessage_Error{
				Error: &pb.ShellError{
					Code:    "RUNTIME_UNAVAILABLE",
					Message: "Shell runtime factory is not configured on Agent",
				},
			},
		})
		return status.Errorf(codes.Unavailable, "shell factory not configured")
	}

	runner, err := s.factory.CreateSession(ctx, initReq)
	if err != nil {
		s.logger.Warn("shell_factory_create_failed", "session_id", sessionID, "error", err)
		_ = stream.Send(&pb.ShellServerMessage{
			Payload: &pb.ShellServerMessage_Error{
				Error: &pb.ShellError{
					Code:    "SESSION_CREATE_FAILED",
					Message: terminal.RedactCredentials(err.Error()),
				},
			},
		})
		return status.Errorf(codes.Internal, "failed to start shell session: %v", err)
	}
	defer func() {
		closeCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = runner.Close(closeCtx)
	}()

	// 7. Explicit Initialization Acknowledgement
	banner := fmt.Sprintf("PrimeCloud Managed Database Shell [%s]\nConnected to %s (%s). Type \\q or quit to exit.\n",
		initReq.Command, initReq.ResourceType, initReq.ResourceId)
	err = stream.Send(&pb.ShellServerMessage{
		Payload: &pb.ShellServerMessage_InitAck{
			InitAck: &pb.ShellInitAck{
				SessionId: sessionID,
				Engine:    initReq.ResourceType,
				Banner:    banner,
				Success:   true,
			},
		},
	})
	if err != nil {
		s.logger.Warn("shell_stream_send_init_ack_failed", "session_id", sessionID, "error", err)
		return err
	}

	// 8. Stream Execution Pump with Timers
	streamCtx, cancelStream := context.WithCancel(ctx)
	defer cancelStream()

	inactivityTimer := time.NewTimer(s.inactivityLimit)
	defer inactivityTimer.Stop()

	lifetimeTimer := time.NewTimer(s.maxLifetime)
	defer lifetimeTimer.Stop()

	errChan := make(chan error, 2)

	// Pump: Runner stdout -> gRPC stream
	go func() {
		outChan := runner.OutputChan()
		for {
			select {
			case <-streamCtx.Done():
				return
			case chunk, ok := <-outChan:
				if !ok {
					// PTY closed / process terminated
					errChan <- nil
					return
				}
				if len(chunk) == 0 {
					continue
				}

				// Forward stdout chunks bounded to MaxFrameSize
				for len(chunk) > 0 {
					step := len(chunk)
					if step > MaxFrameSize {
						step = MaxFrameSize
					}
					sendChunk := chunk[:step]
					chunk = chunk[step:]

					sendErr := stream.Send(&pb.ShellServerMessage{
						Payload: &pb.ShellServerMessage_Stdout{
							Stdout: sendChunk,
						},
					})
					if sendErr != nil {
						errChan <- sendErr
						return
					}
				}
			}
		}
	}()

	// Pump: gRPC stream -> Runner stdin / resize / signal
	go func() {
		for {
			msg, recvErr := stream.Recv()
			if recvErr != nil {
				if errors.Is(recvErr, io.EOF) {
					errChan <- nil
				} else {
					errChan <- recvErr
				}
				return
			}

			// Reset inactivity timer on any valid client message
			if !inactivityTimer.Stop() {
				select {
				case <-inactivityTimer.C:
				default:
				}
			}
			inactivityTimer.Reset(s.inactivityLimit)

			switch payload := msg.Payload.(type) {
			case *pb.ShellClientMessage_Init:
				// Unexpected second init message
				s.logger.Warn("shell_stream_unexpected_duplicate_init", "session_id", sessionID)
				_ = stream.Send(&pb.ShellServerMessage{
					Payload: &pb.ShellServerMessage_Error{
						Error: &pb.ShellError{
							Code:    "UNEXPECTED_MESSAGE",
							Message: "Session is already initialized; duplicate init message rejected",
						},
					},
				})
				errChan <- status.Errorf(codes.FailedPrecondition, "duplicate init message rejected")
				return

			case *pb.ShellClientMessage_Stdin:
				data := payload.Stdin
				if len(data) > MaxFrameSize {
					s.logger.Warn("shell_stream_oversized_stdin_rejected", "size", len(data))
					_ = stream.Send(&pb.ShellServerMessage{
						Payload: &pb.ShellServerMessage_Error{
							Error: &pb.ShellError{
								Code:    "OVERSIZED_FRAME",
								Message: fmt.Sprintf("Stdin payload %d bytes exceeds 32KB limit", len(data)),
							},
						},
					})
					continue
				}

				if err := runner.ForwardStdin(data); err != nil {
					s.logger.Warn("shell_stream_forward_stdin_failed", "error", err)
				}

			case *pb.ShellClientMessage_Resize:
				resize := payload.Resize
				if resize != nil {
					_ = runner.Resize(streamCtx, resize.Rows, resize.Cols)
				}

			case *pb.ShellClientMessage_Signal:
				sig := payload.Signal
				if sig != nil {
					var mappedSig syscall.Signal
					switch sig.Signal {
					case pb.ShellSignalType_SIGINT:
						mappedSig = syscall.SIGINT
					case pb.ShellSignalType_SIGTERM:
						mappedSig = syscall.SIGTERM
					case pb.ShellSignalType_SIGWINCH:
						mappedSig = syscall.Signal(28) // SIGWINCH
					}
					if mappedSig != 0 {
						_ = runner.SendSignal(streamCtx, mappedSig)
					}
				}

			default:
				s.logger.Warn("shell_stream_empty_client_message")
			}
		}
	}()

	// Wait for completion, timer, or error
	select {
	case <-streamCtx.Done():
		return streamCtx.Err()
	case <-inactivityTimer.C:
		s.logger.Info("shell_stream_inactivity_timeout", "session_id", sessionID)
		_ = stream.Send(&pb.ShellServerMessage{
			Payload: &pb.ShellServerMessage_Exit{
				Exit: &pb.ShellExit{
					ExitCode: 0,
					Reason:   "Session closed due to inactivity timeout (15m)",
				},
			},
		})
		return nil
	case <-lifetimeTimer.C:
		s.logger.Info("shell_stream_max_lifetime_exceeded", "session_id", sessionID)
		_ = stream.Send(&pb.ShellServerMessage{
			Payload: &pb.ShellServerMessage_Exit{
				Exit: &pb.ShellExit{
					ExitCode: 0,
					Reason:   "Session closed: maximum duration exceeded (2h)",
				},
			},
		})
		return nil
	case exitErr := <-errChan:
		if exitErr != nil && !errors.Is(exitErr, io.EOF) {
			s.logger.Warn("shell_stream_terminated_with_error", "session_id", sessionID, "error", exitErr)
			return exitErr
		}
		// Normal exit
		_ = stream.Send(&pb.ShellServerMessage{
			Payload: &pb.ShellServerMessage_Exit{
				Exit: &pb.ShellExit{
					ExitCode: 0,
					Reason:   "Process completed or stream closed",
				},
			},
		})
		return nil
	}
}

func (s *DatabaseShellServer) validateInitRequest(req *pb.ShellInitRequest) error {
	if req.SessionId == "" {
		return errors.New("session_id must not be empty")
	}
	if req.ResourceId == "" {
		return errors.New("resource_id must not be empty")
	}
	if req.TenantId == "" {
		return errors.New("tenant_id must not be empty")
	}
	if req.ResourceType == "" {
		return errors.New("resource_type must not be empty")
	}

	// Strictly validate requested command against whitelist
	_, err := terminal.ValidateCommand(req.ResourceType, req.Command)
	if err != nil {
		return err
	}

	return nil
}

func (s *DatabaseShellServer) verifyPeerIdentity(ctx context.Context) error {
	p, ok := peer.FromContext(ctx)
	if !ok || p.AuthInfo == nil {
		return errors.New("no peer authentication info available")
	}

	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return errors.New("unsupported peer transport security")
	}

	certs := tlsInfo.State.VerifiedChains
	if len(certs) == 0 || len(certs[0]) == 0 {
		return errors.New("peer did not present a verified certificate chain")
	}

	leafCert := certs[0][0]

	// Check certificate validity period
	now := time.Now()
	if now.Before(leafCert.NotBefore) {
		return errors.New("peer certificate is not yet valid")
	}
	if now.After(leafCert.NotAfter) {
		return errors.New("peer certificate has expired")
	}

	// If ExpectedNodeID or AllowedNodeURI is configured, verify SAN
	if s.allowedNodeURI != "" || s.expectedNodeID != "" {
		expected := s.allowedNodeURI
		if expected == "" && s.expectedNodeID != "" {
			expected = fmt.Sprintf("primecloud://agent/node/%s", s.expectedNodeID)
		}

		uri, err := identity.ExtractNodeURI(leafCert)
		if err != nil {
			return fmt.Errorf("peer identity SAN missing: %w", err)
		}
		if uri != expected {
			return fmt.Errorf("peer identity mismatch: got %s, expected %s", uri, expected)
		}
	}

	return nil
}

// DefaultShellSessionFactory binds DatabaseShellServer to terminal.RealDatabaseShellRuntime.
type DefaultShellSessionFactory struct {
	runtime *terminal.RealDatabaseShellRuntime
}

func NewDefaultShellSessionFactory(rt *terminal.RealDatabaseShellRuntime) *DefaultShellSessionFactory {
	return &DefaultShellSessionFactory{runtime: rt}
}

func (f *DefaultShellSessionFactory) CreateSession(ctx context.Context, req *pb.ShellInitRequest) (PTYSessionRunner, error) {
	if f.runtime == nil {
		return nil, errors.New("terminal runtime is not initialized")
	}

	cfg := &terminal.SessionConfig{
		SessionID:    req.SessionId,
		ResourceID:   req.ResourceId,
		ResourceType: req.ResourceType,
		TenantID:     req.TenantId,
		Command:      req.Command,
		Timeout:      MaxSessionLifetime,
	}

	rows := req.InitialRows
	cols := req.InitialCols
	if rows == 0 {
		rows = 24
	}
	if cols == 0 {
		cols = 80
	}

	sess, err := f.runtime.OpenPTYSession(ctx, cfg, rows, cols)
	if err != nil {
		return nil, err
	}
	return sess, nil
}
