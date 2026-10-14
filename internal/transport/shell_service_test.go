package transport

import (
	"context"
	"errors"
	"net"
	"sync"
	"syscall"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/primecloud/primecloud-agent/internal/protocol"
	"github.com/primecloud/primecloud-agent/internal/terminal"
)

// fakePTYRunner implements PTYSessionRunner for pure unit testing without Docker daemon.
type fakePTYRunner struct {
	mu          sync.Mutex
	stdinData   []byte
	resizes     [][2]uint32
	signals     []syscall.Signal
	outputChan  chan []byte
	closed      bool
	closeErr    error
	forwardErr  error
	failOnStdin bool
}

func newFakePTYRunner() *fakePTYRunner {
	return &fakePTYRunner{
		outputChan: make(chan []byte, 128),
	}
}

func (f *fakePTYRunner) ForwardStdin(data []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return terminal.ErrSessionClosed
	}
	if f.failOnStdin {
		return errors.New("simulated stdin failure")
	}
	f.stdinData = append(f.stdinData, data...)
	return f.forwardErr
}

func (f *fakePTYRunner) OutputChan() <-chan []byte {
	return f.outputChan
}

func (f *fakePTYRunner) Resize(ctx context.Context, rows, cols uint32) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return terminal.ErrSessionClosed
	}
	f.resizes = append(f.resizes, [2]uint32{rows, cols})
	return nil
}

func (f *fakePTYRunner) SendSignal(ctx context.Context, sig syscall.Signal) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return terminal.ErrSessionClosed
	}
	f.signals = append(f.signals, sig)
	return nil
}

func (f *fakePTYRunner) Close(ctx context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.closed {
		f.closed = true
		close(f.outputChan)
	}
	return f.closeErr
}

// fakeSessionFactory implements ShellSessionFactory
type fakeSessionFactory struct {
	mu          sync.Mutex
	lastReq     *pb.ShellInitRequest
	runnerToUse *fakePTYRunner
	createErr   error
}

func (f *fakeSessionFactory) CreateSession(ctx context.Context, req *pb.ShellInitRequest) (PTYSessionRunner, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lastReq = req
	if f.createErr != nil {
		return nil, f.createErr
	}
	if f.runnerToUse == nil {
		f.runnerToUse = newFakePTYRunner()
	}
	return f.runnerToUse, nil
}

// fakeTicketValidator implements TicketValidator
type fakeTicketValidator struct {
	validTickets map[string]string // sessionID -> ticket
}

func (v *fakeTicketValidator) ValidateTicket(ctx context.Context, sessionID, ticket string) error {
	if expected, ok := v.validTickets[sessionID]; ok && expected == ticket {
		return nil
	}
	return errors.New("invalid or expired shell ticket")
}

// setupInProcessShellTest creates an in-process gRPC client and server
func setupInProcessShellTest(t *testing.T, srvCfg ShellServerConfig, serverOpts ...grpc.ServerOption) (pb.ShellServiceClient, func()) {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create listener: %v", err)
	}

	grpcServer := grpc.NewServer(serverOpts...)
	shellServer := NewDatabaseShellServer(srvCfg)
	pb.RegisterShellServiceServer(grpcServer, shellServer)

	go func() {
		_ = grpcServer.Serve(listener)
	}()

	conn, err := grpc.Dial(listener.Addr().String(), grpc.WithInsecure())
	if err != nil {
		grpcServer.Stop()
		listener.Close()
		t.Fatalf("failed to dial: %v", err)
	}

	client := pb.NewShellServiceClient(conn)

	cleanup := func() {
		_ = conn.Close()
		grpcServer.Stop()
		_ = listener.Close()
	}

	return client, cleanup
}

// 1. Successful bidirectional message exchange
func TestShellService_SuccessBidirectionalFlow(t *testing.T) {
	fakeRunner := newFakePTYRunner()
	factory := &fakeSessionFactory{runnerToUse: fakeRunner}

	client, cleanup := setupInProcessShellTest(t, ShellServerConfig{
		Factory: factory,
	})
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := client.StreamDatabaseShell(ctx)
	if err != nil {
		t.Fatalf("failed to open stream: %v", err)
	}

	// Step 1: Send Init
	err = stream.Send(&pb.ShellClientMessage{
		Payload: &pb.ShellClientMessage_Init{
			Init: &pb.ShellInitRequest{
				SessionId:    "sess-001",
				Ticket:       "ticket-123",
				ResourceId:   "res-pg-001",
				ResourceType: "postgres",
				TenantId:     "tenant-acct-1",
				Command:      "psql",
				InitialRows:  24,
				InitialCols:  80,
			},
		},
	})
	if err != nil {
		t.Fatalf("failed to send init: %v", err)
	}

	// Step 2: Expect InitAck
	resp, err := stream.Recv()
	if err != nil {
		t.Fatalf("failed to receive init ack: %v", err)
	}
	ack := resp.GetInitAck()
	if ack == nil || !ack.Success {
		t.Fatalf("expected successful init ack, got: %v", resp)
	}
	if ack.SessionId != "sess-001" || ack.Engine != "postgres" {
		t.Fatalf("unexpected init ack metadata: %v", ack)
	}

	// Step 3: Server stdout -> Client
	fakeRunner.outputChan <- []byte("postgres=# ")
	resp, err = stream.Recv()
	if err != nil {
		t.Fatalf("failed to receive stdout: %v", err)
	}
	if string(resp.GetStdout()) != "postgres=# " {
		t.Fatalf("expected 'postgres=# ', got: %q", string(resp.GetStdout()))
	}

	// Step 4: Client stdin -> Runner
	err = stream.Send(&pb.ShellClientMessage{
		Payload: &pb.ShellClientMessage_Stdin{
			Stdin: []byte("SELECT 1;\n"),
		},
	})
	if err != nil {
		t.Fatalf("failed to send stdin: %v", err)
	}

	// Allow pump to forward stdin
	time.Sleep(50 * time.Millisecond)
	fakeRunner.mu.Lock()
	stdinRecv := string(fakeRunner.stdinData)
	fakeRunner.mu.Unlock()

	if stdinRecv != "SELECT 1;\n" {
		t.Fatalf("runner received %q, expected 'SELECT 1;\n'", stdinRecv)
	}

	// Close stream
	_ = stream.CloseSend()
}

// 2. Initialization acknowledgement and failure
func TestShellService_InitFailure_InvalidPayload(t *testing.T) {
	factory := &fakeSessionFactory{}
	client, cleanup := setupInProcessShellTest(t, ShellServerConfig{
		Factory: factory,
	})
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	stream, err := client.StreamDatabaseShell(ctx)
	if err != nil {
		t.Fatalf("failed to open stream: %v", err)
	}

	// Missing resource_id and tenant_id
	err = stream.Send(&pb.ShellClientMessage{
		Payload: &pb.ShellClientMessage_Init{
			Init: &pb.ShellInitRequest{
				SessionId:    "sess-bad",
				ResourceType: "postgres",
				Command:      "psql",
			},
		},
	})
	if err != nil {
		t.Fatalf("failed to send init: %v", err)
	}

	resp, err := stream.Recv()
	if err == nil {
		// Expect structured error message
		errMsg := resp.GetError()
		if errMsg == nil || errMsg.Code != "INVALID_INIT" {
			t.Fatalf("expected INVALID_INIT error, got %v", resp)
		}
	} else {
		st, ok := status.FromError(err)
		if !ok || st.Code() != codes.InvalidArgument {
			t.Fatalf("expected InvalidArgument code, got: %v", err)
		}
	}
}

// 3. Every supported client and server message type
func TestShellService_AllSupportedMessageTypes(t *testing.T) {
	fakeRunner := newFakePTYRunner()
	factory := &fakeSessionFactory{runnerToUse: fakeRunner}

	client, cleanup := setupInProcessShellTest(t, ShellServerConfig{
		Factory: factory,
	})
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := client.StreamDatabaseShell(ctx)
	if err != nil {
		t.Fatalf("failed to open stream: %v", err)
	}

	// 1. Init
	_ = stream.Send(&pb.ShellClientMessage{
		Payload: &pb.ShellClientMessage_Init{
			Init: &pb.ShellInitRequest{
				SessionId:    "sess-all-types",
				ResourceId:   "res-vk-1",
				ResourceType: "valkey",
				TenantId:     "tenant-1",
				Command:      "valkey-cli",
			},
		},
	})
	ackMsg, _ := stream.Recv()
	if ackMsg.GetInitAck() == nil {
		t.Fatalf("expected init ack")
	}

	// 2. Resize
	err = stream.Send(&pb.ShellClientMessage{
		Payload: &pb.ShellClientMessage_Resize{
			Resize: &pb.ShellResize{
				Rows: 30,
				Cols: 100,
			},
		},
	})
	if err != nil {
		t.Fatalf("failed to send resize: %v", err)
	}

	// 3. Signal (SIGINT)
	err = stream.Send(&pb.ShellClientMessage{
		Payload: &pb.ShellClientMessage_Signal{
			Signal: &pb.ShellSignal{
				Signal: pb.ShellSignalType_SIGINT,
			},
		},
	})
	if err != nil {
		t.Fatalf("failed to send signal: %v", err)
	}

	// 4. Stdin
	err = stream.Send(&pb.ShellClientMessage{
		Payload: &pb.ShellClientMessage_Stdin{
			Stdin: []byte("PING\r\n"),
		},
	})
	if err != nil {
		t.Fatalf("failed to send stdin: %v", err)
	}

	time.Sleep(50 * time.Millisecond)

	fakeRunner.mu.Lock()
	if len(fakeRunner.resizes) == 0 || fakeRunner.resizes[0] != [2]uint32{30, 100} {
		t.Fatalf("resize not registered on runner: %v", fakeRunner.resizes)
	}
	if len(fakeRunner.signals) == 0 || fakeRunner.signals[0] != syscall.SIGINT {
		t.Fatalf("signal not registered on runner: %v", fakeRunner.signals)
	}
	fakeRunner.mu.Unlock()

	_ = stream.CloseSend()
}

// 4. Invalid messages, unexpected message ordering, and oversized frames
func TestShellService_InvalidOrderingAndOversized(t *testing.T) {
	fakeRunner := newFakePTYRunner()
	factory := &fakeSessionFactory{runnerToUse: fakeRunner}

	client, cleanup := setupInProcessShellTest(t, ShellServerConfig{
		Factory: factory,
	})
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Subtest 4a: First message is STDIN instead of INIT (Ordering violation)
	stream1, err := client.StreamDatabaseShell(ctx)
	if err != nil {
		t.Fatalf("failed to open stream: %v", err)
	}
	_ = stream1.Send(&pb.ShellClientMessage{
		Payload: &pb.ShellClientMessage_Stdin{
			Stdin: []byte("hello"),
		},
	})
	resp1, err1 := stream1.Recv()
	if err1 == nil {
		if resp1.GetError() == nil || resp1.GetError().Code != "INVALID_ORDERING" {
			t.Fatalf("expected INVALID_ORDERING error message, got: %v", resp1)
		}
	} else {
		st, _ := status.FromError(err1)
		if st.Code() != codes.FailedPrecondition {
			t.Fatalf("expected FailedPrecondition, got: %v", err1)
		}
	}

	// Subtest 4b: Oversized frame (> 32 KB)
	stream2, err := client.StreamDatabaseShell(ctx)
	if err != nil {
		t.Fatalf("failed to open stream: %v", err)
	}
	_ = stream2.Send(&pb.ShellClientMessage{
		Payload: &pb.ShellClientMessage_Init{
			Init: &pb.ShellInitRequest{
				SessionId:    "sess-oversize",
				ResourceId:   "res-pg-1",
				ResourceType: "postgres",
				TenantId:     "tenant-1",
				Command:      "psql",
			},
		},
	})
	_, _ = stream2.Recv() // init ack

	// Send 33 KB payload
	hugeBytes := make([]byte, 33*1024)
	_ = stream2.Send(&pb.ShellClientMessage{
		Payload: &pb.ShellClientMessage_Stdin{
			Stdin: hugeBytes,
		},
	})

	resp2, err := stream2.Recv()
	if err != nil {
		t.Fatalf("unexpected stream error: %v", err)
	}
	if resp2.GetError() == nil || resp2.GetError().Code != "OVERSIZED_FRAME" {
		t.Fatalf("expected OVERSIZED_FRAME error, got: %v", resp2)
	}
	_ = stream2.CloseSend()
}

// 5. Stream cancellation and EOF
func TestShellService_StreamCancellationAndEOF(t *testing.T) {
	fakeRunner := newFakePTYRunner()
	factory := &fakeSessionFactory{runnerToUse: fakeRunner}

	client, cleanup := setupInProcessShellTest(t, ShellServerConfig{
		Factory: factory,
	})
	defer cleanup()

	cancelCtx, cancelFunc := context.WithCancel(context.Background())

	stream, err := client.StreamDatabaseShell(cancelCtx)
	if err != nil {
		t.Fatalf("failed to open stream: %v", err)
	}

	_ = stream.Send(&pb.ShellClientMessage{
		Payload: &pb.ShellClientMessage_Init{
			Init: &pb.ShellInitRequest{
				SessionId:    "sess-cancel",
				ResourceId:   "res-pg-1",
				ResourceType: "postgres",
				TenantId:     "tenant-1",
				Command:      "psql",
			},
		},
	})
	_, _ = stream.Recv()

	// Cancel context from client
	cancelFunc()

	// Runner must be closed by server defer
	time.Sleep(100 * time.Millisecond)
	fakeRunner.mu.Lock()
	closed := fakeRunner.closed
	fakeRunner.mu.Unlock()

	if !closed {
		t.Fatalf("expected fakeRunner to be closed when stream context is canceled")
	}
}

// 6. Process exit and structured error propagation
func TestShellService_ProcessExitPropagation(t *testing.T) {
	fakeRunner := newFakePTYRunner()
	factory := &fakeSessionFactory{runnerToUse: fakeRunner}

	client, cleanup := setupInProcessShellTest(t, ShellServerConfig{
		Factory: factory,
	})
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := client.StreamDatabaseShell(ctx)
	if err != nil {
		t.Fatalf("failed to open stream: %v", err)
	}

	_ = stream.Send(&pb.ShellClientMessage{
		Payload: &pb.ShellClientMessage_Init{
			Init: &pb.ShellInitRequest{
				SessionId:    "sess-exit",
				ResourceId:   "res-pg-1",
				ResourceType: "postgres",
				TenantId:     "tenant-1",
				Command:      "psql",
			},
		},
	})
	_, _ = stream.Recv() // init ack

	// Simulate PTY process terminating: close runner outputChan
	fakeRunner.mu.Lock()
	close(fakeRunner.outputChan)
	fakeRunner.closed = true
	fakeRunner.mu.Unlock()

	// Receive exit message
	resp, err := stream.Recv()
	if err != nil {
		t.Fatalf("failed to receive exit message: %v", err)
	}
	exitMsg := resp.GetExit()
	if exitMsg == nil {
		t.Fatalf("expected ShellExit message, got: %v", resp)
	}
	if exitMsg.ExitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitMsg.ExitCode)
	}
}

// 7. Disconnected clients and interrupted streams
func TestShellService_InterruptedStream_FreesSession(t *testing.T) {
	fakeRunner := newFakePTYRunner()
	factory := &fakeSessionFactory{runnerToUse: fakeRunner}
	server := NewDatabaseShellServer(ShellServerConfig{Factory: factory})

	// Directly verify activeSessions map cleanup
	listener, _ := net.Listen("tcp", "127.0.0.1:0")
	grpcServer := grpc.NewServer()
	pb.RegisterShellServiceServer(grpcServer, server)
	go func() { _ = grpcServer.Serve(listener) }()
	defer func() {
		grpcServer.Stop()
		_ = listener.Close()
	}()

	conn, _ := grpc.Dial(listener.Addr().String(), grpc.WithInsecure())
	client := pb.NewShellServiceClient(conn)

	ctx, cancel := context.WithCancel(context.Background())
	stream, _ := client.StreamDatabaseShell(ctx)

	_ = stream.Send(&pb.ShellClientMessage{
		Payload: &pb.ShellClientMessage_Init{
			Init: &pb.ShellInitRequest{
				SessionId:    "sess-disconnect",
				ResourceId:   "res-pg-1",
				ResourceType: "postgres",
				TenantId:     "tenant-1",
				Command:      "psql",
			},
		},
	})
	_, _ = stream.Recv()

	// Confirm session is active in server map
	server.mu.RLock()
	active := server.activeSessions["sess-disconnect"]
	server.mu.RUnlock()
	if !active {
		t.Fatalf("expected session to be marked active")
	}

	// Abruptly terminate client connection
	cancel()
	_ = conn.Close()

	// Session should be freed in activeSessions
	time.Sleep(100 * time.Millisecond)
	server.mu.RLock()
	active = server.activeSessions["sess-disconnect"]
	server.mu.RUnlock()
	if active {
		t.Fatalf("expected session to be cleaned up after disconnect")
	}
}

// 8. Authentication and identity rejection
func TestShellService_AuthRejection_MissingOrInvalidPeer(t *testing.T) {
	factory := &fakeSessionFactory{}
	// Require peer identity
	server := NewDatabaseShellServer(ShellServerConfig{
		Factory:        factory,
		RequireAuth:    true,
		ExpectedNodeID: "pc-node-001",
	})

	listener, _ := net.Listen("tcp", "127.0.0.1:0")
	grpcServer := grpc.NewServer()
	pb.RegisterShellServiceServer(grpcServer, server)
	go func() { _ = grpcServer.Serve(listener) }()
	defer func() {
		grpcServer.Stop()
		_ = listener.Close()
	}()

	// Insecure dial without mTLS certificates
	conn, _ := grpc.Dial(listener.Addr().String(), grpc.WithInsecure())
	defer conn.Close()

	client := pb.NewShellServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	stream, err := client.StreamDatabaseShell(ctx)
	if err != nil {
		t.Fatalf("failed to open stream: %v", err)
	}

	_ = stream.Send(&pb.ShellClientMessage{
		Payload: &pb.ShellClientMessage_Init{
			Init: &pb.ShellInitRequest{
				SessionId:    "sess-no-auth",
				ResourceId:   "res-pg-1",
				ResourceType: "postgres",
				TenantId:     "tenant-1",
				Command:      "psql",
			},
		},
	})

	resp, err := stream.Recv()
	if err == nil {
		if resp.GetError() == nil || resp.GetError().Code != "AUTH_REJECTED" {
			t.Fatalf("expected AUTH_REJECTED error, got: %v", resp)
		}
	} else {
		st, _ := status.FromError(err)
		if st.Code() != codes.Unauthenticated {
			t.Fatalf("expected Unauthenticated status code, got: %v", err)
		}
	}
}

// 9. Generated-code consistency and compatibility with the frozen contract
func TestShellService_GeneratedCodeContractCompatibility(t *testing.T) {
	// Verify all message structs exist and compile
	req := &pb.ShellInitRequest{
		SessionId:    "sess-compat",
		Ticket:       "ticket-compat",
		ResourceId:   "res-compat",
		ResourceType: "postgres",
		TenantId:     "tenant-compat",
		Command:      "psql",
		InitialRows:  24,
		InitialCols:  80,
	}
	if req.GetCommand() != "psql" {
		t.Fatalf("unexpected command")
	}

	ack := &pb.ShellInitAck{
		SessionId: "sess-compat",
		Engine:    "postgres",
		Banner:    "banner",
		Success:   true,
	}
	if !ack.GetSuccess() {
		t.Fatalf("unexpected success value")
	}

	exit := &pb.ShellExit{
		ExitCode: 0,
		Reason:   "normal exit",
	}
	if exit.GetExitCode() != 0 {
		t.Fatalf("unexpected exit code")
	}

	errVal := &pb.ShellError{
		Code:    "ERR_TEST",
		Message: "test message",
	}
	if errVal.GetCode() != "ERR_TEST" {
		t.Fatalf("unexpected error code")
	}

	clientMsg := &pb.ShellClientMessage{
		Payload: &pb.ShellClientMessage_Init{
			Init: req,
		},
	}
	if clientMsg.GetInit() == nil {
		t.Fatalf("unexpected nil init payload")
	}

	serverMsg := &pb.ShellServerMessage{
		Payload: &pb.ShellServerMessage_InitAck{
			InitAck: ack,
		},
	}
	if serverMsg.GetInitAck() == nil {
		t.Fatalf("unexpected nil init ack payload")
	}
}

// 10. Backpressure and bounded message handling
func TestShellService_BackpressureAndBoundedChunking(t *testing.T) {
	fakeRunner := newFakePTYRunner()
	factory := &fakeSessionFactory{runnerToUse: fakeRunner}

	client, cleanup := setupInProcessShellTest(t, ShellServerConfig{
		Factory: factory,
	})
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := client.StreamDatabaseShell(ctx)
	if err != nil {
		t.Fatalf("failed to open stream: %v", err)
	}

	_ = stream.Send(&pb.ShellClientMessage{
		Payload: &pb.ShellClientMessage_Init{
			Init: &pb.ShellInitRequest{
				SessionId:    "sess-chunking",
				ResourceId:   "res-pg-1",
				ResourceType: "postgres",
				TenantId:     "tenant-1",
				Command:      "psql",
			},
		},
	})
	_, _ = stream.Recv() // init ack

	// Send a 60KB stdout chunk from the runner (greater than 32KB frame size)
	largeOutput := make([]byte, 60*1024)
	for i := range largeOutput {
		largeOutput[i] = byte('A' + (i % 26))
	}

	fakeRunner.outputChan <- largeOutput

	// Server should chunk this into <= 32KB frames
	firstFrame, err := stream.Recv()
	if err != nil {
		t.Fatalf("failed to receive first frame: %v", err)
	}
	if len(firstFrame.GetStdout()) > MaxFrameSize {
		t.Fatalf("frame size %d exceeded MaxFrameSize %d", len(firstFrame.GetStdout()), MaxFrameSize)
	}

	secondFrame, err := stream.Recv()
	if err != nil {
		t.Fatalf("failed to receive second frame: %v", err)
	}
	if len(secondFrame.GetStdout()) > MaxFrameSize {
		t.Fatalf("second frame size %d exceeded MaxFrameSize %d", len(secondFrame.GetStdout()), MaxFrameSize)
	}

	totalReceived := len(firstFrame.GetStdout()) + len(secondFrame.GetStdout())
	if totalReceived != 60*1024 {
		t.Fatalf("expected total 61440 bytes across frames, got %d", totalReceived)
	}

	_ = stream.CloseSend()
}

// 11. Ticket validation and rejection
func TestShellService_TicketValidation(t *testing.T) {
	factory := &fakeSessionFactory{}
	validator := &fakeTicketValidator{
		validTickets: map[string]string{
			"sess-valid": "secret-ticket-token",
		},
	}

	client, cleanup := setupInProcessShellTest(t, ShellServerConfig{
		Factory:         factory,
		TicketValidator: validator,
	})
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// 11a: Valid ticket succeeds
	stream1, err := client.StreamDatabaseShell(ctx)
	if err != nil {
		t.Fatalf("failed to open stream: %v", err)
	}
	_ = stream1.Send(&pb.ShellClientMessage{
		Payload: &pb.ShellClientMessage_Init{
			Init: &pb.ShellInitRequest{
				SessionId:    "sess-valid",
				Ticket:       "secret-ticket-token",
				ResourceId:   "res-pg-1",
				ResourceType: "postgres",
				TenantId:     "tenant-1",
				Command:      "psql",
			},
		},
	})
	ack1, err := stream1.Recv()
	if err != nil || ack1.GetInitAck() == nil || !ack1.GetInitAck().Success {
		t.Fatalf("expected successful init with valid ticket, got err: %v, resp: %v", err, ack1)
	}
	_ = stream1.CloseSend()

	// 11b: Invalid ticket rejected
	stream2, err := client.StreamDatabaseShell(ctx)
	if err != nil {
		t.Fatalf("failed to open stream: %v", err)
	}
	_ = stream2.Send(&pb.ShellClientMessage{
		Payload: &pb.ShellClientMessage_Init{
			Init: &pb.ShellInitRequest{
				SessionId:    "sess-valid",
				Ticket:       "wrong-ticket-token",
				ResourceId:   "res-pg-1",
				ResourceType: "postgres",
				TenantId:     "tenant-1",
				Command:      "psql",
			},
		},
	})
	resp2, err := stream2.Recv()
	if err == nil {
		if resp2.GetError() == nil || resp2.GetError().Code != "INVALID_TICKET" {
			t.Fatalf("expected INVALID_TICKET error, got: %v", resp2)
		}
	} else {
		st, _ := status.FromError(err)
		if st.Code() != codes.PermissionDenied {
			t.Fatalf("expected PermissionDenied, got: %v", err)
		}
	}
}

// 12. Command whitelist rejection on gRPC stream
func TestShellService_ForbiddenCommandRejected(t *testing.T) {
	factory := &fakeSessionFactory{}
	client, cleanup := setupInProcessShellTest(t, ShellServerConfig{
		Factory: factory,
	})
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	stream, err := client.StreamDatabaseShell(ctx)
	if err != nil {
		t.Fatalf("failed to open stream: %v", err)
	}

	// Attempt to request /bin/bash or sudo
	_ = stream.Send(&pb.ShellClientMessage{
		Payload: &pb.ShellClientMessage_Init{
			Init: &pb.ShellInitRequest{
				SessionId:    "sess-hacker",
				ResourceId:   "res-pg-1",
				ResourceType: "postgres",
				TenantId:     "tenant-1",
				Command:      "/bin/bash",
			},
		},
	})

	resp, err := stream.Recv()
	if err == nil {
		if resp.GetError() == nil || resp.GetError().Code != "INVALID_INIT" {
			t.Fatalf("expected INVALID_INIT error for forbidden command, got: %v", resp)
		}
	} else {
		st, _ := status.FromError(err)
		if st.Code() != codes.InvalidArgument {
			t.Fatalf("expected InvalidArgument, got: %v", err)
		}
	}
}
