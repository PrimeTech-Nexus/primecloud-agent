package integration_test

import (
	"bytes"
	"context"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/primecloud/primecloud-agent/internal/agent"
	"github.com/primecloud/primecloud-agent/internal/identity"
	pb "github.com/primecloud/primecloud-agent/internal/protocol"
	"github.com/primecloud/primecloud-agent/internal/transport"
	"github.com/primecloud/primecloud-agent/internal/vault"
	"github.com/primecloud/primecloud-agent/tests/testenv"
)

type chunkAControlPlaneServer struct {
	pb.UnimplementedAgentServiceServer
	heartbeats chan *pb.HeartbeatRequest
	registers  chan *pb.RegisterRequest
}

func (s *chunkAControlPlaneServer) Register(ctx context.Context, req *pb.RegisterRequest) (*pb.RegisterResponse, error) {
	if s.registers != nil {
		s.registers <- req
	}
	return &pb.RegisterResponse{
		AgentId:              "agent-chunk-a-id",
		NodeId:               "node-chunk-a-id",
		Registered:           true,
		HeartbeatIntervalSec: 5,
		ReconcileIntervalSec: 15,
		Capabilities:         []string{"docker", "postgres", "valkey", "caddy"},
		Message:              "Chunk A integration registration OK",
	}, nil
}

func (s *chunkAControlPlaneServer) SendHeartbeat(ctx context.Context, req *pb.HeartbeatRequest) (*pb.HeartbeatResponse, error) {
	if s.heartbeats != nil {
		s.heartbeats <- req
	}
	return &pb.HeartbeatResponse{
		Acknowledged:   true,
		ServerTimeUnix: time.Now().Unix(),
	}, nil
}

func TestChunkA_Integration(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()

	// 1. Ensure Real Vault Dev server is ready
	vClient, bootstrapToken := testenv.EnsureVaultDev(t)

	var logBuf bytes.Buffer
	logger := agent.SetupLogging(&logBuf, slog.LevelDebug)

	// 2. Bootstrap token -> certificate
	tempDir := t.TempDir()
	certDir := filepath.Join(tempDir, "agent-certs")
	store, err := identity.NewCertificateStore(certDir)
	if err != nil {
		t.Fatalf("CertificateStore init failed: %v", err)
	}

	bm := vault.NewBootstrapManager(vClient)
	tokenFile := filepath.Join(tempDir, "bootstrap-token")
	_ = osWriteToken(tokenFile, bootstrapToken)

	resolvedToken, err := vault.ResolveBootstrapToken("", tokenFile)
	if err != nil {
		t.Fatalf("ResolveBootstrapToken failed: %v", err)
	}

	vClient.SetToken(resolvedToken)
	clientBundle, err := bm.BootstrapNode(ctx, "agent-node-chunk-a.agent.primecloud.internal", []string{"127.0.0.1"}, 1*time.Hour)
	if err != nil {
		t.Fatalf("BootstrapNode failed: %v", err)
	}
	if err := store.SaveBundle(clientBundle); err != nil {
		t.Fatalf("SaveBundle failed: %v", err)
	}

	// 3. Start local mTLS Control Plane mock server using Vault-issued server cert
	serverBundle, err := bm.BootstrapNode(ctx, "localhost", []string{"127.0.0.1"}, 1*time.Hour)
	if err != nil {
		t.Fatalf("Server certificate issue failed: %v", err)
	}
	serverStore, _ := identity.NewCertificateStore(filepath.Join(tempDir, "cp-certs"))
	_ = serverStore.SaveBundle(serverBundle)

	serverTLS, err := transport.BuildServerTLSConfig(serverStore)
	if err != nil {
		t.Fatalf("Server TLS build failed: %v", err)
	}

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	serverAddr := lis.Addr().String()

	cpServer := grpc.NewServer(grpc.Creds(credentials.NewTLS(serverTLS)))
	cpImpl := &chunkAControlPlaneServer{
		heartbeats: make(chan *pb.HeartbeatRequest, 10),
		registers:  make(chan *pb.RegisterRequest, 10),
	}
	pb.RegisterAgentServiceServer(cpServer, cpImpl)

	go func() {
		_ = cpServer.Serve(lis)
	}()
	defer cpServer.Stop()

	// 4. gRPC connection with mTLS
	dialCtx, dialCancel := context.WithTimeout(ctx, 5*time.Second)
	defer dialCancel()

	grpcClient, err := transport.Dial(dialCtx, transport.DialOptions{
		TargetAddr: serverAddr,
		ServerName: "localhost",
		Store:      store,
		Logger:     logger,
	})
	if err != nil {
		t.Fatalf("mTLS Dial failed: %v", err)
	}
	defer grpcClient.Close()

	// 5. Registration succeeds
	regMgr := agent.NewRegistrationManager(grpcClient, store)
	regResp, err := regMgr.RegisterNode(ctx, "0.3.0")
	if err != nil {
		t.Fatalf("Registration failed: %v", err)
	}
	if !regResp.Registered || regResp.AgentId != "agent-chunk-a-id" {
		t.Errorf("Unexpected RegisterResponse: %+v", regResp)
	}

	// 6. Heartbeat sent
	hbResp, err := grpcClient.SendHeartbeat(ctx, &pb.HeartbeatRequest{
		AgentId:            regResp.AgentId,
		NodeId:             regResp.NodeId,
		CpuUsagePercent:    12.0,
		MemoryUsagePercent: 35.5,
		DiskUsagePercent:   40.1,
		ContainerCount:     3,
		HealthStatus:       "HEALTHY",
		SentAtUnix:         time.Now().Unix(),
	})
	if err != nil {
		t.Fatalf("SendHeartbeat failed: %v", err)
	}
	if !hbResp.Acknowledged {
		t.Error("Heartbeat not acknowledged")
	}

	// 7. Disconnect and reconnect verification
	if err := grpcClient.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	backoff := transport.NewBackoffStrategy(20*time.Millisecond, 200*time.Millisecond)
	_ = backoff.Sleep(ctx)

	reconnectedClient, err := transport.Dial(ctx, transport.DialOptions{
		TargetAddr: serverAddr,
		ServerName: "localhost",
		Store:      store,
		Logger:     logger,
	})
	if err != nil {
		t.Fatalf("Reconnection Dial failed: %v", err)
	}
	defer reconnectedClient.Close()

	// 8. Certificate rotation
	rotMgr := identity.NewRotationManager(store, vClient, "agent", logger)
	newCertBundle, err := vClient.IssueAgentCertificate(ctx, "agent", "agent-node-chunk-a.agent.primecloud.internal", []string{"127.0.0.1"}, 2*time.Hour)
	if err != nil {
		t.Fatalf("Issue renewal certificate failed: %v", err)
	}
	if err := store.SaveBundle(newCertBundle); err != nil {
		t.Fatalf("Save renewed certificate failed: %v", err)
	}

	rotated, err := rotMgr.CheckAndRotate(ctx, 2*time.Hour)
	if err != nil {
		t.Fatalf("CheckAndRotate error: %v", err)
	}
	_ = rotated

	// 9. Verify no secrets in logs
	logs := logBuf.String()
	if strings.Contains(logs, bootstrapToken) {
		t.Errorf("Bootstrap token leaked in logs: %s", logs)
	}
	if strings.Contains(logs, "-----BEGIN RSA PRIVATE KEY-----") {
		t.Errorf("Private key leaked in logs: %s", logs)
	}
}

func osWriteToken(path, token string) error {
	return os.WriteFile(path, []byte(token), 0600)
}
