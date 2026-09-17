package transport_test

import (
	"context"
	"net"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/primecloud/primecloud-agent/internal/identity"
	pb "github.com/primecloud/primecloud-agent/internal/protocol"
	"github.com/primecloud/primecloud-agent/internal/transport"
	"github.com/primecloud/primecloud-agent/internal/vault"
	"github.com/primecloud/primecloud-agent/tests/testenv"
)

type mockControlPlaneServer struct {
	pb.UnimplementedAgentServiceServer
	heartbeatReceived chan *pb.HeartbeatRequest
	registerReceived  chan *pb.RegisterRequest
}

func (s *mockControlPlaneServer) Register(ctx context.Context, req *pb.RegisterRequest) (*pb.RegisterResponse, error) {
	if s.registerReceived != nil {
		s.registerReceived <- req
	}
	return &pb.RegisterResponse{
		AgentId:              "agent-test-123",
		NodeId:               "node-test-456",
		Registered:           true,
		HeartbeatIntervalSec: 10,
		ReconcileIntervalSec: 30,
		Capabilities:         []string{"docker", "postgres", "valkey", "caddy"},
		Message:              "Registration successful",
	}, nil
}

func (s *mockControlPlaneServer) SendHeartbeat(ctx context.Context, req *pb.HeartbeatRequest) (*pb.HeartbeatResponse, error) {
	if s.heartbeatReceived != nil {
		s.heartbeatReceived <- req
	}
	return &pb.HeartbeatResponse{
		Acknowledged:   true,
		ServerTimeUnix: time.Now().Unix(),
	}, nil
}

func TestGRPC_MTLS_Transport(t *testing.T) {
	vClient, _ := testenv.EnsureVaultDev(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	bm := vault.NewBootstrapManager(vClient)

	// Server cert with SAN 127.0.0.1 and localhost
	serverBundle, err := bm.BootstrapNode(ctx, "localhost", []string{"127.0.0.1"}, 1*time.Hour)
	if err != nil {
		t.Fatalf("Failed to issue server certificate: %v", err)
	}

	// Client cert
	clientBundle, err := bm.BootstrapNode(ctx, "agent-node-01.agent.primecloud.internal", []string{"127.0.0.1"}, 1*time.Hour)
	if err != nil {
		t.Fatalf("Failed to issue client certificate: %v", err)
	}

	tempDir := t.TempDir()
	serverStore, _ := identity.NewCertificateStore(filepath.Join(tempDir, "server"))
	if err := serverStore.SaveBundle(serverBundle); err != nil {
		t.Fatalf("Save server bundle failed: %v", err)
	}

	clientStore, _ := identity.NewCertificateStore(filepath.Join(tempDir, "client"))
	if err := clientStore.SaveBundle(clientBundle); err != nil {
		t.Fatalf("Save client bundle failed: %v", err)
	}

	// 2. Start mTLS gRPC Server
	serverTLSConfig, err := transport.BuildServerTLSConfig(serverStore)
	if err != nil {
		t.Fatalf("BuildServerTLSConfig failed: %v", err)
	}

	grpcServer := grpc.NewServer(grpc.Creds(credentials.NewTLS(serverTLSConfig)))
	serverImpl := &mockControlPlaneServer{
		heartbeatReceived: make(chan *pb.HeartbeatRequest, 10),
		registerReceived:  make(chan *pb.RegisterRequest, 10),
	}
	pb.RegisterAgentServiceServer(grpcServer, serverImpl)

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	serverAddr := lis.Addr().String()

	go func() {
		_ = grpcServer.Serve(lis)
	}()
	defer grpcServer.Stop()

	// 3. Connect client via mTLS
	dialCtx, dialCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer dialCancel()

	grpcClient, err := transport.Dial(dialCtx, transport.DialOptions{
		TargetAddr: serverAddr,
		ServerName: "localhost",
		Store:      clientStore,
	})
	if err != nil {
		t.Fatalf("transport.Dial failed: %v", err)
	}
	defer grpcClient.Close()

	// 4. Test Registration call
	regResp, err := grpcClient.Register(ctx, &pb.RegisterRequest{
		AgentVersion:  "0.3.0",
		CertificateCn: clientBundle.ParsedCert.Subject.CommonName,
		Hostname:      "compute-node-1",
		OsName:        "linux",
		KernelVersion: "6.8.0",
		DockerVersion: "26.1.0",
		CpuCoresTotal: 8,
		MemoryMbTotal: 16384,
		DiskGbTotal:   500,
		TimestampUnix: time.Now().Unix(),
	})
	if err != nil {
		t.Fatalf("Register RPC failed: %v", err)
	}

	if !regResp.Registered || regResp.AgentId != "agent-test-123" {
		t.Errorf("Unexpected RegisterResponse: %+v", regResp)
	}

	// 5. Test Heartbeat call
	hbResp, err := grpcClient.SendHeartbeat(ctx, &pb.HeartbeatRequest{
		AgentId:            "agent-test-123",
		NodeId:             "node-test-456",
		CpuUsagePercent:    15.5,
		MemoryUsagePercent: 42.0,
		DiskUsagePercent:   28.3,
		ContainerCount:     4,
		HealthStatus:       "HEALTHY",
		SentAtUnix:         time.Now().Unix(),
	})
	if err != nil {
		t.Fatalf("SendHeartbeat RPC failed: %v", err)
	}

	if !hbResp.Acknowledged {
		t.Error("Heartbeat was not acknowledged")
	}

	select {
	case hb := <-serverImpl.heartbeatReceived:
		if hb.AgentId != "agent-test-123" || hb.ContainerCount != 4 {
			t.Errorf("Server received unexpected heartbeat: %+v", hb)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("Heartbeat was not received by server")
	}
}

func TestBackoffStrategy(t *testing.T) {
	strategy := transport.NewBackoffStrategy(50*time.Millisecond, 500*time.Millisecond)

	d1 := strategy.NextDelay()
	d2 := strategy.NextDelay()

	if d1 <= 0 || d2 <= 0 {
		t.Errorf("Delays must be positive: d1=%v, d2=%v", d1, d2)
	}
	if d2 <= d1 {
		t.Errorf("Subsequent delay should be greater than first delay: d1=%v, d2=%v", d1, d2)
	}

	strategy.Reset()
	dReset := strategy.NextDelay()
	if dReset > d2 {
		t.Errorf("Reset did not return delay to base range: %v", dReset)
	}
}
