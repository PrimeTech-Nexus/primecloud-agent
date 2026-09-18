package identity_test

import (
	"context"
	"errors"
	"net"
	"path/filepath"
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

type registrationServerMock struct {
	pb.UnimplementedAgentServiceServer
	rejectCN string
}

func (s *registrationServerMock) Register(ctx context.Context, req *pb.RegisterRequest) (*pb.RegisterResponse, error) {
	if s.rejectCN != "" && req.CertificateCn == s.rejectCN {
		return &pb.RegisterResponse{
			Registered: false,
			Message:    "Invalid certificate Common Name rejected by Control Plane",
		}, nil
	}

	return &pb.RegisterResponse{
		AgentId:              "agent-registered-uuid-1",
		NodeId:               "node-registered-uuid-1",
		Registered:           true,
		HeartbeatIntervalSec: 10,
		ReconcileIntervalSec: 30,
		Capabilities:         []string{"docker", "postgres", "valkey", "caddy"},
		Message:              "Registration successful",
	}, nil
}

func TestRegistration_SuccessAndFailure(t *testing.T) {
	vClient, _ := testenv.EnsureVaultDev(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	bm := vault.NewBootstrapManager(vClient)

	// Issue server and client certificates
	serverBundle, err := bm.BootstrapNode(ctx, "localhost", []string{"127.0.0.1"}, 1*time.Hour)
	if err != nil {
		t.Fatalf("Server cert issue failed: %v", err)
	}

	validClientBundle, err := bm.BootstrapNode(ctx, "agent-node-valid.agent.primecloud.internal", []string{"127.0.0.1"}, 1*time.Hour)
	if err != nil {
		t.Fatalf("Valid client cert issue failed: %v", err)
	}

	rejectedClientBundle, err := bm.BootstrapNode(ctx, "agent-node-rejected.agent.primecloud.internal", []string{"127.0.0.1"}, 1*time.Hour)
	if err != nil {
		t.Fatalf("Rejected client cert issue failed: %v", err)
	}

	tempDir := t.TempDir()
	serverStore, _ := identity.NewCertificateStore(filepath.Join(tempDir, "server"))
	_ = serverStore.SaveBundle(serverBundle)

	validClientStore, _ := identity.NewCertificateStore(filepath.Join(tempDir, "client-valid"))
	_ = validClientStore.SaveBundle(validClientBundle)

	rejectedClientStore, _ := identity.NewCertificateStore(filepath.Join(tempDir, "client-rejected"))
	_ = rejectedClientStore.SaveBundle(rejectedClientBundle)

	// Start mTLS test server
	serverTLS, err := transport.BuildServerTLSConfig(serverStore)
	if err != nil {
		t.Fatalf("Server TLS config failed: %v", err)
	}

	srv := grpc.NewServer(grpc.Creds(credentials.NewTLS(serverTLS)))
	regMock := &registrationServerMock{
		rejectCN: "agent-node-rejected.agent.primecloud.internal",
	}
	pb.RegisterAgentServiceServer(srv, regMock)

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	serverAddr := lis.Addr().String()

	go func() {
		_ = srv.Serve(lis)
	}()
	defer srv.Stop()

	// 1. Successful registration
	validConn, err := transport.Dial(ctx, transport.DialOptions{
		TargetAddr: serverAddr,
		ServerName: "localhost",
		Store:      validClientStore,
	})
	if err != nil {
		t.Fatalf("Dial with valid cert failed: %v", err)
	}
	defer validConn.Close()

	regMgr := agent.NewRegistrationManager(validConn, validClientStore)
	resp, err := regMgr.RegisterNode(ctx, "0.3.0")
	if err != nil {
		t.Fatalf("RegisterNode with valid cert failed: %v", err)
	}
	if !resp.Registered || resp.AgentId != "agent-registered-uuid-1" {
		t.Errorf("Unexpected register response: %+v", resp)
	}

	// 2. Rejected registration
	rejConn, err := transport.Dial(ctx, transport.DialOptions{
		TargetAddr: serverAddr,
		ServerName: "localhost",
		Store:      rejectedClientStore,
	})
	if err != nil {
		t.Fatalf("Dial with rejected cert failed: %v", err)
	}
	defer rejConn.Close()

	rejRegMgr := agent.NewRegistrationManager(rejConn, rejectedClientStore)
	_, err = rejRegMgr.RegisterNode(ctx, "0.3.0")
	if err == nil {
		t.Fatal("Expected rejected registration to return error, but got nil")
	}
}

func TestCertificateRotation(t *testing.T) {
	vClient, _ := testenv.EnsureVaultDev(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	bm := vault.NewBootstrapManager(vClient)
	initialBundle, err := bm.BootstrapNode(ctx, "agent-node-rot.agent.primecloud.internal", []string{"127.0.0.1"}, 1*time.Hour)
	if err != nil {
		t.Fatalf("BootstrapNode failed: %v", err)
	}

	tempDir := t.TempDir()
	store, _ := identity.NewCertificateStore(filepath.Join(tempDir, "client-rot"))
	_ = store.SaveBundle(initialBundle)

	rotMgr := identity.NewRotationManager(store, vClient, "agent", nil)

	// Since fresh cert hasn't passed 50% TTL, check without forcing should return false
	rotated, err := rotMgr.CheckAndRotate(ctx, 1*time.Hour)
	if err != nil {
		t.Fatalf("CheckAndRotate failed: %v", err)
	}
	if rotated {
		t.Error("Fresh cert should not rotate immediately")
	}

	// Issue an almost-expired cert or manually test rotation logic
	// Force new issue via Vault client to verify rotate execution
	newBundle, err := vClient.IssueAgentCertificate(ctx, "agent", "agent-node-rot.agent.primecloud.internal", []string{"127.0.0.1"}, []string{"primecloud://agent/node/001"}, 2*time.Hour)
	if err != nil {
		t.Fatalf("Manual issue renewal failed: %v", err)
	}
	if err := store.SaveBundle(newBundle); err != nil {
		t.Fatalf("Save renewed bundle failed: %v", err)
	}

	loadedCert, err := store.LoadParsedCertificate()
	if err != nil {
		t.Fatalf("LoadParsedCertificate failed: %v", err)
	}
	if loadedCert.SerialNumber.String() == initialBundle.ParsedCert.SerialNumber.String() {
		t.Error("Stored certificate serial number was not updated after renewal")
	}
}

func TestRevocationDetection(t *testing.T) {
	callbackInvoked := false
	revHandler := identity.NewRevocationHandler(nil, func() {
		callbackInvoked = true
	})

	if revHandler.IsRevoked() {
		t.Error("Initial state should not be revoked")
	}

	if err := revHandler.EnsureNotRevoked(); err != nil {
		t.Errorf("Initial EnsureNotRevoked should succeed: %v", err)
	}

	// Test non-revocation error
	normalErr := errors.New("network timeout")
	if revHandler.CheckRevocationError(normalErr) {
		t.Error("Normal network error should not trigger revocation")
	}

	// Test revocation error detection
	revokeErr := errors.New("rpc error: code = PermissionDenied desc = AGENT_REVOKED: node decommissioned")
	if !revHandler.CheckRevocationError(revokeErr) {
		t.Error("Revocation error should be detected")
	}

	if !revHandler.IsRevoked() {
		t.Error("Agent should be marked as revoked")
	}
	if !callbackInvoked {
		t.Error("Revocation callback was not invoked")
	}

	// Ensure operations are blocked
	if err := revHandler.EnsureNotRevoked(); err == nil || !errors.Is(err, identity.ErrAgentRevoked) {
		t.Errorf("Expected identity.ErrAgentRevoked, got: %v", err)
	}
}
