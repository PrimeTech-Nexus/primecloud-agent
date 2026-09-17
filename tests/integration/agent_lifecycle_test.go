package integration_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/primecloud/primecloud-agent/internal/agent"
	"github.com/primecloud/primecloud-agent/internal/backup"
	"github.com/primecloud/primecloud-agent/internal/caddy"
	"github.com/primecloud/primecloud-agent/internal/identity"
	"github.com/primecloud/primecloud-agent/internal/operations"
	"github.com/primecloud/primecloud-agent/internal/postgres"
	pb "github.com/primecloud/primecloud-agent/internal/protocol"
	"github.com/primecloud/primecloud-agent/internal/reconciliation"
	"github.com/primecloud/primecloud-agent/internal/recovery"
	"github.com/primecloud/primecloud-agent/internal/state"
	"github.com/primecloud/primecloud-agent/internal/telemetry"
	"github.com/primecloud/primecloud-agent/internal/transport"
	"github.com/primecloud/primecloud-agent/internal/valkey"
	"github.com/primecloud/primecloud-agent/internal/vault"
	"github.com/primecloud/primecloud-agent/tests/testenv"
)

type fullLifecycleControlPlaneServer struct {
	pb.UnimplementedAgentServiceServer
	registered     bool
	heartbeatsRecv int
	metricsRecv    int
	eventsRecv     int
	reconcileRecv  int
	desiredJSON    string
}

func (s *fullLifecycleControlPlaneServer) Register(ctx context.Context, req *pb.RegisterRequest) (*pb.RegisterResponse, error) {
	s.registered = true
	return &pb.RegisterResponse{
		AgentId:              "agent-lifecycle-001",
		NodeId:               "node-lifecycle-001",
		Registered:           true,
		HeartbeatIntervalSec: 5,
		ReconcileIntervalSec: 10,
		Capabilities:         []string{"docker", "postgres", "valkey", "caddy", "encryption"},
		Message:              "Registration successful",
	}, nil
}

func (s *fullLifecycleControlPlaneServer) SendHeartbeat(ctx context.Context, req *pb.HeartbeatRequest) (*pb.HeartbeatResponse, error) {
	s.heartbeatsRecv++
	return &pb.HeartbeatResponse{
		Acknowledged:   true,
		ServerTimeUnix: time.Now().Unix(),
	}, nil
}

func (s *fullLifecycleControlPlaneServer) ReportMetrics(ctx context.Context, req *pb.MetricsRequest) (*pb.MetricsResponse, error) {
	s.metricsRecv++
	return &pb.MetricsResponse{Recorded: true}, nil
}

func (s *fullLifecycleControlPlaneServer) ReportEvent(ctx context.Context, req *pb.EventRequest) (*pb.EventResponse, error) {
	s.eventsRecv++
	return &pb.EventResponse{Recorded: true}, nil
}

func (s *fullLifecycleControlPlaneServer) ReportInventory(ctx context.Context, req *pb.InventoryRequest) (*pb.InventoryResponse, error) {
	return &pb.InventoryResponse{Acknowledged: true}, nil
}

func (s *fullLifecycleControlPlaneServer) ReportState(ctx context.Context, req *pb.StateRequest) (*pb.StateResponse, error) {
	return &pb.StateResponse{Acknowledged: true}, nil
}

func (s *fullLifecycleControlPlaneServer) Reconcile(ctx context.Context, req *pb.ReconcileRequest) (*pb.ReconcileResponse, error) {
	s.reconcileRecv++
	return &pb.ReconcileResponse{
		DesiredStateJson: s.desiredJSON,
		HasDrift:         true,
	}, nil
}

func TestPhase03_FullAgentLifecycle(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tempDir := t.TempDir()
	certDir := filepath.Join(tempDir, "agent-certs")
	cpCertDir := filepath.Join(tempDir, "cp-certs")
	resDir := filepath.Join(tempDir, "resources")
	backupDir := filepath.Join(tempDir, "backups")
	caddyConfDir := filepath.Join(tempDir, "caddy-conf")

	var logBuf bytes.Buffer
	logger := agent.SetupLogging(&logBuf, slog.LevelDebug)

	// =========================================================================
	// 1. Vault Dev Server Initialization & Certificate Bootstrapping (AG-01, AG-03)
	// =========================================================================
	vClient, bootstrapToken := testenv.EnsureVaultDev(t)
	vClient.SetToken(bootstrapToken)

	bm := vault.NewBootstrapManager(vClient)
	agentBundle, err := bm.BootstrapNode(ctx, "agent-lifecycle-node.agent.primecloud.internal", []string{"127.0.0.1"}, 2*time.Hour)
	if err != nil {
		t.Fatalf("Failed to bootstrap agent certificate from Vault: %v", err)
	}

	agentStore, err := identity.NewCertificateStore(certDir)
	if err != nil {
		t.Fatalf("Failed to create certificate store: %v", err)
	}
	if err := agentStore.SaveBundle(agentBundle); err != nil {
		t.Fatalf("Failed to persist agent certificate bundle: %v", err)
	}

	// Bootstrap mTLS server certificate for Control Plane
	cpBundle, err := bm.BootstrapNode(ctx, "localhost", []string{"127.0.0.1"}, 2*time.Hour)
	if err != nil {
		t.Fatalf("Failed to issue server certificate: %v", err)
	}
	cpStore, _ := identity.NewCertificateStore(cpCertDir)
	_ = cpStore.SaveBundle(cpBundle)

	// =========================================================================
	// 2. Control Plane Server with Authoritative mTLS (AG-02)
	// =========================================================================
	cpServerTLS, err := transport.BuildServerTLSConfig(cpStore)
	if err != nil {
		t.Fatalf("Failed to build server mTLS config: %v", err)
	}

	desired := &state.DesiredState{
		Version: 1,
		NodeID:  "node-lifecycle-001",
		Workloads: map[string]state.WorkloadSpec{
			"app-monitored": {
				ID:     "app-monitored",
				Image:  "nginx:alpine",
				Status: "RUNNING",
			},
		},
	}
	desiredBytes, _ := json.Marshal(desired)

	cpService := &fullLifecycleControlPlaneServer{desiredJSON: string(desiredBytes)}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	defer listener.Close()

	grpcServer := grpc.NewServer(grpc.Creds(credentials.NewTLS(cpServerTLS)))
	pb.RegisterAgentServiceServer(grpcServer, cpService)
	go func() { _ = grpcServer.Serve(listener) }()
	defer grpcServer.Stop()

	// =========================================================================
	// 3. Agent mTLS Connection & Handshake (AG-02, AG-03)
	// =========================================================================
	clientTLS, err := transport.BuildClientTLSConfig(agentStore, "localhost")
	if err != nil {
		t.Fatalf("Failed to build client mTLS config: %v", err)
	}

	clientConn, err := grpc.DialContext(ctx, listener.Addr().String(),
		grpc.WithTransportCredentials(credentials.NewTLS(clientTLS)),
	)
	if err != nil {
		t.Fatalf("mTLS DialContext failed: %v", err)
	}
	defer clientConn.Close()

	agentClient := pb.NewAgentServiceClient(clientConn)

	// Register with Control Plane
	meta, err := agent.CollectNodeMetadata(agentStore)
	if err != nil {
		t.Fatalf("CollectNodeMetadata failed: %v", err)
	}

	regResp, err := agentClient.Register(ctx, &pb.RegisterRequest{
		AgentVersion:  "1.0.0",
		CertificateCn: meta.CertificateCN,
		Hostname:      meta.Hostname,
		TimestampUnix: time.Now().Unix(),
	})
	if err != nil {
		t.Fatalf("Agent registration failed: %v", err)
	}
	if !regResp.Registered || regResp.AgentId != "agent-lifecycle-001" {
		t.Fatalf("Registration response mismatch: %+v", regResp)
	}

	// =========================================================================
	// 4. Operation Dispatcher, Registry & Execution (AG-04, AG-05, AG-06)
	// =========================================================================
	registry := operations.NewRegistry()
	var deployed bool
	registry.Register("deploy_workload", func(ctx context.Context, env *pb.OperationEnvelope) (*pb.OperationResponse, error) {
		deployed = true
		return &pb.OperationResponse{
			OperationId:     env.OperationId,
			Status:          "SUCCEEDED",
			Message:         "workload deployed under hardened profile",
			CompletedAtUnix: time.Now().Unix(),
			ProgressPercent: 100,
		}, nil
	}, operations.DefaultJSONValidator)

	dispatcher := operations.NewDispatcher(registry, nil, nil, logger)
	deployEnv := &pb.OperationEnvelope{
		OperationId:   "op-lifecycle-deploy-1",
		OperationType: "deploy_workload",
		ResourceId:    "res-lifecycle-1",
		PayloadJson:   `{"spec":"sample"}`,
	}
	opResp, err := dispatcher.Dispatch(ctx, deployEnv)
	if err != nil || opResp.Status != "SUCCEEDED" || !deployed {
		t.Fatalf("Dispatcher execution failed: resp=%v, err=%v", opResp, err)
	}

	// =========================================================================
	// 5. Database Drivers Provisioning & Vault Integration (AG-07, AG-08)
	// =========================================================================
	// PostgreSQL
	pgProv := postgres.NewProvisioner(nil, vClient, resDir, logger)
	pgRes, err := pgProv.Provision(ctx, "pg-lifecycle-db", "postgres:16-alpine", "")
	if err != nil {
		t.Fatalf("PostgreSQL provision failed: %v", err)
	}
	pgSecret, err := vClient.ReadSecret(ctx, pgRes.VaultSecretRef)
	if err != nil || pgSecret == nil || pgSecret["username"] == nil {
		t.Fatalf("PostgreSQL secret missing from Vault: %v", err)
	}

	pgBackup, err := postgres.BackupPostgres(ctx, nil, "pg-lifecycle-db", backupDir)
	if err != nil || pgBackup.SizeBytes == 0 {
		t.Fatalf("PostgreSQL backup failed: %v", err)
	}

	// Valkey
	vkProv := valkey.NewProvisioner(nil, vClient, resDir, logger)
	vkRes, err := vkProv.Provision(ctx, "vk-lifecycle-cache", "valkey/valkey:7.2-alpine", "")
	if err != nil {
		t.Fatalf("Valkey provision failed: %v", err)
	}
	vkSecret, err := vClient.ReadSecret(ctx, vkRes.VaultSecretRef)
	if err != nil || vkSecret == nil || vkSecret["auth_token"] == nil {
		t.Fatalf("Valkey secret missing from Vault: %v", err)
	}

	vkBackup, err := valkey.BackupValkey(ctx, nil, "vk-lifecycle-cache", backupDir)
	if err != nil || vkBackup.SizeBytes == 0 {
		t.Fatalf("Valkey backup failed: %v", err)
	}

	// =========================================================================
	// 6. Ingress Routing with Caddy Driver (AG-09)
	// =========================================================================
	caddyAdmin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer caddyAdmin.Close()

	caddyMgr := caddy.NewManager(caddyConfDir, caddyAdmin.URL, logger)
	if err := caddyMgr.ConfigureRoute(ctx, &caddy.RouteConfig{
		Domain:   "lifecycle.primecloud.dev",
		Upstream: "127.0.0.1:8080",
		TLS:      true,
	}); err != nil {
		t.Fatalf("Caddy ConfigureRoute failed: %v", err)
	}
	if err := caddyMgr.RemoveRoute(ctx, "lifecycle.primecloud.dev"); err != nil {
		t.Fatalf("Caddy RemoveRoute failed: %v", err)
	}

	// =========================================================================
	// 7. Telemetry Pipeline (AG-10)
	// =========================================================================
	collector := telemetry.NewCollector(nil, logger)
	nodeMetrics, err := collector.CollectNodeMetrics(ctx)
	if err != nil {
		t.Fatalf("CollectNodeMetrics failed: %v", err)
	}
	if err := telemetry.ReportMetrics(ctx, agentClient, regResp.AgentId, regResp.NodeId, nodeMetrics); err != nil {
		t.Fatalf("ReportMetrics failed: %v", err)
	}

	eventEmitter := telemetry.NewEventEmitter(agentClient, regResp.AgentId, logger)
	if err := eventEmitter.Emit(ctx, "LIFECYCLE_TEST_STEP", telemetry.SeverityInfo, "telemetry verified", nil); err != nil {
		t.Fatalf("Emit event failed: %v", err)
	}

	inventory, err := telemetry.CollectInventory(ctx, nil)
	if err != nil {
		t.Fatalf("CollectInventory failed: %v", err)
	}
	if err := telemetry.ReportInventory(ctx, agentClient, regResp.AgentId, regResp.NodeId, inventory, logger); err != nil {
		t.Fatalf("ReportInventory failed: %v", err)
	}

	hbSender := telemetry.NewHeartbeatSender(agentClient, regResp.AgentId, regResp.NodeId, 100*time.Millisecond, collector, nil, logger)
	if _, err := hbSender.SendOnce(ctx); err != nil {
		t.Fatalf("Heartbeat SendOnce failed: %v", err)
	}

	// =========================================================================
	// 8. Reconciliation Cycle (AG-11)
	// =========================================================================
	reconciler := reconciliation.NewReconciler(nil, agentClient, regResp.AgentId, regResp.NodeId, logger)
	recSummary, err := reconciler.ReconcileOnce(ctx)
	if err != nil {
		t.Fatalf("ReconcileOnce failed: %v", err)
	}
	if recSummary.DriftCount != 1 {
		t.Errorf("Expected 1 drift item, got %d", recSummary.DriftCount)
	}

	// =========================================================================
	// 9. Backup Packaging & Disaster Recovery Cycle (AG-12, AG-13)
	// =========================================================================
	encKey := make([]byte, 32)
	_, _ = rand.Read(encKey)

	uploader := backup.NewUploader(logger)
	manifest, encPath, err := uploader.PackageAndUpload(ctx, "bk-lifecycle-pg", "pg-lifecycle-db", "postgres", regResp.NodeId, pgBackup.ArtifactPath, encKey, filepath.Join(tempDir, "encrypted-backups"))
	if err != nil {
		t.Fatalf("PackageAndUpload failed: %v", err)
	}

	manifestPath := filepath.Join(tempDir, "encrypted-backups", "bk-lifecycle-pg.manifest.json")
	reconstructor := recovery.NewReconstructor(nil, logger)
	restoredPath, restoredManifest, err := reconstructor.ReconstructArtifact(ctx, encPath, manifestPath, encKey, filepath.Join(tempDir, "restored-data"))
	if err != nil {
		t.Fatalf("ReconstructArtifact failed: %v", err)
	}

	verifier := recovery.NewVerifier(nil)
	if err := verifier.VerifyIntegrity(manifest, restoredPath); err != nil {
		t.Fatalf("Integrity verification failed on restored artifact: %v", err)
	}
	if err := reconstructor.RestoreToWorkload(ctx, restoredManifest, restoredPath); err != nil {
		t.Fatalf("Workload restoration failed: %v", err)
	}

	// =========================================================================
	// 10. Node Failure Handling & Graceful Degradation (AG-14, AG-00)
	// =========================================================================
	failHandler := agent.NewFailureHandler(nil, vClient, logger)
	healthReport := failHandler.AssessHealth(ctx)
	if healthReport.Status != agent.StatusHealthy {
		t.Errorf("Expected node health StatusHealthy, got %v", healthReport.Status)
	}

	failHandler.SetDrain(true)
	if canAccept, reason := failHandler.CanAcceptOperations(); canAccept {
		t.Errorf("Expected operation rejection during drain mode, got reason: %s", reason)
	}
	failHandler.SetDrain(false)

	// Verify all interactions recorded at Control Plane
	if !cpService.registered {
		t.Error("Control Plane did not register node")
	}
	if cpService.heartbeatsRecv == 0 || cpService.metricsRecv == 0 || cpService.eventsRecv == 0 || cpService.reconcileRecv == 0 {
		t.Errorf("Control plane missing lifecycle telemetry calls: hb=%d, met=%d, ev=%d, rec=%d",
			cpService.heartbeatsRecv, cpService.metricsRecv, cpService.eventsRecv, cpService.reconcileRecv)
	}

	t.Log("Phase 03 Full Agent Lifecycle Test Completed Successfully.")
}
