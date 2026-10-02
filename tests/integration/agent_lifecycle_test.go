package integration_test

import (
	"bytes"
	"context"
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
	// Step 1: Vault PKI Setup
	// =========================================================================
	t.Log("STEP 1/13: Vault PKI Setup — Initializing Dev Vault and configuring intermediate CA and roles")
	vClient, bootstrapToken := testenv.EnsureVaultDev(t)
	vClient.SetToken(bootstrapToken)

	// =========================================================================
	// Step 2: Agent Boots
	// =========================================================================
	t.Log("STEP 2/13: Agent Boots — Initializing configuration, state machine, and structured logger")
	cfg := agent.DefaultConfig()
	cfg.NodeID = "node-lifecycle-001"
	ag, err := agent.NewAgent(cfg, logger)
	if err != nil {
		t.Fatalf("Failed to initialize agent skeleton: %v", err)
	}
	if ag.State() != agent.StateInitializing {
		t.Errorf("Expected initial state StateInitializing, got %v", ag.State())
	}

	// =========================================================================
	// Step 3: Bootstrap -> Certificate
	// =========================================================================
	t.Log("STEP 3/13: Bootstrap -> Certificate — Resolving bootstrap token and issuing x509 certificate bundle")
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

	// Bootstrap mTLS server certificate for Control Plane mock
	cpBundle, err := bm.BootstrapNode(ctx, "localhost", []string{"127.0.0.1"}, 2*time.Hour)
	if err != nil {
		t.Fatalf("Failed to issue server certificate: %v", err)
	}
	cpStore, _ := identity.NewCertificateStore(cpCertDir)
	_ = cpStore.SaveBundle(cpBundle)

	// =========================================================================
	// Step 4: gRPC Connection with mTLS
	// =========================================================================
	t.Log("STEP 4/13: gRPC Connection with mTLS — Establishing mutual TLS transport between Agent and Control Plane")
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

	// =========================================================================
	// Step 5: Registration
	// =========================================================================
	t.Log("STEP 5/13: Registration — Exchanging hardware metadata and registering with Control Plane")
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
	// Step 6: Heartbeat
	// =========================================================================
	t.Log("STEP 6/13: Heartbeat — Delivering node metrics and receiving control directives")
	collector := telemetry.NewCollector(nil, logger)
	hbSender := telemetry.NewHeartbeatSender(agentClient, regResp.AgentId, regResp.NodeId, 100*time.Millisecond, collector, nil, logger)
	if _, err := hbSender.SendOnce(ctx); err != nil {
		t.Fatalf("Heartbeat SendOnce failed: %v", err)
	}

	// =========================================================================
	// Step 7: Deploy Application
	// =========================================================================
	t.Log("STEP 7/13: Deploy Application — Executing typed deploy_workload operation through Dispatcher")
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
	// Step 8: Health Check
	// =========================================================================
	t.Log("STEP 8/13: Health Check — Performing node and container health assessment")
	failHandler := agent.NewFailureHandler(nil, vClient, logger)
	healthReport := failHandler.AssessHealth(ctx)
	if healthReport.Status != agent.StatusHealthy {
		t.Errorf("Expected node health StatusHealthy, got %v", healthReport.Status)
	}

	// =========================================================================
	// Step 9: Provision PostgreSQL
	// =========================================================================
	t.Log("STEP 9/13: Provision PostgreSQL — Creating volume, generating credentials in Vault KV, booting datastore")
	pgProv := postgres.NewProvisioner(nil, vClient, resDir, logger)
	pgRes, err := pgProv.ProvisionWithProject(ctx, "lifecycle-project", "", "pg-lifecycle-db", "postgres:16-alpine", "")
	if err != nil {
		t.Fatalf("PostgreSQL provision failed: %v", err)
	}
	pgSecret, err := vClient.ReadSecret(ctx, pgRes.VaultSecretRef)
	if err != nil || pgSecret == nil || pgSecret["username"] == nil {
		t.Fatalf("PostgreSQL secret missing from Vault: %v", err)
	}

	// Also provision Valkey for complete datastore coverage
	vkProv := valkey.NewProvisioner(nil, vClient, resDir, logger)
	vkRes, err := vkProv.ProvisionWithProject(ctx, "lifecycle-project", "", "vk-lifecycle-cache", "valkey/valkey:7.2-alpine", "")
	if err != nil {
		t.Fatalf("Valkey provision failed: %v", err)
	}
	vkSecret, err := vClient.ReadSecret(ctx, vkRes.VaultSecretRef)
	if err != nil || vkSecret == nil || vkSecret["auth_token"] == nil {
		t.Fatalf("Valkey secret missing from Vault: %v", err)
	}

	// =========================================================================
	// Step 10: Configure Route (Caddy)
	// =========================================================================
	t.Log("STEP 10/13: Configure Route — Rendering, validating, and reloading Caddy ingress configuration")
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
	// Step 11: Reconciliation
	// =========================================================================
	t.Log("STEP 11/13: Reconciliation — Evaluating desired vs actual state and applying authorized drift repair")
	reconciler := reconciliation.NewReconciler(nil, agentClient, regResp.AgentId, regResp.NodeId, logger)
	recSummary, err := reconciler.ReconcileOnce(ctx)
	if err != nil {
		t.Fatalf("ReconcileOnce failed: %v", err)
	}
	if recSummary.DriftCount != 1 {
		t.Errorf("Expected 1 drift item, got %d", recSummary.DriftCount)
	}

	// =========================================================================
	// Step 12: Backup & Restore
	// =========================================================================
	t.Log("STEP 12/13: Backup & Restore — Generating dump, Vault-managed key encryption, and verifying recovery")
	pgBackup, err := postgres.BackupPostgres(ctx, nil, "pg-lifecycle-db", backupDir)
	if err != nil || pgBackup.SizeBytes == 0 {
		t.Fatalf("PostgreSQL backup failed: %v", err)
	}

	encKey, err := backup.GetOrCreateBackupKey(ctx, vClient, "pg-lifecycle-db")
	if err != nil {
		t.Fatalf("Failed to fetch Vault-managed backup key: %v", err)
	}

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
	// Step 13: Graceful Shutdown & Drain
	// =========================================================================
	t.Log("STEP 13/13: Graceful Shutdown & Drain — Activating drain mode, rejecting new ops, clean shutdown")
	failHandler.SetDrain(true)
	if canAccept, reason := failHandler.CanAcceptOperations(); canAccept {
		t.Errorf("Expected operation rejection during drain mode, got reason: %s", reason)
	}

	// Stop agent instance gracefully
	ag.Stop()
	if ag.State() != agent.StateStopped {
		t.Errorf("Expected agent state StateStopped after shutdown, got %v", ag.State())
	}

	// Verify all interactions recorded at Control Plane
	if !cpService.registered {
		t.Error("Control Plane did not register node")
	}
	if cpService.heartbeatsRecv == 0 || cpService.reconcileRecv == 0 {
		t.Errorf("Control plane missing lifecycle calls: hb=%d, rec=%d",
			cpService.heartbeatsRecv, cpService.reconcileRecv)
	}

	t.Log("SUCCESS: All 13 Phase 03 Agent Lifecycle Steps Verified Successfully.")
}
