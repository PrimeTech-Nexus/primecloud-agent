package integration_test

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	"github.com/primecloud/primecloud-agent/internal/agent"
	"github.com/primecloud/primecloud-agent/internal/backup"
	"github.com/primecloud/primecloud-agent/internal/caddy"
	"github.com/primecloud/primecloud-agent/internal/operations"
	"github.com/primecloud/primecloud-agent/internal/postgres"
	pb "github.com/primecloud/primecloud-agent/internal/protocol"
	"github.com/primecloud/primecloud-agent/internal/reconciliation"
	"github.com/primecloud/primecloud-agent/internal/recovery"
	"github.com/primecloud/primecloud-agent/internal/runtime"
	"github.com/primecloud/primecloud-agent/internal/state"
	"github.com/primecloud/primecloud-agent/internal/telemetry"
	"github.com/primecloud/primecloud-agent/internal/valkey"
	"github.com/primecloud/primecloud-agent/tests/testenv"
)

type chunkBControlPlaneServer struct {
	pb.UnimplementedAgentServiceServer
	heartbeatCount int
	eventsCount    int
	metricsCount   int
	reconcileCount int
	desiredJSON    string
}

func (s *chunkBControlPlaneServer) SendHeartbeat(ctx context.Context, req *pb.HeartbeatRequest) (*pb.HeartbeatResponse, error) {
	s.heartbeatCount++
	return &pb.HeartbeatResponse{Acknowledged: true, ServerTimeUnix: time.Now().Unix()}, nil
}

func (s *chunkBControlPlaneServer) ReportMetrics(ctx context.Context, req *pb.MetricsRequest) (*pb.MetricsResponse, error) {
	s.metricsCount++
	return &pb.MetricsResponse{Recorded: true}, nil
}

func (s *chunkBControlPlaneServer) ReportEvent(ctx context.Context, req *pb.EventRequest) (*pb.EventResponse, error) {
	s.eventsCount++
	return &pb.EventResponse{Recorded: true}, nil
}

func (s *chunkBControlPlaneServer) ReportInventory(ctx context.Context, req *pb.InventoryRequest) (*pb.InventoryResponse, error) {
	return &pb.InventoryResponse{Acknowledged: true}, nil
}

func (s *chunkBControlPlaneServer) ReportState(ctx context.Context, req *pb.StateRequest) (*pb.StateResponse, error) {
	return &pb.StateResponse{Acknowledged: true}, nil
}

func (s *chunkBControlPlaneServer) Reconcile(ctx context.Context, req *pb.ReconcileRequest) (*pb.ReconcileResponse, error) {
	s.reconcileCount++
	return &pb.ReconcileResponse{
		DesiredStateJson: s.desiredJSON,
		HasDrift:         true,
	}, nil
}

func TestChunkB_FullPipelineIntegration(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()

	tempDir := t.TempDir()
	resDir := filepath.Join(tempDir, "resources")
	backupDir := filepath.Join(tempDir, "backups")
	caddyConfDir := filepath.Join(tempDir, "caddy.sites-enabled")

	// 1. Vault Dev Server Integration
	vClient, _ := testenv.EnsureVaultDev(t)

	// 2. Setup mock Control Plane gRPC Server
	desiredState := &state.DesiredState{
		Version: 1,
		NodeID:  "node-chunk-b-1",
		Workloads: map[string]state.WorkloadSpec{
			"app-prod-1": {
				ID:     "app-prod-1",
				Image:  "nginx:alpine",
				Status: "RUNNING",
			},
		},
	}
	desiredBytes, _ := json.Marshal(desiredState)

	cpServer := &chunkBControlPlaneServer{desiredJSON: string(desiredBytes)}
	listener := bufconn.Listen(1024 * 1024)
	grpcServer := grpc.NewServer()
	pb.RegisterAgentServiceServer(grpcServer, cpServer)
	go func() { _ = grpcServer.Serve(listener) }()
	defer grpcServer.Stop()

	conn, err := grpc.DialContext(ctx, "",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
			return listener.Dial()
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("Failed to dial bufconn: %v", err)
	}
	defer conn.Close()
	grpcClient := pb.NewAgentServiceClient(conn)

	// ----------------------------------------------------
	// AG-04: Operation Dispatcher & Registry
	// ----------------------------------------------------
	reg := operations.NewRegistry()
	var opRan bool
	reg.Register("deploy_application", func(ctx context.Context, env *pb.OperationEnvelope) (*pb.OperationResponse, error) {
		opRan = true
		return &pb.OperationResponse{
			OperationId: env.OperationId,
			Status:      "SUCCEEDED",
			Message:     "deployed successfully",
		}, nil
	}, operations.DefaultJSONValidator)

	dispatcher := operations.NewDispatcher(reg, nil, nil, nil)
	env := &pb.OperationEnvelope{
		OperationId:   "op-test-1",
		OperationType: "deploy_application",
		ResourceId:    "res-test-1",
		PayloadJson:   `{"image":"nginx:alpine"}`,
	}
	resp, err := dispatcher.Dispatch(ctx, env)
	if err != nil || resp.Status != "SUCCEEDED" || !opRan {
		t.Fatalf("Operation dispatch failed: resp=%v, err=%v", resp, err)
	}

	// ----------------------------------------------------
	// AG-05: Docker Hardened Profile & Limits
	// ----------------------------------------------------
	profile := runtime.DefaultHardenedProfile()
	if !profile.DisallowPrivileged || len(profile.DropCapabilities) == 0 || profile.DropCapabilities[0] != "ALL" {
		t.Errorf("Hardened profile missing security constraints")
	}
	limits := runtime.DefaultResourceLimits()
	if limits.MemoryBytes <= 0 {
		t.Errorf("Resource limits memory constraint invalid")
	}

	// ----------------------------------------------------
	// AG-07: PostgreSQL Provisioning & Backup
	// ----------------------------------------------------
	pgProv := postgres.NewProvisioner(nil, vClient, resDir, nil)
	pgRes, err := pgProv.ProvisionWithProject(ctx, "proj-chunk-b", "", "pg-test-res", "postgres:16-alpine", "")
	if err != nil {
		t.Fatalf("Postgres provision failed: %v", err)
	}
	// Verify Vault credentials stored
	vPgData, err := vClient.ReadSecret(ctx, pgRes.VaultSecretRef)
	if err != nil || vPgData == nil || vPgData["username"] == nil {
		t.Fatalf("Postgres credentials missing in Vault: %v", err)
	}

	pgBackup, err := postgres.BackupPostgres(ctx, nil, "pg-test-res", backupDir)
	if err != nil || pgBackup.SizeBytes == 0 {
		t.Fatalf("Postgres backup failed: %v", err)
	}

	// ----------------------------------------------------
	// AG-08: Valkey Provisioning & Backup
	// ----------------------------------------------------
	vkProv := valkey.NewProvisioner(nil, vClient, resDir, nil)
	vkRes, err := vkProv.ProvisionWithProject(ctx, "proj-chunk-b", "", "vk-test-res", "valkey/valkey:7.2-alpine", "")
	if err != nil {
		t.Fatalf("Valkey provision failed: %v", err)
	}
	vVkData, err := vClient.ReadSecret(ctx, vkRes.VaultSecretRef)
	if err != nil || vVkData == nil || vVkData["auth_token"] == nil {
		t.Fatalf("Valkey credentials missing in Vault: %v", err)
	}

	vkBackup, err := valkey.BackupValkey(ctx, nil, "vk-test-res", backupDir)
	if err != nil || vkBackup.SizeBytes == 0 {
		t.Fatalf("Valkey backup failed: %v", err)
	}

	// ----------------------------------------------------
	// AG-09: Caddy Driver
	// ----------------------------------------------------
	caddyAdmin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer caddyAdmin.Close()

	caddyMgr := caddy.NewManager(caddyConfDir, caddyAdmin.URL, nil)
	route := &caddy.RouteConfig{
		Domain:   "service.chunkb.internal",
		Upstream: "127.0.0.1:9000",
		TLS:      false,
	}
	if err := caddyMgr.ConfigureRoute(ctx, route); err != nil {
		t.Fatalf("Caddy ConfigureRoute failed: %v", err)
	}
	if err := caddyMgr.RemoveRoute(ctx, "service.chunkb.internal"); err != nil {
		t.Fatalf("Caddy RemoveRoute failed: %v", err)
	}

	// ----------------------------------------------------
	// AG-10: Telemetry (Metrics, Events, Inventory, Heartbeat)
	// ----------------------------------------------------
	collector := telemetry.NewCollector(nil, nil)
	metrics, err := collector.CollectNodeMetrics(ctx)
	if err != nil {
		t.Fatalf("CollectNodeMetrics failed: %v", err)
	}
	if err := telemetry.ReportMetrics(ctx, grpcClient, "agent-b", "node-b", metrics); err != nil {
		t.Fatalf("ReportMetrics failed: %v", err)
	}

	emitter := telemetry.NewEventEmitter(grpcClient, "agent-b", nil)
	if err := emitter.Emit(ctx, "CHUNK_B_STARTED", telemetry.SeverityInfo, "ready", nil); err != nil {
		t.Fatalf("Emit event failed: %v", err)
	}

	inv, err := telemetry.CollectInventory(ctx, nil)
	if err != nil {
		t.Fatalf("CollectInventory failed: %v", err)
	}
	if err := telemetry.ReportInventory(ctx, grpcClient, "agent-b", "node-b", inv, nil); err != nil {
		t.Fatalf("ReportInventory failed: %v", err)
	}

	hbSender := telemetry.NewHeartbeatSender(grpcClient, "agent-b", "node-b", 50*time.Millisecond, collector, nil, nil)
	if _, err := hbSender.SendOnce(ctx); err != nil {
		t.Fatalf("SendOnce heartbeat failed: %v", err)
	}

	// ----------------------------------------------------
	// AG-11: Reconciliation
	// ----------------------------------------------------
	reconciler := reconciliation.NewReconciler(nil, grpcClient, "agent-b", "node-b", nil)
	reconcileSummary, err := reconciler.ReconcileOnce(ctx)
	if err != nil {
		t.Fatalf("ReconcileOnce failed: %v", err)
	}
	if reconcileSummary.DriftCount != 1 {
		t.Errorf("Expected 1 drift count, got %d", reconcileSummary.DriftCount)
	}

	// ----------------------------------------------------
	// AG-12 & AG-13: Backup Packaging & Recovery Verification
	// ----------------------------------------------------
	encKey := make([]byte, 32)
	_, _ = rand.Read(encKey)

	uploader := backup.NewUploader(nil)
	manifest, encFile, err := uploader.PackageAndUpload(ctx, "bk-chunk-b-1", "pg-test-res", "postgres", "node-b", pgBackup.ArtifactPath, encKey, filepath.Join(tempDir, "pkg-backups"))
	if err != nil {
		t.Fatalf("PackageAndUpload failed: %v", err)
	}

	manifestFile := filepath.Join(tempDir, "pkg-backups", "bk-chunk-b-1.manifest.json")
	reconstructor := recovery.NewReconstructor(nil, nil)
	restoredPath, restoredManifest, err := reconstructor.ReconstructArtifact(ctx, encFile, manifestFile, encKey, filepath.Join(tempDir, "pkg-restores"))
	if err != nil {
		t.Fatalf("ReconstructArtifact failed: %v", err)
	}

	verifier := recovery.NewVerifier(nil)
	if err := verifier.VerifyIntegrity(manifest, restoredPath); err != nil {
		t.Fatalf("VerifyIntegrity failed: %v", err)
	}
	if err := reconstructor.RestoreToWorkload(ctx, restoredManifest, restoredPath); err != nil {
		t.Fatalf("RestoreToWorkload failed: %v", err)
	}

	// ----------------------------------------------------
	// AG-14: Node Failure & Degradation
	// ----------------------------------------------------
	failHandler := agent.NewFailureHandler(nil, vClient, nil)
	report := failHandler.AssessHealth(ctx)
	if report.Status != agent.StatusHealthy {
		t.Errorf("Expected healthy status, got %v", report.Status)
	}

	failHandler.SetDrain(true)
	report = failHandler.AssessHealth(ctx)
	if report.Status != agent.StatusDegraded {
		t.Errorf("Expected degraded status on drain, got %v", report.Status)
	}
	if canAccept, _ := failHandler.CanAcceptOperations(); canAccept {
		t.Error("Expected rejection of operations during drain")
	}

	// Verify Control Plane received all calls
	if cpServer.heartbeatCount == 0 || cpServer.eventsCount == 0 || cpServer.metricsCount == 0 || cpServer.reconcileCount == 0 {
		t.Errorf("Control plane missing reported interactions: hb=%d, ev=%d, met=%d, rec=%d",
			cpServer.heartbeatCount, cpServer.eventsCount, cpServer.metricsCount, cpServer.reconcileCount)
	}
}
