package reconciliation_test

import (
	"context"
	"encoding/json"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/primecloud/primecloud-agent/internal/protocol"
	"github.com/primecloud/primecloud-agent/internal/reconciliation"
	"github.com/primecloud/primecloud-agent/internal/state"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

type mockReconcileServer struct {
	protocol.UnimplementedAgentServiceServer
	mu           sync.Mutex
	reconcileReq *protocol.ReconcileRequest
	stateReq     *protocol.StateRequest
	desiredJSON  string
}

func (m *mockReconcileServer) Reconcile(ctx context.Context, req *protocol.ReconcileRequest) (*protocol.ReconcileResponse, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.reconcileReq = req
	return &protocol.ReconcileResponse{
		DesiredStateJson: m.desiredJSON,
		HasDrift:         true,
	}, nil
}

func (m *mockReconcileServer) ReportState(ctx context.Context, req *protocol.StateRequest) (*protocol.StateResponse, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stateReq = req
	return &protocol.StateResponse{Acknowledged: true}, nil
}

func TestReconciliation_DiffAndPlan(t *testing.T) {
	desired := &state.DesiredState{
		Version: 1,
		NodeID:  "node-1",
		Workloads: map[string]state.WorkloadSpec{
			"app-1": {
				ID:     "app-1",
				Image:  "nginx:alpine",
				Status: "RUNNING",
			},
			"app-2": {
				ID:     "app-2",
				Image:  "redis:7",
				Status: "RUNNING",
			},
		},
	}

	actual := &state.ActualState{
		NodeID: "node-1",
		Workloads: map[string]state.ActualWorkload{
			"app-2": {
				ID:          "app-2",
				ContainerID: "cid-app2",
				Image:       "redis:7",
				State:       "exited",
			},
			"app-unmanaged": {
				ID:          "app-unmanaged",
				ContainerID: "cid-unmanaged",
				Image:       "busybox:latest",
				State:       "running",
			},
		},
	}

	drifts := state.Diff(desired, actual)
	if len(drifts) != 3 {
		t.Fatalf("Expected 3 drift items (missing app-1, stopped app-2, extraneous app-unmanaged), got %d", len(drifts))
	}

	repairs := reconciliation.PlanRepairs(drifts, desired, actual)
	if len(repairs) != 3 {
		t.Fatalf("Expected 3 repairs planned, got %d", len(repairs))
	}

	actions := make(map[string]reconciliation.ActionType)
	for _, r := range repairs {
		actions[r.WorkloadID] = r.Action
	}

	if actions["app-1"] != reconciliation.ActionDeploy {
		t.Errorf("Expected ActionDeploy for app-1, got %v", actions["app-1"])
	}
	if actions["app-2"] != reconciliation.ActionStart {
		t.Errorf("Expected ActionStart for app-2, got %v", actions["app-2"])
	}
	if actions["app-unmanaged"] != reconciliation.ActionRemove {
		t.Errorf("Expected ActionRemove for app-unmanaged, got %v", actions["app-unmanaged"])
	}
}

func TestReconciliation_EndToEnd(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	desired := &state.DesiredState{
		Version: 1,
		NodeID:  "node-1",
		Workloads: map[string]state.WorkloadSpec{
			"app-reconciled": {
				ID:     "app-reconciled",
				Image:  "nginx:alpine",
				Status: "RUNNING",
			},
		},
	}
	desiredBytes, _ := json.Marshal(desired)

	listener := bufconn.Listen(1024 * 1024)
	grpcServer := grpc.NewServer()
	mockServer := &mockReconcileServer{desiredJSON: string(desiredBytes)}
	protocol.RegisterAgentServiceServer(grpcServer, mockServer)

	go func() {
		_ = grpcServer.Serve(listener)
	}()
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

	client := protocol.NewAgentServiceClient(conn)
	reconciler := reconciliation.NewReconciler(nil, client, "agent-1", "node-1", nil)

	summary, err := reconciler.ReconcileOnce(ctx)
	if err != nil {
		t.Fatalf("ReconcileOnce failed: %v", err)
	}

	if summary.DriftCount != 1 {
		t.Errorf("Expected 1 drift count, got %d", summary.DriftCount)
	}
	if mockServer.stateReq == nil {
		t.Error("Expected ReportState to be called back")
	}
}
