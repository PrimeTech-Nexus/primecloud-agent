package telemetry_test

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/primecloud/primecloud-agent/internal/protocol"
	"github.com/primecloud/primecloud-agent/internal/telemetry"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

type mockAgentServer struct {
	protocol.UnimplementedAgentServiceServer
	mu          sync.Mutex
	heartbeats  []*protocol.HeartbeatRequest
	metrics     []*protocol.MetricsRequest
	events      []*protocol.EventRequest
	inventories []*protocol.InventoryRequest
	rotateOnHB  bool
}

func (m *mockAgentServer) SendHeartbeat(ctx context.Context, req *protocol.HeartbeatRequest) (*protocol.HeartbeatResponse, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.heartbeats = append(m.heartbeats, req)
	return &protocol.HeartbeatResponse{
		Acknowledged:      true,
		RotateCertificate: m.rotateOnHB,
		ServerTimeUnix:    time.Now().Unix(),
	}, nil
}

func (m *mockAgentServer) ReportMetrics(ctx context.Context, req *protocol.MetricsRequest) (*protocol.MetricsResponse, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.metrics = append(m.metrics, req)
	return &protocol.MetricsResponse{Recorded: true}, nil
}

func (m *mockAgentServer) ReportEvent(ctx context.Context, req *protocol.EventRequest) (*protocol.EventResponse, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, req)
	return &protocol.EventResponse{Recorded: true}, nil
}

func (m *mockAgentServer) ReportInventory(ctx context.Context, req *protocol.InventoryRequest) (*protocol.InventoryResponse, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.inventories = append(m.inventories, req)
	return &protocol.InventoryResponse{Acknowledged: true}, nil
}

func TestTelemetry_FullPipeline(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// 1. Setup in-memory gRPC server
	listener := bufconn.Listen(1024 * 1024)
	grpcServer := grpc.NewServer()
	mockServer := &mockAgentServer{}
	protocol.RegisterAgentServiceServer(grpcServer, mockServer)

	go func() {
		_ = grpcServer.Serve(listener)
	}()
	defer grpcServer.Stop()

	// 2. Connect client
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

	// 3. Test Collector & Metrics Reporting
	collector := telemetry.NewCollector(nil, nil)
	metrics, err := collector.CollectNodeMetrics(ctx)
	if err != nil {
		t.Fatalf("CollectNodeMetrics failed: %v", err)
	}
	if metrics.MemoryUsagePercent <= 0 {
		t.Error("Expected positive memory usage")
	}

	if err := telemetry.ReportMetrics(ctx, client, "agent-1", "node-1", metrics); err != nil {
		t.Fatalf("ReportMetrics failed: %v", err)
	}
	if len(mockServer.metrics) != 1 {
		t.Errorf("Expected 1 reported metric, got %d", len(mockServer.metrics))
	}

	// 4. Test Event Emission
	emitter := telemetry.NewEventEmitter(client, "agent-1", nil)
	err = emitter.Emit(ctx, "CONTAINER_STARTED", telemetry.SeverityInfo, "container started ok", map[string]interface{}{
		"cid": "test-c1",
	})
	if err != nil {
		t.Fatalf("Emit failed: %v", err)
	}
	if len(mockServer.events) != 1 {
		t.Errorf("Expected 1 reported event, got %d", len(mockServer.events))
	}

	// 5. Test Inventory Reporting
	inv, err := telemetry.CollectInventory(ctx, nil)
	if err != nil {
		t.Fatalf("CollectInventory failed: %v", err)
	}
	if err := telemetry.ReportInventory(ctx, client, "agent-1", "node-1", inv, nil); err != nil {
		t.Fatalf("ReportInventory failed: %v", err)
	}
	if len(mockServer.inventories) != 1 {
		t.Errorf("Expected 1 reported inventory, got %d", len(mockServer.inventories))
	}

	// 6. Test Heartbeat Sender & Directive Handling
	var directiveTriggered bool
	mockServer.rotateOnHB = true

	hbSender := telemetry.NewHeartbeatSender(client, "agent-1", "node-1", 100*time.Millisecond, collector, func(resp *protocol.HeartbeatResponse) error {
		if resp.RotateCertificate {
			directiveTriggered = true
		}
		return nil
	}, nil)

	resp, err := hbSender.SendOnce(ctx)
	if err != nil {
		t.Fatalf("SendOnce heartbeat failed: %v", err)
	}
	if !resp.Acknowledged {
		t.Error("Heartbeat not acknowledged")
	}
	if !directiveTriggered {
		t.Error("Heartbeat directive was not triggered")
	}
}
