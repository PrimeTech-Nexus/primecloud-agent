// Package telemetry handles node metrics, logging, structured events, inventory, and heartbeats.
package telemetry

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/primecloud/primecloud-agent/internal/protocol"
	agentruntime "github.com/primecloud/primecloud-agent/internal/runtime"
)

// ContainerSummary holds snapshot information about a running workload.
type ContainerSummary struct {
	ID     string            `json:"id"`
	Names  []string          `json:"names"`
	Image  string            `json:"image"`
	State  string            `json:"state"`
	Status string            `json:"status"`
	Labels map[string]string `json:"labels"`
}

// NodeInventory summarizes workloads and resources active on the node.
type NodeInventory struct {
	Containers []ContainerSummary `json:"containers"`
	Timestamp  time.Time          `json:"timestamp"`
}

// CollectInventory lists all active workloads on the host container runtime.
func CollectInventory(ctx context.Context, rt agentruntime.ContainerRuntime) (*NodeInventory, error) {
	inv := &NodeInventory{
		Containers: make([]ContainerSummary, 0),
		Timestamp:  time.Now(),
	}

	if rt != nil {
		containers, err := rt.ListContainers(ctx, true)
		if err != nil {
			return nil, fmt.Errorf("failed to query containers for inventory: %w", err)
		}
		for _, c := range containers {
			inv.Containers = append(inv.Containers, ContainerSummary{
				ID:     c.ID,
				Names:  c.Names,
				Image:  c.Image,
				State:  c.State,
				Status: c.Status,
				Labels: c.Labels,
			})
		}
	}

	return inv, nil
}

// ReportInventory submits node inventory snapshot to the Control Plane.
func ReportInventory(ctx context.Context, client protocol.AgentServiceClient, agentID, nodeID string, inv *NodeInventory, logger *slog.Logger) error {
	if client == nil {
		return fmt.Errorf("agent service client cannot be nil")
	}
	if logger == nil {
		logger = slog.Default()
	}

	raw, err := json.Marshal(inv)
	if err != nil {
		return fmt.Errorf("failed to serialize node inventory: %w", err)
	}

	req := &protocol.InventoryRequest{
		AgentId:        agentID,
		NodeId:         nodeID,
		InventoryJson:  string(raw),
		ReportedAtUnix: inv.Timestamp.Unix(),
	}

	resp, err := client.ReportInventory(ctx, req)
	if err != nil {
		return fmt.Errorf("failed to transmit inventory: %w", err)
	}
	if !resp.Acknowledged {
		return fmt.Errorf("control plane did not acknowledge inventory")
	}

	logger.Info("inventory_reported_successfully", "containers", len(inv.Containers))
	return nil
}
