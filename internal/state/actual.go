// Package state defines the models and diff logic for desired and actual workload states.
package state

import (
	"context"
	"fmt"
	"strings"
	"time"

	agentruntime "github.com/primecloud/primecloud-agent/internal/runtime"
)

// ActualWorkload reflects the live condition of a container workload on the node.
type ActualWorkload struct {
	ID          string            `json:"id"`
	ContainerID string            `json:"container_id"`
	Name        string            `json:"name"`
	Image       string            `json:"image"`
	State       string            `json:"state"` // running, exited, paused, etc.
	Status      string            `json:"status"`
	Labels      map[string]string `json:"labels"`
}

// ActualState encapsulates the full set of workloads observed on the node.
type ActualState struct {
	NodeID    string                    `json:"node_id"`
	Workloads map[string]ActualWorkload `json:"workloads"`
	Timestamp time.Time                 `json:"timestamp"`
}

// CollectActualState inspects running containers on the host.
func CollectActualState(ctx context.Context, rt agentruntime.ContainerRuntime, nodeID string) (*ActualState, error) {
	actual := &ActualState{
		NodeID:    nodeID,
		Workloads: make(map[string]ActualWorkload),
		Timestamp: time.Now(),
	}

	if rt == nil {
		return actual, nil
	}

	containers, err := rt.ListContainers(ctx, true)
	if err != nil {
		return nil, fmt.Errorf("failed to list containers for actual state: %w", err)
	}

	for _, c := range containers {
		// Identify workload ID from labels or container name
		workloadID := c.Labels["primecloud.workload.id"]
		if workloadID == "" {
			for _, name := range c.Names {
				cleanName := strings.TrimPrefix(name, "/")
				if strings.HasPrefix(cleanName, "pc-app-") {
					workloadID = strings.TrimPrefix(cleanName, "pc-app-")
					break
				}
				if strings.HasPrefix(cleanName, "pc-pg-") {
					workloadID = strings.TrimPrefix(cleanName, "pc-pg-")
					break
				}
				if strings.HasPrefix(cleanName, "pc-vk-") {
					workloadID = strings.TrimPrefix(cleanName, "pc-vk-")
					break
				}
			}
		}

		if workloadID != "" {
			name := ""
			if len(c.Names) > 0 {
				name = strings.TrimPrefix(c.Names[0], "/")
			}
			actual.Workloads[workloadID] = ActualWorkload{
				ID:          workloadID,
				ContainerID: c.ID,
				Name:        name,
				Image:       c.Image,
				State:       strings.ToLower(c.State),
				Status:      c.Status,
				Labels:      c.Labels,
			}
		}
	}

	return actual, nil
}
