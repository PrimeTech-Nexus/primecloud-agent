// Package reconciliation coordinates desired state convergence, drift detection, and automated repair.
package reconciliation

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/primecloud/primecloud-agent/internal/protocol"
	agentruntime "github.com/primecloud/primecloud-agent/internal/runtime"
	"github.com/primecloud/primecloud-agent/internal/state"
)

// ReconcileSummary reports the outcome of a single reconciliation cycle.
type ReconcileSummary struct {
	DriftCount      int       `json:"drift_count"`
	RepairsExecuted int       `json:"repairs_executed"`
	Timestamp       time.Time `json:"timestamp"`
}

// Reconciler performs automated state convergence on the compute node.
type Reconciler struct {
	rt      agentruntime.ContainerRuntime
	client  protocol.AgentServiceClient
	agentID string
	nodeID  string
	logger  *slog.Logger
}

// NewReconciler constructs a Reconciler instance.
func NewReconciler(rt agentruntime.ContainerRuntime, client protocol.AgentServiceClient, agentID, nodeID string, logger *slog.Logger) *Reconciler {
	if logger == nil {
		logger = slog.Default()
	}
	return &Reconciler{
		rt:      rt,
		client:  client,
		agentID: agentID,
		nodeID:  nodeID,
		logger:  logger.With("component", "reconciler"),
	}
}

// ReconcileOnce queries the Control Plane for desired state, calculates drift, and repairs discrepancies.
func (r *Reconciler) ReconcileOnce(ctx context.Context) (*ReconcileSummary, error) {
	if r.client == nil {
		return nil, fmt.Errorf("agent service client cannot be nil")
	}

	// 1. Collect Actual State
	actual, err := state.CollectActualState(ctx, r.rt, r.nodeID)
	if err != nil {
		return nil, fmt.Errorf("failed to collect actual state: %w", err)
	}

	actualBytes, err := json.Marshal(actual)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize actual state: %w", err)
	}

	// 2. Exchange with Control Plane
	reconcileReq := &protocol.ReconcileRequest{
		AgentId:         r.agentID,
		NodeId:          r.nodeID,
		ActualStateJson: string(actualBytes),
		TimestampUnix:   time.Now().Unix(),
	}

	resp, err := r.client.Reconcile(ctx, reconcileReq)
	if err != nil {
		return nil, fmt.Errorf("reconciliation call failed: %w", err)
	}

	var desired state.DesiredState
	if resp.DesiredStateJson != "" {
		if err := json.Unmarshal([]byte(resp.DesiredStateJson), &desired); err != nil {
			return nil, fmt.Errorf("failed to parse desired state from control plane: %w", err)
		}
	}

	// 3. Diff States
	drifts := state.Diff(&desired, actual)
	repairs := PlanRepairs(drifts, &desired, actual)

	r.logger.Info("reconciliation_cycle_drift_evaluated", "drift_count", len(drifts), "repairs_planned", len(repairs))

	executedCount := 0

	// 4. Apply Remediation Actions
	for _, action := range repairs {
		if err := r.applyRepair(ctx, action); err != nil {
			r.logger.Error("reconciliation_repair_failed", "workload_id", action.WorkloadID, "action", string(action.Action), "error", err.Error())
		} else {
			executedCount++
			r.logger.Info("reconciliation_repair_applied", "workload_id", action.WorkloadID, "action", string(action.Action))
		}
	}

	// 5. Report State back to Control Plane
	reportReq := &protocol.StateRequest{
		AgentId:         r.agentID,
		NodeId:          r.nodeID,
		ActualStateJson: string(actualBytes),
		ReportedAtUnix:  time.Now().Unix(),
	}
	_, _ = r.client.ReportState(ctx, reportReq)

	return &ReconcileSummary{
		DriftCount:      len(drifts),
		RepairsExecuted: executedCount,
		Timestamp:       time.Now(),
	}, nil
}

func (r *Reconciler) applyRepair(ctx context.Context, action RepairAction) error {
	if r.rt == nil {
		return nil // No-op when runtime is nil (test mode)
	}

	switch action.Action {
	case ActionStart:
		if action.ContainerID != "" {
			return r.rt.StartContainer(ctx, action.ContainerID)
		}

	case ActionRemove:
		if action.ContainerID != "" {
			return r.rt.RemoveContainer(ctx, action.ContainerID, true)
		}

	case ActionDeploy:
		if action.Spec != nil {
			// If existing container exists, remove it first
			if action.ContainerID != "" {
				_ = r.rt.RemoveContainer(ctx, action.ContainerID, true)
			}
			cfg := &agentruntime.ContainerConfig{
				Name:    fmt.Sprintf("pc-app-%s", action.WorkloadID),
				Image:   action.Spec.Image,
				Command: action.Spec.Command,
				Ports:   action.Spec.Ports,
				Labels: map[string]string{
					"primecloud.workload.id": action.WorkloadID,
				},
			}
			limits := agentruntime.DefaultResourceLimits()
			profile := agentruntime.DefaultHardenedProfile()
			cid, err := r.rt.CreateContainer(ctx, cfg, limits, profile)
			if err != nil {
				return err
			}
			return r.rt.StartContainer(ctx, cid)
		}
	}

	return nil
}
