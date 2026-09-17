// Package reconciliation coordinates desired state convergence, drift detection, and automated repair.
package reconciliation

import (
	"fmt"

	"github.com/primecloud/primecloud-agent/internal/state"
)

// ActionType defines the remediation step required to fix drift.
type ActionType string

const (
	ActionStart   ActionType = "START"
	ActionRestart ActionType = "RESTART"
	ActionDeploy  ActionType = "DEPLOY"
	ActionRemove  ActionType = "REMOVE"
	ActionNoop    ActionType = "NOOP"
)

// RepairAction prescribes an atomic correction for a single workload.
type RepairAction struct {
	WorkloadID  string              `json:"workload_id"`
	Action      ActionType          `json:"action"`
	Spec        *state.WorkloadSpec `json:"spec,omitempty"`
	ContainerID string              `json:"container_id,omitempty"`
	Reason      string              `json:"reason"`
}

// PlanRepairs evaluates drift items and maps them into ordered repair actions.
func PlanRepairs(drifts []state.DriftItem, desired *state.DesiredState, actual *state.ActualState) []RepairAction {
	var actions []RepairAction

	desiredMap := make(map[string]state.WorkloadSpec)
	if desired != nil && desired.Workloads != nil {
		desiredMap = desired.Workloads
	}

	actualMap := make(map[string]state.ActualWorkload)
	if actual != nil && actual.Workloads != nil {
		actualMap = actual.Workloads
	}

	for _, drift := range drifts {
		spec, hasSpec := desiredMap[drift.WorkloadID]
		act, hasAct := actualMap[drift.WorkloadID]

		switch drift.Type {
		case state.DriftMissing:
			if hasSpec {
				specCopy := spec
				actions = append(actions, RepairAction{
					WorkloadID: drift.WorkloadID,
					Action:     ActionDeploy,
					Spec:       &specCopy,
					Reason:     fmt.Sprintf("workload %s is missing", drift.WorkloadID),
				})
			}

		case state.DriftStateMismatch:
			if hasAct && hasSpec {
				specCopy := spec
				if spec.Status == "RUNNING" && act.State != "running" {
					actions = append(actions, RepairAction{
						WorkloadID:  drift.WorkloadID,
						Action:      ActionStart,
						Spec:        &specCopy,
						ContainerID: act.ContainerID,
						Reason:      fmt.Sprintf("container %s is stopped but desired is running", act.ContainerID),
					})
				}
			}

		case state.DriftImageMismatch:
			if hasSpec && hasAct {
				specCopy := spec
				actions = append(actions, RepairAction{
					WorkloadID:  drift.WorkloadID,
					Action:      ActionDeploy,
					Spec:        &specCopy,
					ContainerID: act.ContainerID,
					Reason:      fmt.Sprintf("updating image to %s", spec.Image),
				})
			}

		case state.DriftExtraneous:
			if hasAct {
				actions = append(actions, RepairAction{
					WorkloadID:  drift.WorkloadID,
					Action:      ActionRemove,
					ContainerID: act.ContainerID,
					Reason:      fmt.Sprintf("removing unmanaged container %s", act.ContainerID),
				})
			}
		}
	}

	return actions
}
