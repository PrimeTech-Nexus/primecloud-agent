// Package state defines the models and diff logic for desired and actual workload states.
package state

import (
	"fmt"
	"strings"
)

// DriftType identifies the category of drift between desired and actual state.
type DriftType string

const (
	DriftMissing       DriftType = "MISSING"
	DriftExtraneous    DriftType = "EXTRANEOUS"
	DriftStateMismatch DriftType = "STATE_MISMATCH"
	DriftImageMismatch DriftType = "IMAGE_MISMATCH"
)

// DriftItem details a discrepancy between desired and actual state.
type DriftItem struct {
	WorkloadID   string    `json:"workload_id"`
	Type         DriftType `json:"type"`
	DesiredState string    `json:"desired_state,omitempty"`
	ActualState  string    `json:"actual_state,omitempty"`
	DesiredImage string    `json:"desired_image,omitempty"`
	ActualImage  string    `json:"actual_image,omitempty"`
	Details      string    `json:"details"`
}

// Diff compares desired state against observed actual state and returns drift items.
func Diff(desired *DesiredState, actual *ActualState) []DriftItem {
	var drifts []DriftItem

	if desired == nil && actual == nil {
		return drifts
	}

	desiredMap := make(map[string]WorkloadSpec)
	if desired != nil && desired.Workloads != nil {
		desiredMap = desired.Workloads
	}

	actualMap := make(map[string]ActualWorkload)
	if actual != nil && actual.Workloads != nil {
		actualMap = actual.Workloads
	}

	// 1. Detect missing or mismatched workloads in actual
	for id, spec := range desiredMap {
		act, exists := actualMap[id]
		if !exists {
			if strings.ToUpper(spec.Status) == "RUNNING" {
				drifts = append(drifts, DriftItem{
					WorkloadID:   id,
					Type:         DriftMissing,
					DesiredState: spec.Status,
					DesiredImage: spec.Image,
					Details:      fmt.Sprintf("workload %s is missing from node", id),
				})
			}
			continue
		}

		// Check image mismatch
		if spec.Image != "" && act.Image != "" && !strings.Contains(act.Image, spec.Image) && !strings.Contains(spec.Image, act.Image) {
			drifts = append(drifts, DriftItem{
				WorkloadID:   id,
				Type:         DriftImageMismatch,
				DesiredImage: spec.Image,
				ActualImage:  act.Image,
				Details:      fmt.Sprintf("image mismatch: desired %s, running %s", spec.Image, act.Image),
			})
		}

		// Check run state mismatch
		desiredRunning := strings.ToUpper(spec.Status) == "RUNNING"
		actualRunning := strings.ToLower(act.State) == "running"

		if desiredRunning != actualRunning {
			drifts = append(drifts, DriftItem{
				WorkloadID:   id,
				Type:         DriftStateMismatch,
				DesiredState: spec.Status,
				ActualState:  act.State,
				Details:      fmt.Sprintf("state mismatch: desired %s, actual %s", spec.Status, act.State),
			})
		}
	}

	// 2. Detect extraneous unmanaged workloads
	for id, act := range actualMap {
		if _, exists := desiredMap[id]; !exists {
			drifts = append(drifts, DriftItem{
				WorkloadID:  id,
				Type:        DriftExtraneous,
				ActualState: act.State,
				ActualImage: act.Image,
				Details:     fmt.Sprintf("extraneous workload %s found on node", id),
			})
		}
	}

	return drifts
}
