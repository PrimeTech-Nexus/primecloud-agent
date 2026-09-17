// Package state defines the models and diff logic for desired and actual workload states.
package state

// WorkloadSpec specifies the intended properties and state of a workload.
type WorkloadSpec struct {
	ID      string            `json:"id"`
	Name    string            `json:"name"`
	Image   string            `json:"image"`
	Command []string          `json:"command,omitempty"`
	Env     map[string]string `json:"env,omitempty"`
	Ports   map[string]string `json:"ports,omitempty"`
	Status  string            `json:"status"` // RUNNING, STOPPED
	Labels  map[string]string `json:"labels,omitempty"`
}

// DesiredState represents the authoritative workload topology assigned to this node.
type DesiredState struct {
	Version   int64                   `json:"version"`
	NodeID    string                  `json:"node_id"`
	Workloads map[string]WorkloadSpec `json:"workloads"`
}

// NewDesiredState initializes a DesiredState object.
func NewDesiredState(nodeID string, version int64) *DesiredState {
	return &DesiredState{
		Version:   version,
		NodeID:    nodeID,
		Workloads: make(map[string]WorkloadSpec),
	}
}
