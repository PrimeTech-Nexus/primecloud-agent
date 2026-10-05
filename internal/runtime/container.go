// Package runtime provides the ContainerRuntime interface and Docker engine abstraction with hardened isolation profiles.
package runtime

import (
	"time"
)

// WorkloadType defines the classification of a container workload for runtime policies.
type WorkloadType string

const (
	// WorkloadTypeApplication is a generic user/customer application workload.
	WorkloadTypeApplication WorkloadType = "APPLICATION"
	// WorkloadTypeManagedPostgres is a managed PostgreSQL database container.
	WorkloadTypeManagedPostgres WorkloadType = "MANAGED_POSTGRES"
	// WorkloadTypeManagedValkey is a managed Valkey key-value cache/store container.
	WorkloadTypeManagedValkey WorkloadType = "MANAGED_VALKEY"
)

// ContainerConfig defines specifications for creating and running a workload container.
type ContainerConfig struct {
	Name           string            `json:"name"`
	Image          string            `json:"image"`
	ImageDigest    string            `json:"image_digest"`
	Command        []string          `json:"command,omitempty"`
	Env            map[string]string `json:"env,omitempty"`
	Labels         map[string]string `json:"labels,omitempty"`
	Ports          map[string]string `json:"ports,omitempty"` // containerPort -> hostPort
	Binds          []string          `json:"binds,omitempty"` // hostPath:containerPath:ro/rw
	HealthCheckCmd []string          `json:"health_check_cmd,omitempty"`
	HealthInterval time.Duration     `json:"health_interval,omitempty"`
	HealthTimeout  time.Duration     `json:"health_timeout,omitempty"`
	HealthRetries  int               `json:"health_retries,omitempty"`
	ProjectID      string            `json:"project_id"`
	EnvironmentID  string            `json:"environment_id"`
	ApplicationID  string            `json:"application_id"`
	InstanceID     string            `json:"instance_id"`
	User           string            `json:"user,omitempty"`
	NetworkMode    string            `json:"network_mode,omitempty"`
	WorkloadType   WorkloadType      `json:"workload_type,omitempty"`
}

// EnsureMandatoryLabels sets standard PrimeCloud system labels.
func (c *ContainerConfig) EnsureMandatoryLabels() {
	if c.Labels == nil {
		c.Labels = make(map[string]string)
	}
	c.Labels["primecloud.managed"] = "true"
	if c.ProjectID != "" {
		c.Labels["primecloud.project_id"] = c.ProjectID
	}
	if c.EnvironmentID != "" {
		c.Labels["primecloud.environment_id"] = c.EnvironmentID
	}
	if c.ApplicationID != "" {
		c.Labels["primecloud.application_id"] = c.ApplicationID
	}
	if c.InstanceID != "" {
		c.Labels["primecloud.instance_id"] = c.InstanceID
	}
}

// ContainerSummary provides lightweight container information.
type ContainerSummary struct {
	ID      string            `json:"id"`
	Names   []string          `json:"names"`
	Image   string            `json:"image"`
	State   string            `json:"state"`
	Status  string            `json:"status"`
	Labels  map[string]string `json:"labels"`
	Created int64             `json:"created"`
}

// ContainerInspect contains detailed container status and configuration.
type ContainerInspect struct {
	ID           string            `json:"id"`
	Name         string            `json:"name"`
	Image        string            `json:"image"`
	State        string            `json:"state"`
	Running      bool              `json:"running"`
	ExitCode     int               `json:"exit_code"`
	Health       string            `json:"health,omitempty"`
	RestartCount int               `json:"restart_count,omitempty"`
	Labels       map[string]string `json:"labels"`
	IPAddress    string            `json:"ip_address"`
	Ports        map[string]string `json:"ports,omitempty"` // containerPort -> hostPort
	StartedAt    time.Time         `json:"started_at"`
	FinishedAt   time.Time         `json:"finished_at"`
}
