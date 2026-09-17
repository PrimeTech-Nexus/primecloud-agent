// Package agent implements node failure detection, health assessment, and graceful degradation.
package agent

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	agentruntime "github.com/primecloud/primecloud-agent/internal/runtime"
	"github.com/primecloud/primecloud-agent/internal/vault"
)

// NodeHealthStatus represents the operational assessment of the node.
type NodeHealthStatus string

const (
	StatusHealthy   NodeHealthStatus = "HEALTHY"
	StatusDegraded  NodeHealthStatus = "DEGRADED"
	StatusUnhealthy NodeHealthStatus = "UNHEALTHY"
)

// HealthAssessment encapsulates current health checks and reasons.
type HealthAssessment struct {
	Status          NodeHealthStatus `json:"status"`
	DockerReachable bool             `json:"docker_reachable"`
	VaultReachable  bool             `json:"vault_reachable"`
	Draining        bool             `json:"draining"`
	FailureReasons  []string         `json:"failure_reasons"`
	LastAssessed    time.Time        `json:"last_assessed"`
}

// FailureHandler manages node failure detection, drain states, and admission control.
type FailureHandler struct {
	mu          sync.RWMutex
	rt          agentruntime.ContainerRuntime
	vaultClient *vault.Client
	status      NodeHealthStatus
	draining    bool
	reasons     []string
	logger      *slog.Logger
}

// NewFailureHandler constructs a FailureHandler.
func NewFailureHandler(rt agentruntime.ContainerRuntime, vaultClient *vault.Client, logger *slog.Logger) *FailureHandler {
	if logger == nil {
		logger = slog.Default()
	}
	return &FailureHandler{
		rt:          rt,
		vaultClient: vaultClient,
		status:      StatusHealthy,
		draining:    false,
		reasons:     make([]string, 0),
		logger:      logger.With("component", "node_failure_handler"),
	}
}

// AssessHealth runs diagnostics against local runtime, storage, and identity services.
func (f *FailureHandler) AssessHealth(ctx context.Context) *HealthAssessment {
	f.mu.Lock()
	defer f.mu.Unlock()

	reasons := make([]string, 0)
	dockerOk := true
	vaultOk := true

	// Check Container Runtime
	if f.rt != nil {
		pingCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		if err := f.rt.Ping(pingCtx); err != nil {
			dockerOk = false
			reasons = append(reasons, fmt.Sprintf("docker runtime unreachable: %v", err))
		}
		cancel()
	}

	// Check Vault Reachability
	if f.vaultClient != nil {
		vCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		if _, err := f.vaultClient.IsHealthy(vCtx); err != nil {
			vaultOk = false
			reasons = append(reasons, fmt.Sprintf("vault service unreachable: %v", err))
		}
		cancel()
	}

	var computedStatus NodeHealthStatus
	if !dockerOk {
		computedStatus = StatusUnhealthy
	} else if !vaultOk || f.draining {
		computedStatus = StatusDegraded
	} else {
		computedStatus = StatusHealthy
	}

	f.status = computedStatus
	f.reasons = reasons

	if computedStatus != StatusHealthy {
		f.logger.Warn("node_health_degraded", "status", string(computedStatus), "reasons", reasons)
	}

	return &HealthAssessment{
		Status:          computedStatus,
		DockerReachable: dockerOk,
		VaultReachable:  vaultOk,
		Draining:        f.draining,
		FailureReasons:  reasons,
		LastAssessed:    time.Now(),
	}
}

// SetDrain sets the draining flag on the compute node.
func (f *FailureHandler) SetDrain(draining bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.draining = draining
	if draining {
		f.logger.Warn("node_drain_mode_enabled")
	} else {
		f.logger.Info("node_drain_mode_disabled")
	}
}

// CanAcceptOperations validates whether new workload operations are permitted.
func (f *FailureHandler) CanAcceptOperations() (bool, string) {
	f.mu.RLock()
	defer f.mu.RUnlock()

	if f.draining {
		return false, "node is in drain mode"
	}
	if f.status == StatusUnhealthy {
		return false, fmt.Sprintf("node is unhealthy: %v", f.reasons)
	}

	return true, ""
}
