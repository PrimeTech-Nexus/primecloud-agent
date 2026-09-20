// Package agent provides core lifecycle, configuration, and orchestration for the PrimeCloud Agent daemon.
package agent

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/primecloud/primecloud-agent/internal/logs"
	"github.com/primecloud/primecloud-agent/internal/metrics"
)

// State represents the runtime state of the Agent daemon.
type State string

const (
	StateInitializing State = "INITIALIZING"
	StateRegistering  State = "REGISTERING"
	StateReady        State = "READY"
	StateDegraded     State = "DEGRADED"
	StateStopping     State = "STOPPING"
	StateStopped      State = "STOPPED"
)

// Agent represents the privileged PrimeCloud Agent daemon running on a compute node.
type Agent struct {
	cfg              *Config
	logger           *slog.Logger
	state            atomic.Value
	ctx              context.Context
	cancel           context.CancelFunc
	wg               sync.WaitGroup
	stopOnce         sync.Once
	startTime        time.Time
	metricsCollector *metrics.Collector
	logHarvester     *logs.Harvester
}

// NewAgent constructs a new Agent daemon instance.
func NewAgent(cfg *Config, logger *slog.Logger) (*Agent, error) {
	if cfg == nil {
		return nil, ErrInvalidConfig
	}
	if logger == nil {
		logger = slog.Default()
	}

	a := &Agent{
		cfg:       cfg,
		logger:    logger.With("component", "agent_daemon"),
		startTime: time.Now(),
	}
	a.state.Store(StateInitializing)

	// Initialize continuous telemetry routines
	a.metricsCollector = metrics.NewCollector(
		15*time.Second,
		cfg.NodeID,
		cfg.AgentID,
		nil, // container runtime initialized when active
		nil, // gRPC client bound upon Control Plane registration
		a.logger,
	)
	a.logHarvester = logs.NewHarvester(
		nil,
		cfg.ControlPlaneURL,
		100,
		5*time.Second,
		a.logger,
	)

	return a, nil
}

// Start boots the agent subsystems and runs the lifecycle loop.
func (a *Agent) Start(parentCtx context.Context) error {
	a.ctx, a.cancel = context.WithCancel(parentCtx)
	a.logger.Info("primecloud_agent_starting",
		"control_plane_url", a.cfg.ControlPlaneURL,
		"vault_addr", a.cfg.VaultAddr,
		"cert_dir", a.cfg.CertDir,
		"log_level", a.cfg.LogLevel.String(),
	)

	// Boot background telemetry collector routines
	if a.metricsCollector != nil {
		a.wg.Add(1)
		go func() {
			defer a.wg.Done()
			a.metricsCollector.Start(a.ctx)
		}()
	}
	if a.logHarvester != nil {
		a.wg.Add(1)
		go func() {
			defer a.wg.Done()
			a.logHarvester.Start(a.ctx)
		}()
	}

	a.state.Store(StateReady)
	a.logger.Info("primecloud_agent_ready", "state", string(StateReady))

	// Keep running until context cancellation
	<-a.ctx.Done()
	return a.Stop()
}

// Stop gracefully shuts down the agent daemon and waits for background routines.
func (a *Agent) Stop() error {
	var err error
	a.stopOnce.Do(func() {
		a.logger.Info("primecloud_agent_stopping")
		a.state.Store(StateStopping)

		if a.cancel != nil {
			a.cancel()
		}

		done := make(chan struct{})
		go func() {
			a.wg.Wait()
			close(done)
		}()

		select {
		case <-done:
			a.logger.Info("primecloud_agent_stopped_cleanly")
		case <-time.After(5 * time.Second):
			a.logger.Warn("primecloud_agent_stop_timeout_exceeded")
			err = fmt.Errorf("graceful shutdown timed out")
		}

		a.state.Store(StateStopped)
	})
	return err
}

// State returns the current lifecycle state of the agent.
func (a *Agent) State() State {
	if s, ok := a.state.Load().(State); ok {
		return s
	}
	return StateStopped
}

// Config returns the active agent configuration.
func (a *Agent) Config() *Config {
	return a.cfg
}

// Logger returns the configured logger.
func (a *Agent) Logger() *slog.Logger {
	return a.logger
}
