// Package agent provides core lifecycle, configuration, and orchestration for the PrimeCloud Agent daemon.
package agent

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/primecloud/primecloud-agent/internal/applications"
	"github.com/primecloud/primecloud-agent/internal/logs"
	"github.com/primecloud/primecloud-agent/internal/metrics"
	"github.com/primecloud/primecloud-agent/internal/operations"
	pb "github.com/primecloud/primecloud-agent/internal/protocol"
	"github.com/primecloud/primecloud-agent/internal/runtime"
	"github.com/primecloud/primecloud-agent/internal/transport"
	"github.com/primecloud/primecloud-agent/internal/vault"
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
	dispatcher       *operations.Dispatcher
	valkeyConsumer   *transport.ValkeyConsumer
	runtime          runtime.ContainerRuntime
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

	// Initialize Container Runtime
	rt, err := runtime.NewDockerRuntime()
	if err != nil {
		a.logger.Warn("docker_runtime_init_warning", "error", err)
	}
	a.runtime = rt

	// Initialize Vault client if specified
	var vaultClient *vault.Client
	if cfg.VaultAddr != "" {
		vClient, err := vault.NewClient(vault.Config{
			Address: cfg.VaultAddr,
			Token:   cfg.BootstrapToken,
		})
		if err != nil {
			a.logger.Warn("vault_client_init_warning", "error", err)
		} else {
			vaultClient = vClient
		}
	}

	// Build Operation Dispatcher with registered handlers
	deployer := applications.NewDeployer(rt, vaultClient, a.logger)
	registry := operations.NewRegistry()

	// 1. deploy_application
	registry.Register("deploy_application", func(ctx context.Context, op *pb.OperationEnvelope) (*pb.OperationResponse, error) {
		appID := op.ResourceId
		if appID == "" {
			appID = op.OperationId
		}
		instanceID := op.OperationId

		containerID, err := deployer.Deploy(ctx, op.ProjectId, op.EnvironmentId, appID, instanceID, op.PayloadJson)
		if err != nil {
			return &pb.OperationResponse{
				OperationId:     op.OperationId,
				Status:          "FAILED",
				ErrorCode:       "DEPLOYMENT_FAILED",
				Message:         err.Error(),
				CompletedAtUnix: time.Now().Unix(),
			}, err
		}

		resJSON := fmt.Sprintf(`{"container_id":%q,"status":"RUNNING","node_id":%q}`, containerID, cfg.NodeID)
		return &pb.OperationResponse{
			OperationId:     op.OperationId,
			Status:          "SUCCEEDED",
			ResultJson:      resJSON,
			Message:         fmt.Sprintf("Application container %s started successfully", containerID),
			CompletedAtUnix: time.Now().Unix(),
			ProgressPercent: 100,
		}, nil
	}, nil)

	// 2. restart_application
	registry.Register("restart_application", func(ctx context.Context, op *pb.OperationEnvelope) (*pb.OperationResponse, error) {
		containerID := op.ResourceId
		if err := applications.RestartApplication(ctx, rt, containerID, 10); err != nil {
			return &pb.OperationResponse{
				OperationId:     op.OperationId,
				Status:          "FAILED",
				ErrorCode:       "RESTART_FAILED",
				Message:         err.Error(),
				CompletedAtUnix: time.Now().Unix(),
			}, err
		}
		return &pb.OperationResponse{
			OperationId:     op.OperationId,
			Status:          "SUCCEEDED",
			Message:         fmt.Sprintf("Application container %s restarted successfully", containerID),
			CompletedAtUnix: time.Now().Unix(),
		}, nil
	}, nil)

	// 3. remove_application
	registry.Register("remove_application", func(ctx context.Context, op *pb.OperationEnvelope) (*pb.OperationResponse, error) {
		containerID := op.ResourceId
		if err := applications.RemoveApplication(ctx, rt, containerID, true); err != nil {
			return &pb.OperationResponse{
				OperationId:     op.OperationId,
				Status:          "FAILED",
				ErrorCode:       "REMOVE_FAILED",
				Message:         err.Error(),
				CompletedAtUnix: time.Now().Unix(),
			}, err
		}
		return &pb.OperationResponse{
			OperationId:     op.OperationId,
			Status:          "SUCCEEDED",
			Message:         fmt.Sprintf("Application container %s removed successfully", containerID),
			CompletedAtUnix: time.Now().Unix(),
		}, nil
	}, nil)

	// 4. health_check_application
	registry.Register("health_check_application", func(ctx context.Context, op *pb.OperationEnvelope) (*pb.OperationResponse, error) {
		containerID := op.ResourceId
		if err := applications.WaitForContainerReady(ctx, rt, containerID, 10*time.Second); err != nil {
			return &pb.OperationResponse{
				OperationId:     op.OperationId,
				Status:          "FAILED",
				ErrorCode:       "HEALTH_CHECK_FAILED",
				Message:         err.Error(),
				CompletedAtUnix: time.Now().Unix(),
			}, err
		}
		return &pb.OperationResponse{
			OperationId:     op.OperationId,
			Status:          "SUCCEEDED",
			Message:         fmt.Sprintf("Application container %s is healthy", containerID),
			CompletedAtUnix: time.Now().Unix(),
		}, nil
	}, nil)

	locks := operations.NewLockManager()
	idempotency := operations.NewIdempotencyTracker(24 * time.Hour)
	a.dispatcher = operations.NewDispatcher(registry, locks, idempotency, a.logger)

	// Initialize Valkey Queue Consumer
	a.valkeyConsumer = transport.NewValkeyConsumer(cfg.QueueURL, cfg.NodeID, a.dispatcher, a.logger)

	// Initialize continuous telemetry routines
	a.metricsCollector = metrics.NewCollector(
		15*time.Second,
		cfg.NodeID,
		cfg.AgentID,
		rt,
		nil,
		a.logger,
	)
	a.logHarvester = logs.NewHarvester(
		rt,
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
		"node_id", a.cfg.NodeID,
		"queue_url", a.cfg.QueueURL,
		"control_plane_url", a.cfg.ControlPlaneURL,
		"vault_addr", a.cfg.VaultAddr,
		"cert_dir", a.cfg.CertDir,
		"log_level", a.cfg.LogLevel.String(),
	)

	// Boot background Valkey Queue Consumer routine
	if a.valkeyConsumer != nil {
		a.wg.Add(1)
		go func() {
			defer a.wg.Done()
			_ = a.valkeyConsumer.Start(a.ctx)
		}()
	}

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
