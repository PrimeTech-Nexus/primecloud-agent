// Package agent provides core lifecycle, configuration, and orchestration for the PrimeCloud Agent daemon.
package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/primecloud/primecloud-agent/internal/applications"
	"github.com/primecloud/primecloud-agent/internal/logs"
	"github.com/primecloud/primecloud-agent/internal/metrics"
	"github.com/primecloud/primecloud-agent/internal/operations"
	"github.com/primecloud/primecloud-agent/internal/postgres"
	pb "github.com/primecloud/primecloud-agent/internal/protocol"
	"github.com/primecloud/primecloud-agent/internal/runtime"
	"github.com/primecloud/primecloud-agent/internal/transport"
	"github.com/primecloud/primecloud-agent/internal/valkey"
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
			Address:  cfg.VaultAddr,
			Token:    cfg.BootstrapToken,
			RoleID:   cfg.VaultRoleID,
			SecretID: cfg.VaultSecretID,
		})
		if err != nil {
			a.logger.Warn("vault_client_init_warning", "error", err)
		} else {
			vaultClient = vClient
			authMode := "none"
			if cfg.VaultRoleID != "" && cfg.VaultSecretID != "" {
				authMode = "approle"
			} else if cfg.BootstrapToken != "" {
				authMode = "token"
			}
			a.logger.Info("vault_client_configured",
				"address", cfg.VaultAddr,
				"auth_mode", authMode,
			)
		}
	}

	// Build Operation Dispatcher with registered handlers
	deployer := applications.NewDeployer(rt, vaultClient, a.logger)
	registry := operations.NewRegistry()

	// 1. deploy_application
	registry.Register("deploy_application", func(ctx context.Context, op *pb.OperationEnvelope) (*pb.OperationResponse, error) {
		payload := parsePayloadMap(op.PayloadJson)

		// 1. Resolve resource_id: use payload.resource_id when present, otherwise fall back to payload.application_id
		resourceID := op.ResourceId
		if resourceID == "" {
			if rID, ok := payload["resource_id"].(string); ok && rID != "" {
				resourceID = rID
			}
		}
		if resourceID == "" {
			if aID, ok := payload["application_id"].(string); ok && aID != "" {
				resourceID = aID
			}
		}

		// 2. Resolve application_id: use payload.application_id; do NOT replace it with operation_id when application_id exists
		appID := ""
		if aID, ok := payload["application_id"].(string); ok && aID != "" {
			appID = aID
		} else if resourceID != "" {
			appID = resourceID
		} else {
			appID = op.OperationId
		}

		if resourceID == "" {
			resourceID = appID
		}

		// 3. Resolve project_id: use payload.project_id; if missing, inspect parameters for project_id;
		// if still missing, fail clearly before Vault secret resolution rather than silently constructing an invalid tenant path
		projectID := op.ProjectId
		if projectID == "" {
			if pID, ok := payload["project_id"].(string); ok && pID != "" {
				projectID = pID
			}
		}
		if projectID == "" {
			if params, ok := payload["parameters"].(map[string]interface{}); ok {
				if pID, ok := params["project_id"].(string); ok && pID != "" {
					projectID = pID
				}
			}
		}

		// Fail clearly if secrets exist but project_id is missing
		hasSecrets := false
		if sRefs, ok := payload["secret_refs"].(map[string]interface{}); ok && len(sRefs) > 0 {
			hasSecrets = true
		}
		if envMap, ok := payload["env"].(map[string]interface{}); ok {
			for _, v := range envMap {
				if strV, ok := v.(string); ok && strings.HasPrefix(strV, "vault:") {
					hasSecrets = true
					break
				}
			}
		}
		if envVarsMap, ok := payload["env_vars"].(map[string]interface{}); ok {
			for _, v := range envVarsMap {
				if strV, ok := v.(string); ok && strings.HasPrefix(strV, "vault:") {
					hasSecrets = true
					break
				}
			}
		}

		if strings.TrimSpace(projectID) == "" && hasSecrets {
			errMsg := "DEPLOYMENT_FAILED: project_id is required for secret resolution but was not provided in deployment operation payload"
			return &pb.OperationResponse{
				OperationId:     op.OperationId,
				Status:          "FAILED",
				ErrorCode:       "MISSING_PROJECT_ID",
				Message:         errMsg,
				CompletedAtUnix: time.Now().Unix(),
			}, fmt.Errorf("%s", errMsg)
		}

		instanceID := op.OperationId

		containerID, err := deployer.Deploy(ctx, projectID, op.EnvironmentId, appID, instanceID, op.PayloadJson)
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

	// Managed Services Drivers
	pgProv := postgres.NewProvisioner(rt, vaultClient, cfg.ResourceDir, a.logger)
	pgLC := postgres.NewLifecycleManager(rt)
	vkProv := valkey.NewProvisioner(rt, vaultClient, cfg.ResourceDir, a.logger)
	vkLC := valkey.NewLifecycleManager(rt)

	// 5. provision_postgres
	registry.Register("provision_postgres", func(ctx context.Context, op *pb.OperationEnvelope) (*pb.OperationResponse, error) {
		resID := extractResourceID(op, "postgres_id")
		payload := parsePayloadMap(op.PayloadJson)

		image := "postgres:16-alpine"
		if img, ok := payload["image"].(string); ok && img != "" {
			image = img
		} else if ver, ok := payload["version"].(string); ok && ver != "" {
			image = fmt.Sprintf("postgres:%s-alpine", ver)
		}

		hostPort := ""
		if hp, ok := payload["host_port"].(string); ok {
			hostPort = hp
		}

		projectID := op.ProjectId
		if projectID == "" {
			if pid, ok := payload["project_id"].(string); ok && pid != "" {
				projectID = pid
			}
		}
		if projectID == "" {
			projectID = "default"
		}

		provRes, err := pgProv.ProvisionWithProject(ctx, projectID, resID, image, hostPort)
		if err != nil {
			return &pb.OperationResponse{
				OperationId:     op.OperationId,
				Status:          "FAILED",
				ErrorCode:       "PROVISION_POSTGRES_FAILED",
				Message:         err.Error(),
				CompletedAtUnix: time.Now().Unix(),
			}, err
		}

		resData := map[string]interface{}{
			"resource_id":      provRes.ResourceID,
			"container_id":     provRes.ContainerID,
			"endpoint":         provRes.Endpoint,
			"vault_secret_ref": provRes.VaultSecretRef,
			"volume_path":      provRes.VolumePath,
			"status":           "AVAILABLE",
			"node_id":          cfg.NodeID,
		}
		resBytes, _ := json.Marshal(resData)

		return &pb.OperationResponse{
			OperationId:     op.OperationId,
			Status:          "SUCCEEDED",
			ResultJson:      string(resBytes),
			Message:         fmt.Sprintf("PostgreSQL container %s provisioned and available", provRes.ContainerID),
			CompletedAtUnix: time.Now().Unix(),
			ProgressPercent: 100,
		}, nil
	}, nil)

	// 6. start_postgres
	registry.Register("start_postgres", func(ctx context.Context, op *pb.OperationEnvelope) (*pb.OperationResponse, error) {
		resID := extractResourceID(op, "postgres_id")
		containerName := resID
		if !strings.HasPrefix(containerName, "pc-pg-") {
			containerName = fmt.Sprintf("pc-pg-%s", resID)
		}
		if err := pgLC.Start(ctx, containerName); err != nil {
			return &pb.OperationResponse{
				OperationId:     op.OperationId,
				Status:          "FAILED",
				ErrorCode:       "START_POSTGRES_FAILED",
				Message:         err.Error(),
				CompletedAtUnix: time.Now().Unix(),
			}, err
		}
		resJSON := fmt.Sprintf(`{"container_id":%q,"status":"AVAILABLE","node_id":%q}`, containerName, cfg.NodeID)
		return &pb.OperationResponse{
			OperationId:     op.OperationId,
			Status:          "SUCCEEDED",
			ResultJson:      resJSON,
			Message:         fmt.Sprintf("PostgreSQL container %s started successfully", containerName),
			CompletedAtUnix: time.Now().Unix(),
		}, nil
	}, nil)

	// 7. stop_postgres
	registry.Register("stop_postgres", func(ctx context.Context, op *pb.OperationEnvelope) (*pb.OperationResponse, error) {
		resID := extractResourceID(op, "postgres_id")
		containerName := resID
		if !strings.HasPrefix(containerName, "pc-pg-") {
			containerName = fmt.Sprintf("pc-pg-%s", resID)
		}
		if err := pgLC.Stop(ctx, containerName, 10); err != nil {
			return &pb.OperationResponse{
				OperationId:     op.OperationId,
				Status:          "FAILED",
				ErrorCode:       "STOP_POSTGRES_FAILED",
				Message:         err.Error(),
				CompletedAtUnix: time.Now().Unix(),
			}, err
		}
		resJSON := fmt.Sprintf(`{"container_id":%q,"status":"STOPPED","node_id":%q}`, containerName, cfg.NodeID)
		return &pb.OperationResponse{
			OperationId:     op.OperationId,
			Status:          "SUCCEEDED",
			ResultJson:      resJSON,
			Message:         fmt.Sprintf("PostgreSQL container %s stopped successfully", containerName),
			CompletedAtUnix: time.Now().Unix(),
		}, nil
	}, nil)

	// 8. restart_postgres
	registry.Register("restart_postgres", func(ctx context.Context, op *pb.OperationEnvelope) (*pb.OperationResponse, error) {
		resID := extractResourceID(op, "postgres_id")
		containerName := resID
		if !strings.HasPrefix(containerName, "pc-pg-") {
			containerName = fmt.Sprintf("pc-pg-%s", resID)
		}
		if err := pgLC.Restart(ctx, containerName, 10); err != nil {
			return &pb.OperationResponse{
				OperationId:     op.OperationId,
				Status:          "FAILED",
				ErrorCode:       "RESTART_POSTGRES_FAILED",
				Message:         err.Error(),
				CompletedAtUnix: time.Now().Unix(),
			}, err
		}
		resJSON := fmt.Sprintf(`{"container_id":%q,"status":"AVAILABLE","node_id":%q}`, containerName, cfg.NodeID)
		return &pb.OperationResponse{
			OperationId:     op.OperationId,
			Status:          "SUCCEEDED",
			ResultJson:      resJSON,
			Message:         fmt.Sprintf("PostgreSQL container %s restarted successfully", containerName),
			CompletedAtUnix: time.Now().Unix(),
		}, nil
	}, nil)

	// 9. deprovision_postgres
	registry.Register("deprovision_postgres", func(ctx context.Context, op *pb.OperationEnvelope) (*pb.OperationResponse, error) {
		resID := extractResourceID(op, "postgres_id")
		containerName := resID
		if !strings.HasPrefix(containerName, "pc-pg-") {
			containerName = fmt.Sprintf("pc-pg-%s", resID)
		}
		if err := pgLC.Remove(ctx, containerName); err != nil {
			return &pb.OperationResponse{
				OperationId:     op.OperationId,
				Status:          "FAILED",
				ErrorCode:       "DEPROVISION_POSTGRES_FAILED",
				Message:         err.Error(),
				CompletedAtUnix: time.Now().Unix(),
			}, err
		}
		volDir := filepath.Join(cfg.ResourceDir, "postgres", resID)
		_ = os.RemoveAll(volDir)

		resJSON := fmt.Sprintf(`{"container_id":%q,"status":"DELETED","node_id":%q}`, containerName, cfg.NodeID)
		return &pb.OperationResponse{
			OperationId:     op.OperationId,
			Status:          "SUCCEEDED",
			ResultJson:      resJSON,
			Message:         fmt.Sprintf("PostgreSQL container %s and resources deprovisioned successfully", containerName),
			CompletedAtUnix: time.Now().Unix(),
		}, nil
	}, nil)

	// 10. health_check_postgres
	registry.Register("health_check_postgres", func(ctx context.Context, op *pb.OperationEnvelope) (*pb.OperationResponse, error) {
		resID := extractResourceID(op, "postgres_id")
		containerName := resID
		if !strings.HasPrefix(containerName, "pc-pg-") {
			containerName = fmt.Sprintf("pc-pg-%s", resID)
		}
		if rt == nil {
			return &pb.OperationResponse{
				OperationId:     op.OperationId,
				Status:          "FAILED",
				ErrorCode:       "RUNTIME_UNAVAILABLE",
				Message:         "container runtime is not available",
				CompletedAtUnix: time.Now().Unix(),
			}, fmt.Errorf("runtime unavailable")
		}
		inspect, err := rt.InspectContainer(ctx, containerName)
		if err != nil {
			return &pb.OperationResponse{
				OperationId:     op.OperationId,
				Status:          "FAILED",
				ErrorCode:       "HEALTH_CHECK_FAILED",
				Message:         fmt.Sprintf("failed to inspect container: %v", err),
				CompletedAtUnix: time.Now().Unix(),
			}, err
		}
		if !inspect.Running {
			return &pb.OperationResponse{
				OperationId:     op.OperationId,
				Status:          "FAILED",
				ErrorCode:       "CONTAINER_NOT_RUNNING",
				Message:         fmt.Sprintf("container %s is not running (state=%s)", containerName, inspect.State),
				CompletedAtUnix: time.Now().Unix(),
			}, fmt.Errorf("container %s is not running", containerName)
		}
		if inspect.Health == "unhealthy" {
			return &pb.OperationResponse{
				OperationId:     op.OperationId,
				Status:          "FAILED",
				ErrorCode:       "CONTAINER_UNHEALTHY",
				Message:         fmt.Sprintf("container %s health status is unhealthy", containerName),
				CompletedAtUnix: time.Now().Unix(),
			}, fmt.Errorf("container %s is unhealthy", containerName)
		}
		return &pb.OperationResponse{
			OperationId:     op.OperationId,
			Status:          "SUCCEEDED",
			Message:         fmt.Sprintf("PostgreSQL container %s is healthy", containerName),
			CompletedAtUnix: time.Now().Unix(),
		}, nil
	}, nil)

	// 11. provision_keyvalue / provision_valkey
	valkeyProvisionHandler := func(ctx context.Context, op *pb.OperationEnvelope) (*pb.OperationResponse, error) {
		resID := extractResourceID(op, "keyvalue_id", "valkey_id")
		payload := parsePayloadMap(op.PayloadJson)

		image := "valkey/valkey:7.2-alpine"
		if img, ok := payload["image"].(string); ok && img != "" {
			image = img
		} else if ver, ok := payload["version"].(string); ok && ver != "" {
			image = fmt.Sprintf("valkey/valkey:%s-alpine", ver)
		}

		hostPort := ""
		if hp, ok := payload["host_port"].(string); ok {
			hostPort = hp
		}

		projectID := op.ProjectId
		if projectID == "" {
			if pid, ok := payload["project_id"].(string); ok && pid != "" {
				projectID = pid
			}
		}
		if projectID == "" {
			projectID = "default"
		}

		provRes, err := vkProv.ProvisionWithProject(ctx, projectID, resID, image, hostPort)
		if err != nil {
			return &pb.OperationResponse{
				OperationId:     op.OperationId,
				Status:          "FAILED",
				ErrorCode:       "PROVISION_VALKEY_FAILED",
				Message:         err.Error(),
				CompletedAtUnix: time.Now().Unix(),
			}, err
		}

		resData := map[string]interface{}{
			"resource_id":      provRes.ResourceID,
			"container_id":     provRes.ContainerID,
			"endpoint":         provRes.Endpoint,
			"vault_secret_ref": provRes.VaultSecretRef,
			"volume_path":      provRes.VolumePath,
			"status":           "AVAILABLE",
			"node_id":          cfg.NodeID,
		}
		resBytes, _ := json.Marshal(resData)

		return &pb.OperationResponse{
			OperationId:     op.OperationId,
			Status:          "SUCCEEDED",
			ResultJson:      string(resBytes),
			Message:         fmt.Sprintf("Valkey container %s provisioned and available", provRes.ContainerID),
			CompletedAtUnix: time.Now().Unix(),
			ProgressPercent: 100,
		}, nil
	}
	registry.Register("provision_keyvalue", valkeyProvisionHandler, nil)
	registry.Register("provision_valkey", valkeyProvisionHandler, nil)

	// 12. start_keyvalue / start_valkey
	valkeyStartHandler := func(ctx context.Context, op *pb.OperationEnvelope) (*pb.OperationResponse, error) {
		resID := extractResourceID(op, "keyvalue_id", "valkey_id")
		containerName := resID
		if !strings.HasPrefix(containerName, "pc-vk-") {
			containerName = fmt.Sprintf("pc-vk-%s", resID)
		}
		if err := vkLC.Start(ctx, containerName); err != nil {
			return &pb.OperationResponse{
				OperationId:     op.OperationId,
				Status:          "FAILED",
				ErrorCode:       "START_VALKEY_FAILED",
				Message:         err.Error(),
				CompletedAtUnix: time.Now().Unix(),
			}, err
		}
		resJSON := fmt.Sprintf(`{"container_id":%q,"status":"AVAILABLE","node_id":%q}`, containerName, cfg.NodeID)
		return &pb.OperationResponse{
			OperationId:     op.OperationId,
			Status:          "SUCCEEDED",
			ResultJson:      resJSON,
			Message:         fmt.Sprintf("Valkey container %s started successfully", containerName),
			CompletedAtUnix: time.Now().Unix(),
		}, nil
	}
	registry.Register("start_keyvalue", valkeyStartHandler, nil)
	registry.Register("start_valkey", valkeyStartHandler, nil)

	// 13. stop_keyvalue / stop_valkey
	valkeyStopHandler := func(ctx context.Context, op *pb.OperationEnvelope) (*pb.OperationResponse, error) {
		resID := extractResourceID(op, "keyvalue_id", "valkey_id")
		containerName := resID
		if !strings.HasPrefix(containerName, "pc-vk-") {
			containerName = fmt.Sprintf("pc-vk-%s", resID)
		}
		if err := vkLC.Stop(ctx, containerName, 10); err != nil {
			return &pb.OperationResponse{
				OperationId:     op.OperationId,
				Status:          "FAILED",
				ErrorCode:       "STOP_VALKEY_FAILED",
				Message:         err.Error(),
				CompletedAtUnix: time.Now().Unix(),
			}, err
		}
		resJSON := fmt.Sprintf(`{"container_id":%q,"status":"STOPPED","node_id":%q}`, containerName, cfg.NodeID)
		return &pb.OperationResponse{
			OperationId:     op.OperationId,
			Status:          "SUCCEEDED",
			ResultJson:      resJSON,
			Message:         fmt.Sprintf("Valkey container %s stopped successfully", containerName),
			CompletedAtUnix: time.Now().Unix(),
		}, nil
	}
	registry.Register("stop_keyvalue", valkeyStopHandler, nil)
	registry.Register("stop_valkey", valkeyStopHandler, nil)

	// 14. restart_keyvalue / restart_valkey
	valkeyRestartHandler := func(ctx context.Context, op *pb.OperationEnvelope) (*pb.OperationResponse, error) {
		resID := extractResourceID(op, "keyvalue_id", "valkey_id")
		containerName := resID
		if !strings.HasPrefix(containerName, "pc-vk-") {
			containerName = fmt.Sprintf("pc-vk-%s", resID)
		}
		if err := vkLC.Restart(ctx, containerName, 10); err != nil {
			return &pb.OperationResponse{
				OperationId:     op.OperationId,
				Status:          "FAILED",
				ErrorCode:       "RESTART_VALKEY_FAILED",
				Message:         err.Error(),
				CompletedAtUnix: time.Now().Unix(),
			}, err
		}
		resJSON := fmt.Sprintf(`{"container_id":%q,"status":"AVAILABLE","node_id":%q}`, containerName, cfg.NodeID)
		return &pb.OperationResponse{
			OperationId:     op.OperationId,
			Status:          "SUCCEEDED",
			ResultJson:      resJSON,
			Message:         fmt.Sprintf("Valkey container %s restarted successfully", containerName),
			CompletedAtUnix: time.Now().Unix(),
		}, nil
	}
	registry.Register("restart_keyvalue", valkeyRestartHandler, nil)
	registry.Register("restart_valkey", valkeyRestartHandler, nil)

	// 15. deprovision_keyvalue / deprovision_valkey
	valkeyDeprovisionHandler := func(ctx context.Context, op *pb.OperationEnvelope) (*pb.OperationResponse, error) {
		resID := extractResourceID(op, "keyvalue_id", "valkey_id")
		containerName := resID
		if !strings.HasPrefix(containerName, "pc-vk-") {
			containerName = fmt.Sprintf("pc-vk-%s", resID)
		}
		if err := vkLC.Remove(ctx, containerName); err != nil {
			return &pb.OperationResponse{
				OperationId:     op.OperationId,
				Status:          "FAILED",
				ErrorCode:       "DEPROVISION_VALKEY_FAILED",
				Message:         err.Error(),
				CompletedAtUnix: time.Now().Unix(),
			}, err
		}
		volDir := filepath.Join(cfg.ResourceDir, "valkey", resID)
		_ = os.RemoveAll(volDir)

		resJSON := fmt.Sprintf(`{"container_id":%q,"status":"DELETED","node_id":%q}`, containerName, cfg.NodeID)
		return &pb.OperationResponse{
			OperationId:     op.OperationId,
			Status:          "SUCCEEDED",
			ResultJson:      resJSON,
			Message:         fmt.Sprintf("Valkey container %s and resources deprovisioned successfully", containerName),
			CompletedAtUnix: time.Now().Unix(),
		}, nil
	}
	registry.Register("deprovision_keyvalue", valkeyDeprovisionHandler, nil)
	registry.Register("deprovision_valkey", valkeyDeprovisionHandler, nil)

	// 16. health_check_keyvalue / health_check_valkey
	valkeyHealthCheckHandler := func(ctx context.Context, op *pb.OperationEnvelope) (*pb.OperationResponse, error) {
		resID := extractResourceID(op, "keyvalue_id", "valkey_id")
		containerName := resID
		if !strings.HasPrefix(containerName, "pc-vk-") {
			containerName = fmt.Sprintf("pc-vk-%s", resID)
		}
		if rt == nil {
			return &pb.OperationResponse{
				OperationId:     op.OperationId,
				Status:          "FAILED",
				ErrorCode:       "RUNTIME_UNAVAILABLE",
				Message:         "container runtime is not available",
				CompletedAtUnix: time.Now().Unix(),
			}, fmt.Errorf("runtime unavailable")
		}
		inspect, err := rt.InspectContainer(ctx, containerName)
		if err != nil {
			return &pb.OperationResponse{
				OperationId:     op.OperationId,
				Status:          "FAILED",
				ErrorCode:       "HEALTH_CHECK_FAILED",
				Message:         fmt.Sprintf("failed to inspect container: %v", err),
				CompletedAtUnix: time.Now().Unix(),
			}, err
		}
		if !inspect.Running {
			return &pb.OperationResponse{
				OperationId:     op.OperationId,
				Status:          "FAILED",
				ErrorCode:       "CONTAINER_NOT_RUNNING",
				Message:         fmt.Sprintf("container %s is not running (state=%s)", containerName, inspect.State),
				CompletedAtUnix: time.Now().Unix(),
			}, fmt.Errorf("container %s is not running", containerName)
		}
		if inspect.Health == "unhealthy" {
			return &pb.OperationResponse{
				OperationId:     op.OperationId,
				Status:          "FAILED",
				ErrorCode:       "CONTAINER_UNHEALTHY",
				Message:         fmt.Sprintf("container %s health status is unhealthy", containerName),
				CompletedAtUnix: time.Now().Unix(),
			}, fmt.Errorf("container %s is unhealthy", containerName)
		}
		return &pb.OperationResponse{
			OperationId:     op.OperationId,
			Status:          "SUCCEEDED",
			Message:         fmt.Sprintf("Valkey container %s is healthy", containerName),
			CompletedAtUnix: time.Now().Unix(),
		}, nil
	}
	registry.Register("health_check_keyvalue", valkeyHealthCheckHandler, nil)
	registry.Register("health_check_valkey", valkeyHealthCheckHandler, nil)

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

// Dispatcher returns the configured operation dispatcher.
func (a *Agent) Dispatcher() *operations.Dispatcher {
	return a.dispatcher
}

func extractResourceID(op *pb.OperationEnvelope, fallbackKeys ...string) string {
	if op.ResourceId != "" {
		return op.ResourceId
	}
	if op.PayloadJson != "" {
		var m map[string]interface{}
		if err := json.Unmarshal([]byte(op.PayloadJson), &m); err == nil {
			for _, k := range fallbackKeys {
				if v, ok := m[k].(string); ok && v != "" {
					return v
				}
			}
			if v, ok := m["resource_id"].(string); ok && v != "" {
				return v
			}
		}
	}
	return op.OperationId
}

func parsePayloadMap(payloadJSON string) map[string]interface{} {
	m := make(map[string]interface{})
	if payloadJSON != "" {
		_ = json.Unmarshal([]byte(payloadJSON), &m)
	}
	return m
}

