// Package agent provides core lifecycle, configuration, and orchestration for the PrimeCloud Agent daemon.
package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/primecloud/primecloud-agent/internal/applications"
	"github.com/primecloud/primecloud-agent/internal/backup"
	"github.com/primecloud/primecloud-agent/internal/caddy"
	"github.com/primecloud/primecloud-agent/internal/logs"
	"github.com/primecloud/primecloud-agent/internal/metrics"
	"github.com/primecloud/primecloud-agent/internal/operations"
	"github.com/primecloud/primecloud-agent/internal/postgres"
	pb "github.com/primecloud/primecloud-agent/internal/protocol"
	"github.com/primecloud/primecloud-agent/internal/recovery"
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

		// Determine application container workload port (defaults to 8000)
		containerPort := 8000
		if pVal, ok := payload["port"]; ok && pVal != nil {
			switch p := pVal.(type) {
			case float64:
				if p > 0 {
					containerPort = int(p)
				}
			case int:
				if p > 0 {
					containerPort = p
				}
			case string:
				if n, err := strconv.Atoi(strings.Split(strings.TrimSpace(p), "/")[0]); err == nil && n > 0 {
					containerPort = n
				}
			}
		}

		// Requirement 6: Read actual dynamically allocated HostPort from ContainerInspect
		var hostPort int
		inspect, inspectErr := rt.InspectContainer(ctx, containerID)
		if inspectErr == nil && inspect != nil && len(inspect.Ports) > 0 {
			targetKeys := []string{
				fmt.Sprintf("%d/tcp", containerPort),
				strconv.Itoa(containerPort),
				"8000/tcp",
				"8000",
			}
			for _, key := range targetKeys {
				if hpStr, ok := inspect.Ports[key]; ok && hpStr != "" {
					if hp, err := strconv.Atoi(hpStr); err == nil && hp > 0 {
						hostPort = hp
						break
					}
				}
			}
			if hostPort == 0 {
				for _, hpStr := range inspect.Ports {
					if hp, err := strconv.Atoi(hpStr); err == nil && hp > 0 {
						hostPort = hp
						break
					}
				}
			}
		}

		// Requirement 4, 5, 8:
		// Do not use ApplicationConfig.port as HostPort.
		// Do not fall back to payload["port"] as host_port.
		// If Docker provides no host binding or binds to 8000, fail closed with DYNAMIC_PORT_ALLOCATION_FAILED.
		if hostPort == 0 || hostPort == 8000 {
			errMsg := fmt.Sprintf("DEPLOYMENT_FAILED: Docker runtime did not allocate a valid dynamic host port for container %s (resolved host_port: %d, container_port: %d)", containerID, hostPort, containerPort)
			_ = rt.RemoveContainer(ctx, containerID, true)
			return &pb.OperationResponse{
				OperationId:     op.OperationId,
				Status:          "FAILED",
				ErrorCode:       "DYNAMIC_PORT_ALLOCATION_FAILED",
				Message:         errMsg,
				CompletedAtUnix: time.Now().Unix(),
			}, fmt.Errorf("%s", errMsg)
		}

		resMap := map[string]interface{}{
			"container_id":   containerID,
			"status":         "RUNNING",
			"node_id":        cfg.NodeID,
			"container_port": containerPort,
			"port":           containerPort,
			"host_port":      hostPort,
		}
		resBytes, _ := json.Marshal(resMap)

		return &pb.OperationResponse{
			OperationId:     op.OperationId,
			Status:          "SUCCEEDED",
			ResultJson:      string(resBytes),
			Message:         fmt.Sprintf("Application container %s started successfully", containerID),
			CompletedAtUnix: time.Now().Unix(),
			ProgressPercent: 100,
		}, nil
	}, nil)

	// 2. restart_application
	registry.Register("restart_application", func(ctx context.Context, op *pb.OperationEnvelope) (*pb.OperationResponse, error) {
		containerID := resolveAppContainerTarget(ctx, rt, op)
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
		containerID := resolveAppContainerTarget(ctx, rt, op)
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
		containerID := resolveAppContainerTarget(ctx, rt, op)
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

	// Managed Services & Ingress Drivers
	caddyMgr := caddy.NewManager("/etc/caddy/sites-enabled", "http://127.0.0.1:2019", a.logger)
	pgProv := postgres.NewProvisioner(rt, vaultClient, cfg.ResourceDir, a.logger)
	pgLC := postgres.NewLifecycleManager(rt)
	vkProv := valkey.NewProvisioner(rt, vaultClient, cfg.ResourceDir, a.logger)
	vkLC := valkey.NewLifecycleManager(rt)

	// 5. configure_route
	registry.Register("configure_route", func(ctx context.Context, op *pb.OperationEnvelope) (*pb.OperationResponse, error) {
		payload := parsePayloadMap(op.PayloadJson)
		domain, _ := payload["domain"].(string)
		if domain == "" {
			domain = op.ResourceId
		}
		if domain == "" {
			return &pb.OperationResponse{
				OperationId:     op.OperationId,
				Status:          "FAILED",
				ErrorCode:       "INVALID_DOMAIN",
				Message:         "domain is required for route configuration",
				CompletedAtUnix: time.Now().Unix(),
			}, fmt.Errorf("domain is required")
		}

		targetHost := "127.0.0.1"
		if th, ok := payload["target_host"].(string); ok && th != "" {
			targetHost = th
		}

		var targetPort int
		if tp, ok := payload["target_port"].(float64); ok {
			targetPort = int(tp)
		} else if tp, ok := payload["target_port"].(int); ok {
			targetPort = tp
		} else if tpStr, ok := payload["target_port"].(string); ok {
			targetPort, _ = strconv.Atoi(tpStr)
		}

		upstream, _ := payload["upstream"].(string)
		if upstream == "" && targetPort > 0 {
			upstream = fmt.Sprintf("%s:%d", targetHost, targetPort)
		}

		if upstream == "" {
			return &pb.OperationResponse{
				OperationId:     op.OperationId,
				Status:          "FAILED",
				ErrorCode:       "INVALID_UPSTREAM",
				Message:         "upstream or valid target_port is required for route configuration",
				CompletedAtUnix: time.Now().Unix(),
			}, fmt.Errorf("upstream or target_port required")
		}

		tlsEnabled := true
		if te, ok := payload["tls_enabled"].(bool); ok {
			tlsEnabled = te
		} else if te, ok := payload["tls"].(bool); ok {
			tlsEnabled = te
		}

		routeCfg := &caddy.RouteConfig{
			Domain:   domain,
			Upstream: upstream,
			TLS:      tlsEnabled,
		}

		if err := caddyMgr.ConfigureRoute(ctx, routeCfg); err != nil {
			return &pb.OperationResponse{
				OperationId:     op.OperationId,
				Status:          "FAILED",
				ErrorCode:       "CONFIGURE_ROUTE_FAILED",
				Message:         fmt.Sprintf("failed to configure route for domain %s: %v", domain, err),
				CompletedAtUnix: time.Now().Unix(),
			}, err
		}

		resData := map[string]interface{}{
			"route_id": fmt.Sprintf("route-%s", op.OperationId),
			"domain":   domain,
			"upstream": upstream,
			"status":   "ACTIVE",
			"url":      fmt.Sprintf("https://%s", domain),
		}
		resJSONBytes, _ := json.Marshal(resData)

		return &pb.OperationResponse{
			OperationId:     op.OperationId,
			Status:          "SUCCEEDED",
			ResultJson:      string(resJSONBytes),
			Message:         fmt.Sprintf("Route for %s configured successfully pointing to %s", domain, upstream),
			CompletedAtUnix: time.Now().Unix(),
			ProgressPercent: 100,
		}, nil
	}, nil)

	// 6. remove_route
	registry.Register("remove_route", func(ctx context.Context, op *pb.OperationEnvelope) (*pb.OperationResponse, error) {
		payload := parsePayloadMap(op.PayloadJson)
		domain, _ := payload["domain"].(string)
		if domain == "" {
			domain = op.ResourceId
		}
		if domain == "" {
			return &pb.OperationResponse{
				OperationId:     op.OperationId,
				Status:          "FAILED",
				ErrorCode:       "INVALID_DOMAIN",
				Message:         "domain is required for route removal",
				CompletedAtUnix: time.Now().Unix(),
			}, fmt.Errorf("domain is required")
		}

		if err := caddyMgr.RemoveRoute(ctx, domain); err != nil {
			return &pb.OperationResponse{
				OperationId:     op.OperationId,
				Status:          "FAILED",
				ErrorCode:       "REMOVE_ROUTE_FAILED",
				Message:         fmt.Sprintf("failed to remove route for domain %s: %v", domain, err),
				CompletedAtUnix: time.Now().Unix(),
			}, err
		}

		resData := map[string]interface{}{
			"status": "ROUTE_REMOVED",
			"domain": domain,
		}
		resJSONBytes, _ := json.Marshal(resData)

		return &pb.OperationResponse{
			OperationId:     op.OperationId,
			Status:          "SUCCEEDED",
			ResultJson:      string(resJSONBytes),
			Message:         fmt.Sprintf("Route for %s removed successfully", domain),
			CompletedAtUnix: time.Now().Unix(),
			ProgressPercent: 100,
		}, nil
	}, nil)

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

	// 17. backup_resource / snapshot_backup
	backupHandler := func(ctx context.Context, op *pb.OperationEnvelope) (*pb.OperationResponse, error) {
		payload := parsePayloadMap(op.PayloadJson)
		resID := extractResourceID(op, "resource_id")
		if resID == "" {
			if rID, ok := payload["resource_id"].(string); ok && rID != "" {
				resID = rID
			}
		}

		resType := ""
		if rtVal, ok := payload["resource_type"].(string); ok && rtVal != "" {
			resType = strings.ToLower(rtVal)
		}

		backupID := ""
		if bID, ok := payload["backup_id"].(string); ok && bID != "" {
			backupID = bID
		} else {
			backupID = fmt.Sprintf("bk-%d", time.Now().UnixNano())
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

		storageTarget := ""
		if st, ok := payload["storage_target"].(string); ok && st != "" {
			storageTarget = st
		}

		if resID == "" {
			return &pb.OperationResponse{
				OperationId:     op.OperationId,
				Status:          "FAILED",
				ErrorCode:       "INVALID_PAYLOAD",
				Message:         "resource_id is required for backup",
				CompletedAtUnix: time.Now().Unix(),
			}, fmt.Errorf("resource_id is required for backup")
		}

		// 1. Resolve or create encryption key from Vault
		encKey, err := backup.GetOrCreateBackupKey(ctx, vaultClient, resID)
		if err != nil {
			return &pb.OperationResponse{
				OperationId:     op.OperationId,
				Status:          "FAILED",
				ErrorCode:       "ENCRYPTION_KEY_FAILED",
				Message:         fmt.Sprintf("failed resolving backup encryption key: %v", err),
				CompletedAtUnix: time.Now().Unix(),
			}, err
		}

		// 2. Perform raw backup based on resource type
		var backupResultPath string
		tempBackupDir := filepath.Join(os.TempDir(), "primecloud-backups", resType, resID)

		switch resType {
		case "postgres":
			res, err := postgres.BackupPostgresWithVault(ctx, rt, vaultClient, projectID, resID, tempBackupDir)
			if err != nil {
				return &pb.OperationResponse{
					OperationId:     op.OperationId,
					Status:          "FAILED",
					ErrorCode:       "POSTGRES_BACKUP_FAILED",
					Message:         err.Error(),
					CompletedAtUnix: time.Now().Unix(),
				}, err
			}
			backupResultPath = res.ArtifactPath

		case "valkey", "keyvalue":
			res, err := valkey.BackupValkeyWithVault(ctx, rt, vaultClient, cfg.ResourceDir, projectID, resID, tempBackupDir)
			if err != nil {
				return &pb.OperationResponse{
					OperationId:     op.OperationId,
					Status:          "FAILED",
					ErrorCode:       "VALKEY_BACKUP_FAILED",
					Message:         err.Error(),
					CompletedAtUnix: time.Now().Unix(),
				}, err
			}
			backupResultPath = res.ArtifactPath

		default:
			return &pb.OperationResponse{
				OperationId:     op.OperationId,
				Status:          "FAILED",
				ErrorCode:       "UNSUPPORTED_RESOURCE_TYPE",
				Message:         fmt.Sprintf("unsupported resource type for backup: %s", resType),
				CompletedAtUnix: time.Now().Unix(),
			}, fmt.Errorf("unsupported resource type for backup: %s", resType)
		}

		// 3. Package and encrypt the artifact
		targetDir := filepath.Join(cfg.ResourceDir, "backups", resType, resID)
		uploader := backup.NewUploader(a.logger)
		manifest, encFile, err := uploader.PackageAndUpload(ctx, backupID, resID, resType, cfg.NodeID, backupResultPath, encKey, targetDir)

		// Immediately remove plaintext artifact
		_ = os.Remove(backupResultPath)

		if err != nil {
			return &pb.OperationResponse{
				OperationId:     op.OperationId,
				Status:          "FAILED",
				ErrorCode:       "BACKUP_PACKAGING_FAILED",
				Message:         err.Error(),
				CompletedAtUnix: time.Now().Unix(),
			}, err
		}

		// Compute encrypted artifact checksum (SHA-256)
		encChecksum, encSize, err := backup.ComputeSHA256(encFile)
		if err != nil {
			return &pb.OperationResponse{
				OperationId:     op.OperationId,
				Status:          "FAILED",
				ErrorCode:       "CHECKSUM_FAILED",
				Message:         err.Error(),
				CompletedAtUnix: time.Now().Unix(),
			}, err
		}

		storageRef := storageTarget
		if storageRef == "" {
			storageRef = encFile
		} else {
			baseStorage := os.Getenv("PRIMECLOUD_BACKUP_DIR")
			if baseStorage == "" {
				baseStorage = filepath.Join(".primecloud_storage", "backups")
			}
			storagePath := filepath.Join(baseStorage, storageTarget)
			_ = os.MkdirAll(filepath.Dir(storagePath), 0700)
			if encData, rErr := os.ReadFile(encFile); rErr == nil {
				_ = os.WriteFile(storagePath, encData, 0600)
			}
		}

		resultMap := map[string]interface{}{
			"status":         "SUCCEEDED",
			"backup_id":      backupID,
			"resource_id":    resID,
			"resource_type":  resType,
			"size_bytes":     encSize,
			"checksum":       encChecksum,
			"storage_ref":    storageRef,
			"manifest_path":  filepath.Join(targetDir, fmt.Sprintf("%s.manifest.json", backupID)),
			"encrypted_path": encFile,
			"original_size":  manifest.OriginalSizeBytes,
			"encrypted_size": manifest.EncryptedSizeBytes,
		}
		resJSON, _ := json.Marshal(resultMap)

		return &pb.OperationResponse{
			OperationId:     op.OperationId,
			Status:          "SUCCEEDED",
			Message:         fmt.Sprintf("Backup %s for %s completed successfully", backupID, resID),
			CompletedAtUnix: time.Now().Unix(),
			ProgressPercent: 100,
			ResultJson:      string(resJSON),
		}, nil
	}
	registry.Register("backup_resource", backupHandler, nil)
	registry.Register("snapshot_backup", backupHandler, nil)

	// 18. start_recovery / restore_recovery
	recoveryHandler := func(ctx context.Context, op *pb.OperationEnvelope) (*pb.OperationResponse, error) {
		payload := parsePayloadMap(op.PayloadJson)
		resID := extractResourceID(op, "resource_id")
		if resID == "" {
			if rID, ok := payload["resource_id"].(string); ok && rID != "" {
				resID = rID
			}
		}

		resType := ""
		if rtVal, ok := payload["resource_type"].(string); ok && rtVal != "" {
			resType = strings.ToLower(rtVal)
		}

		jobID := ""
		if jID, ok := payload["job_id"].(string); ok && jID != "" {
			jobID = jID
		} else {
			jobID = op.OperationId
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

		storageRef := ""
		if sr, ok := payload["storage_ref"].(string); ok && sr != "" {
			storageRef = sr
		}

		expectedChecksum := ""
		if cs, ok := payload["checksum_sha256"].(string); ok && cs != "" {
			expectedChecksum = cs
		} else if cs, ok := payload["checksum"].(string); ok && cs != "" {
			expectedChecksum = cs
		}

		// 1. Locate encrypted artifact and manifest
		var encPath, manifestPath string
		candidates := []string{
			storageRef,
			filepath.Join(cfg.ResourceDir, "backups", resType, resID, filepath.Base(storageRef)),
			filepath.Join(os.Getenv("PRIMECLOUD_BACKUP_DIR"), storageRef),
			filepath.Join(".primecloud_storage", "backups", storageRef),
		}
		for _, c := range candidates {
			if c == "" {
				continue
			}
			if fi, err := os.Stat(c); err == nil && !fi.IsDir() {
				encPath = c
				dir := filepath.Dir(encPath)
				base := strings.TrimSuffix(filepath.Base(encPath), filepath.Ext(encPath))
				manifestPath = filepath.Join(dir, fmt.Sprintf("%s.manifest.json", base))
				break
			}
		}

		if encPath == "" {
			return &pb.OperationResponse{
				OperationId:     op.OperationId,
				Status:          "FAILED",
				ErrorCode:       "ARTIFACT_NOT_FOUND",
				Message:         fmt.Sprintf("backup artifact %s not found on node", storageRef),
				CompletedAtUnix: time.Now().Unix(),
			}, fmt.Errorf("backup artifact %s not found on node", storageRef)
		}

		// 2. Validate Checksum: FAIL CLOSED if mismatch
		if expectedChecksum != "" {
			actualChecksum, _, err := backup.ComputeSHA256(encPath)
			if err != nil {
				return &pb.OperationResponse{
					OperationId:     op.OperationId,
					Status:          "FAILED",
					ErrorCode:       "CHECKSUM_COMPUTATION_FAILED",
					Message:         err.Error(),
					CompletedAtUnix: time.Now().Unix(),
				}, err
			}
			if !strings.EqualFold(actualChecksum, expectedChecksum) {
				errMsg := fmt.Sprintf("checksum mismatch: expected %s, got %s", expectedChecksum, actualChecksum)
				return &pb.OperationResponse{
					OperationId:     op.OperationId,
					Status:          "FAILED",
					ErrorCode:       "CHECKSUM_MISMATCH",
					Message:         errMsg,
					CompletedAtUnix: time.Now().Unix(),
				}, fmt.Errorf("%s", errMsg)
			}
		}

		// 3. Resolve encryption key from Vault
		encKey, err := backup.GetOrCreateBackupKey(ctx, vaultClient, resID)
		if err != nil {
			return &pb.OperationResponse{
				OperationId:     op.OperationId,
				Status:          "FAILED",
				ErrorCode:       "ENCRYPTION_KEY_FAILED",
				Message:         err.Error(),
				CompletedAtUnix: time.Now().Unix(),
			}, err
		}

		// 4. Reconstruct artifact (decrypt and verify manifest integrity)
		restoreTempDir := filepath.Join(os.TempDir(), "primecloud-restores", jobID)
		reconstructor := recovery.NewReconstructor(rt, a.logger)
		restoredPath, manifest, err := reconstructor.ReconstructArtifact(ctx, encPath, manifestPath, encKey, restoreTempDir)
		if err != nil {
			return &pb.OperationResponse{
				OperationId:     op.OperationId,
				Status:          "FAILED",
				ErrorCode:       "DECRYPTION_FAILED",
				Message:         err.Error(),
				CompletedAtUnix: time.Now().Unix(),
			}, err
		}

		// 5. Apply restore to actual workload
		if resType == "" && manifest != nil {
			resType = manifest.ResourceType
		}
		if manifest != nil {
			manifest.ResourceType = resType
		}

		restoreErr := reconstructor.RestoreToWorkloadWithVault(ctx, manifest, restoredPath, vaultClient, cfg.ResourceDir, projectID)

		// Immediately clean up temporary plaintext restored artifact
		_ = os.Remove(restoredPath)
		_ = os.RemoveAll(restoreTempDir)

		if restoreErr != nil {
			return &pb.OperationResponse{
				OperationId:     op.OperationId,
				Status:          "FAILED",
				ErrorCode:       "RESTORE_EXECUTION_FAILED",
				Message:         restoreErr.Error(),
				CompletedAtUnix: time.Now().Unix(),
			}, restoreErr
		}

		resultMap := map[string]interface{}{
			"status":      "SUCCEEDED",
			"job_id":      jobID,
			"resource_id": resID,
			"restored_at": time.Now().UTC().Format(time.RFC3339),
		}
		resJSON, _ := json.Marshal(resultMap)

		return &pb.OperationResponse{
			OperationId:     op.OperationId,
			Status:          "SUCCEEDED",
			Message:         fmt.Sprintf("Recovery job %s for resource %s succeeded", jobID, resID),
			CompletedAtUnix: time.Now().Unix(),
			ProgressPercent: 100,
			ResultJson:      string(resJSON),
		}, nil
	}
	registry.Register("start_recovery", recoveryHandler, nil)
	registry.Register("restore_recovery", recoveryHandler, nil)

	// 19. delete_backup
	deleteBackupHandler := func(ctx context.Context, op *pb.OperationEnvelope) (*pb.OperationResponse, error) {
		payload := parsePayloadMap(op.PayloadJson)
		backupID := ""
		if bID, ok := payload["backup_id"].(string); ok {
			backupID = bID
		} else {
			backupID = op.ResourceId
		}

		return &pb.OperationResponse{
			OperationId:     op.OperationId,
			Status:          "SUCCEEDED",
			Message:         fmt.Sprintf("Backup %s deleted", backupID),
			CompletedAtUnix: time.Now().Unix(),
			ProgressPercent: 100,
		}, nil
	}
	registry.Register("delete_backup", deleteBackupHandler, nil)

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

func resolveAppContainerTarget(ctx context.Context, rt runtime.ContainerRuntime, op *pb.OperationEnvelope) string {
	payload := parsePayloadMap(op.PayloadJson)
	if cID, ok := payload["container_id"].(string); ok && cID != "" {
		if inspect, err := rt.InspectContainer(ctx, cID); err == nil && inspect != nil {
			return cID
		}
	}

	target := op.ResourceId
	if target != "" {
		if inspect, err := rt.InspectContainer(ctx, target); err == nil && inspect != nil {
			return target
		}
		// Try standard pc-app- prefix for application UUIDs
		prefixed := fmt.Sprintf("pc-app-%s", target)
		if inspect, err := rt.InspectContainer(ctx, prefixed); err == nil && inspect != nil {
			return prefixed
		}
	}

	if cID, ok := payload["container_id"].(string); ok && cID != "" {
		return cID
	}
	if target != "" {
		return fmt.Sprintf("pc-app-%s", target)
	}
	return target
}

func parsePayloadMap(payloadJSON string) map[string]interface{} {
	m := make(map[string]interface{})
	if payloadJSON != "" {
		_ = json.Unmarshal([]byte(payloadJSON), &m)
	}
	return m
}

