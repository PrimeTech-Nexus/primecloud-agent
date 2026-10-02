// Package network provides the ManagedDataNetworkManager for environment-scoped isolated Docker bridge networking.
package network

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"

	"github.com/docker/docker/api/types"
	dockerNetwork "github.com/docker/docker/api/types/network"
)

// Standard error codes for Managed Data Networking.
const (
	ErrCodeNetworkCreateFailed         = "NETWORK_CREATE_FAILED"
	ErrCodeNetworkSubnetConflict       = "NETWORK_SUBNET_CONFLICT"
	ErrCodeNetworkOwnershipConflict    = "NETWORK_OWNERSHIP_CONFLICT"
	ErrCodeNetworkAttachFailed         = "NETWORK_ATTACH_FAILED"
	ErrCodeNetworkDetachFailed         = "NETWORK_DETACH_FAILED"
	ErrCodeNetworkNotFound             = "NETWORK_NOT_FOUND"
	ErrCodeNetworkDNSVerificationFailed = "NETWORK_DNS_VERIFICATION_FAILED"
	ErrCodeNetworkReconcileFailed      = "NETWORK_RECONCILIATION_FAILED"
)

// Label constants establishing authoritative ownership and resource metadata.
const (
	LabelPrimeCloudManaged      = "primecloud.managed"
	LabelPrimeCloudResourceType = "primecloud.resource_type"
	LabelPrimeCloudEnvID        = "primecloud.environment_id"
	LabelPrimeCloudNodeID       = "primecloud.node_id"
	LabelPrimeCloudNetVersion   = "primecloud.network_version"

	ResourceTypeManagedDataNetwork = "managed_data_network"
	NetworkVersionV1               = "1"

	SubnetPoolBase   = "10.240"
	DefaultSubnetMask = "/24"
)

// DockerNetworkClient specifies the Docker Engine API subset required for network lifecycle.
type DockerNetworkClient interface {
	NetworkCreate(ctx context.Context, name string, options types.NetworkCreate) (types.NetworkCreateResponse, error)
	NetworkInspect(ctx context.Context, networkID string, options types.NetworkInspectOptions) (types.NetworkResource, error)
	NetworkList(ctx context.Context, options types.NetworkListOptions) ([]types.NetworkResource, error)
	NetworkRemove(ctx context.Context, networkID string) error
	NetworkConnect(ctx context.Context, networkID, containerID string, config *dockerNetwork.EndpointSettings) error
	NetworkDisconnect(ctx context.Context, networkID, containerID string, force bool) error
}

// NetworkInfo represents verified runtime metadata of an environment's managed data network.
type NetworkInfo struct {
	ID            string            `json:"id"`
	Name          string            `json:"name"`
	EnvironmentID string            `json:"environment_id"`
	NodeID        string            `json:"node_id"`
	Subnet        string            `json:"subnet"`
	Gateway       string            `json:"gateway"`
	Driver        string            `json:"driver"`
	Labels        map[string]string `json:"labels"`
}

// ReconcileReport summarizes the actions taken during network reconciliation.
type ReconcileReport struct {
	EnvironmentID      string   `json:"environment_id"`
	NetworkName        string   `json:"network_name"`
	NetworkID          string   `json:"network_id"`
	Created            bool     `json:"created"`
	Subnet             string   `json:"subnet"`
	AttachedContainers []string `json:"attached_containers"`
}

// Manager orchestrates environment-scoped user-defined bridge networks.
type Manager struct {
	cli    DockerNetworkClient
	nodeID string
	logger *slog.Logger
	mu     sync.Mutex
}

// NewManager constructs a ManagedDataNetworkManager.
func NewManager(cli DockerNetworkClient, nodeID string, logger *slog.Logger) *Manager {
	if logger == nil {
		logger = slog.Default()
	}
	if nodeID == "" {
		nodeID = "0191c001-0000-7000-8000-000000000001" // Canonical pc-node-001 fallback
	}
	return &Manager{
		cli:    cli,
		nodeID: nodeID,
		logger: logger.With("component", "managed_data_network_manager"),
	}
}

// CanonicalNetworkName returns the standard deterministic Docker network name: pc-net-<environment_id>.
func CanonicalNetworkName(environmentID string) string {
	cleanEnv := strings.TrimSpace(environmentID)
	return fmt.Sprintf("pc-net-%s", cleanEnv)
}

// NetworkLabels constructs standard immutable labels for network ownership.
func (m *Manager) NetworkLabels(environmentID string) map[string]string {
	return map[string]string{
		LabelPrimeCloudManaged:      "true",
		LabelPrimeCloudResourceType: ResourceTypeManagedDataNetwork,
		LabelPrimeCloudEnvID:        environmentID,
		LabelPrimeCloudNodeID:       m.nodeID,
		LabelPrimeCloudNetVersion:   NetworkVersionV1,
	}
}

// FormatPostgresAliases produces canonical DNS aliases for PostgreSQL in an environment.
func FormatPostgresAliases(resourceID string) []string {
	cleanID := strings.TrimSpace(resourceID)
	return []string{
		fmt.Sprintf("postgres-%s.internal.primecloud", cleanID),
		fmt.Sprintf("postgres-%s", cleanID),
	}
}

// FormatValkeyAliases produces canonical DNS aliases for Valkey in an environment.
func FormatValkeyAliases(resourceID string) []string {
	cleanID := strings.TrimSpace(resourceID)
	return []string{
		fmt.Sprintf("valkey-%s.internal.primecloud", cleanID),
		fmt.Sprintf("valkey-%s", cleanID),
	}
}

// FormatApplicationAliases produces DNS aliases for an application container.
func FormatApplicationAliases(applicationID, slug string) []string {
	cleanAppID := strings.TrimSpace(applicationID)
	aliases := []string{
		fmt.Sprintf("app-%s.internal.primecloud", cleanAppID),
		fmt.Sprintf("app-%s", cleanAppID),
	}
	if cleanSlug := strings.TrimSpace(slug); cleanSlug != "" && cleanSlug != cleanAppID {
		aliases = append(aliases, cleanSlug, fmt.Sprintf("%s.internal.primecloud", cleanSlug))
	}
	return aliases
}

// EnsureEnvironmentNetwork guarantees that pc-net-<environment_id> exists, is configured as an isolated
// bridge network with Docker embedded DNS, has non-overlapping IPAM, and carries authoritative ownership labels.
func (m *Manager) EnsureEnvironmentNetwork(ctx context.Context, environmentID string) (*NetworkInfo, error) {
	if strings.TrimSpace(environmentID) == "" {
		return nil, fmt.Errorf("%s: environment_id cannot be empty", ErrCodeNetworkCreateFailed)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	netName := CanonicalNetworkName(environmentID)

	if m.cli == nil {
		return nil, fmt.Errorf("%s: docker network client is unavailable", ErrCodeNetworkCreateFailed)
	}

	// 1. Inspect existing networks
	existingNets, err := m.cli.NetworkList(ctx, types.NetworkListOptions{})
	if err != nil {
		return nil, fmt.Errorf("%s: failed to list docker networks: %w", ErrCodeNetworkCreateFailed, err)
	}

	for _, n := range existingNets {
		if n.Name == netName {
			// Found existing network by canonical name. Validate ownership.
			inspect, err := m.cli.NetworkInspect(ctx, n.ID, types.NetworkInspectOptions{Verbose: true})
			if err != nil {
				return nil, fmt.Errorf("%s: failed to inspect existing network %s: %w", ErrCodeNetworkCreateFailed, netName, err)
			}

			// Validate ownership labels
			if inspect.Labels[LabelPrimeCloudManaged] != "true" {
				m.logger.Error("managed_data_network_conflict",
					"environment_id", environmentID,
					"node_id", m.nodeID,
					"network_name", netName,
					"reason", "network exists but missing primecloud.managed label",
				)
				return nil, fmt.Errorf("%s: existing network %s is not managed by PrimeCloud", ErrCodeNetworkOwnershipConflict, netName)
			}

			ownerEnv := inspect.Labels[LabelPrimeCloudEnvID]
			if ownerEnv != environmentID {
				m.logger.Error("managed_data_network_conflict",
					"environment_id", environmentID,
					"node_id", m.nodeID,
					"network_name", netName,
					"owner_environment_id", ownerEnv,
					"reason", "network environment_id mismatch",
				)
				return nil, fmt.Errorf("%s: network %s belongs to environment %s, not %s", ErrCodeNetworkOwnershipConflict, netName, ownerEnv, environmentID)
			}

			// Extract IPAM details
			var subnet, gateway string
			if len(inspect.IPAM.Config) > 0 {
				subnet = inspect.IPAM.Config[0].Subnet
				gateway = inspect.IPAM.Config[0].Gateway
			}

			m.logger.Info("managed_data_network_exists",
				"environment_id", environmentID,
				"node_id", m.nodeID,
				"network_name", netName,
				"network_id", inspect.ID,
				"subnet", subnet,
			)

			return &NetworkInfo{
				ID:            inspect.ID,
				Name:          netName,
				EnvironmentID: environmentID,
				NodeID:        m.nodeID,
				Subnet:        subnet,
				Gateway:       gateway,
				Driver:        inspect.Driver,
				Labels:        inspect.Labels,
			}, nil
		}
	}

	// 2. Allocate non-conflicting subnet
	subnet, gateway, err := m.allocateSubnet(existingNets, environmentID)
	if err != nil {
		return nil, err
	}

	// 3. Create user-defined bridge network
	m.logger.Info("managed_data_network_create_started",
		"environment_id", environmentID,
		"node_id", m.nodeID,
		"network_name", netName,
		"subnet", subnet,
	)

	// Short bridge name: br-envID(first 10 chars)
	cleanEnvID := strings.ReplaceAll(environmentID, "-", "")
	if len(cleanEnvID) > 10 {
		cleanEnvID = cleanEnvID[:10]
	}
	bridgeName := fmt.Sprintf("br-%s", cleanEnvID)

	createOpts := types.NetworkCreate{
		Driver:         "bridge",
		CheckDuplicate: true,
		EnableIPv6:     false,
		IPAM: &dockerNetwork.IPAM{
			Driver: "default",
			Config: []dockerNetwork.IPAMConfig{
				{
					Subnet:  subnet,
					Gateway: gateway,
				},
			},
		},
		Options: map[string]string{
			"com.docker.network.bridge.enable_icc": "true",
			"com.docker.network.bridge.name":       bridgeName,
		},
		Labels: m.NetworkLabels(environmentID),
	}

	resp, err := m.cli.NetworkCreate(ctx, netName, createOpts)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to create docker network %s: %w", ErrCodeNetworkCreateFailed, netName, err)
	}

	m.logger.Info("managed_data_network_created",
		"environment_id", environmentID,
		"node_id", m.nodeID,
		"network_name", netName,
		"network_id", resp.ID,
		"subnet", subnet,
	)

	return &NetworkInfo{
		ID:            resp.ID,
		Name:          netName,
		EnvironmentID: environmentID,
		NodeID:        m.nodeID,
		Subnet:        subnet,
		Gateway:       gateway,
		Driver:        "bridge",
		Labels:        createOpts.Labels,
	}, nil
}

// InspectEnvironmentNetwork retrieves verified information about an environment's network.
func (m *Manager) InspectEnvironmentNetwork(ctx context.Context, environmentID string) (*NetworkInfo, error) {
	if strings.TrimSpace(environmentID) == "" {
		return nil, fmt.Errorf("%s: environment_id cannot be empty", ErrCodeNetworkNotFound)
	}

	if m.cli == nil {
		return nil, fmt.Errorf("%s: docker network client is unavailable", ErrCodeNetworkNotFound)
	}

	netName := CanonicalNetworkName(environmentID)
	inspect, err := m.cli.NetworkInspect(ctx, netName, types.NetworkInspectOptions{Verbose: true})
	if err != nil {
		return nil, fmt.Errorf("%s: network %s not found: %w", ErrCodeNetworkNotFound, netName, err)
	}

	var subnet, gateway string
	if len(inspect.IPAM.Config) > 0 {
		subnet = inspect.IPAM.Config[0].Subnet
		gateway = inspect.IPAM.Config[0].Gateway
	}

	return &NetworkInfo{
		ID:            inspect.ID,
		Name:          inspect.Name,
		EnvironmentID: inspect.Labels[LabelPrimeCloudEnvID],
		NodeID:        inspect.Labels[LabelPrimeCloudNodeID],
		Subnet:        subnet,
		Gateway:       gateway,
		Driver:        inspect.Driver,
		Labels:        inspect.Labels,
	}, nil
}

// AttachContainerToEnvironmentNetwork connects a container to the environment's bridge network with aliases.
// Safe and idempotent: if container is already attached with requested aliases, operation succeeds without disruption.
func (m *Manager) AttachContainerToEnvironmentNetwork(
	ctx context.Context,
	environmentID string,
	containerID string,
	aliases []string,
) error {
	if strings.TrimSpace(environmentID) == "" {
		return fmt.Errorf("%s: environment_id cannot be empty", ErrCodeNetworkAttachFailed)
	}
	if strings.TrimSpace(containerID) == "" {
		return fmt.Errorf("%s: container_id cannot be empty", ErrCodeNetworkAttachFailed)
	}

	netInfo, err := m.EnsureEnvironmentNetwork(ctx, environmentID)
	if err != nil {
		return fmt.Errorf("%s: failed ensuring network for attachment: %w", ErrCodeNetworkAttachFailed, err)
	}

	netInspect, err := m.cli.NetworkInspect(ctx, netInfo.ID, types.NetworkInspectOptions{})
	if err != nil {
		return fmt.Errorf("%s: failed to inspect network %s: %w", ErrCodeNetworkAttachFailed, netInfo.Name, err)
	}

	// Check if container already attached
	cleanAliases := sanitizeAliases(aliases)
	for cid := range netInspect.Containers {
		if cid == containerID || strings.HasPrefix(cid, containerID) || strings.HasPrefix(containerID, cid) {
			m.logger.Info("managed_data_network_attached",
				"environment_id", environmentID,
				"node_id", m.nodeID,
				"network_name", netInfo.Name,
				"container_id", containerID,
				"idempotent", true,
			)
			return nil
		}
	}

	m.logger.Info("managed_data_network_attach_started",
		"environment_id", environmentID,
		"node_id", m.nodeID,
		"network_name", netInfo.Name,
		"container_id", containerID,
		"aliases", cleanAliases,
	)

	epConfig := &dockerNetwork.EndpointSettings{
		Aliases: cleanAliases,
	}

	if err := m.cli.NetworkConnect(ctx, netInfo.ID, containerID, epConfig); err != nil {
		m.logger.Error("managed_data_network_attach_failed",
			"environment_id", environmentID,
			"node_id", m.nodeID,
			"network_name", netInfo.Name,
			"container_id", containerID,
			"error", err.Error(),
		)
		return fmt.Errorf("%s: failed connecting container %s to network %s: %w", ErrCodeNetworkAttachFailed, containerID, netInfo.Name, err)
	}

	m.logger.Info("managed_data_network_attached",
		"environment_id", environmentID,
		"node_id", m.nodeID,
		"network_name", netInfo.Name,
		"container_id", containerID,
		"aliases", cleanAliases,
	)

	return nil
}

// DetachContainerFromEnvironmentNetwork safely removes a container from the environment network.
func (m *Manager) DetachContainerFromEnvironmentNetwork(
	ctx context.Context,
	environmentID string,
	containerID string,
) error {
	if strings.TrimSpace(environmentID) == "" || strings.TrimSpace(containerID) == "" {
		return nil
	}

	netName := CanonicalNetworkName(environmentID)
	inspect, err := m.cli.NetworkInspect(ctx, netName, types.NetworkInspectOptions{})
	if err != nil {
		// Network already gone or not found
		return nil
	}

	if err := m.cli.NetworkDisconnect(ctx, inspect.ID, containerID, true); err != nil {
		if !strings.Contains(strings.ToLower(err.Error()), "not connected") &&
			!strings.Contains(strings.ToLower(err.Error()), "no such") {
			return fmt.Errorf("%s: failed to detach container %s from %s: %w", ErrCodeNetworkDetachFailed, containerID, netName, err)
		}
	}
	return nil
}

// ReconcileEnvironmentNetwork ensures convergent network state for an environment.
func (m *Manager) ReconcileEnvironmentNetwork(
	ctx context.Context,
	environmentID string,
	expectedContainers map[string][]string, // containerID -> aliases
) (*ReconcileReport, error) {
	m.logger.Info("managed_data_network_reconcile_started",
		"environment_id", environmentID,
		"node_id", m.nodeID,
	)

	netInfo, err := m.EnsureEnvironmentNetwork(ctx, environmentID)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to ensure network during reconcile: %w", ErrCodeNetworkReconcileFailed, err)
	}

	report := &ReconcileReport{
		EnvironmentID:      environmentID,
		NetworkName:        netInfo.Name,
		NetworkID:          netInfo.ID,
		Subnet:             netInfo.Subnet,
		AttachedContainers: make([]string, 0, len(expectedContainers)),
	}

	for cid, aliases := range expectedContainers {
		if err := m.AttachContainerToEnvironmentNetwork(ctx, environmentID, cid, aliases); err != nil {
			m.logger.Warn("managed_data_network_reconcile_container_attach_warning",
				"environment_id", environmentID,
				"container_id", cid,
				"error", err.Error(),
			)
		} else {
			report.AttachedContainers = append(report.AttachedContainers, cid)
		}
	}

	m.logger.Info("managed_data_network_reconcile_completed",
		"environment_id", environmentID,
		"node_id", m.nodeID,
		"network_name", netInfo.Name,
		"attached_count", len(report.AttachedContainers),
	)

	return report, nil
}

// allocateSubnet determines a collision-free /24 subnet from 10.240.0.0/16.
func (m *Manager) allocateSubnet(existingNets []types.NetworkResource, environmentID string) (string, string, error) {
	// Parse all occupied IPv4 subnets across Docker daemon
	occupiedSubnets := make(map[string]bool)
	for _, n := range existingNets {
		for _, cfg := range n.IPAM.Config {
			if cfg.Subnet != "" {
				occupiedSubnets[cfg.Subnet] = true
			}
		}
	}

	// Deterministic starting candidate index from environmentID hash
	hasher := sha256.New()
	hasher.Write([]byte(environmentID))
	hashBytes := hasher.Sum(nil)
	seedVal := binary.BigEndian.Uint64(hashBytes[:8])

	// 1 to 254
	candidateIdx := int((seedVal % 254) + 1)

	// Try candidate index
	candSubnet := fmt.Sprintf("%s.%d.0%s", SubnetPoolBase, candidateIdx, DefaultSubnetMask)
	if !isSubnetOccupiedOrOverlapping(candSubnet, occupiedSubnets) {
		gateway := fmt.Sprintf("%s.%d.1", SubnetPoolBase, candidateIdx)
		return candSubnet, gateway, nil
	}

	// Collision probe: find first available index from 1 to 254
	for i := 1; i <= 254; i++ {
		candSubnet = fmt.Sprintf("%s.%d.0%s", SubnetPoolBase, i, DefaultSubnetMask)
		if !isSubnetOccupiedOrOverlapping(candSubnet, occupiedSubnets) {
			gateway := fmt.Sprintf("%s.%d.1", SubnetPoolBase, i)
			return candSubnet, gateway, nil
		}
	}

	return "", "", fmt.Errorf("%s: private subnet pool %s.0.0/16 exhausted on node %s", ErrCodeNetworkSubnetConflict, SubnetPoolBase, m.nodeID)
}

func isSubnetOccupiedOrOverlapping(targetCIDR string, occupied map[string]bool) bool {
	if occupied[targetCIDR] {
		return true
	}
	_, targetNet, err := net.ParseCIDR(targetCIDR)
	if err != nil {
		return true
	}

	for occ := range occupied {
		_, occNet, err := net.ParseCIDR(occ)
		if err != nil {
			continue
		}
		if occNet.Contains(targetNet.IP) || targetNet.Contains(occNet.IP) {
			return true
		}
	}
	return false
}

func sanitizeAliases(aliases []string) []string {
	seen := make(map[string]bool)
	res := make([]string, 0, len(aliases))
	for _, a := range aliases {
		clean := strings.TrimSpace(a)
		if clean != "" && !seen[clean] {
			seen[clean] = true
			res = append(res, clean)
		}
	}
	return res
}

