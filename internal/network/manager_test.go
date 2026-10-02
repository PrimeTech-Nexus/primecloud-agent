package network_test

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/docker/docker/api/types"
	dockerNetwork "github.com/docker/docker/api/types/network"
	"github.com/primecloud/primecloud-agent/internal/network"
)

// mockDockerNetworkClient implements DockerNetworkClient in-memory for testing.
type mockDockerNetworkClient struct {
	mu          sync.Mutex
	networks    map[string]types.NetworkResource // id/name -> resource
	attachedMap map[string]map[string]*dockerNetwork.EndpointSettings // netID -> containerID -> endpoint
	createErr   error
	inspectErr  error
	listErr     error
	connectErr  error
	disconnErr  error
}

func newMockDockerClient() *mockDockerNetworkClient {
	return &mockDockerNetworkClient{
		networks:    make(map[string]types.NetworkResource),
		attachedMap: make(map[string]map[string]*dockerNetwork.EndpointSettings),
	}
}

func (m *mockDockerNetworkClient) NetworkCreate(ctx context.Context, name string, options types.NetworkCreate) (types.NetworkCreateResponse, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.createErr != nil {
		return types.NetworkCreateResponse{}, m.createErr
	}

	for _, n := range m.networks {
		if n.Name == name {
			return types.NetworkCreateResponse{}, fmt.Errorf("network %s already exists", name)
		}
	}

	netID := fmt.Sprintf("net-id-%s", name)
	res := types.NetworkResource{
		ID:         netID,
		Name:       name,
		Driver:     options.Driver,
		EnableIPv6: options.EnableIPv6,
		IPAM:       *options.IPAM,
		Labels:     options.Labels,
		Containers: make(map[string]types.EndpointResource),
	}
	m.networks[netID] = res
	m.networks[name] = res
	m.attachedMap[netID] = make(map[string]*dockerNetwork.EndpointSettings)

	return types.NetworkCreateResponse{ID: netID}, nil
}

func (m *mockDockerNetworkClient) NetworkInspect(ctx context.Context, networkID string, options types.NetworkInspectOptions) (types.NetworkResource, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.inspectErr != nil {
		return types.NetworkResource{}, m.inspectErr
	}

	res, ok := m.networks[networkID]
	if !ok {
		return types.NetworkResource{}, fmt.Errorf("network %s not found", networkID)
	}

	// Populate latest container endpoints
	res.Containers = make(map[string]types.EndpointResource)
	if attached, ok := m.attachedMap[res.ID]; ok {
		for cid := range attached {
			res.Containers[cid] = types.EndpointResource{
				Name:        cid,
				EndpointID:  fmt.Sprintf("ep-%s", cid),
				MacAddress:  "02:42:ac:11:00:02",
				IPv4Address: "10.240.1.2/24",
			}
		}
	}

	return res, nil
}

func (m *mockDockerNetworkClient) NetworkList(ctx context.Context, options types.NetworkListOptions) ([]types.NetworkResource, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.listErr != nil {
		return nil, m.listErr
	}

	seen := make(map[string]bool)
	list := make([]types.NetworkResource, 0)
	for _, n := range m.networks {
		if !seen[n.ID] {
			seen[n.ID] = true
			list = append(list, n)
		}
	}
	return list, nil
}

func (m *mockDockerNetworkClient) NetworkRemove(ctx context.Context, networkID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	res, ok := m.networks[networkID]
	if !ok {
		return fmt.Errorf("network %s not found", networkID)
	}
	delete(m.networks, res.ID)
	delete(m.networks, res.Name)
	delete(m.attachedMap, res.ID)
	return nil
}

func (m *mockDockerNetworkClient) NetworkConnect(ctx context.Context, networkID, containerID string, config *dockerNetwork.EndpointSettings) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.connectErr != nil {
		return m.connectErr
	}

	res, ok := m.networks[networkID]
	if !ok {
		return fmt.Errorf("network %s not found", networkID)
	}

	if m.attachedMap[res.ID] == nil {
		m.attachedMap[res.ID] = make(map[string]*dockerNetwork.EndpointSettings)
	}
	m.attachedMap[res.ID][containerID] = config
	return nil
}

func (m *mockDockerNetworkClient) NetworkDisconnect(ctx context.Context, networkID, containerID string, force bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.disconnErr != nil {
		return m.disconnErr
	}

	res, ok := m.networks[networkID]
	if !ok {
		return fmt.Errorf("network %s not found", networkID)
	}

	if attached, ok := m.attachedMap[res.ID]; ok {
		delete(attached, containerID)
	}
	return nil
}

// 1. Network name generation
func TestCanonicalNetworkName(t *testing.T) {
	envID := "0191c000-0000-7000-8000-000000000001"
	name := network.CanonicalNetworkName(envID)
	expected := "pc-net-0191c000-0000-7000-8000-000000000001"
	if name != expected {
		t.Fatalf("expected network name %q, got %q", expected, name)
	}
}

// 2. Network labels & 3. Environment identity & 14. Multi-node identity
func TestNetworkLabels(t *testing.T) {
	nodeID := "0191c001-node-alpha"
	envID := "env-prod-100"
	mgr := network.NewManager(newMockDockerClient(), nodeID, nil)

	labels := mgr.NetworkLabels(envID)
	if labels[network.LabelPrimeCloudManaged] != "true" {
		t.Errorf("missing managed label")
	}
	if labels[network.LabelPrimeCloudResourceType] != network.ResourceTypeManagedDataNetwork {
		t.Errorf("invalid resource_type: %v", labels[network.LabelPrimeCloudResourceType])
	}
	if labels[network.LabelPrimeCloudEnvID] != envID {
		t.Errorf("invalid environment_id: %v", labels[network.LabelPrimeCloudEnvID])
	}
	if labels[network.LabelPrimeCloudNodeID] != nodeID {
		t.Errorf("invalid node_id: %v", labels[network.LabelPrimeCloudNodeID])
	}
	if labels[network.LabelPrimeCloudNetVersion] != "1" {
		t.Errorf("invalid network_version: %v", labels[network.LabelPrimeCloudNetVersion])
	}
}

// 4. Subnet allocation & 5. Subnet collision prevention
func TestSubnetAllocation_CollisionFree(t *testing.T) {
	mockCli := newMockDockerClient()
	nodeID := "node-001"
	mgr := network.NewManager(mockCli, nodeID, nil)
	ctx := context.Background()

	// Ensure two separate environments receive different non-overlapping subnets
	netA, err := mgr.EnsureEnvironmentNetwork(ctx, "env-alpha")
	if err != nil {
		t.Fatalf("failed creating netA: %v", err)
	}
	netB, err := mgr.EnsureEnvironmentNetwork(ctx, "env-beta")
	if err != nil {
		t.Fatalf("failed creating netB: %v", err)
	}

	if netA.Subnet == netB.Subnet {
		t.Fatalf("collision detected: both networks assigned %s", netA.Subnet)
	}
	if !strings.HasPrefix(netA.Subnet, "10.240.") {
		t.Errorf("netA subnet not in 10.240.0.0/16 pool: %s", netA.Subnet)
	}
	if !strings.HasPrefix(netB.Subnet, "10.240.") {
		t.Errorf("netB subnet not in 10.240.0.0/16 pool: %s", netB.Subnet)
	}
}

// 6. Idempotent creation
func TestEnsureEnvironmentNetwork_Idempotent(t *testing.T) {
	mockCli := newMockDockerClient()
	mgr := network.NewManager(mockCli, "node-001", nil)
	ctx := context.Background()
	envID := "env-reconcile-test"

	net1, err := mgr.EnsureEnvironmentNetwork(ctx, envID)
	if err != nil {
		t.Fatalf("first creation failed: %v", err)
	}
	net2, err := mgr.EnsureEnvironmentNetwork(ctx, envID)
	if err != nil {
		t.Fatalf("second creation failed: %v", err)
	}

	if net1.ID != net2.ID {
		t.Fatalf("expected identical network ID, got %s and %s", net1.ID, net2.ID)
	}
	if net1.Subnet != net2.Subnet {
		t.Fatalf("subnet mutated across idempotent calls: %s vs %s", net1.Subnet, net2.Subnet)
	}
}

// 7. Ownership conflict detection
func TestOwnershipConflict_Detected(t *testing.T) {
	mockCli := newMockDockerClient()
	mgr := network.NewManager(mockCli, "node-001", nil)
	ctx := context.Background()

	// Manually create conflicting network with matching name but unmanaged labels
	conflictName := network.CanonicalNetworkName("env-rogue")
	_, err := mockCli.NetworkCreate(ctx, conflictName, types.NetworkCreate{
		Driver: "bridge",
		Labels: map[string]string{
			"unmanaged": "true",
		},
		IPAM: &dockerNetwork.IPAM{
			Config: []dockerNetwork.IPAMConfig{
				{Subnet: "10.240.99.0/24"},
			},
		},
	})
	if err != nil {
		t.Fatalf("setup failed: %v", err)
	}

	// Attempting to EnsureEnvironmentNetwork on env-rogue must fail closed with ownership conflict
	_, err = mgr.EnsureEnvironmentNetwork(ctx, "env-rogue")
	if err == nil {
		t.Fatalf("expected ownership conflict error, got nil")
	}
	if !strings.Contains(err.Error(), network.ErrCodeNetworkOwnershipConflict) {
		t.Fatalf("expected %s in error, got %v", network.ErrCodeNetworkOwnershipConflict, err)
	}
}

// 8. Container attachment & 9. Alias generation
func TestAttachContainerToEnvironmentNetwork(t *testing.T) {
	mockCli := newMockDockerClient()
	mgr := network.NewManager(mockCli, "node-001", nil)
	ctx := context.Background()
	envID := "env-attach-test"
	resID := "res-pg-1234"

	aliases := network.FormatPostgresAliases(resID)
	expectedPrimary := fmt.Sprintf("postgres-%s.internal.primecloud", resID)
	expectedShort := fmt.Sprintf("postgres-%s", resID)

	if len(aliases) != 2 || aliases[0] != expectedPrimary || aliases[1] != expectedShort {
		t.Fatalf("unexpected aliases: %v", aliases)
	}

	containerID := "pc-pg-res-pg-1234"
	if err := mgr.AttachContainerToEnvironmentNetwork(ctx, envID, containerID, aliases); err != nil {
		t.Fatalf("failed attaching container: %v", err)
	}

	// Idempotent re-attach
	if err := mgr.AttachContainerToEnvironmentNetwork(ctx, envID, containerID, aliases); err != nil {
		t.Fatalf("failed idempotent re-attach: %v", err)
	}
}

// 10. Reconciliation
func TestReconcileEnvironmentNetwork(t *testing.T) {
	mockCli := newMockDockerClient()
	mgr := network.NewManager(mockCli, "node-001", nil)
	ctx := context.Background()
	envID := "env-reconcile-full"

	containers := map[string][]string{
		"pc-pg-db-1": network.FormatPostgresAliases("db-1"),
		"pc-vk-kv-1": network.FormatValkeyAliases("kv-1"),
		"app-web-1":  network.FormatApplicationAliases("app-web-1", "web"),
	}

	report, err := mgr.ReconcileEnvironmentNetwork(ctx, envID, containers)
	if err != nil {
		t.Fatalf("reconcile failed: %v", err)
	}

	if len(report.AttachedContainers) != 3 {
		t.Fatalf("expected 3 attached containers, got %d", len(report.AttachedContainers))
	}
	if report.NetworkName != network.CanonicalNetworkName(envID) {
		t.Errorf("wrong network name: %s", report.NetworkName)
	}
}

// 11. Cross-environment isolation
func TestCrossEnvironmentIsolation_Separation(t *testing.T) {
	mockCli := newMockDockerClient()
	mgr := network.NewManager(mockCli, "node-001", nil)
	ctx := context.Background()

	envA := "env-alpha-isolated"
	envB := "env-beta-isolated"

	netA, err := mgr.EnsureEnvironmentNetwork(ctx, envA)
	if err != nil {
		t.Fatalf("failed creating netA: %v", err)
	}
	netB, err := mgr.EnsureEnvironmentNetwork(ctx, envB)
	if err != nil {
		t.Fatalf("failed creating netB: %v", err)
	}

	// Attach app and db in Env A
	err = mgr.AttachContainerToEnvironmentNetwork(ctx, envA, "app-A", []string{"app-A"})
	if err != nil {
		t.Fatalf("attach app-A failed: %v", err)
	}
	err = mgr.AttachContainerToEnvironmentNetwork(ctx, envA, "db-A", network.FormatPostgresAliases("db-A"))
	if err != nil {
		t.Fatalf("attach db-A failed: %v", err)
	}

	// Attach app and db in Env B
	err = mgr.AttachContainerToEnvironmentNetwork(ctx, envB, "app-B", []string{"app-B"})
	if err != nil {
		t.Fatalf("attach app-B failed: %v", err)
	}
	err = mgr.AttachContainerToEnvironmentNetwork(ctx, envB, "db-B", network.FormatPostgresAliases("db-B"))
	if err != nil {
		t.Fatalf("attach db-B failed: %v", err)
	}

	// Inspect Net A
	inspectA, err := mockCli.NetworkInspect(ctx, netA.ID, types.NetworkInspectOptions{})
	if err != nil {
		t.Fatalf("inspectA failed: %v", err)
	}

	// Verify Net A only contains app-A and db-A, NOT app-B or db-B
	if _, ok := inspectA.Containers["app-A"]; !ok {
		t.Errorf("expected app-A in netA")
	}
	if _, ok := inspectA.Containers["db-A"]; !ok {
		t.Errorf("expected db-A in netA")
	}
	if _, ok := inspectA.Containers["app-B"]; ok {
		t.Errorf("CRITICAL LEAK: app-B found in netA")
	}
	if _, ok := inspectA.Containers["db-B"]; ok {
		t.Errorf("CRITICAL LEAK: db-B found in netA")
	}

	// Inspect Net B
	inspectB, err := mockCli.NetworkInspect(ctx, netB.ID, types.NetworkInspectOptions{})
	if err != nil {
		t.Fatalf("inspectB failed: %v", err)
	}

	// Verify Net B only contains app-B and db-B, NOT app-A or db-A
	if _, ok := inspectB.Containers["app-B"]; !ok {
		t.Errorf("expected app-B in netB")
	}
	if _, ok := inspectB.Containers["db-B"]; !ok {
		t.Errorf("expected db-B in netB")
	}
	if _, ok := inspectB.Containers["app-A"]; ok {
		t.Errorf("CRITICAL LEAK: app-A found in netB")
	}
	if _, ok := inspectB.Containers["db-A"]; ok {
		t.Errorf("CRITICAL LEAK: db-A found in netB")
	}
}

// 12. Missing network recovery & 13. Stale network handling
func TestMissingNetworkRecovery(t *testing.T) {
	mockCli := newMockDockerClient()
	mgr := network.NewManager(mockCli, "node-001", nil)
	ctx := context.Background()
	envID := "env-recovery"

	// Create initially
	net1, err := mgr.EnsureEnvironmentNetwork(ctx, envID)
	if err != nil {
		t.Fatalf("init create failed: %v", err)
	}

	// Simulate stale or accidentally removed network in Docker
	_ = mockCli.NetworkRemove(ctx, net1.ID)

	// Ensure again; must recover and re-create without panic or synthetic error
	net2, err := mgr.EnsureEnvironmentNetwork(ctx, envID)
	if err != nil {
		t.Fatalf("recovery create failed: %v", err)
	}
	if net2.Name != net1.Name {
		t.Errorf("expected same network name on recovery: %s vs %s", net1.Name, net2.Name)
	}
}
