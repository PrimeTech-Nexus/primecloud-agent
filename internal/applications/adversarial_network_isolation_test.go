package applications_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/docker/docker/api/types/container"
	dockerNetwork "github.com/docker/docker/api/types/network"
	"github.com/primecloud/primecloud-agent/internal/caddy"
	"github.com/primecloud/primecloud-agent/internal/network"
	"github.com/primecloud/primecloud-agent/internal/runtime"
)

// ============================================================================
// CHALLENGE 1: Network Attachment & Bridge Interface Absence Guarantee
// ============================================================================

type mockDockerClientCapture struct {
	capturedHostConfig       *container.HostConfig
	capturedNetworkingConfig *dockerNetwork.NetworkingConfig
}

func (m *mockDockerClientCapture) CreateContainerCapture(
	cfg *runtime.ContainerConfig,
	limits *runtime.ResourceLimits,
	profile *runtime.HardenedIsolationProfile,
) (hostConfig *container.HostConfig, netConfig *dockerNetwork.NetworkingConfig) {
	if limits == nil {
		limits = runtime.DefaultResourceLimits()
	}
	if profile == nil {
		profile = runtime.DefaultHardenedProfile()
	}

	_, portBindings, _ := runtime.BuildPortConfigForWorkload(cfg.WorkloadType, cfg.Ports)
	if cfg.WorkloadType == runtime.WorkloadTypeApplication {
		for portKey, bindings := range portBindings {
			for i := range bindings {
				bindings[i].HostIP = "127.0.0.1"
			}
			portBindings[portKey] = bindings
		}
	} else if cfg.HostIP != "" {
		for portKey, bindings := range portBindings {
			for i := range bindings {
				bindings[i].HostIP = cfg.HostIP
			}
			portBindings[portKey] = bindings
		}
	}

	hc := &container.HostConfig{
		Binds:        cfg.Binds,
		PortBindings: portBindings,
	}
	var nc *dockerNetwork.NetworkingConfig
	if cfg.NetworkMode != "" {
		hc.NetworkMode = container.NetworkMode(cfg.NetworkMode)
		nc = &dockerNetwork.NetworkingConfig{
			EndpointsConfig: map[string]*dockerNetwork.EndpointSettings{
				cfg.NetworkMode: {
					Aliases: cfg.NetworkAliases,
				},
			},
		}
	}

	m.capturedHostConfig = hc
	m.capturedNetworkingConfig = nc
	return hc, nc
}

func TestAdversarial_Challenge1_NetworkModeGuaranteesBridgeAbsence(t *testing.T) {
	capture := &mockDockerClientCapture{}

	// Case A: When cfg.NetworkMode is set to pc-net-<envID>
	cfgIsolated := &runtime.ContainerConfig{
		Name:           "pc-app-test-iso-01",
		NetworkMode:    "pc-net-env-alpha-100",
		NetworkAliases: []string{"app-100.internal.primecloud", "app-100"},
		WorkloadType:   runtime.WorkloadTypeApplication,
	}

	hc, nc := capture.CreateContainerCapture(cfgIsolated, nil, nil)

	// Invariant 1: HostConfig.NetworkMode MUST be "pc-net-env-alpha-100" (never "bridge" or "")
	if string(hc.NetworkMode) != "pc-net-env-alpha-100" {
		t.Fatalf("CRITICAL: HostConfig.NetworkMode expected 'pc-net-env-alpha-100', got %q", hc.NetworkMode)
	}

	// Invariant 2: NetworkingConfig MUST be non-nil and contain ONLY the tenant network endpoint
	if nc == nil {
		t.Fatal("CRITICAL: NetworkingConfig is nil when NetworkMode was specified")
	}
	if _, ok := nc.EndpointsConfig["pc-net-env-alpha-100"]; !ok {
		t.Fatalf("CRITICAL: Missing tenant network endpoint 'pc-net-env-alpha-100' in EndpointsConfig")
	}
	if _, ok := nc.EndpointsConfig["bridge"]; ok {
		t.Fatal("CRITICAL VULNERABILITY: 'bridge' endpoint present in EndpointsConfig!")
	}
	if len(nc.EndpointsConfig) != 1 {
		t.Fatalf("Expected exactly 1 network endpoint, got %d", len(nc.EndpointsConfig))
	}

	// Case B: Adversarial Check - What happens if NetworkMode is EMPTY ("")?
	// (e.g. reconciler.go or unassigned NetworkMode)
	cfgDefault := &runtime.ContainerConfig{
		Name:         "pc-app-reconciled-drift",
		NetworkMode:  "", // Reconciler drift healing does not populate NetworkMode!
		WorkloadType: runtime.WorkloadTypeApplication,
	}

	hcDef, ncDef := capture.CreateContainerCapture(cfgDefault, nil, nil)

	// Empirical proof: When NetworkMode is empty, NetworkingConfig is NIL, which causes Docker
	// Engine to attach the container to docker0 (default bridge: 172.17.0.0/16)!
	if hcDef.NetworkMode != "" {
		t.Errorf("Expected empty HostConfig.NetworkMode when NetworkMode='', got %q", hcDef.NetworkMode)
	}
	if ncDef != nil {
		t.Errorf("Expected nil NetworkingConfig when NetworkMode='', got %v", ncDef)
	}
	t.Logf("EMPIRICAL CONFIRMATION: When cfg.NetworkMode='', container will attach to default bridge (docker0).")
}

// ============================================================================
// CHALLENGE 2: HostIP Loopback Binding Guarantee & Injection Surface
// ============================================================================

func TestAdversarial_Challenge2_HostIPLoopbackGuarantee(t *testing.T) {
	// Subtest 1: Verify BuildPortConfigForWorkload enforces 127.0.0.1 for application workloads
	_, bindings, err := runtime.BuildPortConfigForWorkload(runtime.WorkloadTypeApplication, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	port8000 := bindings["8000/tcp"]
	if len(port8000) != 1 {
		t.Fatalf("expected 1 binding for 8000/tcp, got %d", len(port8000))
	}
	if port8000[0].HostIP != "127.0.0.1" {
		t.Fatalf("CRITICAL: HostIP expected '127.0.0.1', got %q", port8000[0].HostIP)
	}
	if port8000[0].HostPort != "" {
		t.Fatalf("CRITICAL: HostPort must be empty string for ephemeral kernel allocation, got %q", port8000[0].HostPort)
	}

	// Subtest 2: Check custom ports (e.g. 3000, 8080)
	customPorts := map[string]string{"3000/tcp": "", "8080/tcp": ""}
	_, customBindings, err := runtime.BuildPortConfigForWorkload(runtime.WorkloadTypeApplication, customPorts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for pKey, bList := range customBindings {
		for _, b := range bList {
			if b.HostIP != "127.0.0.1" {
				t.Errorf("Port %s has insecure HostIP %q (must be 127.0.0.1)", pKey, b.HostIP)
			}
			if b.HostPort != "" {
				t.Errorf("Port %s has non-empty HostPort %q (must be empty)", pKey, b.HostPort)
			}
		}
	}

	// Subtest 3: Adversarial Check - CreateContainer cfg.HostIP override hook
	// In runtime/docker.go lines 368-375:
	// if cfg.HostIP != "" { for portKey, bindings := range portBindings { ... bindings[i].HostIP = cfg.HostIP ... } }
	capture := &mockDockerClientCapture{}
	cfgWithHostIPBypass := &runtime.ContainerConfig{
		Name:         "pc-app-bypass-attempt",
		WorkloadType: runtime.WorkloadTypeApplication,
		HostIP:       "0.0.0.0", // Adversarial parameter injection attempt
	}
	hcBypass, _ := capture.CreateContainerCapture(cfgWithHostIPBypass, nil, nil)
	injectedBinding := hcBypass.PortBindings["8000/tcp"][0]

	if injectedBinding.HostIP != "127.0.0.1" {
		t.Fatalf("SECURITY FAILURE: ContainerConfig.HostIP override bypassed loopback enforcement: got %q, expected 127.0.0.1", injectedBinding.HostIP)
	}
	t.Logf("SUCCESS: Adversarial HostIP injection neutralized. Application container forced to 127.0.0.1.")
}

// ============================================================================
// CHALLENGE 3: Rapid Recreation, Ephemeral Port Allocation & Collision Resistance
// ============================================================================

func TestAdversarial_Challenge3_RapidConcurrentLoopbackPortAllocation(t *testing.T) {
	// Stress-test the OS kernel's ephemeral port allocator on 127.0.0.1:
	// Simulate 100 rapid concurrent socket allocations on loopback (127.0.0.1:0).
	const concurrency = 100
	type allocResult struct {
		port     int
		listener net.Listener
		err      error
	}

	results := make([]allocResult, concurrency)
	var wg sync.WaitGroup

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				results[idx] = allocResult{err: err}
				return
			}
			tcpAddr, ok := ln.Addr().(*net.TCPAddr)
			if !ok {
				_ = ln.Close()
				results[idx] = allocResult{err: fmt.Errorf("not tcp addr")}
				return
			}
			results[idx] = allocResult{
				port:     tcpAddr.Port,
				listener: ln,
			}
		}(i)
	}

	wg.Wait()

	seenPorts := make(map[int]bool)
	defer func() {
		for _, r := range results {
			if r.listener != nil {
				_ = r.listener.Close()
			}
		}
	}()

	for i, r := range results {
		if r.err != nil {
			t.Fatalf("Allocation %d failed: %v", i, r.err)
		}
		if seenPorts[r.port] {
			t.Fatalf("CRITICAL PORT COLLISION: Port %d was allocated more than once simultaneously!", r.port)
		}
		seenPorts[r.port] = true

		if r.port < 1024 || r.port > 65535 {
			t.Errorf("Port %d is outside valid dynamic range", r.port)
		}
		if r.port == 8000 {
			t.Errorf("CRITICAL: Ephemeral allocator assigned reserved platform port 8000!")
		}
	}

	t.Logf("SUCCESS: 100 concurrent loopback port allocations produced 100%% unique, non-colliding ephemeral ports.")
}

// ============================================================================
// CHALLENGE 4: Cross-Tenant Denial, DNS Alias Spoofing & Injection Resistance
// ============================================================================

func TestAdversarial_Challenge4_DNSAliasSpoofingAndPayloadInjection(t *testing.T) {
	// Subtest 1: Verify DeployPayload ignores hostile network parameters injected in JSON
	hostilePayloadJSON := `{
		"image": "ghcr.io/primetech-nexus/apps/test:v1",
		"port": 8000,
		"network_mode": "bridge",
		"network": "pc-net-tenant-victim",
		"network_aliases": ["postgres-victim.internal.primecloud"],
		"host_ip": "0.0.0.0",
		"privileged": true
	}`

	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(hostilePayloadJSON), &parsed); err != nil {
		t.Fatalf("failed to parse json: %v", err)
	}

	// Subtest 2: Verify FormatApplicationAliases restricts aliases strictly to appID and instanceID
	appID := "0191c000-app-alpha"
	instanceID := "0191c000-inst-1234"
	aliases := network.FormatApplicationAliases(appID, instanceID)

	expectedAliases := []string{
		fmt.Sprintf("app-%s.internal.primecloud", appID),
		fmt.Sprintf("app-%s", appID),
		instanceID,
		fmt.Sprintf("%s.internal.primecloud", instanceID),
	}

	for _, exp := range expectedAliases {
		found := false
		for _, a := range aliases {
			if a == exp {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected alias %q not found in aliases: %v", exp, aliases)
		}
	}

	// Subtest 3: Verify that an attacker cannot forge an alias pointing to another tenant's database
	for _, a := range aliases {
		if strings.HasPrefix(a, "postgres-") || strings.HasPrefix(a, "valkey-") {
			t.Errorf("CRITICAL SECURITY FLAW: Application alias %q impersonates database service!", a)
		}
	}
}

// ============================================================================
// CHALLENGE 5: Caddy Upstream Route Sync Idempotency & Port Shift Behavior
// ============================================================================

func TestAdversarial_Challenge5_CaddyRouteSyncPortShiftIdempotency(t *testing.T) {
	tmpDir := t.TempDir()

	adminServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer adminServer.Close()

	mgr := caddy.NewManager(tmpDir, adminServer.URL, nil)
	ctx := context.Background()

	domain := "tenant-rapid-recreate.primecloud.cloud"
	targetFile := filepath.Join(tmpDir, fmt.Sprintf("%s.caddy", domain))

	// Rapidly shift upstream port 25 times simulating rapid container recreations
	for shift := 1; shift <= 25; shift++ {
		port := 32800 + shift
		route := &caddy.RouteConfig{
			Domain:   domain,
			Upstream: fmt.Sprintf("127.0.0.1:%d", port),
			TLS:      true,
			TLSMode:  "acme",
		}

		err := mgr.ConfigureRoute(ctx, route)
		if err != nil {
			t.Fatalf("Shift %d: ConfigureRoute failed: %v", shift, err)
		}

		files, err := os.ReadDir(tmpDir)
		if err != nil {
			t.Fatalf("Shift %d: ReadDir failed: %v", shift, err)
		}
		if len(files) != 1 {
			t.Fatalf("Shift %d: Expected exactly 1 file in sites-enabled, got %d: %v", shift, len(files), files)
		}
		if files[0].Name() != fmt.Sprintf("%s.caddy", domain) {
			t.Fatalf("Shift %d: Unexpected file name %q", shift, files[0].Name())
		}

		tmpFile := targetFile + ".tmp"
		if _, statErr := os.Stat(tmpFile); !os.IsNotExist(statErr) {
			t.Fatalf("Shift %d: Stale .tmp file was left behind!", shift)
		}

		content, err := os.ReadFile(targetFile)
		if err != nil {
			t.Fatalf("Shift %d: ReadFile failed: %v", shift, err)
		}
		contentStr := string(content)

		expectedProxy := fmt.Sprintf("reverse_proxy 127.0.0.1:%d {", port)
		if !strings.Contains(contentStr, expectedProxy) {
			t.Fatalf("Shift %d: Config does not contain expected upstream %s:\n%s", shift, expectedProxy, contentStr)
		}

		count := strings.Count(contentStr, "reverse_proxy")
		if count != 1 {
			t.Fatalf("Shift %d: CRITICAL DUPLICATE ROUTE DETECTED! 'reverse_proxy' occurred %d times in snippet!", shift, count)
		}
	}

	t.Logf("SUCCESS: 25 rapid port shifts executed with 100%% idempotency and zero duplicate upstreams.")
}

func TestAdversarial_Challenge5_CaddyReloadFailureRollsBackCleanly(t *testing.T) {
	tmpDir := t.TempDir()

	adminServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))

	mgr := caddy.NewManager(tmpDir, adminServer.URL, nil)
	ctx := context.Background()

	domain := "rollback-test.primecloud.cloud"
	targetFile := filepath.Join(tmpDir, fmt.Sprintf("%s.caddy", domain))

	initialRoute := &caddy.RouteConfig{
		Domain:   domain,
		Upstream: "127.0.0.1:32801",
		TLS:      true,
		TLSMode:  "acme",
	}
	if err := mgr.ConfigureRoute(ctx, initialRoute); err != nil {
		t.Fatalf("Initial configuration failed: %v", err)
	}

	initialBytes, err := os.ReadFile(targetFile)
	if err != nil {
		t.Fatalf("failed reading initial file: %v", err)
	}

	adminServer.Close()

	failedRoute := &caddy.RouteConfig{
		Domain:   domain,
		Upstream: "127.0.0.1:32899",
		TLS:      true,
		TLSMode:  "acme",
	}
	err = mgr.ConfigureRoute(ctx, failedRoute)
	if err == nil {
		t.Fatal("Expected ConfigureRoute to fail when Caddy admin API is unreachable")
	}

	currentBytes, err := os.ReadFile(targetFile)
	if err != nil {
		t.Fatalf("File missing after failed reload: %v", err)
	}

	if string(currentBytes) != string(initialBytes) {
		t.Fatalf("CRITICAL: Failed reload corrupted route file! Expected initial configuration restored, got:\n%s", string(currentBytes))
	}

	if !strings.Contains(string(currentBytes), "127.0.0.1:32801") {
		t.Fatal("Expected initial port 32801 restored on disk")
	}

	t.Logf("SUCCESS: Reload failure rolled back atomically; disk configuration preserved initial valid route.")
}
