package runtime_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/primecloud/primecloud-agent/internal/runtime"
)

func TestIsolationProfile_HardeningEnforcement(t *testing.T) {
	profile := runtime.DefaultHardenedProfile()

	// 1. Verify baseline profile settings
	if len(profile.DropCapabilities) != 1 || profile.DropCapabilities[0] != "ALL" {
		t.Errorf("Expected DropCapabilities to be [ALL], got: %v", profile.DropCapabilities)
	}
	if profile.User != "1000:1000" {
		t.Errorf("Expected default non-root user 1000:1000, got %s", profile.User)
	}

	// 2. Apply to HostConfig
	hc := &container.HostConfig{}
	if err := profile.ApplyToHostConfig(hc); err != nil {
		t.Fatalf("ApplyToHostConfig failed: %v", err)
	}

	if len(hc.CapDrop) == 0 || hc.CapDrop[0] != "ALL" {
		t.Errorf("Capabilities not dropped in HostConfig: %v", hc.CapDrop)
	}

	hasNoNewPrivs := false
	for _, opt := range hc.SecurityOpt {
		if opt == "no-new-privileges:true" {
			hasNoNewPrivs = true
			break
		}
	}
	if !hasNoNewPrivs {
		t.Errorf("SecurityOpt missing no-new-privileges: %v", hc.SecurityOpt)
	}

	if hc.Privileged {
		t.Error("Privileged must be false")
	}
	if hc.IpcMode != "private" {
		t.Errorf("Expected private IPC mode, got %s", hc.IpcMode)
	}
	if hc.UsernsMode != "private" {
		t.Errorf("Expected private UsernsMode, got %s", hc.UsernsMode)
	}

	// 3. Reject privileged container
	hcPrivileged := &container.HostConfig{Privileged: true}
	err := profile.ApplyToHostConfig(hcPrivileged)
	if err == nil || !errors.Is(err, runtime.ErrPrivilegedNotAllowed) {
		t.Errorf("Expected ErrPrivilegedNotAllowed, got err=%v", err)
	}

	// 4. Reject docker.sock mount
	hcSocketMount := &container.HostConfig{
		Binds: []string{"/var/run/docker.sock:/var/run/docker.sock:ro"},
	}
	err = profile.ApplyToHostConfig(hcSocketMount)
	if err == nil || !errors.Is(err, runtime.ErrDockerSocketForbidden) {
		t.Errorf("Expected ErrDockerSocketForbidden, got err=%v", err)
	}

	// 5. Apply to ContainerConfig sets non-root user
	cc := &container.Config{}
	profile.ApplyToContainerConfig(cc)
	if cc.User != "1000:1000" {
		t.Errorf("Expected container user 1000:1000, got %s", cc.User)
	}
}

func TestResourceLimits_CgroupMapping(t *testing.T) {
	limits := &runtime.ResourceLimits{
		NanoCPUs:    2 * 1e9,            // 2 CPUs
		MemoryBytes: 1024 * 1024 * 1024, // 1 GB
		MemorySwap:  1024 * 1024 * 1024, // 1 GB
		PidsLimit:   512,
		CPUShares:   2048,
	}

	hc := &container.HostConfig{}
	limits.ApplyToHostConfig(hc)

	if hc.Resources.NanoCPUs != 2*1e9 {
		t.Errorf("Expected NanoCPUs 2*1e9, got %d", hc.Resources.NanoCPUs)
	}
	if hc.Resources.Memory != 1024*1024*1024 {
		t.Errorf("Expected Memory 1GB, got %d", hc.Resources.Memory)
	}
	if *hc.Resources.PidsLimit != 512 {
		t.Errorf("Expected PidsLimit 512, got %d", *hc.Resources.PidsLimit)
	}
	if hc.Resources.CPUShares != 2048 {
		t.Errorf("Expected CPUShares 2048, got %d", hc.Resources.CPUShares)
	}
}

func TestContainerConfig_MandatoryLabels(t *testing.T) {
	cfg := &runtime.ContainerConfig{
		Name:          "web-app-01",
		Image:         "alpine:3.20",
		ProjectID:     "proj-uuid-1",
		EnvironmentID: "env-uuid-1",
		ApplicationID: "app-uuid-1",
		InstanceID:    "inst-uuid-1",
	}

	cfg.EnsureMandatoryLabels()

	if cfg.Labels["primecloud.managed"] != "true" {
		t.Error("Missing primecloud.managed=true label")
	}
	if cfg.Labels["primecloud.project_id"] != "proj-uuid-1" {
		t.Errorf("Incorrect project_id label: %s", cfg.Labels["primecloud.project_id"])
	}
	if cfg.Labels["primecloud.application_id"] != "app-uuid-1" {
		t.Errorf("Incorrect application_id label: %s", cfg.Labels["primecloud.application_id"])
	}
}

func TestDockerRuntime_IntegrationLiveOrSkip(t *testing.T) {
	rt, err := runtime.NewDockerRuntime()
	if err != nil {
		t.Skipf("Docker client init failed: %v", err)
		return
	}
	defer rt.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := rt.Ping(ctx); err != nil {
		t.Logf("Local Docker daemon not currently responding: %v (skipping live container spawn)", err)
		return
	}

	t.Log("Local Docker daemon responded to Ping successfully")
}
