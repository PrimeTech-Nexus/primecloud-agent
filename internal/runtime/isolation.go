// Package runtime provides the ContainerRuntime interface and Docker engine abstraction with hardened isolation profiles.
package runtime

import (
	"errors"
	"fmt"
	"strings"

	"github.com/docker/docker/api/types/container"
)

var (
	ErrPrivilegedNotAllowed  = errors.New("privileged containers are strictly forbidden")
	ErrDockerSocketForbidden = errors.New("mounting docker socket inside customer container is strictly forbidden")
)

// HardenedIsolationProfile enforces the PrimeCloud multi-tenant security envelope.
type HardenedIsolationProfile struct {
	DropCapabilities   []string
	AddCapabilities    []string
	SecurityOpts       []string
	User               string
	ReadOnlyRootfs     bool
	AutoRemove         bool
	DisallowPrivileged bool
}

// DefaultHardenedProfile returns the standard hardened profile mandated for customer workloads.
func DefaultHardenedProfile() *HardenedIsolationProfile {
	return &HardenedIsolationProfile{
		DropCapabilities: []string{"ALL"},
		AddCapabilities:  []string{"NET_BIND_SERVICE"},
		SecurityOpts: []string{
			"no-new-privileges:true",
			"apparmor=docker-default",
			"seccomp=builtin",
		},
		User:               "1000:1000",
		ReadOnlyRootfs:     false,
		DisallowPrivileged: true,
	}
}

// ApplyToContainerConfig configures the user and security profile on the ContainerConfig.
func (p *HardenedIsolationProfile) ApplyToContainerConfig(cfg *container.Config) {
	if cfg == nil || p == nil {
		return
	}
	if cfg.User == "" && p.User != "" {
		cfg.User = p.User
	}
}

// ApplyToHostConfig enforces the hardened isolation profile onto the Docker HostConfig.
func (p *HardenedIsolationProfile) ApplyToHostConfig(hc *container.HostConfig) error {
	if hc == nil || p == nil {
		return nil
	}

	// 1. Strictly forbid privileged containers
	if hc.Privileged {
		return ErrPrivilegedNotAllowed
	}

	// 2. Validate mounts to ensure NO Docker socket is ever mounted
	for _, bind := range hc.Binds {
		lowerBind := strings.ToLower(bind)
		if strings.Contains(lowerBind, "docker.sock") || strings.Contains(lowerBind, "docker_engine") {
			return fmt.Errorf("%w: mount %s violated security policy", ErrDockerSocketForbidden, bind)
		}
	}
	for _, mount := range hc.Mounts {
		lowerSrc := strings.ToLower(mount.Source)
		if strings.Contains(lowerSrc, "docker.sock") || strings.Contains(lowerSrc, "docker_engine") {
			return fmt.Errorf("%w: mount %s violated security policy", ErrDockerSocketForbidden, mount.Source)
		}
	}

	// 3. Drop all capabilities; add back only minimal
	hc.CapDrop = append([]string(nil), p.DropCapabilities...)
	hc.CapAdd = append([]string(nil), p.AddCapabilities...)

	// 4. Append SecurityOpts (no-new-privileges, etc.)
	hc.SecurityOpt = append(hc.SecurityOpt, p.SecurityOpts...)

	// 5. Enforce isolated PID/IPC namespaces (never host)
	hc.PidMode = container.PidMode("")
	hc.IpcMode = container.IpcMode("private")

	// 6. User namespace private mode
	hc.UsernsMode = container.UsernsMode("private")

	// 7. Read-only rootfs if requested
	if p.ReadOnlyRootfs {
		hc.ReadonlyRootfs = true
	}

	return nil
}
