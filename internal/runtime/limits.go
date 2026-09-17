// Package runtime provides the ContainerRuntime interface and Docker engine abstraction with hardened isolation profiles.
package runtime

import (
	"github.com/docker/docker/api/types/container"
)

// ResourceLimits defines cgroup resource constraints for customer and driver containers.
type ResourceLimits struct {
	NanoCPUs    int64 // CPU quota in units of 10^-9 CPUs (e.g. 1 CPU = 10^9)
	MemoryBytes int64 // Memory limit in bytes
	MemorySwap  int64 // Total memory + swap limit in bytes (-1 to disable swap)
	PidsLimit   int64 // Maximum number of processes/threads in container
	CPUShares   int64 // CPU shares (relative weight vs other containers)
}

// DefaultResourceLimits returns safe baseline container limits.
func DefaultResourceLimits() *ResourceLimits {
	return &ResourceLimits{
		NanoCPUs:    1 * 1e9,           // 1.0 CPU
		MemoryBytes: 512 * 1024 * 1024, // 512 MB
		MemorySwap:  512 * 1024 * 1024, // No extra swap
		PidsLimit:   256,               // Max 256 PIDs
		CPUShares:   1024,
	}
}

// ApplyToHostConfig configures resource limits on the Docker container HostConfig.
func (l *ResourceLimits) ApplyToHostConfig(hc *container.HostConfig) {
	if hc == nil || l == nil {
		return
	}

	res := container.Resources{
		NanoCPUs:   l.NanoCPUs,
		Memory:     l.MemoryBytes,
		MemorySwap: l.MemorySwap,
		CPUShares:  l.CPUShares,
	}

	if l.PidsLimit > 0 {
		res.PidsLimit = &l.PidsLimit
	}

	hc.Resources = res
}
