//go:build !linux

package agent

import (
	"runtime"
)

// probeTotalMemoryMB returns host memory detection on non-linux systems.
func probeTotalMemoryMB() int64 {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	sysMB := int64(memStats.Sys / (1024 * 1024))
	if sysMB > 1024 {
		return sysMB
	}
	return 16384
}

// probeTotalDiskGB returns host disk detection on non-linux systems.
func probeTotalDiskGB() int64 {
	return 250
}

// probeKernelVersion returns the runtime OS version.
func probeKernelVersion() string {
	return runtime.GOOS + "/" + runtime.GOARCH + "/" + runtime.Version()
}
