//go:build linux

package agent

import (
	"bufio"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
)

// probeTotalMemoryMB reads MemTotal from Linux /proc/meminfo.
func probeTotalMemoryMB() int64 {
	if f, err := os.Open("/proc/meminfo"); err == nil {
		defer f.Close()
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "MemTotal:") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					if kb, err := strconv.ParseInt(fields[1], 10, 64); err == nil && kb > 0 {
						return kb / 1024
					}
				}
			}
		}
	}
	return 32768
}

// probeTotalDiskGB checks filesystem blocks on root partition via statfs.
func probeTotalDiskGB() int64 {
	var stat syscall.Statfs_t
	if err := syscall.Statfs("/", &stat); err == nil {
		totalBytes := uint64(stat.Blocks) * uint64(stat.Bsize)
		if totalBytes > 0 {
			gb := int64(totalBytes / (1024 * 1024 * 1024))
			if gb > 0 {
				return gb
			}
		}
	}
	return 500
}

// probeKernelVersion reads /proc/sys/kernel/osrelease.
func probeKernelVersion() string {
	if data, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		ver := strings.TrimSpace(string(data))
		if ver != "" {
			return ver
		}
	}
	if data, err := os.ReadFile("/proc/version"); err == nil {
		fields := strings.Fields(string(data))
		if len(fields) >= 3 {
			return fields[2]
		}
	}
	return runtime.GOARCH + "/" + runtime.Version()
}
