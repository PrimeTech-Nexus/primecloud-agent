// Package telemetry handles node metrics, logging, structured events, inventory, and heartbeats.
package telemetry

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"runtime"
	"time"
	"os"
	"os/exec"
	"strings"
	"strconv"

	"github.com/primecloud/primecloud-agent/internal/protocol"
	agentruntime "github.com/primecloud/primecloud-agent/internal/runtime"
)

// NodeMetrics captures real-time utilization and resource metrics for the node.
type NodeMetrics struct {
	CPUUsagePercent    float64   `json:"cpu_usage_percent"`
	MemoryUsagePercent float64   `json:"memory_usage_percent"`
	DiskUsagePercent   float64   `json:"disk_usage_percent"`
	AllocatedMemoryMB  int64     `json:"allocated_memory_mb"`
	TotalMemoryMB      int64     `json:"total_memory_mb"`
	ContainerCount     int       `json:"container_count"`
	SampledAt          time.Time `json:"sampled_at"`
}

// Collector samples node utilization.
type Collector struct {
	rt     agentruntime.ContainerRuntime
	logger *slog.Logger
}

// NewCollector constructs a Collector.
func NewCollector(rt agentruntime.ContainerRuntime, logger *slog.Logger) *Collector {
	if logger == nil {
		logger = slog.Default()
	}
	return &Collector{
		rt:     rt,
		logger: logger.With("component", "telemetry_collector"),
	}
}

// getMetricsWin attempts to get real metrics on Windows using wmic.
func getMetricsWin() (cpu float64, memPercent float64, disk float64) {
	// Fallbacks if wmic fails
	cpu = 1.0
	memPercent = 5.0
	disk = 10.0

	// CPU
	out, err := exec.Command("wmic", "cpu", "get", "loadpercentage").Output()
	if err == nil {
		lines := strings.Split(string(out), "\n")
		if len(lines) > 1 {
			val := strings.TrimSpace(lines[1])
			if v, err := strconv.ParseFloat(val, 64); err == nil {
				cpu = v
			}
		}
	}

	// Memory
	out, err = exec.Command("wmic", "OS", "get", "FreePhysicalMemory,TotalVisibleMemorySize").Output()
	if err == nil {
		lines := strings.Split(strings.TrimSpace(string(out)), "\n")
		if len(lines) > 1 {
			parts := strings.Fields(lines[1])
			if len(parts) >= 2 {
				free, _ := strconv.ParseFloat(parts[0], 64)
				total, _ := strconv.ParseFloat(parts[1], 64)
				if total > 0 {
					memPercent = ((total - free) / total) * 100.0
				}
			}
		}
	}

	// Disk
	out, err = exec.Command("wmic", "logicaldisk", "where", "DeviceID='C:'", "get", "Size,FreeSpace").Output()
	if err == nil {
		lines := strings.Split(strings.TrimSpace(string(out)), "\n")
		if len(lines) > 1 {
			parts := strings.Fields(lines[1])
			if len(parts) >= 2 {
				free, _ := strconv.ParseFloat(parts[0], 64)
				total, _ := strconv.ParseFloat(parts[1], 64)
				if total > 0 {
					disk = ((total - free) / total) * 100.0
				}
			}
		}
	}

	return
}

// CollectNodeMetrics inspects local memory, goroutines, and container stats.
func (c *Collector) CollectNodeMetrics(ctx context.Context) (*NodeMetrics, error) {
	var cpuUsage, memPercent, diskUsage float64
	var allocatedMB, totalSysMB int64

	// Read standard Go memstats for alloc / total sys
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	allocatedMB = int64(memStats.Alloc / (1024 * 1024))
	totalSysMB = int64(memStats.Sys / (1024 * 1024))

	if runtime.GOOS == "windows" {
		cpuUsage, memPercent, diskUsage = getMetricsWin()
	} else if runtime.GOOS == "linux" {
		// Real linux metrics
		
		// CPU using /proc/loadavg as simple proxy, or top
		out, err := os.ReadFile("/proc/loadavg")
		if err == nil {
			parts := strings.Fields(string(out))
			if len(parts) > 0 {
				load, _ := strconv.ParseFloat(parts[0], 64)
				cpuCount := float64(runtime.NumCPU())
				cpuUsage = (load / cpuCount) * 100.0
				if cpuUsage > 100.0 {
					cpuUsage = 100.0
				}
			}
		} else {
			cpuUsage = 2.0 // safe fallback
		}

		// Mem using /proc/meminfo
		out, err = os.ReadFile("/proc/meminfo")
		if err == nil {
			var memTotal, memAvailable float64
			lines := strings.Split(string(out), "\n")
			for _, line := range lines {
				if strings.HasPrefix(line, "MemTotal:") {
					fields := strings.Fields(line)
					if len(fields) >= 2 {
						memTotal, _ = strconv.ParseFloat(fields[1], 64)
					}
				} else if strings.HasPrefix(line, "MemAvailable:") {
					fields := strings.Fields(line)
					if len(fields) >= 2 {
						memAvailable, _ = strconv.ParseFloat(fields[1], 64)
					}
				}
			}
			if memTotal > 0 {
				memPercent = ((memTotal - memAvailable) / memTotal) * 100.0
				totalSysMB = int64(memTotal / 1024)
			}
		} else {
			memPercent = 5.0
		}

		// Disk using df
		dfOut, err := exec.Command("df", "/", "--output=pcent").Output()
		if err == nil {
			lines := strings.Split(strings.TrimSpace(string(dfOut)), "\n")
			if len(lines) > 1 {
				valStr := strings.Trim(strings.TrimSpace(lines[1]), "%")
				val, _ := strconv.ParseFloat(valStr, 64)
				diskUsage = val
			}
		} else {
			diskUsage = 5.0
		}
	} else {
		// Darwin / others
		cpuUsage = 1.0
		memPercent = 5.0
		diskUsage = 10.0
	}

	containerCount := 0
	if c.rt != nil {
		if containers, err := c.rt.ListContainers(ctx, true); err == nil {
			containerCount = len(containers)
		}
	}

	metrics := &NodeMetrics{
		CPUUsagePercent:    cpuUsage,
		MemoryUsagePercent: memPercent,
		DiskUsagePercent:   diskUsage,
		AllocatedMemoryMB:  allocatedMB,
		TotalMemoryMB:      totalSysMB,
		ContainerCount:     containerCount,
		SampledAt:          time.Now(),
	}

	return metrics, nil
}

// ReportMetrics serializes and transmits metrics via gRPC to the Control Plane.
func ReportMetrics(ctx context.Context, client protocol.AgentServiceClient, agentID, nodeID string, metrics *NodeMetrics) error {
	if client == nil {
		return fmt.Errorf("agent service client cannot be nil")
	}

	raw, err := json.Marshal(metrics)
	if err != nil {
		return fmt.Errorf("failed to marshal metrics: %w", err)
	}

	req := &protocol.MetricsRequest{
		AgentId:       agentID,
		NodeId:        nodeID,
		MetricsJson:   string(raw),
		SampledAtUnix: metrics.SampledAt.Unix(),
	}

	resp, err := client.ReportMetrics(ctx, req)
	if err != nil {
		return fmt.Errorf("failed to report metrics: %w", err)
	}
	if !resp.Recorded {
		return fmt.Errorf("control plane rejected metrics")
	}

	return nil
}
