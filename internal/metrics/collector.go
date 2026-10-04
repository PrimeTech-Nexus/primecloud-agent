// Package metrics provides continuous background resource and container utilization sampling.
package metrics

import (
	"context"
	"encoding/json"
	"log/slog"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/primecloud/primecloud-agent/internal/protocol"
	agentruntime "github.com/primecloud/primecloud-agent/internal/runtime"
)

// MetricPayload encapsulates node and workload resource telemetry.

type ContainerMetric struct {
	ResourceID        string  `json:"resource_id,omitempty"`
	Engine            string  `json:"engine,omitempty"`
	State             string  `json:"state"`
	CPUUsagePercent   float64 `json:"cpu_usage_percent"`
	MemoryUsageBytes  int64   `json:"memory_usage_bytes"`
	MemoryLimitBytes  int64   `json:"memory_limit_bytes"`
	NetworkRxBytes    int64   `json:"network_rx_bytes"`
	NetworkTxBytes    int64   `json:"network_tx_bytes"`
	UptimeSeconds     int64   `json:"uptime_seconds"`
	HealthStatus      string  `json:"health_status"`
	RestartCount      int     `json:"restart_count"`
	ActiveConnections int64   `json:"active_connections,omitempty"`
	DatabaseSizeBytes int64   `json:"database_size_bytes,omitempty"`
	TransactionCount  int64   `json:"transaction_count,omitempty"`
	QueryHealth       string  `json:"query_health,omitempty"`
	ConnectedClients  int64   `json:"connected_clients,omitempty"`
	CommandsProcessed int64   `json:"commands_processed,omitempty"`
	KeyCount          int64   `json:"key_count,omitempty"`
	ReplicationStatus string  `json:"replication_status,omitempty"`
}

type MetricPayload struct {
	NodeID             string                     `json:"node_id"`
	AgentID            string                     `json:"agent_id"`
	CPUUsagePercent    float64                    `json:"cpu_usage_percent"`
	MemoryUsagePercent float64                    `json:"memory_usage_percent"`
	DiskUsagePercent   float64                    `json:"disk_usage_percent"`
	AllocatedMemoryMB  int64                      `json:"allocated_memory_mb"`
	TotalMemoryMB      int64                      `json:"total_memory_mb"`
	ContainerCount     int                        `json:"container_count"`
	ContainerStats     map[string]ContainerMetric `json:"container_stats,omitempty"`
	SampledAt          time.Time                  `json:"sampled_at"`
}

// Collector continuously samples metrics and transmits them to the Control Plane.
type Collector struct {
	mu          sync.Mutex
	interval    time.Duration
	nodeID      string
	agentID     string
	rt          agentruntime.ContainerRuntime
	grpcClient  protocol.AgentServiceClient
	logger      *slog.Logger
	draining    bool
	failedCount int
}

// NewCollector constructs a Collector instance.
func NewCollector(
	interval time.Duration,
	nodeID, agentID string,
	rt agentruntime.ContainerRuntime,
	grpcClient protocol.AgentServiceClient,
	logger *slog.Logger,
) *Collector {
	if interval <= 0 {
		interval = 15 * time.Second
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Collector{
		interval:   interval,
		nodeID:     nodeID,
		agentID:    agentID,
		rt:         rt,
		grpcClient: grpcClient,
		logger:     logger.With("component", "metrics_collector"),
	}
}

// SetDrain updates the collector's node drain awareness.
func (c *Collector) SetDrain(draining bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.draining = draining
}

// Sample collects current utilization metrics.
func (c *Collector) Sample(ctx context.Context) (*MetricPayload, error) {
	c.mu.Lock()
	draining := c.draining
	c.mu.Unlock()

	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	allocatedMB := int64(memStats.Alloc / (1024 * 1024))
	sysMB := int64(memStats.Sys / (1024 * 1024))
	if sysMB == 0 {
		sysMB = 1024
	}

	memPercent := 5.0
	if memStats.Sys > 0 {
		memPercent = float64(memStats.Alloc) / float64(memStats.Sys) * 100.0
	}

	containerCount := 0
	containerStats := make(map[string]ContainerMetric)

	var nodeCPU float64 = 0.0
	var nodeDisk float64 = 0.0
	// Real OS metrics would be collected here.

	if c.rt != nil {
		if containers, err := c.rt.ListContainers(ctx, true); err == nil {
			containerCount = len(containers)
			for _, cnt := range containers {
				shortID := cnt.ID[:min(12, len(cnt.ID))]
				stat := ContainerMetric{State: cnt.State}

				if cnt.State == "running" {
					if statsReader, err := c.rt.GetContainerStats(ctx, cnt.ID); err == nil && statsReader != nil {
						defer statsReader.Close()
						var v types.StatsJSON
						if err := json.NewDecoder(statsReader).Decode(&v); err == nil {
							cpuDelta := float64(v.CPUStats.CPUUsage.TotalUsage) - float64(v.PreCPUStats.CPUUsage.TotalUsage)
							systemDelta := float64(v.CPUStats.SystemUsage) - float64(v.PreCPUStats.SystemUsage)
							if systemDelta > 0.0 && cpuDelta > 0.0 {
								stat.CPUUsagePercent = (cpuDelta / systemDelta) * float64(len(v.CPUStats.CPUUsage.PercpuUsage)) * 100.0
							}
							stat.MemoryUsageBytes = int64(v.MemoryStats.Usage)
							stat.MemoryLimitBytes = int64(v.MemoryStats.Limit)
							var rx, tx int64
							for _, netStat := range v.Networks {
								rx += int64(netStat.RxBytes)
								tx += int64(netStat.TxBytes)
							}
							stat.NetworkRxBytes = rx
							stat.NetworkTxBytes = tx
						}
						statsReader.Close()
					}

					if insp, err := c.rt.InspectContainer(ctx, cnt.ID); err == nil {
						stat.HealthStatus = insp.Health
						stat.RestartCount = insp.RestartCount
						uptime := time.Since(insp.StartedAt).Seconds()
						if uptime > 0 {
							stat.UptimeSeconds = int64(uptime)
						}
						if insp.Labels != nil {
							if rid, ok := insp.Labels["primecloud.resource_id"]; ok && rid != "" {
								stat.ResourceID = rid
							}
						}

						cntName := ""
						if len(cnt.Names) > 0 {
							cntName = cnt.Names[0]
						}

						// Fallback: extract resource ID from standard container name pc-pg-<uuid> / pc-vk-<uuid>
						if stat.ResourceID == "" {
							cleanName := strings.TrimPrefix(cntName, "/")
							if strings.HasPrefix(cleanName, "pc-pg-") {
								stat.ResourceID = strings.TrimPrefix(cleanName, "pc-pg-")
							} else if strings.HasPrefix(cleanName, "pc-vk-") {
								stat.ResourceID = strings.TrimPrefix(cleanName, "pc-vk-")
							}
						}

						if isPostgres(cnt.Image) || isPostgres(cntName) {
							stat.Engine = "postgres"
							cmd := []string{"psql", "-U", "postgres", "-c", "SELECT count(*) FROM pg_stat_activity;"}
							stdout, _, exit, err := c.rt.ExecContainer(ctx, cnt.ID, cmd, nil, nil)
							if err == nil && exit == 0 {
								lines := strings.Split(string(stdout), "\n")
								for _, line := range lines {
									line = strings.TrimSpace(line)
									if val, err := strconv.ParseInt(line, 10, 64); err == nil {
										stat.ActiveConnections = val
									}
								}
							}

							cmd = []string{"psql", "-U", "postgres", "-c", "SELECT sum(pg_database_size(datname)) FROM pg_database;"}
							stdout, _, exit, err = c.rt.ExecContainer(ctx, cnt.ID, cmd, nil, nil)
							if err == nil && exit == 0 {
								lines := strings.Split(string(stdout), "\n")
								for _, line := range lines {
									line = strings.TrimSpace(line)
									if val, err := strconv.ParseInt(line, 10, 64); err == nil {
										stat.DatabaseSizeBytes = val
									}
								}
							}
						}

						if isValkey(cnt.Image) || isValkey(cntName) {
							stat.Engine = "valkey"
							cmd := []string{"valkey-cli", "info"}
							stdout, _, exit, err := c.rt.ExecContainer(ctx, cnt.ID, cmd, nil, nil)
							if err == nil && exit == 0 {
								lines := strings.Split(string(stdout), "\n")
								for _, line := range lines {
									line = strings.TrimSpace(line)
									if strings.HasPrefix(line, "connected_clients:") {
										if val, err := strconv.ParseInt(strings.TrimPrefix(line, "connected_clients:"), 10, 64); err == nil {
											stat.ConnectedClients = val
										}
									} else if strings.HasPrefix(line, "used_memory:") {
										if val, err := strconv.ParseInt(strings.TrimPrefix(line, "used_memory:"), 10, 64); err == nil {
											stat.MemoryUsageBytes = val
										}
									} else if strings.HasPrefix(line, "total_commands_processed:") {
										if val, err := strconv.ParseInt(strings.TrimPrefix(line, "total_commands_processed:"), 10, 64); err == nil {
											stat.CommandsProcessed = val
										}
									} else if strings.HasPrefix(line, "role:") {
										stat.ReplicationStatus = strings.TrimPrefix(line, "role:")
									}
								}
							}
						}
					}
				}
				containerStats[shortID] = stat
			}
		}
	}

	if draining {
		c.logger.Info("metrics_sampled_under_node_drain", "container_count", containerCount)
	}

	return &MetricPayload{
		NodeID:             c.nodeID,
		AgentID:            c.agentID,
		CPUUsagePercent:    nodeCPU,
		MemoryUsagePercent: memPercent,
		DiskUsagePercent:   nodeDisk,
		AllocatedMemoryMB:  allocatedMB,
		TotalMemoryMB:      sysMB,
		ContainerCount:     containerCount,
		ContainerStats:     containerStats,
		SampledAt:          time.Now(),
	}, nil

}

// Start boots the continuous collection ticker in a background goroutine.
func (c *Collector) Start(ctx context.Context) {
	c.logger.Info("metrics_collector_started", "interval_sec", c.interval.Seconds())
	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			c.logger.Info("metrics_collector_stopped")
			return
		case <-ticker.C:
			sampleCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			metrics, err := c.Sample(sampleCtx)
			cancel()

			if err != nil {
				c.logger.Warn("metrics_sampling_failed", "error", err)
				continue
			}

			if c.grpcClient != nil {
				raw, err := json.Marshal(metrics)
				if err != nil {
					continue
				}

				req := &protocol.MetricsRequest{
					AgentId:       c.agentID,
					NodeId:        c.nodeID,
					MetricsJson:   string(raw),
					SampledAtUnix: metrics.SampledAt.Unix(),
				}

				reportCtx, rCancel := context.WithTimeout(ctx, 5*time.Second)
				resp, err := c.grpcClient.ReportMetrics(reportCtx, req)
				rCancel()

				if err != nil {
					c.mu.Lock()
					c.failedCount++
					c.mu.Unlock()
					c.logger.Warn("metrics_report_failed_retrying_next_tick", "error", err, "failed_count", c.failedCount)
				} else if resp != nil && resp.Recorded {
					c.mu.Lock()
					c.failedCount = 0
					c.mu.Unlock()
					c.logger.Debug("metrics_report_successful")
				}
			}
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func isPostgres(name string) bool {
	return strings.Contains(strings.ToLower(name), "postgres")
}

func isValkey(name string) bool {
	return strings.Contains(strings.ToLower(name), "valkey")
}
