// Package metrics provides continuous background resource and container utilization sampling.
package metrics

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/primecloud/primecloud-agent/internal/protocol"
	agentruntime "github.com/primecloud/primecloud-agent/internal/runtime"
)

// ContainerMetric encapsulates workload container and database telemetry.
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

// HostMetricsSample represents a single host OS resource measurement with explicit availability flags.
// Unavailable metrics are never reported as fake zeros.
type HostMetricsSample struct {
	CPUUsagePercent    float64
	CPUAvailable       bool
	MemoryUsagePercent float64
	MemoryAvailable    bool
	AllocatedMemoryMB  int64
	TotalMemoryMB      int64
	DiskUsagePercent   float64
	DiskAvailable      bool
}

// MetricPayload encapsulates node and workload resource telemetry.
type MetricPayload struct {
	NodeID             string                     `json:"node_id"`
	AgentID            string                     `json:"agent_id"`
	CPUUsagePercent    float64                    `json:"cpu_usage_percent"`
	CPUAvailable       bool                       `json:"cpu_available"`
	MemoryUsagePercent float64                    `json:"memory_usage_percent"`
	MemoryAvailable    bool                       `json:"memory_available"`
	DiskUsagePercent   float64                    `json:"disk_usage_percent"`
	DiskAvailable      bool                       `json:"disk_available"`
	AllocatedMemoryMB  int64                      `json:"allocated_memory_mb"`
	TotalMemoryMB      int64                      `json:"total_memory_mb"`
	ContainerCount     int                        `json:"container_count"`
	ContainerStats     map[string]ContainerMetric `json:"container_stats,omitempty"`
	SampledAt          time.Time                  `json:"sampled_at"`
}

// Collector continuously samples metrics and transmits them to the Control Plane.
type Collector struct {
	mu              sync.Mutex
	interval        time.Duration
	nodeID          string
	agentID         string
	rt              agentruntime.ContainerRuntime
	grpcClient      protocol.AgentServiceClient
	controlPlaneURL string
	agentKey        string
	httpClient      *http.Client
	logger          *slog.Logger
	draining        bool
	failedCount     int

	// Host OS telemetry state & injectable readers for deterministic testing across OS targets
	goos            string
	prevCPUTotal    uint64
	prevCPUIdle     uint64
	hasPrevCPU      bool
	readFileFunc    func(path string) ([]byte, error)
	runCommandFunc  func(ctx context.Context, name string, args ...string) ([]byte, error)
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
		interval:       interval,
		nodeID:         nodeID,
		agentID:        agentID,
		rt:             rt,
		grpcClient:     grpcClient,
		httpClient:     &http.Client{Timeout: 10 * time.Second},
		logger:         logger.With("component", "metrics_collector"),
		goos:           runtime.GOOS,
		readFileFunc:   os.ReadFile,
		runCommandFunc: defaultRunCommand,
	}
}

// NewCollectorWithAuth constructs a Collector instance with direct authenticated HTTP transport to Control Plane.
func NewCollectorWithAuth(
	interval time.Duration,
	nodeID, agentID string,
	rt agentruntime.ContainerRuntime,
	controlPlaneURL string,
	agentKey string,
	logger *slog.Logger,
) *Collector {
	if interval <= 0 {
		interval = 15 * time.Second
	}
	if logger == nil {
		logger = slog.Default()
	}
	cleanURL := strings.TrimRight(controlPlaneURL, "/")
	if cleanURL != "" {
		if strings.HasSuffix(cleanURL, ":50051") {
			cleanURL = strings.TrimSuffix(cleanURL, ":50051") + ":8000"
		}
		if !strings.HasPrefix(cleanURL, "http://") && !strings.HasPrefix(cleanURL, "https://") {
			cleanURL = "http://" + cleanURL
		}
	}
	return &Collector{
		interval:        interval,
		nodeID:          nodeID,
		agentID:         agentID,
		rt:              rt,
		controlPlaneURL: cleanURL,
		agentKey:        agentKey,
		httpClient:      &http.Client{Timeout: 10 * time.Second},
		logger:          logger.With("component", "metrics_collector"),
		goos:            runtime.GOOS,
		readFileFunc:    os.ReadFile,
		runCommandFunc:  defaultRunCommand,
	}
}

func defaultRunCommand(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	return cmd.Output()
}

// SetDrain updates the collector's node drain awareness.
func (c *Collector) SetDrain(draining bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.draining = draining
}

// parseLinuxProcStat parses the aggregate "cpu " line from /proc/stat and returns (total, idle, ok).
func parseLinuxProcStat(raw string) (uint64, uint64, bool) {
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "cpu ") {
			fields := strings.Fields(line)
			if len(fields) < 5 {
				return 0, 0, false
			}
			var total uint64
			var idle uint64
			for i := 1; i < len(fields); i++ {
				v, err := strconv.ParseUint(fields[i], 10, 64)
				if err != nil {
					return 0, 0, false
				}
				total += v
				// idle (index 4) + iowait (index 5)
				if i == 4 || i == 5 {
					idle += v
				}
			}
			if total == 0 {
				return 0, 0, false
			}
			return total, idle, true
		}
	}
	return 0, 0, false
}

// parseLinuxMeminfo parses MemTotal and MemAvailable (or MemFree+Buffers+Cached) from /proc/meminfo.
func parseLinuxMeminfo(raw string) (usedPct float64, allocMB int64, totalMB int64, ok bool) {
	var memTotalKB, memAvailKB, memFreeKB, buffersKB, cachedKB uint64
	var hasTotal, hasAvail, hasFree bool

	for _, line := range strings.Split(raw, "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) < 2 {
			continue
		}
		val, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			continue
		}
		switch strings.TrimSuffix(fields[0], ":") {
		case "MemTotal":
			memTotalKB = val
			hasTotal = true
		case "MemAvailable":
			memAvailKB = val
			hasAvail = true
		case "MemFree":
			memFreeKB = val
			hasFree = true
		case "Buffers":
			buffersKB = val
		case "Cached":
			cachedKB = val
		}
	}

	if !hasTotal || memTotalKB == 0 {
		return 0, 0, 0, false
	}
	if !hasAvail {
		if !hasFree {
			return 0, 0, 0, false
		}
		memAvailKB = memFreeKB + buffersKB + cachedKB
	}
	if memAvailKB > memTotalKB {
		memAvailKB = memTotalKB
	}
	usedKB := memTotalKB - memAvailKB
	usedPct = (float64(usedKB) / float64(memTotalKB)) * 100.0
	allocMB = int64(usedKB / 1024)
	totalMB = int64(memTotalKB / 1024)
	return usedPct, allocMB, totalMB, true
}

// parsePOSIXDfOutput parses `df -kP /` output and returns disk usage percentage in [0, 100].
func parsePOSIXDfOutput(raw string) (float64, bool) {
	lines := strings.Split(strings.TrimSpace(raw), "\n")
	if len(lines) < 2 {
		return 0, false
	}
	// Find the last non-empty line
	dataLine := strings.TrimSpace(lines[len(lines)-1])
	fields := strings.Fields(dataLine)
	if len(fields) < 5 {
		return 0, false
	}
	// Prefer exact block calculation from 1K-blocks Used and Available (fields[2], fields[3])
	usedBlocks, errUsed := strconv.ParseFloat(fields[2], 64)
	availBlocks, errAvail := strconv.ParseFloat(fields[3], 64)
	if errUsed == nil && errAvail == nil && (usedBlocks+availBlocks) > 0 {
		pct := (usedBlocks / (usedBlocks + availBlocks)) * 100.0
		if pct >= 0.0 && pct <= 100.0 {
			return pct, true
		}
	}
	// Fallback to capacity column (e.g. "42%")
	capStr := strings.TrimSuffix(fields[4], "%")
	if pct, err := strconv.ParseFloat(capStr, 64); err == nil && pct >= 0.0 && pct <= 100.0 {
		return pct, true
	}
	return 0, false
}

// collectHostMetrics gathers real OS CPU, memory, and disk utilization.
// Never emits synthetic zero values when a measurement is unavailable.
func (c *Collector) collectHostMetrics(ctx context.Context) HostMetricsSample {
	var sample HostMetricsSample

	readFile := c.readFileFunc
	if readFile == nil {
		readFile = os.ReadFile
	}
	runCmd := c.runCommandFunc
	if runCmd == nil {
		runCmd = defaultRunCommand
	}
	goos := c.goos
	if goos == "" {
		goos = runtime.GOOS
	}

	switch goos {
	case "linux":
		// 1. CPU via /proc/stat delta (or /proc/loadavg on initial sample)
		if rawStat, err := readFile("/proc/stat"); err == nil {
			if total, idle, ok := parseLinuxProcStat(string(rawStat)); ok {
				c.mu.Lock()
				hasPrev := c.hasPrevCPU
				prevTotal := c.prevCPUTotal
				prevIdle := c.prevCPUIdle
				c.prevCPUTotal = total
				c.prevCPUIdle = idle
				c.hasPrevCPU = true
				c.mu.Unlock()

				if hasPrev && total > prevTotal {
					totalDelta := total - prevTotal
					idleDelta := uint64(0)
					if idle >= prevIdle {
						idleDelta = idle - prevIdle
					}
					if totalDelta >= idleDelta {
						sample.CPUUsagePercent = (float64(totalDelta-idleDelta) / float64(totalDelta)) * 100.0
						sample.CPUAvailable = true
					}
				}
			}
		}
		if !sample.CPUAvailable {
			if rawLoad, err := readFile("/proc/loadavg"); err == nil {
				parts := strings.Fields(string(rawLoad))
				if len(parts) > 0 {
					if load1, err := strconv.ParseFloat(parts[0], 64); err == nil && load1 >= 0 {
						cpuCount := float64(runtime.NumCPU())
						if cpuCount <= 0 {
							cpuCount = 1.0
						}
						pct := (load1 / cpuCount) * 100.0
						if pct > 100.0 {
							pct = 100.0
						}
						sample.CPUUsagePercent = pct
						sample.CPUAvailable = true
					}
				}
			}
		}

		// 2. Memory via /proc/meminfo
		if rawMem, err := readFile("/proc/meminfo"); err == nil {
			if pct, allocMB, totalMB, ok := parseLinuxMeminfo(string(rawMem)); ok {
				sample.MemoryUsagePercent = pct
				sample.AllocatedMemoryMB = allocMB
				sample.TotalMemoryMB = totalMB
				sample.MemoryAvailable = true
			}
		}

		// 3. Disk via POSIX df -kP /
		cmdCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		dfOut, err := runCmd(cmdCtx, "df", "-kP", "/")
		cancel()
		if err == nil {
			if pct, ok := parsePOSIXDfOutput(string(dfOut)); ok {
				sample.DiskUsagePercent = pct
				sample.DiskAvailable = true
			}
		}

	case "windows":
		// 1. CPU via wmic
		cmdCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		cpuOut, err := runCmd(cmdCtx, "wmic", "cpu", "get", "loadpercentage")
		cancel()
		if err == nil {
			for _, line := range strings.Split(string(cpuOut), "\n") {
				line = strings.TrimSpace(line)
				if line == "" || strings.EqualFold(line, "LoadPercentage") {
					continue
				}
				if v, parseErr := strconv.ParseFloat(line, 64); parseErr == nil && v >= 0.0 && v <= 100.0 {
					sample.CPUUsagePercent = v
					sample.CPUAvailable = true
					break
				}
			}
		}

		// 2. Memory via wmic OS
		cmdCtx2, cancel2 := context.WithTimeout(ctx, 2*time.Second)
		memOut, err := runCmd(cmdCtx2, "wmic", "OS", "get", "FreePhysicalMemory,TotalVisibleMemorySize")
		cancel2()
		if err == nil {
			for _, line := range strings.Split(strings.TrimSpace(string(memOut)), "\n") {
				fields := strings.Fields(strings.TrimSpace(line))
				if len(fields) >= 2 && !strings.EqualFold(fields[0], "FreePhysicalMemory") {
					freeKB, err1 := strconv.ParseFloat(fields[0], 64)
					totalKB, err2 := strconv.ParseFloat(fields[1], 64)
					if err1 == nil && err2 == nil && totalKB > 0 && freeKB <= totalKB {
						usedKB := totalKB - freeKB
						sample.MemoryUsagePercent = (usedKB / totalKB) * 100.0
						sample.AllocatedMemoryMB = int64(usedKB / 1024.0)
						sample.TotalMemoryMB = int64(totalKB / 1024.0)
						sample.MemoryAvailable = true
						break
					}
				}
			}
		}

		// 3. Disk via wmic logicaldisk
		cmdCtx3, cancel3 := context.WithTimeout(ctx, 2*time.Second)
		diskOut, err := runCmd(cmdCtx3, "wmic", "logicaldisk", "where", "DeviceID='C:'", "get", "FreeSpace,Size")
		cancel3()
		if err == nil {
			for _, line := range strings.Split(strings.TrimSpace(string(diskOut)), "\n") {
				fields := strings.Fields(strings.TrimSpace(line))
				if len(fields) >= 2 && !strings.EqualFold(fields[0], "FreeSpace") {
					freeB, err1 := strconv.ParseFloat(fields[0], 64)
					totalB, err2 := strconv.ParseFloat(fields[1], 64)
					if err1 == nil && err2 == nil && totalB > 0 && freeB <= totalB {
						sample.DiskUsagePercent = ((totalB - freeB) / totalB) * 100.0
						sample.DiskAvailable = true
						break
					}
				}
			}
		}
	default:
		// Unsupported operating system: explicitly mark host OS CPU and Disk as unavailable
		// rather than fabricating 0.0 values.
		sample.CPUAvailable = false
		sample.DiskAvailable = false
		sample.MemoryAvailable = false
	}

	return sample
}

// Sample collects current utilization metrics.
func (c *Collector) Sample(ctx context.Context) (*MetricPayload, error) {
	c.mu.Lock()
	draining := c.draining
	c.mu.Unlock()

	hostSample := c.collectHostMetrics(ctx)

	containerCount := 0
	containerStats := make(map[string]ContainerMetric)

	if c.rt != nil {
		if containers, err := c.rt.ListContainers(ctx, true); err == nil {
			containerCount = len(containers)
			for _, cnt := range containers {
				shortID := cnt.ID[:min(12, len(cnt.ID))]
				stat := ContainerMetric{State: cnt.State}

				if cnt.State == "running" {
					if statsReader, err := c.rt.GetContainerStats(ctx, cnt.ID); err == nil && statsReader != nil {
						var v types.StatsJSON
						if err := json.NewDecoder(statsReader).Decode(&v); err == nil {
							cpuDelta := float64(v.CPUStats.CPUUsage.TotalUsage) - float64(v.PreCPUStats.CPUUsage.TotalUsage)
							systemDelta := float64(v.CPUStats.SystemUsage) - float64(v.PreCPUStats.SystemUsage)
							if systemDelta > 0.0 && cpuDelta > 0.0 {
								cpuCount := len(v.CPUStats.CPUUsage.PercpuUsage)
								if cpuCount == 0 {
									cpuCount = int(v.CPUStats.OnlineCPUs)
								}
								if cpuCount == 0 {
									cpuCount = 1
								}
								stat.CPUUsagePercent = (cpuDelta / systemDelta) * float64(cpuCount) * 100.0
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
							} else if aid, ok := insp.Labels["primecloud.application_id"]; ok && aid != "" {
								stat.ResourceID = aid
							} else if wid, ok := insp.Labels["primecloud.workload.id"]; ok && wid != "" {
								stat.ResourceID = wid
							}
						}

						cntName := ""
						if len(cnt.Names) > 0 {
							cntName = cnt.Names[0]
						}

						cleanName := strings.TrimPrefix(cntName, "/")
						if strings.HasPrefix(cleanName, "primecloud-") {
							// Skip platform infrastructure and control-plane containers from tenant workload metrics
							continue
						}

						// Fallback: extract resource ID from standard container name pc-pg-<uuid> / pc-vk-<uuid> / pc-app-<uuid>
						if stat.ResourceID == "" {
							if strings.HasPrefix(cleanName, "pc-pg-") {
								stat.ResourceID = strings.TrimPrefix(cleanName, "pc-pg-")
							} else if strings.HasPrefix(cleanName, "pc-vk-") {
								stat.ResourceID = strings.TrimPrefix(cleanName, "pc-vk-")
							} else if strings.HasPrefix(cleanName, "pc-my-") || strings.HasPrefix(cleanName, "pc-mysql-") {
								stat.ResourceID = strings.TrimPrefix(strings.TrimPrefix(cleanName, "pc-mysql-"), "pc-my-")
							} else if strings.HasPrefix(cleanName, "pc-mg-") || strings.HasPrefix(cleanName, "pc-mongodb-") {
								stat.ResourceID = strings.TrimPrefix(strings.TrimPrefix(cleanName, "pc-mongodb-"), "pc-mg-")
							} else if strings.HasPrefix(cleanName, "pc-app-") {
								suffix := strings.TrimPrefix(cleanName, "pc-app-")
								parts := strings.Split(suffix, "-")
								if len(parts) >= 10 {
									// Format pc-app-<account-uuid>-<app-uuid>: 5 parts per UUID
									stat.ResourceID = strings.Join(parts[len(parts)-5:], "-")
								} else if len(parts) == 5 {
									stat.ResourceID = suffix
								}
							}
						}

						if isPostgres(cnt.Image) || isPostgres(cntName) {
							stat.Engine = "postgres"
							stat.QueryHealth = "failed"
							cmd := []string{"psql", "-U", "postgres", "-c", "SELECT count(*) FROM pg_stat_activity;"}
							stdout, _, exit, err := c.rt.ExecContainer(ctx, cnt.ID, cmd, nil, nil)
							if err == nil && exit == 0 {
								stat.QueryHealth = "healthy"
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

						if isMySQL(cnt.Image) || isMySQL(cntName) {
							stat.Engine = "mysql"
							stat.QueryHealth = "failed"
							cmd := []string{"mysql", "-h", "127.0.0.1", "-u", "root", "-N", "-B", "-e", "SHOW GLOBAL STATUS WHERE Variable_name IN ('Threads_connected', 'Questions', 'Uptime');"}
							stdout, _, exit, err := c.rt.ExecContainer(ctx, cnt.ID, cmd, nil, nil)
							if err == nil && exit == 0 {
								stat.QueryHealth = "healthy"
								lines := strings.Split(string(stdout), "\n")
								for _, line := range lines {
									fields := strings.Fields(strings.TrimSpace(line))
									if len(fields) >= 2 {
										val, parseErr := strconv.ParseInt(fields[1], 10, 64)
										if parseErr == nil {
											switch fields[0] {
											case "Threads_connected":
												stat.ActiveConnections = val
											case "Questions":
												stat.CommandsProcessed = val
											case "Uptime":
												if stat.UptimeSeconds == 0 {
													stat.UptimeSeconds = val
												}
											}
										}
									}
								}
							}

							sizeCmd := []string{"mysql", "-h", "127.0.0.1", "-u", "root", "-N", "-B", "-e", "SELECT COALESCE(SUM(data_length + index_length), 0) FROM information_schema.tables;"}
							sOut, _, sExit, sErr := c.rt.ExecContainer(ctx, cnt.ID, sizeCmd, nil, nil)
							if sErr == nil && sExit == 0 {
								if val, err := strconv.ParseInt(strings.TrimSpace(string(sOut)), 10, 64); err == nil {
									stat.DatabaseSizeBytes = val
								}
							}
						}

						if isMongoDB(cnt.Image) || isMongoDB(cntName) {
							stat.Engine = "mongodb"
							stat.QueryHealth = "failed"
							cmd := []string{"mongosh", "--quiet", "--eval", "JSON.stringify(db.serverStatus())"}
							stdout, _, exit, err := c.rt.ExecContainer(ctx, cnt.ID, cmd, nil, nil)
							if err == nil && exit == 0 {
								stat.QueryHealth = "healthy"
								var srv map[string]interface{}
								if jsonErr := json.Unmarshal(stdout, &srv); jsonErr == nil {
									if conns, ok := srv["connections"].(map[string]interface{}); ok {
										if cur, ok := conns["current"].(float64); ok {
											stat.ActiveConnections = int64(cur)
										}
									}
									if ops, ok := srv["opcounters"].(map[string]interface{}); ok {
										var totalOps int64
										for _, k := range []string{"insert", "query", "update", "delete", "command"} {
											if v, ok := ops[k].(float64); ok {
												totalOps += int64(v)
											}
										}
										stat.CommandsProcessed = totalOps
									}
									if mem, ok := srv["mem"].(map[string]interface{}); ok {
										if resMB, ok := mem["resident"].(float64); ok && stat.MemoryUsageBytes == 0 {
											stat.MemoryUsageBytes = int64(resMB) * 1024 * 1024
										}
									}
								}
							}

							sizeCmd := []string{"mongosh", "--quiet", "--eval", "db.stats().dataSize || 0"}
							sOut, _, sExit, sErr := c.rt.ExecContainer(ctx, cnt.ID, sizeCmd, nil, nil)
							if sErr == nil && sExit == 0 {
								if val, err := strconv.ParseInt(strings.TrimSpace(string(sOut)), 10, 64); err == nil {
									stat.DatabaseSizeBytes = val
								}
							}
						}

						if isValkey(cnt.Image) || isValkey(cntName) {
							stat.Engine = "valkey"
							stat.QueryHealth = "failed"
							cmd := []string{"valkey-cli", "info"}
							stdout, _, exit, err := c.rt.ExecContainer(ctx, cnt.ID, cmd, nil, nil)
							if err == nil && exit == 0 {
								stat.QueryHealth = "healthy"
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
				if cnt.State != "running" {
					stat.HealthStatus = "stopped"
					stat.QueryHealth = "failed"
					cntName := ""
					if len(cnt.Names) > 0 {
						cntName = strings.TrimPrefix(cnt.Names[0], "/")
					}
					if isPostgres(cnt.Image) || isPostgres(cntName) {
						stat.Engine = "postgres"
					} else if isMySQL(cnt.Image) || isMySQL(cntName) {
						stat.Engine = "mysql"
					} else if isMongoDB(cnt.Image) || isMongoDB(cntName) {
						stat.Engine = "mongodb"
					} else if isValkey(cnt.Image) || isValkey(cntName) {
						stat.Engine = "valkey"
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
		CPUUsagePercent:    hostSample.CPUUsagePercent,
		CPUAvailable:       hostSample.CPUAvailable,
		MemoryUsagePercent: hostSample.MemoryUsagePercent,
		MemoryAvailable:    hostSample.MemoryAvailable,
		DiskUsagePercent:   hostSample.DiskUsagePercent,
		DiskAvailable:      hostSample.DiskAvailable,
		AllocatedMemoryMB:  hostSample.AllocatedMemoryMB,
		TotalMemoryMB:      hostSample.TotalMemoryMB,
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
			} else if c.controlPlaneURL != "" {
				reportCtx, rCancel := context.WithTimeout(ctx, 10*time.Second)
				c.transmitHTTP(reportCtx, metrics)
				rCancel()
			}
		}
	}
}

type IngestMetricPoint struct {
	ResourceID   string  `json:"resource_id"`
	ResourceType string  `json:"resource_type"`
	MetricName   string  `json:"metric_name"`
	Value        float64 `json:"value"`
	Unit         string  `json:"unit"`
	Timestamp    string  `json:"timestamp,omitempty"`
}

type IngestMetricBatch struct {
	NodeID  string              `json:"node_id,omitempty"`
	Metrics []IngestMetricPoint `json:"metrics"`
}

// BuildIngestBatch converts a MetricPayload into the canonical IngestMetricBatch contract.
// Host metrics are only included when their corresponding *Available flag is true, preventing fake zero emissions.
func (c *Collector) BuildIngestBatch(metrics *MetricPayload) IngestMetricBatch {
	sampledIso := metrics.SampledAt.UTC().Format(time.RFC3339)
	var points []IngestMetricPoint

	// 1. Host Node Level Metrics (only emitted when genuinely available)
	if metrics.CPUAvailable {
		points = append(points, IngestMetricPoint{
			ResourceID:   c.nodeID,
			ResourceType: "node",
			MetricName:   "cpu_usage_percent",
			Value:        metrics.CPUUsagePercent,
			Unit:         "percent",
			Timestamp:    sampledIso,
		})
	}
	if metrics.MemoryAvailable {
		points = append(points, IngestMetricPoint{
			ResourceID:   c.nodeID,
			ResourceType: "node",
			MetricName:   "memory_usage_percent",
			Value:        metrics.MemoryUsagePercent,
			Unit:         "percent",
			Timestamp:    sampledIso,
		})
	}
	if metrics.DiskAvailable {
		points = append(points, IngestMetricPoint{
			ResourceID:   c.nodeID,
			ResourceType: "node",
			MetricName:   "disk_usage_percent",
			Value:        metrics.DiskUsagePercent,
			Unit:         "percent",
			Timestamp:    sampledIso,
		})
	}

	// 2. Container / Workload Level Metrics
	for shortID, stat := range metrics.ContainerStats {
		resID := stat.ResourceID
		if resID == "" {
			resID = shortID
		}
		resType := "application"
		if stat.Engine != "" {
			resType = stat.Engine
		}

		// Only emit running container CPU/memory points so stopped containers don't masquerade as healthy 0% usage
		if stat.State == "running" {
			points = append(points,
				IngestMetricPoint{
					ResourceID:   resID,
					ResourceType: resType,
					MetricName:   "cpu_usage_percent",
					Value:        stat.CPUUsagePercent,
					Unit:         "percent",
					Timestamp:    sampledIso,
				},
				IngestMetricPoint{
					ResourceID:   resID,
					ResourceType: resType,
					MetricName:   "memory_usage_bytes",
					Value:        float64(stat.MemoryUsageBytes),
					Unit:         "bytes",
					Timestamp:    sampledIso,
				},
			)
			if stat.NetworkRxBytes > 0 {
				points = append(points, IngestMetricPoint{
					ResourceID:   resID,
					ResourceType: resType,
					MetricName:   "network_rx_bytes",
					Value:        float64(stat.NetworkRxBytes),
					Unit:         "bytes",
					Timestamp:    sampledIso,
				})
			}
			if stat.NetworkTxBytes > 0 {
				points = append(points, IngestMetricPoint{
					ResourceID:   resID,
					ResourceType: resType,
					MetricName:   "network_tx_bytes",
					Value:        float64(stat.NetworkTxBytes),
					Unit:         "bytes",
					Timestamp:    sampledIso,
				})
			}
		}

		if stat.UptimeSeconds > 0 {
			points = append(points, IngestMetricPoint{
				ResourceID:   resID,
				ResourceType: resType,
				MetricName:   "uptime_seconds",
				Value:        float64(stat.UptimeSeconds),
				Unit:         "s",
				Timestamp:    sampledIso,
			})
		}
		if stat.ActiveConnections > 0 {
			points = append(points, IngestMetricPoint{
				ResourceID:   resID,
				ResourceType: resType,
				MetricName:   "active_connections",
				Value:        float64(stat.ActiveConnections),
				Unit:         "count",
				Timestamp:    sampledIso,
			})
		}
		if stat.DatabaseSizeBytes > 0 {
			points = append(points, IngestMetricPoint{
				ResourceID:   resID,
				ResourceType: resType,
				MetricName:   "database_size_bytes",
				Value:        float64(stat.DatabaseSizeBytes),
				Unit:         "bytes",
				Timestamp:    sampledIso,
			})
		}
		if stat.ConnectedClients > 0 {
			points = append(points, IngestMetricPoint{
				ResourceID:   resID,
				ResourceType: resType,
				MetricName:   "connected_clients",
				Value:        float64(stat.ConnectedClients),
				Unit:         "count",
				Timestamp:    sampledIso,
			})
		}
		if stat.CommandsProcessed > 0 {
			points = append(points, IngestMetricPoint{
				ResourceID:   resID,
				ResourceType: resType,
				MetricName:   "commands_processed",
				Value:        float64(stat.CommandsProcessed),
				Unit:         "count",
				Timestamp:    sampledIso,
			})
		}
		if stat.QueryHealth != "" {
			qVal := 0.0
			if stat.QueryHealth == "healthy" {
				qVal = 1.0
			}
			points = append(points, IngestMetricPoint{
				ResourceID:   resID,
				ResourceType: resType,
				MetricName:   "query_health",
				Value:        qVal,
				Unit:         "status",
				Timestamp:    sampledIso,
			})
		}
	}

	return IngestMetricBatch{
		NodeID:  c.nodeID,
		Metrics: points,
	}
}

func (c *Collector) transmitHTTP(ctx context.Context, metrics *MetricPayload) {
	if c.controlPlaneURL == "" {
		return
	}

	batch := c.BuildIngestBatch(metrics)
	if len(batch.Metrics) == 0 {
		return
	}

	bodyBytes, err := json.Marshal(batch)
	if err != nil {
		c.logger.Warn("metrics_marshal_failed", "error", err)
		return
	}

	ingestURL := fmt.Sprintf("%s/v1/monitoring/ingest/metrics", c.controlPlaneURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ingestURL, bytes.NewReader(bodyBytes))
	if err != nil {
		c.logger.Warn("metrics_request_creation_failed", "error", err)
		return
	}

	b := make([]byte, 16)
	_, _ = rand.Read(b)
	idempKey := fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])

	req.Header.Set("Content-Type", "application/json")
	if c.agentKey != "" {
		req.Header.Set("X-Agent-Key", c.agentKey)
	}
	req.Header.Set("X-Sender-Identity", "agent:"+c.nodeID)
	req.Header.Set("Idempotency-Key", idempKey)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		c.mu.Lock()
		c.failedCount++
		c.mu.Unlock()
		c.logger.Warn("metrics_http_ingest_failed", "error", err, "failed_count", c.failedCount)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		c.mu.Lock()
		c.failedCount = 0
		c.mu.Unlock()
		c.logger.Debug("metrics_http_ingest_successful", "accepted_points", len(batch.Metrics))
	} else {
		c.mu.Lock()
		c.failedCount++
		c.mu.Unlock()
		c.logger.Warn("metrics_http_ingest_rejected", "status_code", resp.StatusCode, "failed_count", c.failedCount)
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

func isMySQL(name string) bool {
	lower := strings.ToLower(name)
	return strings.Contains(lower, "mysql") || strings.HasPrefix(strings.TrimPrefix(lower, "/"), "pc-my-")
}

func isMongoDB(name string) bool {
	lower := strings.ToLower(name)
	return strings.Contains(lower, "mongo") || strings.HasPrefix(strings.TrimPrefix(lower, "/"), "pc-mg-")
}

func isValkeyLegacy(name string) bool {
	return strings.Contains(strings.ToLower(name), "valkey")
}
