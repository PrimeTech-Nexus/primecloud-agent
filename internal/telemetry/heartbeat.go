// Package telemetry handles node metrics, logging, structured events, inventory, and heartbeats.
package telemetry

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/primecloud/primecloud-agent/internal/protocol"
)

// DirectiveHandler callback for control plane instructions returned in heartbeats.
type DirectiveHandler func(resp *protocol.HeartbeatResponse) error

// HeartbeatSender manages periodic node health and capacity heartbeats.
type HeartbeatSender struct {
	client      protocol.AgentServiceClient
	agentID     string
	nodeID      string
	interval    time.Duration
	collector   *Collector
	onDirective DirectiveHandler
	logger      *slog.Logger
}

// NewHeartbeatSender creates a HeartbeatSender.
func NewHeartbeatSender(client protocol.AgentServiceClient, agentID, nodeID string, interval time.Duration, collector *Collector, onDirective DirectiveHandler, logger *slog.Logger) *HeartbeatSender {
	if interval <= 0 {
		interval = 10 * time.Second
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &HeartbeatSender{
		client:      client,
		agentID:     agentID,
		nodeID:      nodeID,
		interval:    interval,
		collector:   collector,
		onDirective: onDirective,
		logger:      logger.With("component", "heartbeat_sender"),
	}
}

// SendOnce sends a single heartbeat to the Control Plane.
func (s *HeartbeatSender) SendOnce(ctx context.Context) (*protocol.HeartbeatResponse, error) {
	if s.client == nil {
		return nil, fmt.Errorf("agent service client cannot be nil")
	}

	metrics, err := s.collector.CollectNodeMetrics(ctx)
	if err != nil {
		s.logger.Warn("failed_to_collect_metrics_for_heartbeat", "error", err.Error())
		metrics = &NodeMetrics{SampledAt: time.Now()}
	}

	req := &protocol.HeartbeatRequest{
		AgentId:            s.agentID,
		NodeId:             s.nodeID,
		CpuUsagePercent:    metrics.CPUUsagePercent,
		MemoryUsagePercent: metrics.MemoryUsagePercent,
		DiskUsagePercent:   metrics.DiskUsagePercent,
		ContainerCount:     int32(metrics.ContainerCount),
		HealthStatus:       "HEALTHY",
		SentAtUnix:         time.Now().Unix(),
	}

	resp, err := s.client.SendHeartbeat(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("heartbeat transmission failed: %w", err)
	}

	if !resp.Acknowledged {
		return nil, fmt.Errorf("control plane rejected heartbeat")
	}

	if s.onDirective != nil {
		if err := s.onDirective(resp); err != nil {
			s.logger.Error("failed_to_execute_heartbeat_directive", "error", err.Error())
		}
	}

	return resp, nil
}

// Start initiates the periodic heartbeat loop.
func (s *HeartbeatSender) Start(ctx context.Context) error {
	s.logger.Info("starting_heartbeat_loop", "interval_sec", s.interval.Seconds())
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			s.logger.Info("stopping_heartbeat_loop")
			return ctx.Err()
		case <-ticker.C:
			sendCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			_, err := s.SendOnce(sendCtx)
			cancel()
			if err != nil {
				s.logger.Warn("heartbeat_failed", "error", err.Error())
			}
		}
	}
}
