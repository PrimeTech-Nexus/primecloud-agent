// Package telemetry handles node metrics, logging, structured events, inventory, and heartbeats.
package telemetry

import (
	"context"
	"fmt"
	"time"

	"github.com/primecloud/primecloud-agent/internal/logs"
	agentruntime "github.com/primecloud/primecloud-agent/internal/runtime"
)

// LogEntry encapsulates a structured log record.
type LogEntry struct {
	Timestamp   time.Time `json:"timestamp"`
	ContainerID string    `json:"container_id"`
	Stream      string    `json:"stream"` // stdout or stderr
	Message     string    `json:"message"`
}

// FetchContainerLogs retrieves log lines from a managed container using proper stream demultiplexing.
func FetchContainerLogs(ctx context.Context, rt agentruntime.ContainerRuntime, containerID string, tailLines int) ([]LogEntry, error) {
	if rt == nil {
		return nil, fmt.Errorf("runtime is nil")
	}

	reader, err := rt.GetContainerLogs(ctx, containerID)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch container logs: %w", err)
	}
	defer reader.Close()

	items, err := logs.DemuxDockerLogStream(reader, "stdout")
	if err != nil {
		return nil, fmt.Errorf("failed to demux container logs: %w", err)
	}

	var entries []LogEntry
	for _, item := range items {
		ts := time.Now().UTC()
		if item.Timestamp != nil {
			ts = *item.Timestamp
		}
		entries = append(entries, LogEntry{
			Timestamp:   ts,
			ContainerID: containerID,
			Stream:      item.Stream,
			Message:     item.Message,
		})
	}

	if tailLines > 0 && len(entries) > tailLines {
		entries = entries[len(entries)-tailLines:]
	}

	return entries, nil
}
