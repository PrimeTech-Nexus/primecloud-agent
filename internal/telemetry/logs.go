// Package telemetry handles node metrics, logging, structured events, inventory, and heartbeats.
package telemetry

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	agentruntime "github.com/primecloud/primecloud-agent/internal/runtime"
)

// LogEntry encapsulates a structured log record.
type LogEntry struct {
	Timestamp   time.Time `json:"timestamp"`
	ContainerID string    `json:"container_id"`
	Stream      string    `json:"stream"` // stdout or stderr
	Message     string    `json:"message"`
}

// FetchContainerLogs retrieves log lines from a managed container.
func FetchContainerLogs(ctx context.Context, rt agentruntime.ContainerRuntime, containerID string, tailLines int) ([]LogEntry, error) {
	if rt == nil {
		return nil, fmt.Errorf("runtime is nil")
	}

	reader, err := rt.GetContainerLogs(ctx, containerID)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch container logs: %w", err)
	}
	defer reader.Close()

	buf, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read container logs: %w", err)
	}

	lines := strings.Split(string(buf), "\n")
	var entries []LogEntry
	now := time.Now()

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		entries = append(entries, LogEntry{
			Timestamp:   now,
			ContainerID: containerID,
			Stream:      "stdout",
			Message:     trimmed,
		})
	}

	if tailLines > 0 && len(entries) > tailLines {
		entries = entries[len(entries)-tailLines:]
	}

	return entries, nil
}
