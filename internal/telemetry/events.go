// Package telemetry handles node metrics, logging, structured events, inventory, and heartbeats.
package telemetry

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/primecloud/primecloud-agent/internal/protocol"
)

// EventSeverity specifies the logging and alert priority.
type EventSeverity string

const (
	SeverityInfo     EventSeverity = "INFO"
	SeverityWarn     EventSeverity = "WARN"
	SeverityError    EventSeverity = "ERROR"
	SeverityCritical EventSeverity = "CRITICAL"
)

// Event represents an operational event occurring on the agent.
type Event struct {
	EventType  string                 `json:"event_type"`
	Severity   EventSeverity          `json:"severity"`
	Message    string                 `json:"message"`
	Metadata   map[string]interface{} `json:"metadata,omitempty"`
	OccurredAt time.Time              `json:"occurred_at"`
}

// EventEmitter publishes structured events to the control plane.
type EventEmitter struct {
	client  protocol.AgentServiceClient
	agentID string
	logger  *slog.Logger
}

// NewEventEmitter constructs an EventEmitter.
func NewEventEmitter(client protocol.AgentServiceClient, agentID string, logger *slog.Logger) *EventEmitter {
	if logger == nil {
		logger = slog.Default()
	}
	return &EventEmitter{
		client:  client,
		agentID: agentID,
		logger:  logger.With("component", "event_emitter"),
	}
}

// Emit sends an event to the control plane.
func (e *EventEmitter) Emit(ctx context.Context, eventType string, severity EventSeverity, message string, meta map[string]interface{}) error {
	e.logger.Info("emitting_event", "type", eventType, "severity", string(severity), "msg", message)

	if e.client == nil {
		return nil
	}

	rawMeta := "{}"
	if meta != nil {
		if b, err := json.Marshal(meta); err == nil {
			rawMeta = string(b)
		}
	}

	req := &protocol.EventRequest{
		AgentId:        e.agentID,
		EventType:      eventType,
		Severity:       string(severity),
		Message:        message,
		MetadataJson:   rawMeta,
		OccurredAtUnix: time.Now().Unix(),
	}

	resp, err := e.client.ReportEvent(ctx, req)
	if err != nil {
		return fmt.Errorf("failed to report event to control plane: %w", err)
	}
	if !resp.Recorded {
		return fmt.Errorf("control plane rejected event")
	}

	return nil
}
