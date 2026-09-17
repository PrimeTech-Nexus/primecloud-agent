// Package agent provides core lifecycle, configuration, and orchestration for the PrimeCloud Agent daemon.
package agent

import (
	"context"
	"io"
	"log/slog"
	"os"
	"regexp"
	"strings"
)

var sensitiveKeyPattern = regexp.MustCompile(`(?i)(secret|token|password|key|credential|private|auth)`)

// RedactionHandler wraps an slog.Handler to sanitize sensitive keys and values.
type RedactionHandler struct {
	slog.Handler
}

// NewRedactionHandler creates a handler that redacts sensitive values.
func NewRedactionHandler(h slog.Handler) *RedactionHandler {
	return &RedactionHandler{Handler: h}
}

// Handle inspects record attributes and redacts sensitive information.
func (h *RedactionHandler) Handle(ctx context.Context, r slog.Record) error {
	sanitizedRecord := slog.NewRecord(r.Time, r.Level, r.Message, r.PC)
	r.Attrs(func(a slog.Attr) bool {
		sanitizedRecord.AddAttrs(sanitizeAttr(a))
		return true
	})
	return h.Handler.Handle(ctx, sanitizedRecord)
}

func sanitizeAttr(a slog.Attr) slog.Attr {
	if a.Value.Kind() == slog.KindGroup {
		attrs := a.Value.Group()
		sanitizedGroup := make([]slog.Attr, 0, len(attrs))
		for _, subAttr := range attrs {
			sanitizedGroup = append(sanitizedGroup, sanitizeAttr(subAttr))
		}
		return slog.Attr{
			Key:   a.Key,
			Value: slog.GroupValue(sanitizedGroup...),
		}
	}

	if sensitiveKeyPattern.MatchString(a.Key) {
		return slog.String(a.Key, "[REDACTED]")
	}

	strVal := a.Value.String()
	if strings.Contains(strVal, "-----BEGIN") {
		return slog.String(a.Key, "[REDACTED_CERT_OR_KEY]")
	}

	return a
}

// SetupLogging initializes the global structured JSON logger.
func SetupLogging(w io.Writer, level slog.Level) *slog.Logger {
	if w == nil {
		w = os.Stdout
	}
	baseHandler := slog.NewJSONHandler(w, &slog.HandlerOptions{
		Level: level,
	})
	redactingHandler := NewRedactionHandler(baseHandler)
	logger := slog.New(redactingHandler)
	slog.SetDefault(logger)
	return logger
}
