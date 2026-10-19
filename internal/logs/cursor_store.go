// Package logs provides log harvesting, multiline grouping, and durable checkpoint management.
package logs

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// DefaultMaxCursorEntries bounds memory and file size to prevent unbounded growth.
const DefaultMaxCursorEntries = 500

// CursorStore defines the interface for tracking acknowledged container log timestamps.
type CursorStore interface {
	Get(containerID string) (time.Time, bool)
	Set(containerID string, t time.Time)
	Commit(batchTimestamps map[string]time.Time) error
	Load() error
	Save() error
	Close() error
	Count() int
}

// CursorFilePayload defines the versioned JSON schema stored on disk.
type CursorFilePayload struct {
	Version   int                  `json:"version"`
	UpdatedAt string               `json:"updated_at"`
	Cursors   map[string]time.Time `json:"cursors"`
}

// FileCursorStore provides atomic on-disk persistence for container log checkpoints.
type FileCursorStore struct {
	mu         sync.RWMutex
	filePath   string
	cursors    map[string]time.Time
	maxEntries int
	logger     *slog.Logger
}

// NewFileCursorStore constructs a FileCursorStore.
// If filePath is empty, the store acts as a safe in-memory store.
func NewFileCursorStore(filePath string, maxEntries int, logger *slog.Logger) *FileCursorStore {
	if maxEntries <= 0 {
		maxEntries = DefaultMaxCursorEntries
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &FileCursorStore{
		filePath:   filePath,
		cursors:    make(map[string]time.Time),
		maxEntries: maxEntries,
		logger:     logger.With("component", "log_cursor_store"),
	}
}

// NewInMemoryCursorStore creates a cursor store without disk persistence (for testing).
func NewInMemoryCursorStore() *FileCursorStore {
	return NewFileCursorStore("", DefaultMaxCursorEntries, nil)
}

// Get retrieves the last acknowledged high-water mark timestamp for a container.
func (s *FileCursorStore) Get(containerID string) (time.Time, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t, ok := s.cursors[containerID]
	return t, ok
}

// Set updates the in-memory cursor for a container (used during seeding or direct setting).
func (s *FileCursorStore) Set(containerID string, t time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cursors[containerID] = t
}

// Count returns the number of active tracked container cursors.
func (s *FileCursorStore) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.cursors)
}

// Commit updates checkpoints for containers in an acknowledged batch and persists to disk.
// A durable checkpoint MUST NOT advance past records that the Control Plane has not accepted.
func (s *FileCursorStore) Commit(batchTimestamps map[string]time.Time) error {
	if len(batchTimestamps) == 0 {
		return nil
	}

	s.mu.Lock()
	for containerID, ts := range batchTimestamps {
		if containerID == "" || ts.IsZero() {
			continue
		}
		if existing, ok := s.cursors[containerID]; !ok || ts.After(existing) {
			s.cursors[containerID] = ts
		}
	}

	// Bound entries to prevent unbounded disk growth
	if len(s.cursors) > s.maxEntries {
		s.pruneOldestLocked()
	}
	s.mu.Unlock()

	return s.Save()
}

// pruneOldestLocked removes oldest timestamp entries when exceeding maxEntries.
func (s *FileCursorStore) pruneOldestLocked() {
	type entry struct {
		id string
		ts time.Time
	}
	entries := make([]entry, 0, len(s.cursors))
	for id, ts := range s.cursors {
		entries = append(entries, entry{id: id, ts: ts})
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].ts.Before(entries[j].ts)
	})

	toRemove := len(entries) - s.maxEntries
	for i := 0; i < toRemove; i++ {
		delete(s.cursors, entries[i].id)
	}
	s.logger.Debug("cursor_store_pruned", "pruned_count", toRemove, "remaining", len(s.cursors))
}

// Load reads and parses the cursor JSON file from disk.
// Safely handles missing, corrupt, empty, or unreadable files.
func (s *FileCursorStore) Load() error {
	if s.filePath == "" {
		return nil
	}

	data, err := os.ReadFile(s.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			s.logger.Debug("cursor_file_not_found_starting_fresh", "path", s.filePath)
			return nil
		}
		s.logger.Warn("cursor_file_read_failed", "path", s.filePath, "error", err)
		return fmt.Errorf("failed to read cursor file: %w", err)
	}

	if len(data) == 0 {
		return nil
	}

	var payload CursorFilePayload
	if err := json.Unmarshal(data, &payload); err != nil {
		s.logger.Warn("corrupt_cursor_file_recovering", "path", s.filePath, "error", err)
		// Corrupt file fallback: don't crash, start clean to ensure forward progress
		return nil
	}

	if payload.Version != 1 {
		s.logger.Warn("unsupported_cursor_file_version", "version", payload.Version, "path", s.filePath)
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	for k, v := range payload.Cursors {
		s.cursors[k] = v
	}

	s.logger.Info("log_cursors_loaded_successfully", "path", s.filePath, "count", len(s.cursors))
	return nil
}

// Save writes current cursor checkpoints atomically to disk using a temporary file and rename.
func (s *FileCursorStore) Save() error {
	if s.filePath == "" {
		return nil
	}

	s.mu.RLock()
	payload := CursorFilePayload{
		Version:   1,
		UpdatedAt: time.Now().UTC().Format(time.RFC3339),
		Cursors:   make(map[string]time.Time, len(s.cursors)),
	}
	for k, v := range s.cursors {
		payload.Cursors[k] = v
	}
	s.mu.RUnlock()

	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal cursor payload: %w", err)
	}

	dir := filepath.Dir(s.filePath)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			s.logger.Warn("failed_creating_cursor_directory", "dir", dir, "error", err)
			return fmt.Errorf("failed to create cursor directory: %w", err)
		}
	}

	tmpFile := fmt.Sprintf("%s.tmp.%d", s.filePath, time.Now().UnixNano())
	if err := os.WriteFile(tmpFile, data, 0640); err != nil {
		s.logger.Warn("cursor_temp_write_failed", "tmp_file", tmpFile, "error", err)
		return fmt.Errorf("failed to write temporary cursor file: %w", err)
	}

	if err := os.Rename(tmpFile, s.filePath); err != nil {
		_ = os.Remove(tmpFile)
		s.logger.Warn("cursor_atomic_rename_failed", "path", s.filePath, "error", err)
		return fmt.Errorf("failed to commit cursor file atomically: %w", err)
	}

	return nil
}

// Close persists final checkpoints and closes the store.
func (s *FileCursorStore) Close() error {
	return s.Save()
}
