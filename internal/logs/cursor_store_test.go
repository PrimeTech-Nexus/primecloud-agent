package logs

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCursorStore_SaveAndReload(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "cursor_test_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	filePath := filepath.Join(tmpDir, "log_cursors.json")
	store1 := NewFileCursorStore(filePath, 100, nil)

	t1 := time.Date(2026, 10, 19, 5, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 10, 19, 5, 1, 0, 0, time.UTC)

	batch := map[string]time.Time{
		"cnt-app-1": t1,
		"cnt-app-2": t2,
	}

	if err := store1.Commit(batch); err != nil {
		t.Fatalf("failed to commit batch: %v", err)
	}

	// Verify file was written to disk
	if _, err := os.Stat(filePath); err != nil {
		t.Fatalf("cursor file does not exist after commit: %v", err)
	}

	// Simulate Agent restart by creating a new store instance with same path
	store2 := NewFileCursorStore(filePath, 100, nil)
	if err := store2.Load(); err != nil {
		t.Fatalf("failed to reload cursors on restart: %v", err)
	}

	got1, ok1 := store2.Get("cnt-app-1")
	if !ok1 || !got1.Equal(t1) {
		t.Errorf("expected cnt-app-1 = %v, got %v (ok=%v)", t1, got1, ok1)
	}

	got2, ok2 := store2.Get("cnt-app-2")
	if !ok2 || !got2.Equal(t2) {
		t.Errorf("expected cnt-app-2 = %v, got %v (ok=%v)", t2, got2, ok2)
	}
}

func TestCursorStore_CrashBeforeAcknowledgement_NoAdvance(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "cursor_test_unack_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	filePath := filepath.Join(tmpDir, "log_cursors.json")
	store := NewFileCursorStore(filePath, 100, nil)

	tInitial := time.Date(2026, 10, 19, 4, 0, 0, 0, time.UTC)
	_ = store.Commit(map[string]time.Time{"cnt-app-1": tInitial})

	// Simulate log arrival tUnacked, but Control Plane connection fails before commit
	tUnacked := time.Date(2026, 10, 19, 4, 30, 0, 0, time.UTC)
	_ = tUnacked // deliberately NOT committed to store!

	// Restart store
	reloaded := NewFileCursorStore(filePath, 100, nil)
	_ = reloaded.Load()

	// Checkpoint must NOT have advanced past unacknowledged record
	ts, ok := reloaded.Get("cnt-app-1")
	if !ok || !ts.Equal(tInitial) {
		t.Fatalf("expected checkpoint to remain at %v, got %v", tInitial, ts)
	}
}

func TestCursorStore_MissingAndCorruptFiles(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "cursor_test_corrupt_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Case 1: Missing file should load cleanly with 0 entries
	missingPath := filepath.Join(tmpDir, "non_existent.json")
	storeMissing := NewFileCursorStore(missingPath, 100, nil)
	if err := storeMissing.Load(); err != nil {
		t.Fatalf("expected nil error on missing file, got: %v", err)
	}
	if storeMissing.Count() != 0 {
		t.Fatalf("expected 0 cursors, got %d", storeMissing.Count())
	}

	// Case 2: Corrupted JSON should recover safely without crashing
	corruptPath := filepath.Join(tmpDir, "corrupt.json")
	if err := os.WriteFile(corruptPath, []byte("{ malformed json ::: invalid"), 0644); err != nil {
		t.Fatalf("failed to write corrupt file: %v", err)
	}
	storeCorrupt := NewFileCursorStore(corruptPath, 100, nil)
	if err := storeCorrupt.Load(); err != nil {
		t.Fatalf("expected graceful fallback on corrupt file, got error: %v", err)
	}
	if storeCorrupt.Count() != 0 {
		t.Fatalf("expected 0 cursors after corrupt recovery, got %d", storeCorrupt.Count())
	}
}

func TestCursorStore_PruningMaxEntries(t *testing.T) {
	store := NewFileCursorStore("", 3, nil) // Max 3 entries

	baseTime := time.Date(2026, 10, 19, 0, 0, 0, 0, time.UTC)
	batch := map[string]time.Time{
		"c1": baseTime.Add(1 * time.Minute),
		"c2": baseTime.Add(2 * time.Minute),
		"c3": baseTime.Add(3 * time.Minute),
		"c4": baseTime.Add(4 * time.Minute),
		"c5": baseTime.Add(5 * time.Minute),
	}

	if err := store.Commit(batch); err != nil {
		t.Fatalf("failed to commit: %v", err)
	}

	// Store must be pruned to max 3 entries
	if store.Count() != 3 {
		t.Fatalf("expected exactly 3 cursors after pruning, got %d", store.Count())
	}

	// Oldest c1 and c2 must be pruned; newest c3, c4, c5 must remain
	if _, ok := store.Get("c1"); ok {
		t.Errorf("expected c1 to be pruned")
	}
	if _, ok := store.Get("c2"); ok {
		t.Errorf("expected c2 to be pruned")
	}
	if _, ok := store.Get("c5"); !ok {
		t.Errorf("expected c5 to remain in store")
	}
}

func TestCursorStore_ContainerRecreationTrackedSeparately(t *testing.T) {
	store := NewFileCursorStore("", 100, nil)

	t1 := time.Date(2026, 10, 19, 1, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 10, 19, 2, 0, 0, 0, time.UTC)

	// Container 1
	_ = store.Commit(map[string]time.Time{"cnt-replica-1-uuidA": t1})
	// Container recreated with new ID
	_ = store.Commit(map[string]time.Time{"cnt-replica-1-uuidB": t2})

	tsA, _ := store.Get("cnt-replica-1-uuidA")
	tsB, _ := store.Get("cnt-replica-1-uuidB")

	if !tsA.Equal(t1) || !tsB.Equal(t2) {
		t.Errorf("recreated containers must have independent timestamps: got %v and %v", tsA, tsB)
	}
}
