// Package operations provides the authoritative operation dispatcher, handler registry, idempotency tracking, and resource locking.
package operations

import (
	"sync"
	"time"

	pb "github.com/primecloud/primecloud-agent/internal/protocol"
)

type idempotencyEntry struct {
	response  *pb.OperationResponse
	timestamp time.Time
}

// IdempotencyTracker provides deduplication and result caching for operations.
type IdempotencyTracker struct {
	mu      sync.RWMutex
	records map[string]*idempotencyEntry
	ttl     time.Duration
}

// NewIdempotencyTracker constructs a tracker with a retention TTL.
func NewIdempotencyTracker(ttl time.Duration) *IdempotencyTracker {
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	return &IdempotencyTracker{
		records: make(map[string]*idempotencyEntry),
		ttl:     ttl,
	}
}

// Record stores the result of an operation execution.
func (t *IdempotencyTracker) Record(opID string, resp *pb.OperationResponse) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.records[opID] = &idempotencyEntry{
		response:  resp,
		timestamp: time.Now(),
	}
}

// Get checks if an operation ID was already executed and returns the cached response.
func (t *IdempotencyTracker) Get(opID string) (*pb.OperationResponse, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	entry, exists := t.records[opID]
	if !exists {
		return nil, false
	}

	if time.Since(entry.timestamp) > t.ttl {
		return nil, false
	}

	return entry.response, true
}

// CleanExpired removes entries older than the configured TTL.
func (t *IdempotencyTracker) CleanExpired() {
	t.mu.Lock()
	defer t.mu.Unlock()

	now := time.Now()
	for id, entry := range t.records {
		if now.Sub(entry.timestamp) > t.ttl {
			delete(t.records, id)
		}
	}
}
