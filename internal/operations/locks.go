// Package operations provides the authoritative operation dispatcher, handler registry, idempotency tracking, and resource locking.
package operations

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// LockManager coordinates in-memory mutexes partitioned by resource ID.
type LockManager struct {
	mu    sync.Mutex
	locks map[string]*resourceLock
}

type resourceLock struct {
	mu       sync.Mutex
	refCount int
}

// NewLockManager constructs a LockManager.
func NewLockManager() *LockManager {
	return &LockManager{
		locks: make(map[string]*resourceLock),
	}
}

// AcquireLock acquires exclusive lock for the specified resource ID.
// It returns an unlock function or an error if the context was cancelled before acquiring.
func (lm *LockManager) AcquireLock(ctx context.Context, resourceID string) (func(), error) {
	if resourceID == "" {
		// Global or unpartitioned operation; return no-op unlock
		return func() {}, nil
	}

	lm.mu.Lock()
	lock, exists := lm.locks[resourceID]
	if !exists {
		lock = &resourceLock{}
		lm.locks[resourceID] = lock
	}
	lock.refCount++
	lm.mu.Unlock()

	acquired := make(chan struct{})
	go func() {
		lock.mu.Lock()
		close(acquired)
	}()

	select {
	case <-acquired:
		unlockOnce := sync.Once{}
		return func() {
			unlockOnce.Do(func() {
				lock.mu.Unlock()
				lm.mu.Lock()
				lock.refCount--
				if lock.refCount <= 0 {
					delete(lm.locks, resourceID)
				}
				lm.mu.Unlock()
			})
		}, nil
	case <-ctx.Done():
		// Clean up ref count if context timed out or was cancelled while waiting
		go func() {
			<-acquired
			lock.mu.Unlock()
			lm.mu.Lock()
			lock.refCount--
			if lock.refCount <= 0 {
				delete(lm.locks, resourceID)
			}
			lm.mu.Unlock()
		}()
		return nil, fmt.Errorf("lock acquisition cancelled for resource %s: %w", resourceID, ctx.Err())
	}
}

// TryAcquire attempts to lock the resource without blocking. Returns true if acquired.
func (lm *LockManager) TryAcquire(resourceID string, timeout time.Duration) (func(), bool) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	unlock, err := lm.AcquireLock(ctx, resourceID)
	if err != nil {
		return nil, false
	}
	return unlock, true
}
