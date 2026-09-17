// Package transport provides mTLS configuration, gRPC client connections, and automatic reconnection mechanics.
package transport

import (
	"context"
	"crypto/rand"
	"math/big"
	"time"
)

// BackoffStrategy handles exponential backoff delays with jitter.
type BackoffStrategy struct {
	BaseDelay time.Duration
	MaxDelay  time.Duration
	Factor    float64
	attempt   int
}

// NewBackoffStrategy initializes backoff parameters.
func NewBackoffStrategy(baseDelay, maxDelay time.Duration) *BackoffStrategy {
	if baseDelay <= 0 {
		baseDelay = 100 * time.Millisecond
	}
	if maxDelay <= 0 {
		maxDelay = 30 * time.Second
	}
	return &BackoffStrategy{
		BaseDelay: baseDelay,
		MaxDelay:  maxDelay,
		Factor:    2.0,
		attempt:   0,
	}
}

// NextDelay calculates the next backoff duration with jitter.
func (b *BackoffStrategy) NextDelay() time.Duration {
	delay := float64(b.BaseDelay) * float64(int(1)<<b.attempt)
	if delay > float64(b.MaxDelay) {
		delay = float64(b.MaxDelay)
	} else {
		b.attempt++
	}

	// Add random jitter up to 25% of delay
	maxJitter := int64(delay * 0.25)
	if maxJitter > 0 {
		n, err := rand.Int(rand.Reader, big.NewInt(maxJitter))
		if err == nil {
			delay += float64(n.Int64())
		}
	}

	return time.Duration(delay)
}

// Reset clears the backoff attempt counter after a successful connection.
func (b *BackoffStrategy) Reset() {
	b.attempt = 0
}

// Sleep blocks until next delay expires or context is cancelled.
func (b *BackoffStrategy) Sleep(ctx context.Context) error {
	delay := b.NextDelay()
	select {
	case <-time.After(delay):
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
