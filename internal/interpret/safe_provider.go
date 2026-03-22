package interpret

import (
	"context"
	"errors"
	"fmt"
	"math"
	"math/rand"
	"sync"
	"time"
)

// ProviderConfig controls the hardening behaviour of SafeProvider.
type ProviderConfig struct {
	Timeout          time.Duration // Per-request timeout. Default: 30s
	MaxRetries       int           // Extra attempts after first failure. Default: 2 (total 3 attempts)
	MaxResponseBytes int64         // Not enforced here; used by HTTP providers. Default: 65536
	RetryBaseDelay   time.Duration // Initial backoff delay. Default: 1s
	MaxRetryDelay    time.Duration // Cap on backoff delay. Default: 10s
	BudgetLimit      int           // Max total calls allowed. 0 = unlimited. Default: 100
}

// DefaultProviderConfig returns production-safe defaults.
func DefaultProviderConfig() ProviderConfig {
	return ProviderConfig{
		Timeout:          30 * time.Second,
		MaxRetries:       2,
		MaxResponseBytes: 65536,
		RetryBaseDelay:   1 * time.Second,
		MaxRetryDelay:    10 * time.Second,
		BudgetLimit:      100,
	}
}

// SafeProvider wraps any LLMProvider with timeout, retry, backoff, and budget
// controls. It is safe for concurrent use.
type SafeProvider struct {
	inner  LLMProvider
	config ProviderConfig
	mu     sync.Mutex
	calls  int
}

// NewSafeProvider creates a hardened wrapper around the given provider.
func NewSafeProvider(inner LLMProvider, config ProviderConfig) *SafeProvider {
	return &SafeProvider{
		inner:  inner,
		config: config,
	}
}

// Calls returns the current call count (thread-safe).
func (s *SafeProvider) Calls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

// Complete implements LLMProvider with timeout, retry/backoff, and budget.
func (s *SafeProvider) Complete(ctx context.Context, prompt string) (string, error) {
	// Budget check
	s.mu.Lock()
	if s.config.BudgetLimit > 0 && s.calls >= s.config.BudgetLimit {
		s.mu.Unlock()
		return "", ErrBudgetExceeded
	}
	s.calls++
	s.mu.Unlock()

	maxAttempts := 1 + s.config.MaxRetries
	var lastErr error

	for attempt := 0; attempt < maxAttempts; attempt++ {
		// Wait for backoff before retrying (not on first attempt)
		if attempt > 0 {
			delay := s.backoff(attempt)
			select {
			case <-ctx.Done():
				return "", ErrTimeout
			case <-time.After(delay):
			}
		}

		result, err := s.doOnce(ctx, prompt)
		if err == nil {
			return result, nil
		}
		lastErr = err

		// Don't retry on context cancellation / deadline
		if ctx.Err() != nil {
			return "", ErrTimeout
		}
	}

	// If the underlying error is already a typed sentinel, preserve it.
	if errors.Is(lastErr, ErrTimeout) {
		return "", ErrTimeout
	}
	return "", fmt.Errorf("%w: %v", ErrRetryExhausted, lastErr)
}

// doOnce executes a single call with per-request timeout.
func (s *SafeProvider) doOnce(ctx context.Context, prompt string) (string, error) {
	timeout := s.config.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}

	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	result, err := s.inner.Complete(callCtx, prompt)
	if err != nil {
		if callCtx.Err() != nil && ctx.Err() == nil {
			// The per-request timeout fired, not the parent context.
			return "", ErrTimeout
		}
		return "", err
	}
	return result, nil
}

// backoff returns an exponential delay with jitter capped at MaxRetryDelay.
func (s *SafeProvider) backoff(attempt int) time.Duration {
	base := s.config.RetryBaseDelay
	if base <= 0 {
		base = time.Second
	}
	maxDelay := s.config.MaxRetryDelay
	if maxDelay <= 0 {
		maxDelay = 10 * time.Second
	}

	exp := math.Pow(2, float64(attempt-1))
	delay := time.Duration(float64(base) * exp)
	if delay > maxDelay {
		delay = maxDelay
	}
	// Add jitter: 0.5–1.0x of computed delay
	jitter := 0.5 + rand.Float64()*0.5
	delay = time.Duration(float64(delay) * jitter)
	return delay
}
