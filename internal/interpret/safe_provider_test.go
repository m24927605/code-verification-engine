package interpret

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/verabase/code-verification-engine/internal/rules"
)

// mockProvider tracks call count and fails the first failN calls.
type mockProvider struct {
	mu       sync.Mutex
	calls    int
	failN    int
	response string
}

func (m *mockProvider) Complete(ctx context.Context, prompt string) (string, error) {
	m.mu.Lock()
	m.calls++
	n := m.calls
	m.mu.Unlock()

	if n <= m.failN {
		return "", fmt.Errorf("mock error %d", n)
	}
	return m.response, nil
}

// blockingProvider blocks until the context is cancelled.
type blockingProvider struct{}

func (b *blockingProvider) Complete(ctx context.Context, prompt string) (string, error) {
	<-ctx.Done()
	return "", ctx.Err()
}

// --- SafeProvider tests ---

func TestSafeProvider_Timeout(t *testing.T) {
	cfg := DefaultProviderConfig()
	cfg.Timeout = 50 * time.Millisecond
	cfg.MaxRetries = 0

	sp := NewSafeProvider(&blockingProvider{}, cfg)

	start := time.Now()
	_, err := sp.Complete(context.Background(), "test")
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected timeout error")
	}
	if !errors.Is(err, ErrTimeout) {
		t.Errorf("expected ErrTimeout, got: %v", err)
	}
	if elapsed > 500*time.Millisecond {
		t.Errorf("took too long: %v (expected ~50ms)", elapsed)
	}
}

func TestSafeProvider_RetrySuccess(t *testing.T) {
	mock := &mockProvider{failN: 2, response: "success"}

	cfg := DefaultProviderConfig()
	cfg.MaxRetries = 2
	cfg.RetryBaseDelay = 1 * time.Millisecond
	cfg.MaxRetryDelay = 5 * time.Millisecond
	cfg.Timeout = 1 * time.Second

	sp := NewSafeProvider(mock, cfg)
	result, err := sp.Complete(context.Background(), "test")
	if err != nil {
		t.Fatalf("expected success after retries, got: %v", err)
	}
	if result != "success" {
		t.Errorf("expected 'success', got %q", result)
	}
	mock.mu.Lock()
	if mock.calls != 3 {
		t.Errorf("expected 3 calls, got %d", mock.calls)
	}
	mock.mu.Unlock()
}

func TestSafeProvider_RetryExhausted(t *testing.T) {
	mock := &mockProvider{failN: 100, response: "never"}

	cfg := DefaultProviderConfig()
	cfg.MaxRetries = 2
	cfg.RetryBaseDelay = 1 * time.Millisecond
	cfg.MaxRetryDelay = 2 * time.Millisecond
	cfg.Timeout = 1 * time.Second

	sp := NewSafeProvider(mock, cfg)
	_, err := sp.Complete(context.Background(), "test")
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, ErrRetryExhausted) {
		t.Errorf("expected ErrRetryExhausted, got: %v", err)
	}
	mock.mu.Lock()
	if mock.calls != 3 {
		t.Errorf("expected 3 calls (1 + 2 retries), got %d", mock.calls)
	}
	mock.mu.Unlock()
}

func TestSafeProvider_BudgetExceeded(t *testing.T) {
	mock := &mockProvider{response: "ok"}

	cfg := DefaultProviderConfig()
	cfg.BudgetLimit = 3
	cfg.MaxRetries = 0
	cfg.Timeout = 1 * time.Second

	sp := NewSafeProvider(mock, cfg)

	// Use up the budget
	for i := 0; i < 3; i++ {
		_, err := sp.Complete(context.Background(), "test")
		if err != nil {
			t.Fatalf("call %d should succeed: %v", i+1, err)
		}
	}

	// Next call should fail
	_, err := sp.Complete(context.Background(), "test")
	if err == nil {
		t.Fatal("expected budget exceeded error")
	}
	if !errors.Is(err, ErrBudgetExceeded) {
		t.Errorf("expected ErrBudgetExceeded, got: %v", err)
	}

	if sp.Calls() != 3 {
		t.Errorf("expected 3 counted calls, got %d", sp.Calls())
	}
}

func TestSafeProvider_NormalOperation(t *testing.T) {
	mock := &mockProvider{response: "hello world"}

	cfg := DefaultProviderConfig()
	cfg.MaxRetries = 0
	cfg.Timeout = 1 * time.Second

	sp := NewSafeProvider(mock, cfg)
	result, err := sp.Complete(context.Background(), "prompt")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "hello world" {
		t.Errorf("expected 'hello world', got %q", result)
	}
	if sp.Calls() != 1 {
		t.Errorf("expected 1 call, got %d", sp.Calls())
	}
}

func TestSafeProvider_UnlimitedBudget(t *testing.T) {
	mock := &mockProvider{response: "ok"}

	cfg := DefaultProviderConfig()
	cfg.BudgetLimit = 0 // unlimited
	cfg.MaxRetries = 0
	cfg.Timeout = 1 * time.Second

	sp := NewSafeProvider(mock, cfg)

	for i := 0; i < 200; i++ {
		_, err := sp.Complete(context.Background(), "test")
		if err != nil {
			t.Fatalf("call %d failed: %v", i+1, err)
		}
	}
}

func TestSafeProvider_ConcurrentBudget(t *testing.T) {
	mock := &mockProvider{response: "ok"}

	cfg := DefaultProviderConfig()
	cfg.BudgetLimit = 50
	cfg.MaxRetries = 0
	cfg.Timeout = 1 * time.Second

	sp := NewSafeProvider(mock, cfg)

	var wg sync.WaitGroup
	var successCount int
	var mu sync.Mutex

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := sp.Complete(context.Background(), "test")
			if err == nil {
				mu.Lock()
				successCount++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	if successCount != 50 {
		t.Errorf("expected exactly 50 successful calls, got %d", successCount)
	}
}

func TestInterpreter_ProviderFailureNonFatal(t *testing.T) {
	// Provider that always fails
	failProvider := &MockProvider{Err: fmt.Errorf("total failure")}
	interp, err := New(failProvider)
	if err != nil {
		t.Fatal(err)
	}

	findings := []rules.Finding{
		{RuleID: "R1", Status: rules.StatusFail, Message: "fail finding"},
		{RuleID: "R2", Status: rules.StatusFail, Message: "another fail"},
		{RuleID: "R3", Status: rules.StatusUnknown, Message: "unknown",
			UnknownReasons: []string{"reason"}},
		{RuleID: "R4", Status: rules.StatusPass, Message: "pass finding"},
	}

	report, err := interp.Interpret(context.Background(), findings, nil)
	if err != nil {
		t.Fatalf("Interpret should succeed despite provider failures: %v", err)
	}

	if len(report.Findings) != 4 {
		t.Fatalf("expected 4 findings, got %d", len(report.Findings))
	}

	// All findings should be present with original data intact
	for _, f := range report.Findings {
		if f.LLMGenerated {
			t.Errorf("finding %s should not be LLMGenerated when provider fails", f.RuleID)
		}
	}

	// Error and skip counts should reflect failures
	if report.ErrorCount == 0 {
		t.Error("expected non-zero error count")
	}
	if report.SkipCount == 0 {
		t.Error("expected non-zero skip count")
	}

	// Base verdicts must be preserved
	if report.Findings[0].Status != rules.StatusFail {
		t.Errorf("expected StatusFail, got %s", report.Findings[0].Status)
	}
	if report.Findings[3].Status != rules.StatusPass {
		t.Errorf("expected StatusPass, got %s", report.Findings[3].Status)
	}
}

func TestSafeProvider_ZeroTimeoutUsesDefault(t *testing.T) {
	mock := &mockProvider{response: "ok"}
	cfg := DefaultProviderConfig()
	cfg.Timeout = 0 // should use default 30s
	cfg.MaxRetries = 0

	sp := NewSafeProvider(mock, cfg)
	result, err := sp.Complete(context.Background(), "test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "ok" {
		t.Errorf("expected 'ok', got %q", result)
	}
}

func TestSafeProvider_BackoffDefaults(t *testing.T) {
	mock := &mockProvider{failN: 1, response: "ok"}
	cfg := DefaultProviderConfig()
	cfg.RetryBaseDelay = 0  // should default to 1s
	cfg.MaxRetryDelay = 0   // should default to 10s
	cfg.MaxRetries = 1
	cfg.Timeout = 5 * time.Second

	sp := NewSafeProvider(mock, cfg)
	_, err := sp.Complete(context.Background(), "test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSafeProvider_ContextCancelledDuringRetry(t *testing.T) {
	mock := &mockProvider{failN: 100, response: "never"}
	cfg := DefaultProviderConfig()
	cfg.MaxRetries = 5
	cfg.RetryBaseDelay = 100 * time.Millisecond
	cfg.MaxRetryDelay = 100 * time.Millisecond
	cfg.Timeout = 1 * time.Second

	sp := NewSafeProvider(mock, cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	_, err := sp.Complete(ctx, "test")
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, ErrTimeout) {
		t.Errorf("expected ErrTimeout from cancelled context, got: %v", err)
	}
}

func TestSafeProvider_BackoffCappedAtMax(t *testing.T) {
	mock := &mockProvider{failN: 1, response: "ok"}
	cfg := DefaultProviderConfig()
	cfg.MaxRetries = 1
	cfg.RetryBaseDelay = 1 * time.Millisecond
	cfg.MaxRetryDelay = 2 * time.Millisecond
	cfg.Timeout = 1 * time.Second

	sp := NewSafeProvider(mock, cfg)
	// backoff for attempt 1 = 2^0 * 1ms = 1ms, should be within max
	delay := sp.backoff(1)
	if delay > 3*time.Millisecond {
		t.Errorf("backoff should be capped, got %v", delay)
	}

	// High attempt to test cap
	delay = sp.backoff(20)
	if delay > 3*time.Millisecond {
		t.Errorf("backoff at high attempt should be capped at max, got %v", delay)
	}
}

func TestInterpreter_ErrorCountTracking(t *testing.T) {
	// Provider that fails on evidence calls but we can still check counts
	failProvider := &MockProvider{Err: fmt.Errorf("err")}
	interp, err := New(failProvider)
	if err != nil {
		t.Fatal(err)
	}

	findings := []rules.Finding{
		{RuleID: "R1", Status: rules.StatusFail, Message: "fail"},
		{RuleID: "R2", Status: rules.StatusFail, Message: "fail"},
	}

	report, _ := interp.Interpret(context.Background(), findings, nil)
	if report.ErrorCount != 2 {
		t.Errorf("expected ErrorCount=2, got %d", report.ErrorCount)
	}
	if report.SkipCount != 2 {
		t.Errorf("expected SkipCount=2, got %d", report.SkipCount)
	}
}
