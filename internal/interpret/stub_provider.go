package interpret

import "context"

// StubProvider is a no-op LLM provider for testing and offline mode.
// It returns empty responses, which means interpretation fields remain empty.
type StubProvider struct{}

func (s *StubProvider) Complete(ctx context.Context, prompt string) (string, error) {
	return "", nil
}

// MockProvider returns fixed responses for testing.
type MockProvider struct {
	Response string
	Err      error
}

func (m *MockProvider) Complete(ctx context.Context, prompt string) (string, error) {
	return m.Response, m.Err
}
