package interpret

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/verabase/code-verification-engine/internal/rules"
)

func mustNew(t *testing.T, provider LLMProvider) *Interpreter {
	t.Helper()
	interp, err := New(provider)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	return interp
}

func TestInterpretFailFinding(t *testing.T) {
	provider := &MockProvider{
		Response: "EXPLANATION: This controller directly queries the database, bypassing the repository layer.\nTRIAGE: likely_real\nTRIAGE_REASON: Direct SQL in handler file is a clear layering violation.\nFIX: Move database queries to a repository class and inject it into the controller.",
	}
	interp := mustNew(t, provider)

	findings := []rules.Finding{
		{
			RuleID:  "ARCH-001",
			Status:  rules.StatusFail,
			Message: "Controllers must not access database directly.",
			Evidence: []rules.Evidence{
				{File: "handlers/user.go", LineStart: 14, LineEnd: 18, Symbol: "GetUser"},
			},
		},
	}

	report, err := interp.Interpret(context.Background(), findings, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(report.Findings))
	}

	f := report.Findings[0]
	if f.Explanation == "" {
		t.Error("expected explanation")
	}
	if f.TriageHint != "likely_real" {
		t.Errorf("triage = %s, want likely_real", f.TriageHint)
	}
	if f.SuggestedFix == "" {
		t.Error("expected suggested fix")
	}
	if !f.LLMGenerated {
		t.Error("should be marked as LLM generated")
	}
	if report.Summary.LikelyRealIssues != 1 {
		t.Errorf("summary likely_real = %d, want 1", report.Summary.LikelyRealIssues)
	}
}

func TestInterpretUnknownFinding(t *testing.T) {
	interp := mustNew(t, &sequentialProvider{
		responses: []string{
			"EXPLANATION: Cannot determine if routes are protected.\nTRIAGE: needs_review\nTRIAGE_REASON: Static analysis cannot trace middleware binding.\nFIX: Add explicit middleware annotations.",
			"CATEGORY: missing_binding_data\nMISSING: Per-route middleware binding information from the framework router setup.\nNEXT_STEPS: Add NestJS @UseGuards decorators or Express inline middleware parameters.",
		},
	})

	findings := []rules.Finding{
		{
			RuleID:         "SEC-AUTH-002",
			Status:         rules.StatusUnknown,
			Message:        "Protected routes must use auth middleware.",
			UnknownReasons: []string{"route-to-middleware binding cannot be determined"},
		},
	}

	report, err := interp.Interpret(context.Background(), findings, nil)
	if err != nil {
		t.Fatal(err)
	}

	f := report.Findings[0]
	if f.UnknownCategory != "missing_binding_data" {
		t.Errorf("unknown_category = %s, want missing_binding_data", f.UnknownCategory)
	}
	if f.MissingEvidence == "" {
		t.Error("expected missing evidence description")
	}
	if f.NextSteps == "" {
		t.Error("expected next steps")
	}
	if report.Summary.UnknownsClassified != 1 {
		t.Errorf("unknowns_classified = %d, want 1", report.Summary.UnknownsClassified)
	}
}

func TestInterpretPassFindingSkipped(t *testing.T) {
	interp := mustNew(t, &MockProvider{Response: "should not be called"})

	findings := []rules.Finding{
		{RuleID: "AUTH-001", Status: rules.StatusPass, Message: "JWT exists."},
	}

	report, err := interp.Interpret(context.Background(), findings, nil)
	if err != nil {
		t.Fatal(err)
	}
	if report.Findings[0].Explanation != "" {
		t.Error("pass findings should not be interpreted")
	}
	if report.Findings[0].LLMGenerated {
		t.Error("pass findings should have LLMGenerated = false")
	}
}

func TestInterpretLLMFailureNonFatal(t *testing.T) {
	interp := mustNew(t, &MockProvider{Err: fmt.Errorf("LLM unavailable")})

	findings := []rules.Finding{
		{RuleID: "ARCH-001", Status: rules.StatusFail, Message: "Direct DB access."},
	}

	report, err := interp.Interpret(context.Background(), findings, nil)
	if err != nil {
		t.Fatal("LLM failure should be non-fatal")
	}
	if report.Findings[0].LLMGenerated {
		t.Error("should not be marked as LLM generated when LLM failed")
	}
}

func TestNewNilProviderReturnsError(t *testing.T) {
	_, err := New(nil)
	if err == nil {
		t.Fatal("New(nil) should return error")
	}
}

func TestParseEvidenceResponse(t *testing.T) {
	response := "EXPLANATION: Bad pattern detected.\nTRIAGE: possible_false_positive\nTRIAGE_REASON: Looks like test code.\nFIX: Move to test directory."
	f := &InterpretedFinding{}
	parseEvidenceResponse(response, f)

	if f.Explanation != "Bad pattern detected." {
		t.Errorf("explanation = %q", f.Explanation)
	}
	if f.TriageHint != "possible_false_positive" {
		t.Errorf("triage = %q", f.TriageHint)
	}
}

func TestParseUnknownResponse(t *testing.T) {
	response := "CATEGORY: unsupported_framework\nMISSING: Framework-specific route parser.\nNEXT_STEPS: Add support for Hapi.js route detection."
	f := &InterpretedFinding{}
	parseUnknownResponse(response, f)

	if f.UnknownCategory != "unsupported_framework" {
		t.Errorf("category = %q", f.UnknownCategory)
	}
	if f.MissingEvidence == "" {
		t.Error("expected missing evidence")
	}
}

func TestStubProviderDoesNotMarkLLMGenerated(t *testing.T) {
	// StubProvider returns empty string — findings must NOT be marked llm_generated
	interp := mustNew(t, &StubProvider{})
	findings := []rules.Finding{
		{RuleID: "TEST-001", Status: rules.StatusFail, Message: "test fail"},
		{RuleID: "TEST-002", Status: rules.StatusUnknown, Message: "test unknown",
			UnknownReasons: []string{"test"}},
	}
	report, err := interp.Interpret(context.Background(), findings, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i, f := range report.Findings {
		if f.LLMGenerated {
			t.Errorf("finding[%d] %s: LLMGenerated should be false for StubProvider", i, f.RuleID)
		}
		if f.Explanation != "" {
			t.Errorf("finding[%d]: explanation should be empty, got %q", i, f.Explanation)
		}
	}
}

func TestHTTPProviderSuccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify headers
		if r.Header.Get("x-api-key") != "test-key" {
			t.Errorf("expected x-api-key=test-key, got %q", r.Header.Get("x-api-key"))
		}
		if r.Header.Get("anthropic-version") != "2023-06-01" {
			t.Errorf("unexpected anthropic-version header")
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("expected Content-Type application/json")
		}

		resp := map[string]interface{}{
			"content": []map[string]string{
				{"text": "EXPLANATION: Test response\nTRIAGE: likely_real\nTRIAGE_REASON: test\nFIX: test fix"},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	provider := NewHTTPProvider("test-key", server.URL)
	result, err := provider.Complete(context.Background(), "test prompt")
	if err != nil {
		t.Fatalf("Complete failed: %v", err)
	}
	if result == "" {
		t.Fatal("expected non-empty response")
	}
	if result != "EXPLANATION: Test response\nTRIAGE: likely_real\nTRIAGE_REASON: test\nFIX: test fix" {
		t.Errorf("unexpected response: %q", result)
	}
}

func TestHTTPProviderErrorStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":{"message":"invalid api key"}}`))
	}))
	defer server.Close()

	provider := NewHTTPProvider("bad-key", server.URL)
	_, err := provider.Complete(context.Background(), "test")
	if err == nil {
		t.Fatal("expected error for 401 response")
	}
}

func TestHTTPProviderCancelledContext(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Should not reach here if context is cancelled
		t.Error("request should not have been sent")
	}))
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	provider := NewHTTPProvider("key", server.URL)
	_, err := provider.Complete(ctx, "test")
	if err == nil {
		t.Fatal("expected error for cancelled context")
	}
}

func TestHTTPProviderEmptyContent(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{"content": []map[string]string{}}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	provider := NewHTTPProvider("key", server.URL)
	result, err := provider.Complete(context.Background(), "test")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result != "" {
		t.Errorf("expected empty result for empty content, got %q", result)
	}
}

func TestHTTPProviderIntegrationWithInterpreter(t *testing.T) {
	// Full integration: HTTPProvider → Interpreter → InterpretedReport
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{
			"content": []map[string]string{
				{"text": "EXPLANATION: Direct DB access in handler\nTRIAGE: likely_real\nTRIAGE_REASON: Clear violation\nFIX: Use repository pattern"},
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	provider := NewHTTPProvider("test-key", server.URL)
	interp := mustNew(t, provider)

	findings := []rules.Finding{
		{RuleID: "ARCH-001", Status: rules.StatusFail, Message: "Direct DB in handler"},
	}
	report, err := interp.Interpret(context.Background(), findings, nil)
	if err != nil {
		t.Fatal(err)
	}
	f := report.Findings[0]
	if !f.LLMGenerated {
		t.Error("should be LLMGenerated when HTTPProvider returns content")
	}
	if f.Explanation == "" {
		t.Error("expected explanation from HTTPProvider")
	}
	if f.TriageHint != "likely_real" {
		t.Errorf("expected triage likely_real, got %q", f.TriageHint)
	}
}

// sequentialProvider returns responses in order for multi-call tests.
type sequentialProvider struct {
	responses []string
	index     int
}

func (s *sequentialProvider) Complete(ctx context.Context, prompt string) (string, error) {
	if s.index >= len(s.responses) {
		return "", nil
	}
	resp := s.responses[s.index]
	s.index++
	return resp, nil
}
