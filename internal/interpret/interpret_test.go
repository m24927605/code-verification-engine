package interpret

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/verabase/code-verification-engine/internal/rules"
)

// roundTripFunc adapts a function to http.RoundTripper for hermetic HTTP tests
// that don't require real network listeners.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

// jsonResponse builds an *http.Response with JSON body and 200 status.
func jsonResponse(v interface{}) *http.Response {
	data, _ := json.Marshal(v)
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(bytes.NewReader(data)),
	}
}

// errorResponse builds an *http.Response with the given status code and body.
func errorResponse(code int, body string) *http.Response {
	return &http.Response{
		StatusCode: code,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

// textResponse builds an *http.Response with a plain text body and 200 status.
func textResponse(body string) *http.Response {
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{},
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

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

func TestBuildUnknownPromptWithEvidenceAndSnippets(t *testing.T) {
	f := rules.Finding{
		RuleID:         "SEC-AUTH-002",
		Status:         rules.StatusUnknown,
		Message:        "Cannot verify auth middleware",
		UnknownReasons: []string{"binding unknown", "framework unsupported"},
		Evidence: []rules.Evidence{
			{File: "routes.go", LineStart: 10, LineEnd: 15, Symbol: "SetupRoutes"},
		},
	}

	snippets := map[string]string{
		"routes.go": "func SetupRoutes() { r.GET(\"/api\", handler) }",
	}

	prompt := buildUnknownPrompt(f, snippets)
	if !strings.Contains(prompt, "SEC-AUTH-002") {
		t.Error("prompt should contain rule ID")
	}
	if !strings.Contains(prompt, "binding unknown; framework unsupported") {
		t.Error("prompt should contain unknown reasons")
	}
	if !strings.Contains(prompt, "routes.go") {
		t.Error("prompt should contain evidence file")
	}
	if !strings.Contains(prompt, "SetupRoutes") {
		t.Error("prompt should contain evidence symbol")
	}
	if !strings.Contains(prompt, "func SetupRoutes()") {
		t.Error("prompt should contain code snippet")
	}
}

func TestBuildEvidencePromptWithSnippetsAndUnknownReasons(t *testing.T) {
	f := rules.Finding{
		RuleID:         "ARCH-001",
		Status:         rules.StatusFail,
		Message:        "Direct DB access",
		UnknownReasons: []string{"partial data"},
		Evidence: []rules.Evidence{
			{File: "handler.go", LineStart: 10, LineEnd: 20, Symbol: "GetUser"},
		},
	}

	snippets := map[string]string{
		"handler.go": "func GetUser() { db.Query(...) }",
	}

	prompt := buildEvidencePrompt(f, snippets)
	if !strings.Contains(prompt, "handler.go") {
		t.Error("prompt should contain evidence file")
	}
	if !strings.Contains(prompt, "func GetUser()") {
		t.Error("prompt should contain code snippet")
	}
	if !strings.Contains(prompt, "partial data") {
		t.Error("prompt should contain unknown reasons")
	}
}

func TestParseEvidenceResponseInvalidTriage(t *testing.T) {
	response := "EXPLANATION: Test.\nTRIAGE: invalid_value\nTRIAGE_REASON: test\nFIX: do something"
	f := &InterpretedFinding{}
	parseEvidenceResponse(response, f)

	if f.TriageHint != "needs_review" {
		t.Errorf("invalid triage should default to needs_review, got %q", f.TriageHint)
	}
}

func TestParseEvidenceResponseTestFixtureTriage(t *testing.T) {
	response := "EXPLANATION: Looks like test code.\nTRIAGE: test_fixture\nTRIAGE_REASON: test file\nFIX: none needed"
	f := &InterpretedFinding{}
	parseEvidenceResponse(response, f)

	if f.TriageHint != "test_fixture" {
		t.Errorf("expected test_fixture triage, got %q", f.TriageHint)
	}
}

func TestParseUnknownResponseInvalidCategory(t *testing.T) {
	response := "CATEGORY: totally_bogus\nMISSING: something\nNEXT_STEPS: do things"
	f := &InterpretedFinding{}
	parseUnknownResponse(response, f)

	if f.UnknownCategory != "analyzer_limitation" {
		t.Errorf("invalid category should default to analyzer_limitation, got %q", f.UnknownCategory)
	}
}

func TestParseEvidenceResponseFixWithNewlines(t *testing.T) {
	response := "EXPLANATION: Issue found.\nTRIAGE: likely_real\nTRIAGE_REASON: clear violation\nFIX: Step 1\\nStep 2\\nStep 3"
	f := &InterpretedFinding{}
	parseEvidenceResponse(response, f)

	if !strings.Contains(f.SuggestedFix, "\n") {
		t.Error("FIX should have newlines expanded from \\n")
	}
}

func TestParseUnknownResponseNextStepsWithNewlines(t *testing.T) {
	response := "CATEGORY: partial_evidence\nMISSING: need more data\nNEXT_STEPS: Step A\\nStep B"
	f := &InterpretedFinding{}
	parseUnknownResponse(response, f)

	if !strings.Contains(f.NextSteps, "\n") {
		t.Error("NEXT_STEPS should have newlines expanded from \\n")
	}
}

func TestInterpretSummaryCounts(t *testing.T) {
	interp := mustNew(t, &sequentialProvider{
		responses: []string{
			"EXPLANATION: FP.\nTRIAGE: possible_false_positive\nTRIAGE_REASON: test\nFIX: none",
			"EXPLANATION: TF.\nTRIAGE: test_fixture\nTRIAGE_REASON: test code\nFIX: none",
		},
	})

	findings := []rules.Finding{
		{RuleID: "R1", Status: rules.StatusFail, Message: "fail 1"},
		{RuleID: "R2", Status: rules.StatusFail, Message: "fail 2"},
	}

	report, err := interp.Interpret(context.Background(), findings, nil)
	if err != nil {
		t.Fatal(err)
	}

	if report.Summary.PossibleFalsePositives != 2 {
		t.Errorf("expected 2 possible_false_positives (fp + test_fixture), got %d", report.Summary.PossibleFalsePositives)
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

// ---------------------------------------------------------------------------
// ChatCompletionsProvider tests
// ---------------------------------------------------------------------------

func TestChatCompletionsProviderSuccess(t *testing.T) {
	provider := NewChatCompletionsProvider("test-key", "http://localhost:11434/v1/chat/completions", "")
	provider.client = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.Header.Get("Authorization") != "Bearer test-key" {
			t.Errorf("expected Authorization=Bearer test-key, got %q", req.Header.Get("Authorization"))
		}
		if req.Header.Get("Content-Type") != "application/json" {
			t.Errorf("expected Content-Type application/json")
		}
		if req.Header.Get("x-api-key") != "" {
			t.Error("chat completions provider should not send x-api-key header")
		}
		if req.Header.Get("anthropic-version") != "" {
			t.Error("chat completions provider should not send anthropic-version header")
		}
		var reqBody map[string]interface{}
		json.NewDecoder(req.Body).Decode(&reqBody)
		if reqBody["model"] != "codellama:8b" {
			t.Errorf("expected model=codellama:8b, got %v", reqBody["model"])
		}
		return jsonResponse(map[string]interface{}{
			"choices": []map[string]interface{}{
				{"message": map[string]string{
					"content": "EXPLANATION: Test response\nTRIAGE: likely_real\nTRIAGE_REASON: test\nFIX: test fix",
				}},
			},
		}), nil
	})}

	result, err := provider.Complete(context.Background(), "test prompt")
	if err != nil {
		t.Fatalf("Complete failed: %v", err)
	}
	if result != "EXPLANATION: Test response\nTRIAGE: likely_real\nTRIAGE_REASON: test\nFIX: test fix" {
		t.Errorf("unexpected response: %q", result)
	}
}

func TestChatCompletionsProviderCustomModel(t *testing.T) {
	provider := NewChatCompletionsProvider("key", "http://localhost:11434/v1/chat/completions", "codellama:13b")
	provider.client = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		var reqBody map[string]interface{}
		json.NewDecoder(req.Body).Decode(&reqBody)
		if reqBody["model"] != "codellama:13b" {
			t.Errorf("expected model=codellama:13b, got %v", reqBody["model"])
		}
		return jsonResponse(map[string]interface{}{
			"choices": []map[string]interface{}{
				{"message": map[string]string{"content": "ok"}},
			},
		}), nil
	})}

	result, err := provider.Complete(context.Background(), "test")
	if err != nil {
		t.Fatalf("Complete failed: %v", err)
	}
	if result != "ok" {
		t.Errorf("unexpected response: %q", result)
	}
}

func TestChatCompletionsProviderWithoutAPIKeyDoesNotSendAuthorization(t *testing.T) {
	provider := NewChatCompletionsProvider("", "http://localhost:11434/v1/chat/completions", "codellama:8b")
	provider.client = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.Header.Get("Authorization") != "" {
			t.Errorf("expected no Authorization header, got %q", req.Header.Get("Authorization"))
		}
		var reqBody map[string]interface{}
		json.NewDecoder(req.Body).Decode(&reqBody)
		if reqBody["model"] != "codellama:8b" {
			t.Errorf("expected model=codellama:8b, got %v", reqBody["model"])
		}
		return jsonResponse(map[string]interface{}{
			"choices": []map[string]interface{}{
				{"message": map[string]string{"content": "ok"}},
			},
		}), nil
	})}

	result, err := provider.Complete(context.Background(), "test")
	if err != nil {
		t.Fatalf("Complete failed: %v", err)
	}
	if result != "ok" {
		t.Errorf("unexpected response: %q", result)
	}
}

func TestChatCompletionsProviderErrorStatus(t *testing.T) {
	provider := NewChatCompletionsProvider("bad-key", "http://localhost:11434/v1/chat/completions", "")
	provider.client = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return errorResponse(http.StatusUnauthorized, `{"error":{"message":"invalid api key"}}`), nil
	})}

	_, err := provider.Complete(context.Background(), "test")
	if err == nil {
		t.Fatal("expected error for 401 response")
	}
}

func TestChatCompletionsProviderCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	provider := NewChatCompletionsProvider("key", "http://localhost:11434/v1/chat/completions", "")
	_, err := provider.Complete(ctx, "test")
	if err == nil {
		t.Fatal("expected error for cancelled context")
	}
}

func TestChatCompletionsProviderEmptyChoices(t *testing.T) {
	provider := NewChatCompletionsProvider("key", "http://localhost:11434/v1/chat/completions", "")
	provider.client = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return jsonResponse(map[string]interface{}{"choices": []map[string]interface{}{}}), nil
	})}

	result, err := provider.Complete(context.Background(), "test")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result != "" {
		t.Errorf("expected empty result for empty choices, got %q", result)
	}
}

func TestChatCompletionsProviderInvalidJSON(t *testing.T) {
	provider := NewChatCompletionsProvider("key", "http://localhost:11434/v1/chat/completions", "")
	provider.client = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return textResponse("not json"), nil
	})}

	_, err := provider.Complete(context.Background(), "test")
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestChatCompletionsProviderIntegrationWithInterpreter(t *testing.T) {
	provider := NewChatCompletionsProvider("test-key", "http://localhost:11434/v1/chat/completions", "codellama:8b")
	provider.client = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return jsonResponse(map[string]interface{}{
			"choices": []map[string]interface{}{
				{"message": map[string]string{
					"content": "EXPLANATION: Direct DB access\nTRIAGE: likely_real\nTRIAGE_REASON: Clear violation\nFIX: Use repository pattern",
				}},
			},
		}), nil
	})}

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
		t.Error("should be LLMGenerated when chat completions provider returns content")
	}
	if f.Explanation == "" {
		t.Error("expected explanation from chat completions provider")
	}
	if f.TriageHint != "likely_real" {
		t.Errorf("expected triage likely_real, got %q", f.TriageHint)
	}
}

func TestChatCompletionsProviderOversizedResponse(t *testing.T) {
	bigBody := strings.Repeat("x", 200)
	provider := NewChatCompletionsProvider("test-key", "http://localhost:11434/v1/chat/completions", "")
	provider.MaxResponseBytes = 100
	provider.client = &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return textResponse(bigBody), nil
		}),
	}
	_, err := provider.Complete(context.Background(), "test")
	if err == nil {
		t.Fatal("expected error for oversized response")
	}
	if err != ErrResponseTooLarge {
		t.Errorf("expected ErrResponseTooLarge, got: %v", err)
	}
}

func TestChatCompletionsProviderNetworkError(t *testing.T) {
	provider := NewChatCompletionsProvider("key", "http://localhost:11434/v1/chat/completions", "")
	provider.client = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return nil, fmt.Errorf("connection refused")
	})}

	_, err := provider.Complete(context.Background(), "test")
	if err == nil {
		t.Fatal("expected error for network failure")
	}
	if !strings.Contains(err.Error(), "API call failed") {
		t.Errorf("expected 'API call failed' error, got: %v", err)
	}
}

func TestChatCompletionsProviderInvalidURL(t *testing.T) {
	// Invalid URL with control characters to trigger NewRequestWithContext error
	provider := NewChatCompletionsProvider("key", "http://localhost:11434/\x00invalid", "")

	_, err := provider.Complete(context.Background(), "test")
	if err == nil {
		t.Fatal("expected error for invalid URL")
	}
	if !strings.Contains(err.Error(), "create request") {
		t.Errorf("expected 'create request' error, got: %v", err)
	}
}

func TestChatCompletionsProviderNegativeMaxBytes(t *testing.T) {
	provider := NewChatCompletionsProvider("key", "http://localhost:11434/v1/chat/completions", "")
	provider.MaxResponseBytes = -1 // should use default
	provider.client = &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return jsonResponse(map[string]interface{}{
				"choices": []map[string]interface{}{
					{"message": map[string]string{"content": "ok"}},
				},
			}), nil
		}),
	}
	result, err := provider.Complete(context.Background(), "test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "ok" {
		t.Errorf("expected 'ok', got %q", result)
	}
}

func TestChatCompletionsProviderZeroMaxBytes(t *testing.T) {
	provider := NewChatCompletionsProvider("test-key", "http://localhost:11434/v1/chat/completions", "")
	provider.MaxResponseBytes = 0
	provider.client = &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return jsonResponse(map[string]interface{}{
				"choices": []map[string]interface{}{
					{"message": map[string]string{"content": "ok"}},
				},
			}), nil
		}),
	}
	result, err := provider.Complete(context.Background(), "test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "ok" {
		t.Errorf("expected 'ok', got %q", result)
	}
}
