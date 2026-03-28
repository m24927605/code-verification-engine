package engine

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/verabase/code-verification-engine/internal/artifactsv2"
	"github.com/verabase/code-verification-engine/internal/interpret"
	"github.com/verabase/code-verification-engine/internal/report"
)

func TestNewLLMAgentExecutorProducesCompletedEvidence(t *testing.T) {
	t.Parallel()

	exec := NewLLMAgentExecutor(context.Background(), &interpret.MockProvider{
		Response: `{
			"status": "completed",
			"evidence": [
				{
					"claim": "security_review",
					"summary": "bounded evidence confirms the issue",
					"file": "service.ts",
					"start_line": 10,
					"end_line": 12,
					"symbol_id": "getUser"
				}
			]
		}`,
	}, report.ScanReport{
		RepoPath:     "/tmp/repo",
		RepoName:     "github.com/acme/repo",
		CommitSHA:    "abc123",
		ScannedAt:    "2026-03-27T12:00:00Z",
		BoundaryMode: "repo",
	}, "verabase@dev")

	result, err := exec(artifactsv2.AgentTask{
		ID:        "agent-1",
		Kind:      "security",
		IssueID:   "iss-1",
		IssueType: "security_review",
		Question:  "Assess the issue",
		Context: artifactsv2.ContextBundle{
			ID:          "ctx-1",
			EvidenceIDs: []string{"ev-1"},
			EntityIDs:   []string{"getUser"},
			Spans:       []artifactsv2.LocationRef{{RepoRelPath: "service.ts", StartLine: 10, EndLine: 12, SymbolID: "getUser"}},
		},
		Constraints: artifactsv2.AgentConstraints{MaxFiles: 2, MaxTokens: 1200},
	})
	if err != nil {
		t.Fatalf("executor(): %v", err)
	}
	if result.Status != "completed" {
		t.Fatalf("expected completed status, got %#v", result)
	}
	if len(result.EmittedEvidence) != 1 {
		t.Fatalf("expected 1 emitted evidence record, got %#v", result)
	}
	record := result.EmittedEvidence[0]
	if record.Source != "agent" || record.ProducerID != "agent:security" {
		t.Fatalf("unexpected agent evidence provenance: %#v", record)
	}
	if len(record.DerivedFrom) != 1 || record.DerivedFrom[0] != "ev-1" {
		t.Fatalf("expected derived-from evidence linkage, got %#v", record)
	}
}

func TestNewLLMAgentExecutorBuildsPromptAndFailsOnInvalidJSON(t *testing.T) {
	t.Parallel()

	var prompt string
	exec := NewLLMAgentExecutor(context.Background(), &captureProvider{
		response: "not-json",
		capture:  func(s string) { prompt = s },
	}, report.ScanReport{
		RepoPath:     "/tmp/repo",
		RepoName:     "github.com/acme/repo",
		CommitSHA:    "abc123",
		ScannedAt:    "2026-03-27T12:00:00Z",
		BoundaryMode: "repo",
	}, "verabase@dev")

	_, err := exec(artifactsv2.AgentTask{
		ID:        "agent-1",
		Kind:      "design",
		IssueID:   "iss-1",
		IssueType: "design_review",
		Question:  "Assess the issue",
		Context: artifactsv2.ContextBundle{
			ID:          "ctx-1",
			EvidenceIDs: []string{"ev-1"},
			Spans:       []artifactsv2.LocationRef{{RepoRelPath: "service.ts", StartLine: 10, EndLine: 12}},
		},
		Constraints: artifactsv2.AgentConstraints{MaxFiles: 1, MaxTokens: 500},
	})
	if err == nil {
		t.Fatal("expected invalid JSON response to fail")
	}
	if !strings.Contains(prompt, `"issue_id":"iss-1"`) || !strings.Contains(prompt, `"max_tokens":500`) {
		t.Fatalf("expected bounded task context in prompt, got %q", prompt)
	}
}

type captureProvider struct {
	response string
	err      error
	capture  func(string)
}

func (p *captureProvider) Complete(_ context.Context, prompt string) (string, error) {
	if p.capture != nil {
		p.capture(prompt)
	}
	return p.response, p.err
}

// --- parseAgentResponse edge cases ---

func TestParseAgentResponse_EmptyString(t *testing.T) {
	_, err := parseAgentResponse("")
	if err == nil {
		t.Fatal("expected error for empty string")
	}
	if !strings.Contains(err.Error(), "empty_agent_response") {
		t.Errorf("expected empty_agent_response error, got %v", err)
	}
}

func TestParseAgentResponse_WhitespaceOnly(t *testing.T) {
	_, err := parseAgentResponse("   \n\t  ")
	if err == nil {
		t.Fatal("expected error for whitespace-only string")
	}
}

func TestParseAgentResponse_CodeFenceWrapped(t *testing.T) {
	input := "```json\n{\"status\": \"completed\", \"evidence\": []}\n```"
	resp, err := parseAgentResponse(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Status != "completed" {
		t.Errorf("status = %q, want completed", resp.Status)
	}
}

func TestParseAgentResponse_CodeFenceWithoutJsonTag(t *testing.T) {
	input := "```\n{\"status\": \"failed\"}\n```"
	resp, err := parseAgentResponse(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Status != "failed" {
		t.Errorf("status = %q, want failed", resp.Status)
	}
}

func TestParseAgentResponse_ValidJSON(t *testing.T) {
	input := `{"status": "insufficient_context", "unresolved_reasons": ["missing data"]}`
	resp, err := parseAgentResponse(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Status != "insufficient_context" {
		t.Errorf("status = %q, want insufficient_context", resp.Status)
	}
	if len(resp.UnresolvedReasons) != 1 {
		t.Errorf("expected 1 unresolved reason, got %d", len(resp.UnresolvedReasons))
	}
}

// --- agentEvidenceClaim edge cases ---

func TestAgentEvidenceClaim_WithClaim(t *testing.T) {
	task := artifactsv2.AgentTask{IssueType: "fallback_type"}
	item := llmAgentEvidence{Claim: "explicit_claim"}
	got := agentEvidenceClaim(task, item)
	if got != "explicit_claim" {
		t.Errorf("agentEvidenceClaim = %q, want explicit_claim", got)
	}
}

func TestAgentEvidenceClaim_EmptyClaimFallsBackToIssueType(t *testing.T) {
	task := artifactsv2.AgentTask{IssueType: "fallback_type"}
	item := llmAgentEvidence{Claim: ""}
	got := agentEvidenceClaim(task, item)
	if got != "fallback_type" {
		t.Errorf("agentEvidenceClaim = %q, want fallback_type", got)
	}
}

func TestAgentEvidenceClaim_WhitespaceClaimFallsBackToIssueType(t *testing.T) {
	task := artifactsv2.AgentTask{IssueType: "issue_fallback"}
	item := llmAgentEvidence{Claim: "   "}
	got := agentEvidenceClaim(task, item)
	if got != "issue_fallback" {
		t.Errorf("agentEvidenceClaim = %q, want issue_fallback", got)
	}
}

// --- agentEvidenceEntityIDs edge cases ---

func TestAgentEvidenceEntityIDs_WithSymbolID(t *testing.T) {
	task := artifactsv2.AgentTask{Context: artifactsv2.ContextBundle{EntityIDs: []string{"ctx-entity"}}}
	item := llmAgentEvidence{SymbolID: "mySymbol"}
	got := agentEvidenceEntityIDs(task, item)
	if len(got) != 1 || got[0] != "mySymbol" {
		t.Errorf("agentEvidenceEntityIDs = %v, want [mySymbol]", got)
	}
}

func TestAgentEvidenceEntityIDs_EmptySymbolIDFallsBackToContext(t *testing.T) {
	task := artifactsv2.AgentTask{Context: artifactsv2.ContextBundle{EntityIDs: []string{"ctx-1", "ctx-2"}}}
	item := llmAgentEvidence{SymbolID: ""}
	got := agentEvidenceEntityIDs(task, item)
	if len(got) != 2 || got[0] != "ctx-1" || got[1] != "ctx-2" {
		t.Errorf("agentEvidenceEntityIDs = %v, want [ctx-1 ctx-2]", got)
	}
}

func TestAgentEvidenceEntityIDs_WhitespaceSymbolIDFallsBackToContext(t *testing.T) {
	task := artifactsv2.AgentTask{Context: artifactsv2.ContextBundle{EntityIDs: []string{"e1"}}}
	item := llmAgentEvidence{SymbolID: "  "}
	got := agentEvidenceEntityIDs(task, item)
	if len(got) != 1 || got[0] != "e1" {
		t.Errorf("agentEvidenceEntityIDs = %v, want [e1]", got)
	}
}

// --- agentEvidenceLocations edge cases ---

func TestAgentEvidenceLocations_ValidLocation(t *testing.T) {
	task := artifactsv2.AgentTask{}
	item := llmAgentEvidence{File: "main.go", StartLine: 10, EndLine: 20, SymbolID: "foo"}
	got := agentEvidenceLocations(task, item)
	if len(got) != 1 {
		t.Fatalf("expected 1 location, got %d", len(got))
	}
	if got[0].RepoRelPath != "main.go" || got[0].StartLine != 10 || got[0].EndLine != 20 {
		t.Errorf("unexpected location: %+v", got[0])
	}
}

func TestAgentEvidenceLocations_InvalidLocationFallsBackToSpans(t *testing.T) {
	task := artifactsv2.AgentTask{
		Context: artifactsv2.ContextBundle{
			Spans: []artifactsv2.LocationRef{{RepoRelPath: "fallback.go", StartLine: 1, EndLine: 5}},
		},
	}
	// No file path => invalid location, falls back to context spans
	item := llmAgentEvidence{File: "", StartLine: 10, EndLine: 20}
	got := agentEvidenceLocations(task, item)
	if len(got) != 1 || got[0].RepoRelPath != "fallback.go" {
		t.Errorf("expected fallback to context span, got %v", got)
	}
}

func TestAgentEvidenceLocations_InvalidStartLineUsesSpansFallback(t *testing.T) {
	task := artifactsv2.AgentTask{
		Context: artifactsv2.ContextBundle{
			Spans: []artifactsv2.LocationRef{{RepoRelPath: "span.go", StartLine: 5, EndLine: 10}},
		},
	}
	// StartLine=0 => invalid, falls back to context spans
	item := llmAgentEvidence{File: "main.go", StartLine: 0, EndLine: 20}
	got := agentEvidenceLocations(task, item)
	if len(got) != 1 || got[0].RepoRelPath != "span.go" {
		t.Errorf("expected fallback to span, got %v", got)
	}
}

func TestAgentEvidenceLocations_EndBeforeStartUsesSpansFallback(t *testing.T) {
	task := artifactsv2.AgentTask{
		Context: artifactsv2.ContextBundle{
			Spans: []artifactsv2.LocationRef{{RepoRelPath: "span.go", StartLine: 1, EndLine: 2}},
		},
	}
	// EndLine < StartLine => invalid
	item := llmAgentEvidence{File: "main.go", StartLine: 20, EndLine: 10}
	got := agentEvidenceLocations(task, item)
	if len(got) != 1 || got[0].RepoRelPath != "span.go" {
		t.Errorf("expected fallback to span, got %v", got)
	}
}

func TestAgentEvidenceLocations_NoSpansReturnsNil(t *testing.T) {
	task := artifactsv2.AgentTask{Context: artifactsv2.ContextBundle{Spans: nil}}
	item := llmAgentEvidence{File: "", StartLine: 0, EndLine: 0}
	got := agentEvidenceLocations(task, item)
	if got != nil {
		t.Errorf("expected nil, got %v", got)
	}
}

// --- NewLLMAgentExecutor: insufficient_context status (no evidence emitted) ---

func TestNewLLMAgentExecutor_InsufficientContext(t *testing.T) {
	t.Parallel()
	exec := NewLLMAgentExecutor(context.Background(), &captureProvider{
		response: `{"status": "insufficient_context", "unresolved_reasons": ["missing file"]}`,
	}, report.ScanReport{
		RepoPath: "/tmp/repo", RepoName: "test", CommitSHA: "abc", ScannedAt: "2026-01-01T00:00:00Z",
	}, "v1")

	result, err := exec(artifactsv2.AgentTask{
		ID: "t1", Kind: "review", IssueID: "i1", IssueType: "code_review", Question: "q",
		Context: artifactsv2.ContextBundle{ID: "c1"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != "insufficient_context" {
		t.Errorf("status = %q, want insufficient_context", result.Status)
	}
	if len(result.EmittedEvidence) != 0 {
		t.Errorf("expected no emitted evidence, got %d", len(result.EmittedEvidence))
	}
	if len(result.UnresolvedReasons) != 1 {
		t.Errorf("expected 1 unresolved reason, got %d", len(result.UnresolvedReasons))
	}
}

// --- NewLLMAgentExecutor: empty status defaults to "completed" ---

func TestNewLLMAgentExecutor_EmptyStatusDefaultsToCompleted(t *testing.T) {
	t.Parallel()
	exec := NewLLMAgentExecutor(context.Background(), &captureProvider{
		response: `{"status": "", "evidence": [{"claim": "test_claim", "summary": "s", "file": "f.go", "start_line": 1, "end_line": 2}]}`,
	}, report.ScanReport{
		RepoPath: "/tmp", RepoName: "test", CommitSHA: "abc", ScannedAt: "2026-01-01T00:00:00Z",
	}, "v1")

	result, err := exec(artifactsv2.AgentTask{
		ID: "t1", Kind: "check", IssueID: "i1", IssueType: "type1", Question: "q",
		Context: artifactsv2.ContextBundle{ID: "c1", EvidenceIDs: []string{"ev1"}, EntityIDs: []string{"e1"}},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != "completed" {
		t.Errorf("status = %q, want completed (default for empty)", result.Status)
	}
	if len(result.EmittedEvidence) != 1 {
		t.Errorf("expected 1 evidence record, got %d", len(result.EmittedEvidence))
	}
}

// --- NewLLMAgentExecutor: completed with no evidence ---

func TestNewLLMAgentExecutor_CompletedNoEvidence(t *testing.T) {
	t.Parallel()
	exec := NewLLMAgentExecutor(context.Background(), &captureProvider{
		response: `{"status": "completed", "evidence": []}`,
	}, report.ScanReport{
		RepoPath: "/tmp", RepoName: "test", CommitSHA: "abc", ScannedAt: "2026-01-01T00:00:00Z",
	}, "v1")

	result, err := exec(artifactsv2.AgentTask{
		ID: "t1", Kind: "check", IssueID: "i1", IssueType: "type1", Question: "q",
		Context: artifactsv2.ContextBundle{ID: "c1"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != "completed" {
		t.Errorf("status = %q, want completed", result.Status)
	}
	if len(result.EmittedEvidence) != 0 {
		t.Errorf("expected 0 evidence, got %d", len(result.EmittedEvidence))
	}
}

// --- NewLLMAgentExecutor: provider error ---

func TestNewLLMAgentExecutor_ProviderError(t *testing.T) {
	t.Parallel()
	exec := NewLLMAgentExecutor(context.Background(), &captureProvider{
		err: fmt.Errorf("provider unavailable"),
	}, report.ScanReport{
		RepoPath: "/tmp", RepoName: "test", CommitSHA: "abc", ScannedAt: "2026-01-01T00:00:00Z",
	}, "v1")

	_, err := exec(artifactsv2.AgentTask{
		ID: "t1", Kind: "check", IssueID: "i1", IssueType: "type1", Question: "q",
		Context: artifactsv2.ContextBundle{ID: "c1"},
	})
	if err == nil {
		t.Fatal("expected provider error to propagate")
	}
	if !strings.Contains(err.Error(), "provider unavailable") {
		t.Errorf("expected 'provider unavailable' in error, got %v", err)
	}
}

// --- NewLLMAgentExecutor: evidence with empty claim, empty symbol, invalid location ---

func TestNewLLMAgentExecutor_EvidenceEdgeCases(t *testing.T) {
	t.Parallel()
	exec := NewLLMAgentExecutor(context.Background(), &captureProvider{
		response: `{
			"status": "completed",
			"evidence": [
				{
					"claim": "",
					"summary": "no claim provided",
					"file": "",
					"start_line": 0,
					"end_line": 0,
					"symbol_id": ""
				}
			]
		}`,
	}, report.ScanReport{
		RepoPath: "/tmp", RepoName: "test", CommitSHA: "abc", ScannedAt: "2026-01-01T00:00:00Z",
	}, "v1")

	result, err := exec(artifactsv2.AgentTask{
		ID: "t1", Kind: "check", IssueID: "i1", IssueType: "fallback_issue", Question: "q",
		Context: artifactsv2.ContextBundle{
			ID:          "c1",
			EvidenceIDs: []string{"ev1"},
			EntityIDs:   []string{"entity1"},
			Spans:       []artifactsv2.LocationRef{{RepoRelPath: "ctx.go", StartLine: 1, EndLine: 5}},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != "completed" {
		t.Errorf("status = %q, want completed", result.Status)
	}
	if len(result.EmittedEvidence) != 1 {
		t.Fatalf("expected 1 evidence record, got %d", len(result.EmittedEvidence))
	}

	record := result.EmittedEvidence[0]
	// Empty claim should fall back to issue type
	if len(record.Claims) != 1 || record.Claims[0] != "fallback_issue" {
		t.Errorf("claims = %v, want [fallback_issue]", record.Claims)
	}
	// Empty symbol should fall back to context entity IDs
	if len(record.EntityIDs) != 1 || record.EntityIDs[0] != "entity1" {
		t.Errorf("entity_ids = %v, want [entity1]", record.EntityIDs)
	}
	// Invalid location should fall back to context spans
	if len(record.Locations) != 1 || record.Locations[0].RepoRelPath != "ctx.go" {
		t.Errorf("locations = %v, want fallback to ctx.go", record.Locations)
	}
}

// --- NewLLMAgentExecutor: evidence with no spans fallback (nil locations) ---

func TestNewLLMAgentExecutor_EvidenceNoSpansFallback(t *testing.T) {
	t.Parallel()
	exec := NewLLMAgentExecutor(context.Background(), &captureProvider{
		response: `{
			"status": "completed",
			"evidence": [{"claim": "c", "summary": "s", "file": "", "start_line": 0, "end_line": 0}]
		}`,
	}, report.ScanReport{
		RepoPath: "/tmp", RepoName: "test", CommitSHA: "abc", ScannedAt: "2026-01-01T00:00:00Z",
	}, "v1")

	result, err := exec(artifactsv2.AgentTask{
		ID: "t1", Kind: "check", IssueID: "i1", IssueType: "type1", Question: "q",
		Context: artifactsv2.ContextBundle{
			ID:    "c1",
			Spans: nil, // no spans to fall back to
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.EmittedEvidence) != 1 {
		t.Fatalf("expected 1 evidence, got %d", len(result.EmittedEvidence))
	}
	if result.EmittedEvidence[0].Locations != nil {
		t.Errorf("expected nil locations, got %v", result.EmittedEvidence[0].Locations)
	}
}
