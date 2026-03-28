package engine

import (
	"context"
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
