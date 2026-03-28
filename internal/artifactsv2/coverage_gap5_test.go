package artifactsv2

import (
	"errors"
	"testing"

	"github.com/verabase/code-verification-engine/internal/report"
	"github.com/verabase/code-verification-engine/internal/rules"
)

func TestBuildIssueCandidateSetAgentExecutorReturnsError(t *testing.T) {
	t.Parallel()

	input := IssueCandidateBuildInput{
		Scan: report.ScanReport{
			RepoName:     "github.com/acme/repo",
			CommitSHA:    "abc123def456",
			ScannedAt:    "2026-03-27T12:00:00Z",
			FileCount:    3,
			BoundaryMode: "repo",
		},
		Verification: VerificationSource{
			ReportSchemaVersion: "1.0.0",
			IssueSeeds: []IssueSeed{{
				RuleID:     "DESIGN-001",
				Title:      "Unknown layering issue",
				Source:     "rule",
				Category:   "design",
				Severity:   "high",
				Status:     "unknown",
				Confidence: 0.62,
				Quality:    0.7,
				File:       "service.ts",
				Symbol:     "getUser",
				StartLine:  44,
				EndLine:    48,
			}},
		},
		AgentExecutor: func(task AgentTask) (AgentResult, error) {
			return AgentResult{}, errors.New("agent_failure")
		},
		EngineVersion: "dev",
	}

	_, err := BuildIssueCandidateSet(input)
	if err != nil {
		t.Fatalf("BuildIssueCandidateSet should not propagate agent errors: %v", err)
	}
}

func TestBuildIssueCandidateSetDefaultsEngineVersion(t *testing.T) {
	t.Parallel()

	input := IssueCandidateBuildInput{
		Scan: report.ScanReport{
			RepoName:     "github.com/acme/repo",
			CommitSHA:    "abc123def456",
			ScannedAt:    "2026-03-27T12:00:00Z",
			FileCount:    3,
			BoundaryMode: "repo",
		},
		Verification: VerificationSource{
			ReportSchemaVersion: "1.0.0",
			IssueSeeds: []IssueSeed{{
				RuleID: "SEC-001", Title: "Test", Source: "rule", Category: "security",
				Severity: "high", Status: "open", Confidence: 0.9, Quality: 1.0,
				File: "service.ts", Symbol: "getUser", StartLine: 10, EndLine: 10,
			}},
		},
		EngineVersion: "",
	}

	set, err := BuildIssueCandidateSet(input)
	if err != nil {
		t.Fatalf("BuildIssueCandidateSet(): %v", err)
	}
	if set.EngineVersion != "dev" {
		t.Fatalf("expected default engine version 'dev', got %q", set.EngineVersion)
	}
}

func TestBuildIssueCandidateSetSkipsExecutorWhenResultsExist(t *testing.T) {
	t.Parallel()

	input := IssueCandidateBuildInput{
		Scan: report.ScanReport{
			RepoName:     "github.com/acme/repo",
			CommitSHA:    "abc123def456",
			ScannedAt:    "2026-03-27T12:00:00Z",
			FileCount:    3,
			BoundaryMode: "repo",
		},
		Verification: VerificationSource{
			ReportSchemaVersion: "1.0.0",
			IssueSeeds: []IssueSeed{{
				RuleID: "SEC-001", Title: "Test", Source: "rule", Category: "security",
				Severity: "high", Status: "unknown", Confidence: 0.9, Quality: 1.0,
				File: "service.ts", Symbol: "getUser", StartLine: 10, EndLine: 10,
			}},
			AgentResults: []AgentResult{{TaskID: "pre-existing", Kind: "security", IssueID: "iss-1", Status: "completed"}},
		},
		AgentExecutor: func(task AgentTask) (AgentResult, error) {
			t.Fatal("executor should not be called when results already exist")
			return AgentResult{}, nil
		},
		EngineVersion: "dev",
	}

	_, err := BuildIssueCandidateSet(input)
	if err != nil {
		t.Fatalf("BuildIssueCandidateSet(): %v", err)
	}
}

func TestCompatPrimaryLocationFixesInvertedLineRange(t *testing.T) {
	t.Parallel()

	finding := rules.Finding{
		Evidence: []rules.Evidence{{File: "a.ts", LineStart: 5, LineEnd: 3, Symbol: "fn"}},
	}
	file, _, start, end := compatPrimaryLocation(finding)
	if file != "a.ts" || start != 5 || end != 5 {
		t.Fatalf("expected inverted lines to be fixed, got file=%q start=%d end=%d", file, start, end)
	}
}

func TestPreferredCategoryBothEmpty(t *testing.T) {
	t.Parallel()

	got := preferredCategory("", "")
	if got != "" {
		t.Fatalf("expected empty for both empty, got %q", got)
	}
}

func TestBuildAgentTasksSortsDeterministically(t *testing.T) {
	t.Parallel()

	candidates := []IssueCandidate{
		{
			ID: "iss-2", Category: "security", Severity: "critical",
			Status: "open", PolicyClass: "advisory",
			EvidenceIDs: []string{"ev-2"}, CounterEvidenceIDs: []string{"ev-3"},
		},
		{
			ID: "iss-1", Category: "bug", Severity: "high",
			Status: "unknown", PolicyClass: "unknown_retained",
			EvidenceIDs: []string{"ev-1"},
		},
	}
	evidence := EvidenceArtifact{
		Evidence: []EvidenceRecord{
			{ID: "ev-1", Locations: []LocationRef{{RepoRelPath: "a.ts", StartLine: 1, EndLine: 1}}, EntityIDs: []string{"fn-1"}},
			{ID: "ev-2", Locations: []LocationRef{{RepoRelPath: "b.ts", StartLine: 5, EndLine: 5}}, EntityIDs: []string{"fn-2"}},
			{ID: "ev-3", Locations: []LocationRef{{RepoRelPath: "b.ts", StartLine: 10, EndLine: 10}}, EntityIDs: []string{"fn-3"}},
		},
	}

	tasks := buildAgentTasks(candidates, evidence)
	if len(tasks) < 1 {
		t.Fatalf("expected at least 1 task, got %d", len(tasks))
	}
	for i := 1; i < len(tasks); i++ {
		if tasks[i-1].Kind > tasks[i].Kind {
			t.Fatalf("expected sorted tasks by kind")
		}
	}
}
