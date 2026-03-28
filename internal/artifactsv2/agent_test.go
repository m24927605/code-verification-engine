package artifactsv2

import (
	"errors"
	"testing"
)

func TestBuildAgentRunsFromContextSelections(t *testing.T) {
	t.Parallel()

	candidates := []IssueCandidate{
		{
			ID:          "iss-1",
			Category:    "security",
			Severity:    "high",
			PolicyClass: "advisory",
		},
	}
	selections := []ContextSelectionRecord{
		{
			ID:                  "ctx-1",
			TriggerType:         "issue",
			TriggerID:           "iss-1",
			SelectedEvidenceIDs: []string{"ev-2", "ev-1"},
			SelectedSpans:       []LocationRef{{RepoRelPath: "service.ts", StartLine: 10, EndLine: 12}},
			MaxFiles:            2,
			MaxTokens:           1200,
			SelectionTrace:      []string{"trigger_reason:high_severity_review"},
		},
	}

	runs := buildAgentRuns(candidates, selections, nil)
	if len(runs) != 1 {
		t.Fatalf("expected 1 planned agent run, got %d", len(runs))
	}
	if runs[0].Kind != "security" {
		t.Fatalf("expected security agent kind, got %q", runs[0].Kind)
	}
	if runs[0].Status != "planned" {
		t.Fatalf("expected planned status, got %q", runs[0].Status)
	}
	if runs[0].IssueType != "security_review" {
		t.Fatalf("expected security_review issue type, got %q", runs[0].IssueType)
	}
	if runs[0].Question == "" {
		t.Fatalf("expected planned question to be populated, got %#v", runs[0])
	}
	if runs[0].TriggerReason != "high_severity_review" {
		t.Fatalf("expected trigger reason to propagate, got %q", runs[0].TriggerReason)
	}
	if len(runs[0].InputEvidenceIDs) != 2 || runs[0].InputEvidenceIDs[0] != "ev-1" {
		t.Fatalf("expected deterministic input evidence ordering, got %#v", runs[0].InputEvidenceIDs)
	}
	if runs[0].IssueID != "iss-1" || runs[0].ContextSelectionID != "ctx-1" {
		t.Fatalf("expected issue/context linkage on agent run, got %#v", runs[0])
	}
	if runs[0].MaxFiles != 2 || runs[0].MaxTokens != 1200 || runs[0].AllowSpeculation {
		t.Fatalf("expected planned agent budget constraints, got %#v", runs[0])
	}
}

func TestBuildAgentRunsMarksInsufficientContext(t *testing.T) {
	t.Parallel()

	candidates := []IssueCandidate{{
		ID:          "iss-1",
		Category:    "bug",
		Severity:    "high",
		PolicyClass: "advisory",
	}}
	selections := []ContextSelectionRecord{{
		ID:             "ctx-1",
		TriggerType:    "issue",
		TriggerID:      "iss-1",
		MaxFiles:       2,
		MaxTokens:      1200,
		SelectionTrace: []string{"trigger_reason:unknown_issue"},
	}}

	runs := buildAgentRuns(candidates, selections, nil)
	if len(runs) != 1 {
		t.Fatalf("expected 1 agent run, got %d", len(runs))
	}
	if runs[0].Status != "insufficient_context" {
		t.Fatalf("expected insufficient_context status, got %#v", runs[0])
	}
	if len(runs[0].UnresolvedReasons) != 2 {
		t.Fatalf("expected unresolved reasons to be populated, got %#v", runs[0])
	}
}

func TestBuildAgentRunsAppliesAgentResult(t *testing.T) {
	t.Parallel()

	candidates := []IssueCandidate{{
		ID:          "iss-1",
		Category:    "security",
		Severity:    "high",
		PolicyClass: "advisory",
	}}
	selections := []ContextSelectionRecord{{
		ID:                  "ctx-1",
		TriggerType:         "issue",
		TriggerID:           "iss-1",
		SelectedEvidenceIDs: []string{"ev-1"},
		SelectedSpans:       []LocationRef{{RepoRelPath: "service.ts", StartLine: 10, EndLine: 12}},
		MaxFiles:            2,
		MaxTokens:           1200,
		SelectionTrace:      []string{"trigger_reason:high_severity_review"},
	}}
	results := []AgentResult{{
		TaskID:  plannedAgentID(candidates[0], "high_severity_review"),
		Kind:    "security",
		IssueID: "iss-1",
		Status:  "completed",
		EmittedEvidence: []EvidenceRecord{{
			ID: "ev-agent-1",
		}},
	}}

	runs := buildAgentRuns(candidates, selections, results)
	if len(runs) != 1 {
		t.Fatalf("expected 1 agent run, got %d", len(runs))
	}
	if runs[0].Status != "completed" {
		t.Fatalf("expected completed status after applying result, got %#v", runs[0])
	}
	if len(runs[0].OutputEvidenceIDs) != 1 || runs[0].OutputEvidenceIDs[0] != "ev-agent-1" {
		t.Fatalf("expected emitted evidence ids to propagate, got %#v", runs[0])
	}
}

func TestBuildAgentTasksUsesBoundedSelections(t *testing.T) {
	t.Parallel()

	candidates := []IssueCandidate{{
		ID:          "iss-1",
		Category:    "security",
		Severity:    "high",
		Status:      "open",
		PolicyClass: "advisory",
		EvidenceIDs: []string{"ev-1"},
	}}
	evidence := EvidenceArtifact{
		Evidence: []EvidenceRecord{{
			ID:        "ev-1",
			Locations: []LocationRef{{RepoRelPath: "service.ts", StartLine: 10, EndLine: 12}},
			EntityIDs: []string{"fn-1"},
		}},
	}

	tasks := buildAgentTasks(candidates, evidence)
	if len(tasks) != 1 {
		t.Fatalf("expected 1 agent task, got %d", len(tasks))
	}
	if tasks[0].ID == "" || tasks[0].Context.ID == "" {
		t.Fatalf("expected stable task/context ids, got %#v", tasks[0])
	}
	if tasks[0].Kind != "security" || tasks[0].IssueType != "security_review" {
		t.Fatalf("expected security task semantics, got %#v", tasks[0])
	}
	if tasks[0].Constraints.AllowSpeculation {
		t.Fatalf("expected speculation to be disabled, got %#v", tasks[0].Constraints)
	}
	if len(tasks[0].Context.EvidenceIDs) != 1 || tasks[0].Context.EvidenceIDs[0] != "ev-1" {
		t.Fatalf("expected selected evidence to flow into context, got %#v", tasks[0].Context)
	}
}

func TestExecuteAgentTasksNormalizesExecutorResults(t *testing.T) {
	t.Parallel()

	tasks := []AgentTask{{
		ID:        "agent-1",
		Kind:      "bug",
		IssueID:   "iss-1",
		IssueType: "bug_review",
		Question:  "Review bug",
		Context:   ContextBundle{ID: "ctx-1"},
	}}

	results, err := executeAgentTasks(tasks, func(task AgentTask) (AgentResult, error) {
		return AgentResult{
			Status: "completed",
			EmittedEvidence: []EvidenceRecord{{
				ID: "ev-agent-1",
			}},
		}, nil
	})
	if err != nil {
		t.Fatalf("executeAgentTasks(): %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].TaskID != "agent-1" || results[0].IssueID != "iss-1" || results[0].ContextSelectionID != "ctx-1" {
		t.Fatalf("expected task linkage defaults to be normalized, got %#v", results[0])
	}
	if results[0].Kind != "bug" || results[0].Status != "completed" {
		t.Fatalf("expected normalized kind/status, got %#v", results[0])
	}
}

func TestExecuteAgentTasksPreservesFailedExecutionAsResult(t *testing.T) {
	t.Parallel()

	tasks := []AgentTask{{
		ID:      "agent-1",
		Kind:    "design",
		IssueID: "iss-1",
		Context: ContextBundle{ID: "ctx-1"},
	}}

	results, err := executeAgentTasks(tasks, func(task AgentTask) (AgentResult, error) {
		return AgentResult{}, errors.New("runtime_unavailable")
	})
	if err != nil {
		t.Fatalf("executeAgentTasks(): %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 failed result, got %d", len(results))
	}
	if results[0].Status != "failed" {
		t.Fatalf("expected failed status, got %#v", results[0])
	}
	if len(results[0].UnresolvedReasons) != 1 || results[0].UnresolvedReasons[0] == "" {
		t.Fatalf("expected executor failure reason, got %#v", results[0])
	}
}
