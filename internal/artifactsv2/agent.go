package artifactsv2

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

func buildAgentTasks(candidates []IssueCandidate, evidence EvidenceArtifact) []AgentTask {
	if len(candidates) == 0 || len(evidence.Evidence) == 0 {
		return nil
	}

	selections := buildContextSelections(candidates, evidence)
	if len(selections) == 0 {
		return nil
	}

	candidateIndex := make(map[string]IssueCandidate, len(candidates))
	for _, candidate := range candidates {
		candidateIndex[candidate.ID] = candidate
	}

	var tasks []AgentTask
	for _, selection := range selections {
		if selection.TriggerType != "issue" {
			continue
		}
		candidate, ok := candidateIndex[selection.TriggerID]
		if !ok {
			continue
		}
		status, unresolvedReasons := plannedAgentStatus(selection)
		if status == "insufficient_context" {
			_ = unresolvedReasons
			continue
		}
		triggerReason := plannedAgentTriggerReason(selection.SelectionTrace)
		tasks = append(tasks, AgentTask{
			ID:        plannedAgentID(candidate, triggerReason),
			Kind:      plannedAgentKind(candidate),
			IssueID:   candidate.ID,
			IssueType: plannedAgentIssueType(candidate),
			Question:  plannedAgentQuestion(candidate, triggerReason),
			Context:   contextBundleFromSelection(selection),
			Constraints: AgentConstraints{
				MaxFiles:         selection.MaxFiles,
				MaxTokens:        selection.MaxTokens,
				AllowSpeculation: false,
			},
		})
	}

	sort.Slice(tasks, func(i, j int) bool {
		if tasks[i].Kind != tasks[j].Kind {
			return tasks[i].Kind < tasks[j].Kind
		}
		if tasks[i].IssueID != tasks[j].IssueID {
			return tasks[i].IssueID < tasks[j].IssueID
		}
		return tasks[i].ID < tasks[j].ID
	})
	return tasks
}

func executeAgentTasks(tasks []AgentTask, exec AgentExecutor) ([]AgentResult, error) {
	if len(tasks) == 0 || exec == nil {
		return nil, nil
	}

	results := make([]AgentResult, 0, len(tasks))
	for _, task := range tasks {
		result, err := exec(task)
		if err != nil {
			results = append(results, AgentResult{
				TaskID:             task.ID,
				Kind:               task.Kind,
				IssueID:            task.IssueID,
				ContextSelectionID: task.Context.ID,
				Status:             "failed",
				UnresolvedReasons:  []string{fmt.Sprintf("executor_error:%v", err)},
			})
			continue
		}

		if result.TaskID == "" {
			result.TaskID = task.ID
		}
		if result.Kind == "" {
			result.Kind = task.Kind
		}
		if result.IssueID == "" {
			result.IssueID = task.IssueID
		}
		if result.ContextSelectionID == "" {
			result.ContextSelectionID = task.Context.ID
		}
		if result.Status == "" {
			result.Status = "completed"
		}
		if result.Status == "failed" && len(result.UnresolvedReasons) == 0 {
			result.UnresolvedReasons = []string{"executor_failed"}
		}
		if result.Status == "insufficient_context" && len(result.UnresolvedReasons) == 0 {
			result.UnresolvedReasons = []string{"insufficient_context"}
		}
		results = append(results, result)
	}

	sort.Slice(results, func(i, j int) bool {
		if results[i].TaskID != results[j].TaskID {
			return results[i].TaskID < results[j].TaskID
		}
		if results[i].IssueID != results[j].IssueID {
			return results[i].IssueID < results[j].IssueID
		}
		return results[i].Kind < results[j].Kind
	})
	return results, nil
}

func buildAgentRuns(candidates []IssueCandidate, selections []ContextSelectionRecord, results []AgentResult) []AgentRun {
	if len(candidates) == 0 || len(selections) == 0 {
		return nil
	}

	candidateIndex := make(map[string]IssueCandidate, len(candidates))
	for _, candidate := range candidates {
		candidateIndex[candidate.ID] = candidate
	}

	resultIndex := make(map[string]AgentResult, len(results))
	for _, result := range results {
		if result.TaskID == "" {
			continue
		}
		resultIndex[result.TaskID] = result
	}

	var runs []AgentRun
	for _, selection := range selections {
		if selection.TriggerType != "issue" {
			continue
		}
		candidate, ok := candidateIndex[selection.TriggerID]
		if !ok {
			continue
		}
		triggerReason := plannedAgentTriggerReason(selection.SelectionTrace)
		status, unresolvedReasons := plannedAgentStatus(selection)
		run := AgentRun{
			ID:                 plannedAgentID(candidate, triggerReason),
			Kind:               plannedAgentKind(candidate),
			IssueType:          plannedAgentIssueType(candidate),
			Question:           plannedAgentQuestion(candidate, triggerReason),
			IssueID:            candidate.ID,
			ContextSelectionID: selection.ID,
			TriggerReason:      triggerReason,
			InputEvidenceIDs:   dedupeStringsSorted(selection.SelectedEvidenceIDs),
			OutputEvidenceIDs:  nil,
			UnresolvedReasons:  unresolvedReasons,
			MaxFiles:           selection.MaxFiles,
			MaxTokens:          selection.MaxTokens,
			AllowSpeculation:   false,
			Status:             status,
		}
		if result, ok := resultIndex[run.ID]; ok {
			run = applyAgentResult(run, result)
		}
		runs = append(runs, run)
	}

	sort.Slice(runs, func(i, j int) bool {
		if runs[i].Kind != runs[j].Kind {
			return runs[i].Kind < runs[j].Kind
		}
		if runs[i].TriggerReason != runs[j].TriggerReason {
			return runs[i].TriggerReason < runs[j].TriggerReason
		}
		return runs[i].ID < runs[j].ID
	})
	return runs
}

func applyAgentResult(run AgentRun, result AgentResult) AgentRun {
	if result.Kind != "" {
		run.Kind = result.Kind
	}
	if result.IssueID != "" {
		run.IssueID = result.IssueID
	}
	if result.ContextSelectionID != "" {
		run.ContextSelectionID = result.ContextSelectionID
	}
	if result.Status != "" {
		run.Status = result.Status
	}
	run.UnresolvedReasons = dedupeStringsSorted(append([]string(nil), result.UnresolvedReasons...))
	if len(result.EmittedEvidence) > 0 {
		outputIDs := make([]string, 0, len(result.EmittedEvidence))
		for _, record := range result.EmittedEvidence {
			if record.ID != "" {
				outputIDs = append(outputIDs, record.ID)
			}
		}
		run.OutputEvidenceIDs = dedupeStringsSorted(outputIDs)
	}
	return run
}

func plannedAgentKind(candidate IssueCandidate) string {
	switch candidate.Category {
	case "security", "frontend_security":
		return "security"
	case "architecture", "design":
		return "design"
	default:
		return "bug"
	}
}

func plannedAgentIssueType(candidate IssueCandidate) string {
	switch candidate.Category {
	case "security", "frontend_security":
		return "security_review"
	case "architecture", "design":
		return "design_review"
	default:
		return "bug_review"
	}
}

func plannedAgentTriggerReason(selectionTrace []string) string {
	for _, entry := range selectionTrace {
		if strings.HasPrefix(entry, "trigger_reason:") {
			return strings.TrimPrefix(entry, "trigger_reason:")
		}
	}
	return "policy_review"
}

func plannedAgentQuestion(candidate IssueCandidate, triggerReason string) string {
	switch triggerReason {
	case "unknown_issue":
		return "Assess whether the issue should remain unknown or can be confirmed with the selected bounded context."
	case "conflict_review":
		return "Assess conflicting support and counter-evidence using the selected bounded context."
	case "high_severity_review":
		return "Assess whether the high-severity issue is sufficiently supported by the selected bounded context."
	default:
		return "Assess the issue using the selected bounded context."
	}
}

func plannedAgentStatus(selection ContextSelectionRecord) (string, []string) {
	var unresolved []string
	if len(selection.SelectedEvidenceIDs) == 0 {
		unresolved = append(unresolved, "no_selected_evidence")
	}
	if len(selection.SelectedSpans) == 0 {
		unresolved = append(unresolved, "no_selected_spans")
	}
	if len(unresolved) > 0 {
		return "insufficient_context", unresolved
	}
	return "planned", nil
}

func contextBundleFromSelection(selection ContextSelectionRecord) ContextBundle {
	return ContextBundle{
		ID:             selection.ID,
		TriggerType:    selection.TriggerType,
		TriggerID:      selection.TriggerID,
		EvidenceIDs:    dedupeStringsSorted(selection.SelectedEvidenceIDs),
		EntityIDs:      dedupeStringsSorted(selection.EntityIDs),
		Spans:          append([]LocationRef(nil), selection.SelectedSpans...),
		SelectionTrace: append([]string(nil), selection.SelectionTrace...),
	}
}

func plannedAgentID(candidate IssueCandidate, triggerReason string) string {
	sum := sha256.Sum256([]byte(candidate.ID + ":" + triggerReason + ":" + plannedAgentKind(candidate)))
	return "agent-" + hex.EncodeToString(sum[:8])
}
