package engine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/verabase/code-verification-engine/internal/artifactsv2"
	"github.com/verabase/code-verification-engine/internal/interpret"
	"github.com/verabase/code-verification-engine/internal/report"
)

type llmAgentResponse struct {
	Status            string             `json:"status"`
	UnresolvedReasons []string           `json:"unresolved_reasons,omitempty"`
	Evidence          []llmAgentEvidence `json:"evidence,omitempty"`
}

type llmAgentEvidence struct {
	Claim     string `json:"claim"`
	Summary   string `json:"summary,omitempty"`
	File      string `json:"file,omitempty"`
	StartLine int    `json:"start_line,omitempty"`
	EndLine   int    `json:"end_line,omitempty"`
	SymbolID  string `json:"symbol_id,omitempty"`
}

// NewLLMAgentExecutor returns the bounded agent runtime used by the engine to
// execute non-deterministic agent tasks while preserving evidence-first output.
func NewLLMAgentExecutor(ctx context.Context, provider interpret.LLMProvider, scan report.ScanReport, engineVersion string) artifactsv2.AgentExecutor {
	repo := scan.RepoName
	commit := scan.CommitSHA
	timestamp := scan.ScannedAt
	boundaryHash := agentRuntimeBoundaryHash(scan)

	return func(task artifactsv2.AgentTask) (artifactsv2.AgentResult, error) {
		raw, err := provider.Complete(ctx, buildAgentPrompt(task))
		if err != nil {
			return artifactsv2.AgentResult{}, err
		}
		response, err := parseAgentResponse(raw)
		if err != nil {
			return artifactsv2.AgentResult{}, err
		}

		result := artifactsv2.AgentResult{
			TaskID:             task.ID,
			Kind:               task.Kind,
			IssueID:            task.IssueID,
			ContextSelectionID: task.Context.ID,
			Status:             response.Status,
			UnresolvedReasons:  append([]string(nil), response.UnresolvedReasons...),
		}
		if result.Status == "" {
			result.Status = "completed"
		}

		if result.Status != "completed" || len(response.Evidence) == 0 {
			return result, nil
		}

		result.EmittedEvidence = make([]artifactsv2.EvidenceRecord, 0, len(response.Evidence))
		for i, item := range response.Evidence {
			record := artifactsv2.EvidenceRecord{
				ID:              agentEvidenceID(task, item, i),
				Kind:            "agent_assertion",
				Source:          "agent",
				ProducerID:      "agent:" + task.Kind,
				ProducerVersion: engineVersion,
				Repo:            repo,
				Commit:          commit,
				BoundaryHash:    boundaryHash,
				FactQuality:     "heuristic",
				EntityIDs:       agentEvidenceEntityIDs(task, item),
				Locations:       agentEvidenceLocations(task, item),
				Claims:          []string{agentEvidenceClaim(task, item)},
				Payload: map[string]any{
					"summary":    strings.TrimSpace(item.Summary),
					"issue_type": task.IssueType,
					"question":   task.Question,
				},
				DerivedFrom: append([]string(nil), task.Context.EvidenceIDs...),
				CreatedAt:   timestamp,
			}
			result.EmittedEvidence = append(result.EmittedEvidence, record)
		}
		return result, nil
	}
}

func buildAgentPrompt(task artifactsv2.AgentTask) string {
	payload := map[string]any{
		"issue_id":   task.IssueID,
		"issue_type": task.IssueType,
		"kind":       task.Kind,
		"question":   task.Question,
		"context": map[string]any{
			"id":              task.Context.ID,
			"evidence_ids":    task.Context.EvidenceIDs,
			"entity_ids":      task.Context.EntityIDs,
			"spans":           task.Context.Spans,
			"selection_trace": task.Context.SelectionTrace,
		},
		"constraints": map[string]any{
			"max_files":         task.Constraints.MaxFiles,
			"max_tokens":        task.Constraints.MaxTokens,
			"allow_speculation": task.Constraints.AllowSpeculation,
		},
	}
	data, _ := json.Marshal(payload)
	return strings.TrimSpace(fmt.Sprintf(`You are a bounded verification agent.
Use only the provided JSON context. Do not speculate beyond it.
Return strict JSON only with this shape:
{
  "status": "completed" | "insufficient_context" | "failed",
  "unresolved_reasons": ["..."],
  "evidence": [
    {
      "claim": "short_claim",
      "summary": "brief evidence-backed summary",
      "file": "repo/relative/path",
      "start_line": 1,
      "end_line": 1,
      "symbol_id": "optional"
    }
  ]
}
If context is insufficient, return status="insufficient_context" and no evidence.
If you cannot complete the task reliably, return status="failed" and no evidence.
Context JSON:
%s`, string(data)))
}

func parseAgentResponse(raw string) (llmAgentResponse, error) {
	var out llmAgentResponse
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return out, fmt.Errorf("empty_agent_response")
	}
	trimmed = strings.TrimPrefix(trimmed, "```json")
	trimmed = strings.TrimPrefix(trimmed, "```")
	trimmed = strings.TrimSuffix(trimmed, "```")
	trimmed = strings.TrimSpace(trimmed)
	if err := json.Unmarshal([]byte(trimmed), &out); err != nil {
		return out, fmt.Errorf("parse_agent_response: %w", err)
	}
	return out, nil
}

func agentRuntimeBoundaryHash(scan report.ScanReport) string {
	sum := sha256.Sum256([]byte(scan.RepoPath + ":" + scan.CommitSHA + ":" + scan.ScanSubdir + ":" + scan.BoundaryMode))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func agentEvidenceID(task artifactsv2.AgentTask, item llmAgentEvidence, idx int) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s:%d:%s:%s:%d:%d:%s", task.ID, idx, item.Claim, item.File, item.StartLine, item.EndLine, item.SymbolID)))
	return "ev-" + hex.EncodeToString(sum[:8])
}

func agentEvidenceClaim(task artifactsv2.AgentTask, item llmAgentEvidence) string {
	if strings.TrimSpace(item.Claim) != "" {
		return strings.TrimSpace(item.Claim)
	}
	return task.IssueType
}

func agentEvidenceEntityIDs(task artifactsv2.AgentTask, item llmAgentEvidence) []string {
	if strings.TrimSpace(item.SymbolID) != "" {
		return []string{strings.TrimSpace(item.SymbolID)}
	}
	return append([]string(nil), task.Context.EntityIDs...)
}

func agentEvidenceLocations(task artifactsv2.AgentTask, item llmAgentEvidence) []artifactsv2.LocationRef {
	loc := artifactsv2.LocationRef{
		RepoRelPath: strings.TrimSpace(item.File),
		StartLine:   item.StartLine,
		EndLine:     item.EndLine,
		SymbolID:    strings.TrimSpace(item.SymbolID),
	}
	if loc.RepoRelPath != "" && loc.StartLine > 0 && loc.EndLine >= loc.StartLine {
		return []artifactsv2.LocationRef{loc}
	}
	if len(task.Context.Spans) > 0 {
		return []artifactsv2.LocationRef{task.Context.Spans[0]}
	}
	return nil
}
