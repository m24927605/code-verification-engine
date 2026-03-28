package artifactsv2

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
)

const (
	defaultContextMaxFiles  = 2
	defaultContextMaxSpans  = 4
	defaultContextMaxTokens = 1200
)

type ContextRequest struct {
	TriggerType string
	TriggerID   string
	MaxFiles    int
	MaxSpans    int
	MaxTokens   int
}

type ContextBundle struct {
	ID             string
	TriggerType    string
	TriggerID      string
	EvidenceIDs    []string
	EntityIDs      []string
	Spans          []LocationRef
	SelectionTrace []string
}

func buildContextSelections(candidates []IssueCandidate, evidence EvidenceArtifact) []ContextSelectionRecord {
	if len(candidates) == 0 || len(evidence.Evidence) == 0 {
		return nil
	}

	evidenceIndex := make(map[string]EvidenceRecord, len(evidence.Evidence))
	for _, record := range evidence.Evidence {
		evidenceIndex[record.ID] = record
	}

	var out []ContextSelectionRecord
	for _, candidate := range candidates {
		triggerReason, ok := contextSelectionTrigger(candidate)
		if !ok {
			continue
		}
		req := ContextRequest{
			TriggerType: "issue",
			TriggerID:   candidate.ID,
			MaxFiles:    defaultContextMaxFiles,
			MaxSpans:    defaultContextMaxSpans,
			MaxTokens:   defaultContextMaxTokens,
		}
		bundle := buildContextBundle(req, candidate, evidenceIndex)
		trace := append([]string{"trigger_reason:" + triggerReason}, bundle.SelectionTrace...)
		out = append(out, ContextSelectionRecord{
			ID:                  bundle.ID,
			TriggerType:         bundle.TriggerType,
			TriggerID:           bundle.TriggerID,
			SelectedEvidenceIDs: bundle.EvidenceIDs,
			EntityIDs:           bundle.EntityIDs,
			SelectedSpans:       bundle.Spans,
			MaxFiles:            req.MaxFiles,
			MaxSpans:            req.MaxSpans,
			MaxTokens:           req.MaxTokens,
			SelectionTrace:      trace,
		})
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].TriggerType != out[j].TriggerType {
			return out[i].TriggerType < out[j].TriggerType
		}
		return out[i].TriggerID < out[j].TriggerID
	})
	return out
}

func contextSelectionTrigger(candidate IssueCandidate) (string, bool) {
	switch {
	case candidate.Status == "unknown":
		return "unknown_issue", true
	case len(candidate.CounterEvidenceIDs) > 0:
		return "conflict_review", true
	case (candidate.Severity == "high" || candidate.Severity == "critical") && candidate.PolicyClass != "machine_trusted":
		return "high_severity_review", true
	default:
		return "", false
	}
}

func buildContextBundle(req ContextRequest, candidate IssueCandidate, evidenceIndex map[string]EvidenceRecord) ContextBundle {
	evidenceIDs := dedupeStringsSorted(append(append([]string(nil), candidate.EvidenceIDs...), candidate.CounterEvidenceIDs...))
	bundle := ContextBundle{
		ID:          contextBundleID(req),
		TriggerType: req.TriggerType,
		TriggerID:   req.TriggerID,
		EvidenceIDs: evidenceIDs,
	}

	files := make(map[string]struct{})
	entityIDs := make(map[string]struct{})
	var spans []LocationRef
	var trace []string

	for _, evidenceID := range evidenceIDs {
		record, ok := evidenceIndex[evidenceID]
		if !ok {
			trace = append(trace, "skip_missing_evidence:"+evidenceID)
			continue
		}
		trace = append(trace, "include_evidence:"+evidenceID)
		for _, entityID := range record.EntityIDs {
			if entityID == "" {
				continue
			}
			entityIDs[entityID] = struct{}{}
		}
		for _, loc := range sortedLocations(record.Locations) {
			if len(spans) >= req.MaxSpans {
				trace = append(trace, "span_budget_reached")
				break
			}
			if loc.RepoRelPath == "" {
				continue
			}
			if _, ok := files[loc.RepoRelPath]; !ok && len(files) >= req.MaxFiles {
				trace = append(trace, "file_budget_reached:"+loc.RepoRelPath)
				continue
			}
			files[loc.RepoRelPath] = struct{}{}
			spans = append(spans, loc)
			trace = append(trace, "include_span:"+loc.RepoRelPath)
		}
		if len(spans) >= req.MaxSpans {
			break
		}
	}

	bundle.EntityIDs = sortedStringKeys(entityIDs)
	bundle.Spans = spans
	bundle.SelectionTrace = trace
	return bundle
}

func contextBundleID(req ContextRequest) string {
	sum := sha256.Sum256([]byte(req.TriggerType + ":" + req.TriggerID))
	return "ctx-" + hex.EncodeToString(sum[:8])
}

func sortedLocations(in []LocationRef) []LocationRef {
	out := append([]LocationRef(nil), in...)
	sort.Slice(out, func(i, j int) bool {
		if out[i].RepoRelPath != out[j].RepoRelPath {
			return out[i].RepoRelPath < out[j].RepoRelPath
		}
		if out[i].StartLine != out[j].StartLine {
			return out[i].StartLine < out[j].StartLine
		}
		if out[i].EndLine != out[j].EndLine {
			return out[i].EndLine < out[j].EndLine
		}
		return out[i].SymbolID < out[j].SymbolID
	})
	return out
}

func sortedStringKeys(in map[string]struct{}) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, 0, len(in))
	for key := range in {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}
