package rules

import (
	"sort"
	"strings"
)

// BuildIssueSeeds derives deterministic aggregation seeds from rule findings.
// It prefers rule-file metadata over heuristic backfilling.
func BuildIssueSeeds(rf *RuleFile, findings []Finding) []IssueSeed {
	ruleIndex := RuleIndexFromFile(rf)

	seeds := make([]IssueSeed, 0, len(findings))
	for _, finding := range findings {
		if finding.Status == StatusPass {
			continue
		}
		rule := ruleIndex[finding.RuleID]
		semantics := ResolveIssueSeedSemantics(rule, finding)
		file, symbol, startLine, endLine := primaryIssueSeedLocation(finding)
		seeds = append(seeds, IssueSeed{
			RuleID:      finding.RuleID,
			Title:       semantics.Title,
			Source:      semantics.Source,
			Category:    semantics.Category,
			Severity:    semantics.Severity,
			Status:      issueSeedStatus(finding.Status),
			Confidence:  issueSeedConfidence(finding.Confidence),
			Quality:     issueSeedQuality(finding.FactQualityFloor),
			File:        file,
			Symbol:      symbol,
			StartLine:   startLine,
			EndLine:     endLine,
			EvidenceIDs: issueSeedEvidenceIDs(finding),
		})
	}
	return seeds
}

// RefreshIssueSeeds recomputes issue seeds from the current execution result.
// Call this after any post-processing that mutates findings, such as evidence ID
// assignment or trust normalization.
func RefreshIssueSeeds(rf *RuleFile, result *ExecutionResult) {
	if result == nil {
		return
	}
	result.IssueSeeds = BuildIssueSeeds(rf, result.Findings)
}

func primaryIssueSeedLocation(f Finding) (file, symbol string, startLine, endLine int) {
	if len(f.Evidence) == 0 {
		return "unknown", "", 1, 1
	}
	evs := append([]Evidence(nil), f.Evidence...)
	sort.Slice(evs, func(i, j int) bool {
		if evs[i].File != evs[j].File {
			return evs[i].File < evs[j].File
		}
		if evs[i].LineStart != evs[j].LineStart {
			return evs[i].LineStart < evs[j].LineStart
		}
		return evs[i].Symbol < evs[j].Symbol
	})
	ev := evs[0]
	return filepathToSlash(ev.File), ev.Symbol, maxInt(1, ev.LineStart), maxInt(ev.LineStart, ev.LineEnd)
}

func issueSeedEvidenceIDs(f Finding) []string {
	if len(f.Evidence) == 0 {
		return nil
	}
	ids := make([]string, 0, len(f.Evidence))
	for _, ev := range f.Evidence {
		id := ev.ID
		if id == "" {
			id = EvidenceID(ev)
		}
		ids = append(ids, id)
	}
	return dedupeStringsSorted(ids)
}

func issueSeedStatus(status Status) string {
	switch status {
	case StatusFail:
		return "open"
	case StatusUnknown:
		return "unknown"
	default:
		return "resolved"
	}
}

func issueSeedConfidence(c Confidence) float64 {
	switch c {
	case ConfidenceHigh:
		return 0.9
	case ConfidenceMedium:
		return 0.7
	default:
		return 0.45
	}
}

func issueSeedQuality(q string) float64 {
	switch q {
	case "proof":
		return 1.0
	case "structural":
		return 0.7
	default:
		return 0.4
	}
}

func dedupeStringsSorted(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func filepathToSlash(path string) string {
	return strings.ReplaceAll(path, "\\", "/")
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
