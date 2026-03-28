package report

import (
	"testing"

	"github.com/verabase/code-verification-engine/internal/rules"
)

func TestFactQualitySummaryCountingFromIssues(t *testing.T) {
	vr := GenerateVerificationReport(ReportInput{
		Issues: []Issue{
			{FactQuality: "proof", Title: "a", Category: "security", Status: "open"},
			{FactQuality: "proof", Title: "b", Category: "security", Status: "open"},
			{FactQuality: "structural", Title: "c", Category: "architecture", Status: "resolved"},
			{FactQuality: "heuristic", Title: "d", Category: "quality", Status: "open"},
			{FactQuality: "runtime_required", Title: "e", Category: "security", Status: "unknown"},
		},
	})

	if vr.FactQualitySummary.ProofBacked != 2 || vr.FactQualitySummary.StructuralBacked != 1 || vr.FactQualitySummary.HeuristicBacked != 1 || vr.FactQualitySummary.RuntimeRequired != 1 {
		t.Fatalf("unexpected fact quality summary: %+v", vr.FactQualitySummary)
	}
}

func TestFactQualitySummaryFindingFallback(t *testing.T) {
	vr := GenerateVerificationReport(ReportInput{
		Findings: rulesFindingForFallback{{}}.toFindings(),
	})
	if vr.FactQualitySummary.HeuristicBacked != 1 {
		t.Fatalf("expected heuristic fallback count, got %+v", vr.FactQualitySummary)
	}
}

type rulesFindingForFallback []struct{}

func (rulesFindingForFallback) toFindings() []rules.Finding {
	return []rules.Finding{{
		RuleID:       "R-1",
		Status:       rules.StatusFail,
		TrustClass:   rules.TrustAdvisory,
		Message:      "fallback",
		VerdictBasis: "",
	}}
}
