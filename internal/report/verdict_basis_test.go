package report

import (
	"strings"
	"testing"

	"github.com/verabase/code-verification-engine/internal/rules"
)

func TestFactQualitySummaryCounting(t *testing.T) {
	input := ReportInput{
		Findings: []rules.Finding{
			{RuleID: "R1", Status: rules.StatusPass, VerdictBasis: "proof"},
			{RuleID: "R2", Status: rules.StatusPass, VerdictBasis: "proof"},
			{RuleID: "R3", Status: rules.StatusFail, VerdictBasis: "structural_binding"},
			{RuleID: "R4", Status: rules.StatusFail, VerdictBasis: "heuristic_inference"},
			{RuleID: "R5", Status: rules.StatusUnknown, VerdictBasis: "runtime_required"},
			{RuleID: "R6", Status: rules.StatusPass, VerdictBasis: "heuristic_inference"},
		},
	}

	vr := GenerateVerificationReport(input)

	if vr.FactQualitySummary.ProofBacked != 2 {
		t.Errorf("ProofBacked = %d, want 2", vr.FactQualitySummary.ProofBacked)
	}
	if vr.FactQualitySummary.StructuralBacked != 1 {
		t.Errorf("StructuralBacked = %d, want 1", vr.FactQualitySummary.StructuralBacked)
	}
	if vr.FactQualitySummary.HeuristicBacked != 2 {
		t.Errorf("HeuristicBacked = %d, want 2", vr.FactQualitySummary.HeuristicBacked)
	}
	if vr.FactQualitySummary.RuntimeRequired != 1 {
		t.Errorf("RuntimeRequired = %d, want 1", vr.FactQualitySummary.RuntimeRequired)
	}
}

func TestFactQualitySummaryEmptyFindings(t *testing.T) {
	input := ReportInput{
		Findings: []rules.Finding{},
	}

	vr := GenerateVerificationReport(input)

	if vr.FactQualitySummary.ProofBacked != 0 {
		t.Errorf("ProofBacked = %d, want 0", vr.FactQualitySummary.ProofBacked)
	}
	if vr.FactQualitySummary.StructuralBacked != 0 {
		t.Errorf("StructuralBacked = %d, want 0", vr.FactQualitySummary.StructuralBacked)
	}
	if vr.FactQualitySummary.HeuristicBacked != 0 {
		t.Errorf("HeuristicBacked = %d, want 0", vr.FactQualitySummary.HeuristicBacked)
	}
	if vr.FactQualitySummary.RuntimeRequired != 0 {
		t.Errorf("RuntimeRequired = %d, want 0", vr.FactQualitySummary.RuntimeRequired)
	}
}

func TestFactQualitySummaryNoVerdictBasis(t *testing.T) {
	// Findings without VerdictBasis should not increment any counter.
	input := ReportInput{
		Findings: []rules.Finding{
			{RuleID: "R1", Status: rules.StatusPass},
			{RuleID: "R2", Status: rules.StatusFail},
		},
	}

	vr := GenerateVerificationReport(input)

	total := vr.FactQualitySummary.ProofBacked +
		vr.FactQualitySummary.StructuralBacked +
		vr.FactQualitySummary.HeuristicBacked +
		vr.FactQualitySummary.RuntimeRequired
	if total != 0 {
		t.Errorf("total counted = %d, want 0 for findings without VerdictBasis", total)
	}
}

func TestMarkdownContainsVerdictBasisSection(t *testing.T) {
	scan := ScanReport{
		RepoName:  "test-repo",
		Ref:       "main",
		Languages: []string{"go"},
		Profile:   "backend-api",
	}
	vr := VerificationReport{
		Summary: Summary{Pass: 2, Fail: 1},
		FactQualitySummary: FactQualitySummary{
			ProofBacked:      2,
			StructuralBacked: 1,
			HeuristicBacked:  3,
			RuntimeRequired:  0,
		},
		Findings: []rules.Finding{
			{
				RuleID:  "SEC-001",
				Status:  rules.StatusPass,
				Message: "test finding",
			},
		},
	}

	md := GenerateMarkdown(scan, vr)

	if !strings.Contains(md, "## Verdict Basis") {
		t.Error("markdown missing '## Verdict Basis' section")
	}
	if !strings.Contains(md, "Proof-backed: 2") {
		t.Error("markdown missing proof-backed count")
	}
	if !strings.Contains(md, "Structural/Binding: 1") {
		t.Error("markdown missing structural/binding count")
	}
	if !strings.Contains(md, "Heuristic: 3") {
		t.Error("markdown missing heuristic count")
	}
	if !strings.Contains(md, "Runtime Required: 0") {
		t.Error("markdown missing runtime required count")
	}
}
