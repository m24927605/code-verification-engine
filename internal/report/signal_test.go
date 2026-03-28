package report

import (
	"strings"
	"testing"

	"github.com/verabase/code-verification-engine/internal/rules"
)

func TestClassifySignal_GOFIsInformational(t *testing.T) {
	f := rules.Finding{RuleID: "GOF-C-001", Status: rules.StatusFail}
	if got := ClassifySignal(f, nil); got != SignalInformationalDetection {
		t.Errorf("GOF fail = %q, want informational_detection", got)
	}
}

func TestClassifySignal_GOFPassIsPass(t *testing.T) {
	f := rules.Finding{RuleID: "GOF-C-001", Status: rules.StatusPass}
	if got := ClassifySignal(f, nil); got != SignalPass {
		t.Errorf("GOF pass = %q, want pass", got)
	}
}

func TestClassifySignal_SecurityIsActionable(t *testing.T) {
	f := rules.Finding{RuleID: "SEC-SECRET-001", Status: rules.StatusFail}
	if got := ClassifySignal(f, nil); got != SignalActionableFail {
		t.Errorf("SEC fail = %q, want actionable_fail", got)
	}
}

func TestClassifySignal_ArchLayerIsActionable(t *testing.T) {
	f := rules.Finding{RuleID: "ARCH-LAYER-001", Status: rules.StatusFail}
	if got := ClassifySignal(f, nil); got != SignalActionableFail {
		t.Errorf("ARCH-LAYER fail = %q, want actionable_fail", got)
	}
}

func TestClassifySignal_ArchPatternIsAdvisory(t *testing.T) {
	f := rules.Finding{RuleID: "ARCH-PATTERN-002", Status: rules.StatusFail}
	if got := ClassifySignal(f, nil); got != SignalAdvisoryFail {
		t.Errorf("ARCH-PATTERN fail = %q, want advisory_fail", got)
	}
}

func TestClassifySignal_QualityIsAdvisory(t *testing.T) {
	f := rules.Finding{RuleID: "QUAL-LOG-001", Status: rules.StatusFail}
	if got := ClassifySignal(f, nil); got != SignalAdvisoryFail {
		t.Errorf("QUAL fail = %q, want advisory_fail", got)
	}
}

func TestClassifySignal_FrontendSecurityIsActionable(t *testing.T) {
	f := rules.Finding{RuleID: "FE-TOKEN-001", Status: rules.StatusFail}
	if got := ClassifySignal(f, nil); got != SignalActionableFail {
		t.Errorf("FE-TOKEN fail = %q, want actionable_fail", got)
	}
}

func TestClassifySignal_FrontendQualityIsAdvisory(t *testing.T) {
	f := rules.Finding{RuleID: "FE-DEP-001", Status: rules.StatusFail}
	if got := ClassifySignal(f, nil); got != SignalAdvisoryFail {
		t.Errorf("FE-DEP fail = %q, want advisory_fail", got)
	}
}

func TestClassifySignal_UnknownIsUnknown(t *testing.T) {
	f := rules.Finding{RuleID: "SEC-AUTH-001", Status: rules.StatusUnknown}
	if got := ClassifySignal(f, nil); got != SignalUnknown {
		t.Errorf("unknown = %q, want unknown", got)
	}
}

func TestClassifySignal_TestOnlyEvidenceIsAdvisory(t *testing.T) {
	f := rules.Finding{
		RuleID: "SEC-SECRET-001",
		Status: rules.StatusFail,
		Evidence: []rules.Evidence{
			{File: "__tests__/auth.spec.ts"},
			{File: "test/fixtures/data.ts"},
		},
	}
	if got := ClassifySignal(f, nil); got != SignalAdvisoryFail {
		t.Errorf("test-only evidence SEC = %q, want advisory_fail", got)
	}
}

func TestClassifySignal_MixedEvidenceStaysActionable(t *testing.T) {
	f := rules.Finding{
		RuleID: "SEC-SECRET-001",
		Status: rules.StatusFail,
		Evidence: []rules.Evidence{
			{File: "__tests__/auth.spec.ts"},
			{File: "src/main.ts"},
		},
	}
	if got := ClassifySignal(f, nil); got != SignalActionableFail {
		t.Errorf("mixed evidence SEC = %q, want actionable_fail", got)
	}
}

func TestComputeSignalSummary(t *testing.T) {
	findings := []rules.Finding{
		{RuleID: "SEC-SECRET-001", Status: rules.StatusFail},
		{RuleID: "ARCH-PATTERN-002", Status: rules.StatusFail},
		{RuleID: "GOF-C-001", Status: rules.StatusFail},
		{RuleID: "GOF-B-009", Status: rules.StatusFail},
		{RuleID: "SEC-AUTH-001", Status: rules.StatusUnknown},
		{RuleID: "SEC-AUTH-001", Status: rules.StatusPass},
	}
	ss := ComputeSignalSummary(findings, nil)
	if ss.ActionableFail != 1 {
		t.Errorf("actionable_fail = %d, want 1", ss.ActionableFail)
	}
	if ss.AdvisoryFail != 1 {
		t.Errorf("advisory_fail = %d, want 1", ss.AdvisoryFail)
	}
	if ss.InformationalDetection != 2 {
		t.Errorf("informational_detection = %d, want 2", ss.InformationalDetection)
	}
	if ss.Unknown != 1 {
		t.Errorf("unknown = %d, want 1", ss.Unknown)
	}
}

func TestIsGOFRule(t *testing.T) {
	if !IsGOFRule("GOF-C-001") {
		t.Error("expected GOF-C-001 to be GOF rule")
	}
	if IsGOFRule("SEC-AUTH-001") {
		t.Error("expected SEC-AUTH-001 to NOT be GOF rule")
	}
}

func TestSignalSummaryInReport(t *testing.T) {
	input := ReportInput{
		Findings: []rules.Finding{
			{RuleID: "SEC-SECRET-001", Status: rules.StatusFail},
			{RuleID: "GOF-C-001", Status: rules.StatusFail},
		},
	}
	vr := GenerateVerificationReport(input)
	if vr.SignalSummary.ActionableFail != 1 {
		t.Errorf("report signal actionable_fail = %d, want 1", vr.SignalSummary.ActionableFail)
	}
	if vr.SignalSummary.InformationalDetection != 1 {
		t.Errorf("report signal informational_detection = %d, want 1", vr.SignalSummary.InformationalDetection)
	}
}

func TestClassifySignal_UsesRuleMetadataBeforeRuleIDHeuristics(t *testing.T) {
	f := rules.Finding{RuleID: "CUSTOM-001", Status: rules.StatusFail}
	metadata := map[string]rules.Rule{
		"CUSTOM-001": {
			ID:       "CUSTOM-001",
			Category: "security",
		},
	}
	if got := ClassifySignal(f, metadata); got != SignalActionableFail {
		t.Errorf("CUSTOM-001 with security metadata = %q, want actionable_fail", got)
	}
}

func TestMarkdownSeparatesGOFFindings(t *testing.T) {
	scan := ScanReport{RepoName: "test", Profile: "fullstack"}
	vr := VerificationReport{
		Summary: Summary{Fail: 2},
		SignalSummary: SignalSummary{ActionableFail: 1, InformationalDetection: 1},
		Findings: []rules.Finding{
			{RuleID: "SEC-SECRET-001", Status: rules.StatusFail, Message: "Hardcoded secret found"},
			{RuleID: "GOF-C-001", Status: rules.StatusFail, Message: "Singleton detected"},
		},
	}
	md := GenerateMarkdown(scan, vr)

	if !strings.Contains(md, "## Pattern Detections") {
		t.Error("markdown should contain Pattern Detections section")
	}
	if !strings.Contains(md, "Actionable Failures:") {
		t.Error("markdown should contain signal summary in Results section")
	}
	// GOF should be under Pattern Detections, not under Findings
	findingsIdx := strings.Index(md, "## Findings")
	patternsIdx := strings.Index(md, "## Pattern Detections")
	gofIdx := strings.Index(md, "GOF-C-001")
	secIdx := strings.Index(md, "SEC-SECRET-001")

	if secIdx < findingsIdx || secIdx > patternsIdx {
		t.Error("SEC-SECRET-001 should be in Findings section before Pattern Detections")
	}
	if gofIdx < patternsIdx {
		t.Error("GOF-C-001 should be in Pattern Detections section, not Findings")
	}
}

func TestMarkdownSignalSummary(t *testing.T) {
	scan := ScanReport{RepoName: "test", Profile: "fullstack"}
	vr := VerificationReport{
		SignalSummary: SignalSummary{ActionableFail: 7, AdvisoryFail: 6, InformationalDetection: 19},
	}
	md := GenerateMarkdown(scan, vr)
	if !strings.Contains(md, "Actionable Failures: 7") {
		t.Error("markdown should show actionable failures count")
	}
	if !strings.Contains(md, "Advisory Failures: 6") {
		t.Error("markdown should show advisory failures count")
	}
	if !strings.Contains(md, "Informational Detections: 19") {
		t.Error("markdown should show informational detections count")
	}
}
