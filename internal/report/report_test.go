package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/verabase/code-verification-engine/internal/rules"
	"github.com/verabase/code-verification-engine/internal/schema"
)

func TestGenerateVerificationReportUsesCanonicalIssues(t *testing.T) {
	vr := GenerateVerificationReport(ReportInput{
		Partial: true,
		Issues: []Issue{
			{ID: "i-1", RuleID: "SEC-001", Title: "Secret", Category: "security", Severity: "high", Status: "open", TrustClass: "advisory", Capability: "partial", SignalClass: "actionable_fail", FactQuality: "heuristic"},
			{ID: "i-2", RuleID: "GOF-001", Title: "Factory", Category: "architecture", Severity: "low", Status: "open", TrustClass: "machine_trusted", Capability: "fully_supported", SignalClass: "informational_detection", FactQuality: "proof"},
			{ID: "i-3", RuleID: "AUTH-001", Title: "Protected", Category: "security", Severity: "medium", Status: "unknown", TrustClass: "human_or_runtime_required", Capability: "unsupported", SignalClass: "unknown", FactQuality: "runtime_required"},
			{ID: "i-4", RuleID: "TEST-001", Title: "Tests", Category: "testing", Severity: "low", Status: "resolved", TrustClass: "machine_trusted", Capability: "fully_supported", SignalClass: "pass", FactQuality: "structural"},
		},
		SkippedRules: []rules.SkippedRule{{RuleID: "R-5", Reason: "capability_unsupported"}},
		Degraded:     true,
	})

	if vr.ReportSchemaVersion != schema.ReportSchemaVersion {
		t.Fatalf("schema version = %q, want %q", vr.ReportSchemaVersion, schema.ReportSchemaVersion)
	}
	if vr.Summary.Pass != 1 || vr.Summary.Fail != 2 || vr.Summary.Unknown != 1 {
		t.Fatalf("unexpected summary: %+v", vr.Summary)
	}
	if vr.TrustSummary.MachineTrusted != 2 || vr.TrustSummary.Advisory != 1 || vr.TrustSummary.HumanOrRuntimeRequired != 1 {
		t.Fatalf("unexpected trust summary: %+v", vr.TrustSummary)
	}
	if vr.CapabilitySummary.FullySupported != 2 || vr.CapabilitySummary.Partial != 1 || vr.CapabilitySummary.Unsupported != 2 || !vr.CapabilitySummary.Degraded {
		t.Fatalf("unexpected capability summary: %+v", vr.CapabilitySummary)
	}
	if vr.SignalSummary.ActionableFail != 1 || vr.SignalSummary.InformationalDetection != 1 || vr.SignalSummary.Unknown != 1 {
		t.Fatalf("unexpected signal summary: %+v", vr.SignalSummary)
	}
	if vr.FactQualitySummary.ProofBacked != 1 || vr.FactQualitySummary.StructuralBacked != 1 || vr.FactQualitySummary.HeuristicBacked != 1 || vr.FactQualitySummary.RuntimeRequired != 1 {
		t.Fatalf("unexpected fact quality summary: %+v", vr.FactQualitySummary)
	}
}

func TestGenerateVerificationReportFallsBackToFindings(t *testing.T) {
	vr := GenerateVerificationReport(ReportInput{
		Findings: []rules.Finding{{
			RuleID:            "SEC-001",
			Status:            rules.StatusFail,
			Confidence:        rules.ConfidenceMedium,
			VerificationLevel: rules.VerificationStrongInference,
			TrustClass:        rules.TrustAdvisory,
			Message:           "secret found",
			Evidence:          []rules.Evidence{{File: "main.go", LineStart: 3, LineEnd: 3, Symbol: "main"}},
			VerdictBasis:      "heuristic_inference",
		}},
		RuleMetadata: map[string]rules.Rule{
			"SEC-001": {ID: "SEC-001", Category: "security", Title: "Hardcoded secret"},
		},
	})

	if len(vr.Issues) != 1 {
		t.Fatalf("expected derived issue, got %d", len(vr.Issues))
	}
	if vr.Issues[0].RuleID != "SEC-001" || vr.Issues[0].Status != "open" {
		t.Fatalf("unexpected derived issue: %+v", vr.Issues[0])
	}
}

func TestGenerateMarkdownRendersIssues(t *testing.T) {
	scan := GenerateScanReport(ScanInput{
		RepoPath: "/tmp/repo", RepoName: "repo", Ref: "HEAD", CommitSHA: "abc",
		Languages: []string{"go"}, FileCount: 1, Analyzers: map[string]string{"go": "ok"}, Profile: "backend-api",
	})
	vr := VerificationReport{
		ReportSchemaVersion: schema.ReportSchemaVersion,
		Summary:             Summary{Fail: 2, Unknown: 1},
		TrustSummary:        TrustSummary{Advisory: 1, HumanOrRuntimeRequired: 1},
		CapabilitySummary:   CapabilitySummary{FullySupported: 1, Partial: 1, Degraded: true},
		SignalSummary:       SignalSummary{ActionableFail: 1, InformationalDetection: 1, Unknown: 1},
		FactQualitySummary:  FactQualitySummary{ProofBacked: 1, HeuristicBacked: 1},
		Issues: []Issue{
			{ID: "i-1", RuleID: "SEC-001", Title: "Secret detected", Status: "open", TrustClass: "advisory", Confidence: "medium", Severity: "high", Evidence: []IssueEvidence{{ID: "ev-1", File: "main.go", LineStart: 3, LineEnd: 3, Symbol: "main"}}},
			{ID: "i-2", RuleID: "GOF-001", Title: "Factory", Status: "open", Severity: "low"},
			{ID: "i-3", RuleID: "AUTH-001", Title: "Unknown auth", Status: "unknown", UnknownReasons: []string{"missing_context"}},
		},
	}

	md := GenerateMarkdown(scan, vr)
	for _, fragment := range []string{"## Issues", "Secret detected", "Pattern Detections", "Unknown reasons:", "missing_context", "Trust Class: advisory", "`main.go:3-3` `main`"} {
		if !strings.Contains(md, fragment) {
			t.Fatalf("markdown missing fragment %q\n%s", fragment, md)
		}
	}
}

func TestWriteOutputsWritesIssueCentricReport(t *testing.T) {
	outputDir := t.TempDir()
	scan := GenerateScanReport(ScanInput{
		RepoPath: "/tmp/repo", RepoName: "repo", Ref: "HEAD", CommitSHA: "abc",
		Languages: []string{"go"}, FileCount: 1, Analyzers: map[string]string{"go": "ok"}, Profile: "backend-api",
	})
	vr := VerificationReport{
		ReportSchemaVersion: schema.ReportSchemaVersion,
		Issues: []Issue{{
			ID:          "i-1",
			RuleID:      "SEC-001",
			Title:       "Secret detected",
			Category:    "security",
			Severity:    "high",
			Status:      "open",
			TrustClass:  "advisory",
			EvidenceIDs: []string{"ev-1"},
		}},
	}
	if err := WriteOutputs(outputDir, scan, vr, "both"); err != nil {
		t.Fatalf("WriteOutputs: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(outputDir, "report.json"))
	if err != nil {
		t.Fatalf("read report.json: %v", err)
	}
	var got VerificationReport
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal report.json: %v", err)
	}
	if len(got.Issues) != 1 {
		t.Fatalf("unexpected output report: %+v", got)
	}
	if _, err := os.Stat(filepath.Join(outputDir, "report.md")); err != nil {
		t.Fatalf("missing report.md: %v", err)
	}
}
