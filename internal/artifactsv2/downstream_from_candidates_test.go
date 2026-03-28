package artifactsv2

import (
	"testing"

	"github.com/verabase/code-verification-engine/internal/report"
	"github.com/verabase/code-verification-engine/internal/rules"
	"github.com/verabase/code-verification-engine/internal/skills"
)

func TestBuildSkillsArtifactUsesCandidateRuleMapping(t *testing.T) {
	t.Parallel()

	scan := report.ScanReport{
		RepoName:  "github.com/acme/repo",
		CommitSHA: "abc123",
		ScannedAt: "2026-03-27T12:00:00Z",
	}
	candidates := []IssueCandidate{
		{ID: "iss-1", Fingerprint: "fp-1", RuleIDs: []string{"SEC-001"}},
	}
	skillReport := &skills.Report{
		Signals: []skills.Signal{
			{
				SkillID:          "backend",
				Status:           skills.StatusObserved,
				Confidence:       skills.ConfidenceHigh,
				EvidenceStrength: skills.EvidenceDirect,
				SourceRuleIDs:    []string{"SEC-001"},
				Evidence: []rules.Evidence{{
					File:      "service.ts",
					LineStart: 10,
					LineEnd:   10,
					Symbol:    "getUser",
				}},
			},
		},
	}

	artifact := buildSkillsArtifact(scan, skillReport, "verabase@dev", candidates)
	if len(artifact.Skills) != 1 {
		t.Fatalf("expected 1 skill, got %d", len(artifact.Skills))
	}
	if len(artifact.Skills[0].ContributingIssueIDs) != 1 || artifact.Skills[0].ContributingIssueIDs[0] != "iss-1" {
		t.Fatalf("expected candidate-derived issue id mapping, got %#v", artifact.Skills[0].ContributingIssueIDs)
	}
}

func TestBuildTraceArtifactUsesCandidateRuleMapping(t *testing.T) {
	t.Parallel()

	scan := report.ScanReport{
		RepoName:     "github.com/acme/repo",
		CommitSHA:    "abc123",
		ScannedAt:    "2026-03-27T12:00:00Z",
		FileCount:    5,
		BoundaryMode: "repo",
		Analyzers:    map[string]string{"typescript": "ok"},
	}
	findings := []rules.Finding{{
		RuleID:  "SEC-001",
		Status:  rules.StatusFail,
		Message: "Missing null check",
		Evidence: []rules.Evidence{{
			File:      "service.ts",
			LineStart: 10,
			LineEnd:   10,
			Symbol:    "getUser",
		}},
	}}
	verification := VerificationSource{
		ReportSchemaVersion: "1.0.0",
		Findings:            findings,
		RuleMetadata: map[string]RuleMetadata{
			"SEC-001": {RuleID: "SEC-001", MigrationState: string(rules.MigrationIssueNative), MigrationReason: "audited issue-native"},
		},
	}
	candidates := []IssueCandidate{{
		ID:          "iss-1",
		Fingerprint: "fp-1",
		RuleIDs:     []string{"SEC-001"},
		Category:    "security",
		Severity:    "high",
		PolicyClass: "advisory",
		EvidenceIDs: []string{compatEvidenceID("SEC-001", findings[0].Evidence[0])},
	}}
	evidence := EvidenceArtifact{
		SchemaVersion: EvidenceSchemaVersion,
		EngineVersion: "verabase@dev",
		Repo:          "github.com/acme/repo",
		Commit:        "abc123",
		Timestamp:     "2026-03-27T12:00:00Z",
		Evidence: []EvidenceRecord{{
			ID:              compatEvidenceID("SEC-001", findings[0].Evidence[0]),
			Kind:            "rule_assertion",
			Source:          "rule",
			ProducerID:      "rule:SEC-001",
			ProducerVersion: "1.0.0",
			Repo:            "github.com/acme/repo",
			Commit:          "abc123",
			BoundaryHash:    "sha256:x",
			FactQuality:     "proof",
			Locations:       []LocationRef{{RepoRelPath: "service.ts", StartLine: 10, EndLine: 10}},
			Claims:          []string{"SEC-001"},
			Payload:         map[string]any{},
			CreatedAt:       "2026-03-27T12:00:00Z",
		}},
	}

	trace := buildTraceArtifact(scan, verification, evidence, "trace-abc123", "verabase@dev", candidates)
	if len(trace.Derivations) != 1 {
		t.Fatalf("expected 1 derivation, got %d", len(trace.Derivations))
	}
	if trace.MigrationSummary == nil {
		t.Fatal("expected migration summary")
	}
	if trace.Derivations[0].IssueID != "iss-1" {
		t.Fatalf("expected derivation to use candidate issue id, got %q", trace.Derivations[0].IssueID)
	}
	if trace.Derivations[0].IssueFingerprint != "fp-1" {
		t.Fatalf("expected derivation to use candidate fingerprint, got %q", trace.Derivations[0].IssueFingerprint)
	}
	if trace.Rules[0].MigrationState != string(rules.MigrationIssueNative) {
		t.Fatalf("expected trace rule migration state, got %q", trace.Rules[0].MigrationState)
	}
	if trace.Rules[0].MigrationReason != "audited issue-native" {
		t.Fatalf("expected trace rule migration reason, got %q", trace.Rules[0].MigrationReason)
	}
	if trace.MigrationSummary.IssueNativeCount != 1 {
		t.Fatalf("expected 1 issue_native rule, got %#v", trace.MigrationSummary)
	}
	if trace.MigrationSummary.RuleStates["SEC-001"] != string(rules.MigrationIssueNative) {
		t.Fatalf("expected migration summary rule state, got %#v", trace.MigrationSummary.RuleStates)
	}
	if trace.MigrationSummary.RuleReasons["SEC-001"] != "audited issue-native" {
		t.Fatalf("expected migration summary rule reason, got %#v", trace.MigrationSummary.RuleReasons)
	}
	if trace.ConfidenceCalibration == nil {
		t.Fatal("expected confidence calibration metadata")
	}
	if trace.ConfidenceCalibration.Version == "" || trace.ConfidenceCalibration.RuleFamilyBaselines["sec_secret"] == 0 {
		t.Fatalf("expected calibrated rule-family metadata, got %#v", trace.ConfidenceCalibration)
	}
	if len(trace.ContextSelections) != 1 {
		t.Fatalf("expected 1 context selection for high-severity advisory issue, got %d", len(trace.ContextSelections))
	}
	if trace.ContextSelections[0].TriggerType != "issue" || trace.ContextSelections[0].TriggerID != "iss-1" {
		t.Fatalf("unexpected context selection trace output: %#v", trace.ContextSelections[0])
	}
	if trace.ContextSelections[0].ID == "" || trace.ContextSelections[0].MaxSpans != defaultContextMaxSpans {
		t.Fatalf("expected bounded context id/max spans, got %#v", trace.ContextSelections[0])
	}
	if len(trace.Agents) != 1 {
		t.Fatalf("expected 1 planned agent run, got %d", len(trace.Agents))
	}
	if trace.Agents[0].Status != "planned" || trace.Agents[0].Kind != "security" {
		t.Fatalf("unexpected planned agent output: %#v", trace.Agents[0])
	}
	if trace.Agents[0].IssueType != "security_review" || trace.Agents[0].Question == "" {
		t.Fatalf("expected planned agent task contract output, got %#v", trace.Agents[0])
	}
	if len(trace.Agents[0].UnresolvedReasons) != 0 {
		t.Fatalf("expected planned agent to have no unresolved reasons, got %#v", trace.Agents[0])
	}
	if trace.Agents[0].IssueID != "iss-1" || trace.Agents[0].ContextSelectionID != trace.ContextSelections[0].ID {
		t.Fatalf("expected planned agent to reference selected context, got %#v", trace.Agents[0])
	}
}
