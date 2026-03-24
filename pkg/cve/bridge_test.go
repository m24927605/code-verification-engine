package cve

import (
	"testing"

	"github.com/verabase/code-verification-engine/internal/rules"
	"github.com/verabase/code-verification-engine/internal/skills"
)

// --- bridgeSkillReport ---

func TestBridgeSkillReport_Empty(t *testing.T) {
	r := &skills.Report{
		SchemaVersion: "1.0.0",
		Profile:       "test-profile",
	}
	out := bridgeSkillReport(r)
	if out.SchemaVersion != "1.0.0" {
		t.Errorf("expected schema_version 1.0.0, got %s", out.SchemaVersion)
	}
	if out.Profile != "test-profile" {
		t.Errorf("expected profile test-profile, got %s", out.Profile)
	}
	if len(out.Signals) != 0 {
		t.Errorf("expected 0 signals, got %d", len(out.Signals))
	}
}

func TestBridgeSkillReport_WithSignals(t *testing.T) {
	r := &skills.Report{
		SchemaVersion: "1.0.0",
		Profile:       "test",
		Signals: []skills.Signal{
			{
				ID:               "sig-1",
				SkillID:          "skill-1",
				Category:         skills.CategoryImplementation,
				Status:           skills.StatusObserved,
				Confidence:       skills.ConfidenceHigh,
				TrustClass:       "machine_trusted",
				EvidenceStrength: skills.EvidenceDirect,
				Message:          "found it",
				SourceRuleIDs:    []string{"RULE-001"},
				Evidence: []rules.Evidence{
					{ID: "ev-1", File: "main.go", LineStart: 10, LineEnd: 20, Symbol: "Handler", Excerpt: "func Handler()"},
				},
				UnknownReasons: []string{"reason1"},
			},
			{
				ID:               "sig-2",
				SkillID:          "skill-2",
				Category:         skills.CategoryRiskExposure,
				Status:           skills.StatusUnsupported,
				Confidence:       skills.ConfidenceLow,
				TrustClass:       "advisory",
				EvidenceStrength: skills.EvidenceHeuristic,
				Message:          "not supported",
			},
		},
		Summary: skills.Summary{Observed: 1, Unsupported: 1},
	}
	out := bridgeSkillReport(r)
	if len(out.Signals) != 2 {
		t.Fatalf("expected 2 signals, got %d", len(out.Signals))
	}

	s0 := out.Signals[0]
	if s0.ID != "sig-1" || s0.SkillID != "skill-1" {
		t.Errorf("signal 0 ID/SkillID mismatch")
	}
	if s0.Category != "implementation" || s0.Status != "observed" {
		t.Errorf("signal 0 category/status mismatch: %s/%s", s0.Category, s0.Status)
	}
	if len(s0.Evidence) != 1 {
		t.Errorf("expected 1 evidence, got %d", len(s0.Evidence))
	}
	if len(s0.SourceRuleIDs) != 1 || s0.SourceRuleIDs[0] != "RULE-001" {
		t.Errorf("source rule IDs mismatch")
	}
	if len(s0.UnknownReasons) != 1 || s0.UnknownReasons[0] != "reason1" {
		t.Errorf("unknown reasons mismatch")
	}

	s1 := out.Signals[1]
	if s1.Status != "unsupported" || s1.EvidenceStrength != "heuristic" {
		t.Errorf("signal 1 fields mismatch")
	}

	if out.Summary.Observed != 1 || out.Summary.Unsupported != 1 {
		t.Errorf("summary mismatch")
	}
}

// --- computeTrustGuidance ---

func TestComputeTrustGuidance_Empty(t *testing.T) {
	g := computeTrustGuidance(nil, TrustSummary{}, CapabilitySummaryOutput{})
	if g.Summary != "No findings to evaluate." {
		t.Errorf("expected no-findings summary, got %q", g.Summary)
	}
	if g.CanAutomate {
		t.Error("should not be automatable with no findings")
	}
}

func TestComputeTrustGuidance_AllMachineTrustedVerified(t *testing.T) {
	findings := []FindingOutput{
		{TrustClass: "machine_trusted", VerificationLevel: "verified"},
		{TrustClass: "machine_trusted", VerificationLevel: "verified"},
	}
	g := computeTrustGuidance(findings, TrustSummary{}, CapabilitySummaryOutput{})
	if !g.CanAutomate {
		t.Error("should be automatable when all machine_trusted+verified")
	}
	if g.Summary != "All findings are machine-trusted and verified. Safe for automated consumption." {
		t.Errorf("unexpected summary: %q", g.Summary)
	}
}

func TestComputeTrustGuidance_Degraded(t *testing.T) {
	findings := []FindingOutput{
		{TrustClass: "machine_trusted", VerificationLevel: "verified"},
	}
	g := computeTrustGuidance(findings, TrustSummary{}, CapabilitySummaryOutput{Degraded: true})
	if g.CanAutomate {
		t.Error("should not be automatable when degraded")
	}
	if !g.RequiresReview {
		t.Error("degraded should require review")
	}
}

func TestComputeTrustGuidance_RequiresReview(t *testing.T) {
	findings := []FindingOutput{
		{TrustClass: "advisory", VerificationLevel: "verified"},
	}
	g := computeTrustGuidance(findings, TrustSummary{Advisory: 2, HumanOrRuntimeRequired: 1}, CapabilitySummaryOutput{})
	if !g.RequiresReview {
		t.Error("should require review with advisory findings")
	}
	if g.CanAutomate {
		t.Error("should not be automatable")
	}
}

func TestComputeTrustGuidance_DefaultMixedTrust(t *testing.T) {
	findings := []FindingOutput{
		{TrustClass: "machine_trusted", VerificationLevel: "strong_inference"},
	}
	g := computeTrustGuidance(findings, TrustSummary{}, CapabilitySummaryOutput{})
	if g.CanAutomate {
		t.Error("should not be automatable with non-verified findings")
	}
	if g.Summary != "Findings contain mixed trust levels. Review recommended." {
		t.Errorf("expected default summary, got %q", g.Summary)
	}
}
