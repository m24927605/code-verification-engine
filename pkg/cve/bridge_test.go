package cve

import (
	"testing"

	"github.com/verabase/code-verification-engine/internal/artifactsv2"
	"github.com/verabase/code-verification-engine/internal/claims"
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
	if len(out.Skills) != 0 || len(out.Languages) != 0 || len(out.Frameworks) != 0 || len(out.Technologies) != 0 {
		t.Errorf("expected empty simplified arrays, got skills=%v languages=%v frameworks=%v technologies=%v", out.Skills, out.Languages, out.Frameworks, out.Technologies)
	}
	if len(out.Signals) != 0 {
		t.Errorf("expected 0 signals, got %d", len(out.Signals))
	}
}

func TestBridgeSkillReport_WithSignals(t *testing.T) {
	r := &skills.Report{
		SchemaVersion: "1.0.0",
		Profile:       "test",
		Skills:        []string{"skill-1", "skill-2"},
		Languages:     []string{"go", "typescript"},
		Frameworks:    []string{"gin"},
		Technologies: []skills.Technology{
			{Name: "gin", Kind: "framework"},
			{Name: "react", Kind: "library"},
		},
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
	if len(out.Skills) != 2 || out.Skills[0] != "skill-1" || out.Skills[1] != "skill-2" {
		t.Fatalf("skills mismatch: %v", out.Skills)
	}
	if len(out.Languages) != 2 || out.Languages[0] != "go" || out.Languages[1] != "typescript" {
		t.Fatalf("languages mismatch: %v", out.Languages)
	}
	if len(out.Frameworks) != 1 || out.Frameworks[0] != "gin" {
		t.Fatalf("frameworks mismatch: %v", out.Frameworks)
	}
	if len(out.Technologies) != 2 || out.Technologies[0].Name != "gin" || out.Technologies[0].Kind != "framework" || out.Technologies[1].Name != "react" || out.Technologies[1].Kind != "library" {
		t.Fatalf("technologies mismatch: %v", out.Technologies)
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

func TestBridgeClaimReport(t *testing.T) {
	r := &claims.ClaimReport{
		SchemaVersion: "1.0.0",
		ClaimSetName:  "backend-security",
		TotalClaims:   1,
		Verdicts: claims.VerdictSummary{
			Verified: 1,
			Passed:   1,
			Failed:   0,
			Unknown:  0,
			Partial:  0,
		},
		Claims: []claims.ClaimVerdict{
			{
				ClaimID:           "architecture.multi_agent_pipeline",
				Title:             "Multi-agent pipeline",
				Category:          "architecture",
				Status:            "pass",
				Confidence:        "high",
				VerificationLevel: "verified",
				TrustBreakdown: claims.TrustBreakdown{
					MachineTrusted:         2,
					Advisory:               0,
					HumanOrRuntimeRequired: 0,
					EffectiveTrustClass:    "machine_trusted",
				},
				Summary: "verified from code and tests",
				SupportingRules: []claims.RuleResult{
					{RuleID: "ARCH-001", Status: "pass", Confidence: "high", Message: "rule hit"},
				},
				EvidenceChain: []claims.EvidenceLink{
					{
						ID:        "ev-1",
						Type:      "supports",
						File:      "main.go",
						LineStart: 10,
						LineEnd:   20,
						Symbol:    "Run",
						Excerpt:   "func Run() {}",
						FromRule:  "ARCH-001",
						Relation:  "supports",
					},
				},
				UnknownReasons: []string{"none"},
			},
		},
	}

	out := bridgeClaimReport(r)
	if out == nil {
		t.Fatal("expected bridged claim report")
	}
	if out.SchemaVersion != "1.0.0" || out.ClaimSetName != "backend-security" || out.TotalClaims != 1 {
		t.Fatalf("unexpected top-level bridged fields: %#v", out)
	}
	if out.Verdicts.Verified != 1 || out.Verdicts.Passed != 1 {
		t.Fatalf("unexpected verdict summary: %#v", out.Verdicts)
	}
	if len(out.Claims) != 1 {
		t.Fatalf("expected 1 claim verdict, got %d", len(out.Claims))
	}
	cv := out.Claims[0]
	if cv.ClaimID != "architecture.multi_agent_pipeline" || cv.VerificationLevel != "verified" {
		t.Fatalf("unexpected claim verdict: %#v", cv)
	}
	if len(cv.SupportingRules) != 1 || cv.SupportingRules[0].RuleID != "ARCH-001" {
		t.Fatalf("supporting rule bridge mismatch: %#v", cv.SupportingRules)
	}
	if len(cv.EvidenceChain) != 1 || cv.EvidenceChain[0].ID != "ev-1" {
		t.Fatalf("evidence chain bridge mismatch: %#v", cv.EvidenceChain)
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

func TestBridgeVerifiableBundle(t *testing.T) {
	b := &artifactsv2.Bundle{
		Report: artifactsv2.ReportArtifact{
			SchemaVersion: "2.0.0",
			EngineVersion: "verabase@dev",
			Repo:          "github.com/acme/repo",
			Commit:        "abc123",
			Timestamp:     "2026-03-27T12:00:00Z",
			TraceID:       "trace-abc123",
			Summary: artifactsv2.ReportSummary{
				OverallScore: 0.82,
				RiskLevel:    "medium",
				IssueCounts:  artifactsv2.IssueCountSummary{High: 1},
			},
			Skills: []artifactsv2.ReportSkillScore{{SkillID: "backend", Score: 0.9}},
			Issues: []artifactsv2.Issue{{
				ID:                 "iss-1",
				Fingerprint:        "fp-1",
				RuleFamily:         "sec_secret",
				MergeBasis:         "same_symbol",
				Category:           "security",
				Title:              "Missing null check",
				Severity:           "high",
				Confidence:         0.9,
				ConfidenceClass:    "high",
				PolicyClass:        "machine_trusted",
				Status:             "open",
				EvidenceIDs:        []string{"ev-1"},
				CounterEvidenceIDs: []string{"ev-2"},
				SourceSummary:      artifactsv2.IssueSourceSummary{RuleCount: 1, DeterministicSources: 1, AgentSources: 0, TotalSources: 1, MultiSource: false},
			}},
		},
		Evidence: artifactsv2.EvidenceArtifact{
			SchemaVersion: "2.0.0",
			EngineVersion: "verabase@dev",
			Repo:          "github.com/acme/repo",
			Commit:        "abc123",
			Timestamp:     "2026-03-27T12:00:00Z",
			Evidence: []artifactsv2.EvidenceRecord{
				{
					ID:              "ev-1",
					Kind:            "rule_assertion",
					Source:          "rule",
					ProducerID:      "rule:SEC-001",
					ProducerVersion: "1.0.0",
					Repo:            "github.com/acme/repo",
					Commit:          "abc123",
					BoundaryHash:    "sha256:x",
					FactQuality:     "proof",
					Locations:       []artifactsv2.LocationRef{{RepoRelPath: "service.ts", StartLine: 10, EndLine: 10}},
					Claims:          []string{"SEC-001"},
					Payload:         map[string]any{"message": "x"},
					CreatedAt:       "2026-03-27T12:00:00Z",
				},
				{
					ID:              "ev-2",
					Kind:            "counter_evidence",
					Source:          "rule",
					ProducerID:      "rule:SEC-002",
					ProducerVersion: "1.0.0",
					Repo:            "github.com/acme/repo",
					Commit:          "abc123",
					BoundaryHash:    "sha256:x",
					FactQuality:     "structural",
					Locations:       []artifactsv2.LocationRef{{RepoRelPath: "service.ts", StartLine: 12, EndLine: 12}},
					Claims:          []string{"SEC-002"},
					Payload:         map[string]any{"message": "counter"},
					CreatedAt:       "2026-03-27T12:00:00Z",
				},
			},
		},
		Skills: artifactsv2.SkillsArtifact{
			SchemaVersion: "2.0.0",
			EngineVersion: "verabase@dev",
			Repo:          "github.com/acme/repo",
			Commit:        "abc123",
			Timestamp:     "2026-03-27T12:00:00Z",
			Skills: []artifactsv2.SkillScore{{
				SkillID:                 "backend",
				Score:                   0.9,
				Confidence:              0.8,
				ContributingIssueIDs:    []string{"iss-1"},
				ContributingEvidenceIDs: []string{"ev-1"},
			}},
		},
		Trace: artifactsv2.TraceArtifact{
			SchemaVersion: "2.0.0",
			EngineVersion: "verabase@dev",
			TraceID:       "trace-abc123",
			Repo:          "github.com/acme/repo",
			Commit:        "abc123",
			Timestamp:     "2026-03-27T12:00:00Z",
			Partial:       true,
			Degraded:      true,
			Errors:        []string{"analysis degraded"},
			ScanBoundary:  artifactsv2.TraceScanBoundary{Mode: "repo", IncludedFiles: 10, ExcludedFiles: 0},
			MigrationSummary: &artifactsv2.RuleMigrationSummary{
				FindingBridgedCount: 1,
				IssueNativeCount:    1,
				RuleStates: map[string]string{
					"QUAL-001": "finding_bridged",
					"SEC-001":  "issue_native",
				},
				RuleReasons: map[string]string{
					"QUAL-001": "v2 path still depends on finding-derived issue semantics",
					"SEC-001":  "proof-grade secret evidence spans are deterministic and replayable",
				},
			},
			ConfidenceCalibration: &artifactsv2.ConfidenceCalibration{
				Version:                 "v2-release-blocking-calibration-1",
				MachineTrustedThreshold: 0.85,
				UnknownCap:              0.55,
				AgentOnlyCap:            0.60,
				RuleFamilyBaselines:     map[string]float64{"sec_secret": 0.94},
				OrderingRules:           []string{"issue_native > seed_native > finding_bridged", "proof > structural > heuristic"},
			},
			Rules: []artifactsv2.RuleRun{
				{ID: "SEC-001", Version: "1.0.0", MigrationState: "issue_native", MigrationReason: "proof-grade secret evidence spans are deterministic and replayable", TriggeredIssueIDs: []string{"iss-1"}, EmittedEvidenceIDs: []string{"ev-1"}},
			},
			SkippedRules: []artifactsv2.SkippedRuleTrace{
				{ID: "SKIP-001", Reason: "capability_unsupported"},
			},
			ContextSelections: []artifactsv2.ContextSelectionRecord{
				{
					ID:                  "ctx-1",
					TriggerType:         "issue",
					TriggerID:           "iss-1",
					SelectedEvidenceIDs: []string{"ev-1"},
					EntityIDs:           []string{"fn-1"},
					SelectedSpans:       []artifactsv2.LocationRef{{RepoRelPath: "service.ts", StartLine: 10, EndLine: 10}},
					MaxFiles:            2,
					MaxSpans:            4,
					MaxTokens:           1200,
					SelectionTrace:      []string{"trigger_reason:high_severity_review", "include_evidence:ev-1"},
				},
			},
			Agents: []artifactsv2.AgentRun{
				{ID: "agent-1", Kind: "security", IssueType: "security_review", Question: "Assess whether the high-severity issue is sufficiently supported by the selected bounded context.", IssueID: "iss-1", ContextSelectionID: "ctx-1", TriggerReason: "high_severity_review", InputEvidenceIDs: []string{"ev-1"}, MaxFiles: 2, MaxTokens: 1200, AllowSpeculation: false, Status: "planned"},
			},
			Derivations: []artifactsv2.IssueDerivation{
				{IssueID: "iss-1", IssueFingerprint: "fp-1", DerivedFromEvidenceIDs: []string{"ev-1"}},
			},
		},
		SummaryMD: "summary",
		Signature: artifactsv2.SignatureArtifact{
			Version:        "1.0.0",
			SignedBy:       "verabase",
			Timestamp:      "2026-03-27T12:00:00Z",
			ArtifactHashes: map[string]string{"report.json": "sha256:x"},
			BundleHash:     "sha256:y",
		},
	}
	out := bridgeVerifiableBundle(b)
	if out.Report.TraceID != "trace-abc123" {
		t.Fatalf("unexpected report trace id %q", out.Report.TraceID)
	}
	if len(out.Evidence.Evidence) != 2 || out.Evidence.Evidence[0].ID != "ev-1" || out.Evidence.Evidence[1].ID != "ev-2" {
		t.Fatalf("unexpected evidence bridge output")
	}
	if len(out.Skills.Skills) != 1 || out.Skills.Skills[0].SkillID != "backend" {
		t.Fatalf("unexpected skills bridge output")
	}
	if out.Signature.BundleHash != "sha256:y" {
		t.Fatalf("unexpected signature bundle hash %q", out.Signature.BundleHash)
	}
	if !out.Trace.Partial || !out.Trace.Degraded {
		t.Fatalf("expected trace partial/degraded flags to bridge")
	}
	if out.Trace.MigrationSummary == nil || out.Trace.MigrationSummary.IssueNativeCount != 1 || out.Trace.MigrationSummary.RuleStates["QUAL-001"] != "finding_bridged" {
		t.Fatalf("unexpected migration summary bridge output: %#v", out.Trace.MigrationSummary)
	}
	if out.Trace.MigrationSummary.RuleReasons["SEC-001"] == "" {
		t.Fatalf("expected migration summary reasons to bridge: %#v", out.Trace.MigrationSummary)
	}
	if out.Trace.ConfidenceCalibration == nil || out.Trace.ConfidenceCalibration.RuleFamilyBaselines["sec_secret"] != 0.94 {
		t.Fatalf("unexpected confidence calibration bridge output: %#v", out.Trace.ConfidenceCalibration)
	}
	if len(out.Report.Issues) != 1 || len(out.Report.Issues[0].CounterEvidenceIDs) != 1 || out.Report.Issues[0].CounterEvidenceIDs[0] != "ev-2" {
		t.Fatalf("unexpected counter evidence bridge output: %#v", out.Report.Issues)
	}
	if out.Report.Issues[0].Fingerprint != "fp-1" {
		t.Fatalf("unexpected fingerprint bridge output: %#v", out.Report.Issues[0])
	}
	if out.Report.Issues[0].RuleFamily != "sec_secret" {
		t.Fatalf("unexpected rule family bridge output: %#v", out.Report.Issues[0])
	}
	if out.Report.Issues[0].MergeBasis != "same_symbol" {
		t.Fatalf("unexpected merge basis bridge output: %#v", out.Report.Issues[0])
	}
	if out.Report.Issues[0].ConfidenceClass != "high" || out.Report.Issues[0].PolicyClass != "machine_trusted" {
		t.Fatalf("unexpected confidence/policy bridge output: %#v", out.Report.Issues[0])
	}
	if out.Report.Issues[0].SourceSummary.RuleCount != 1 || out.Report.Issues[0].SourceSummary.TotalSources != 1 {
		t.Fatalf("unexpected source summary bridge output: %#v", out.Report.Issues[0].SourceSummary)
	}
	if len(out.Trace.SkippedRules) != 1 || out.Trace.SkippedRules[0].ID != "SKIP-001" {
		t.Fatalf("unexpected skipped rule bridge output: %#v", out.Trace.SkippedRules)
	}
	if len(out.Trace.ContextSelections) != 1 || out.Trace.ContextSelections[0].TriggerID != "iss-1" {
		t.Fatalf("unexpected context selection bridge output: %#v", out.Trace.ContextSelections)
	}
	if out.Trace.ContextSelections[0].ID != "ctx-1" || out.Trace.ContextSelections[0].MaxSpans != 4 || len(out.Trace.ContextSelections[0].EntityIDs) != 1 {
		t.Fatalf("unexpected context selection contract bridge output: %#v", out.Trace.ContextSelections[0])
	}
	if len(out.Trace.Agents) != 1 || out.Trace.Agents[0].ContextSelectionID != "ctx-1" || out.Trace.Agents[0].IssueID != "iss-1" {
		t.Fatalf("unexpected planned agent bridge output: %#v", out.Trace.Agents)
	}
	if out.Trace.Agents[0].IssueType != "security_review" || out.Trace.Agents[0].Question == "" {
		t.Fatalf("unexpected planned agent task bridge output: %#v", out.Trace.Agents[0])
	}
	if len(out.Trace.Rules) != 1 || out.Trace.Rules[0].MigrationState != "issue_native" {
		t.Fatalf("unexpected trace rule bridge output: %#v", out.Trace.Rules)
	}
	if out.Trace.Rules[0].MigrationReason == "" {
		t.Fatalf("expected trace rule migration reason to bridge: %#v", out.Trace.Rules)
	}
	if len(out.Trace.Derivations) != 1 || out.Trace.Derivations[0].IssueFingerprint != "fp-1" {
		t.Fatalf("unexpected derivation bridge output: %#v", out.Trace.Derivations)
	}
}

// --- nil guard tests ---

func TestBridgeClaimReport_Nil(t *testing.T) {
	out := bridgeClaimReport(nil)
	if out != nil {
		t.Fatal("bridgeClaimReport(nil) should return nil")
	}
}

func TestBridgeVerifiableBundle_Nil(t *testing.T) {
	out := bridgeVerifiableBundle(nil)
	if out != nil {
		t.Fatal("bridgeVerifiableBundle(nil) should return nil")
	}
}

func TestBridgeClaimsProjection_Nil(t *testing.T) {
	out := bridgeClaimsProjection(nil)
	if out != nil {
		t.Fatal("bridgeClaimsProjection(nil) should return nil")
	}
}

// --- bridgeSkillsV2 with FormulaInputs ---

func TestBridgeSkillsV2_WithFormulaInputs(t *testing.T) {
	a := artifactsv2.SkillsArtifact{
		SchemaVersion: "2.0.0",
		EngineVersion: "verabase@dev",
		Repo:          "github.com/acme/repo",
		Commit:        "abc123",
		Timestamp:     "2026-03-27T12:00:00Z",
		Skills: []artifactsv2.SkillScore{
			{
				SkillID:                 "backend",
				Score:                   0.85,
				Confidence:              0.9,
				ContributingIssueIDs:    []string{"iss-1", "iss-2"},
				ContributingEvidenceIDs: []string{"ev-1"},
				FormulaInputs: &artifactsv2.SkillFormulaInputs{
					Positive: []artifactsv2.WeightedContribution{
						{IssueID: "iss-1", Weight: 0.7, Value: 1.0},
						{IssueID: "iss-2", Weight: 0.3, Value: 0.5},
					},
					Negative: []artifactsv2.WeightedContribution{
						{IssueID: "iss-3", Weight: 0.2, Value: -0.5},
					},
				},
			},
			{
				SkillID:    "frontend",
				Score:      0.5,
				Confidence: 0.6,
			},
		},
	}

	out := bridgeSkillsV2(a)
	if out.SchemaVersion != "2.0.0" {
		t.Fatalf("unexpected schema version %q", out.SchemaVersion)
	}
	if len(out.Skills) != 2 {
		t.Fatalf("expected 2 skills, got %d", len(out.Skills))
	}

	// Skill with formula inputs
	s0 := out.Skills[0]
	if s0.SkillID != "backend" || s0.Score != 0.85 || s0.Confidence != 0.9 {
		t.Fatalf("unexpected skill 0: %#v", s0)
	}
	if s0.FormulaInputs == nil {
		t.Fatal("expected formula inputs for skill 0")
	}
	if len(s0.FormulaInputs.Positive) != 2 {
		t.Fatalf("expected 2 positive contributions, got %d", len(s0.FormulaInputs.Positive))
	}
	if s0.FormulaInputs.Positive[0].IssueID != "iss-1" || s0.FormulaInputs.Positive[0].Weight != 0.7 {
		t.Fatalf("unexpected positive[0]: %#v", s0.FormulaInputs.Positive[0])
	}
	if s0.FormulaInputs.Positive[1].IssueID != "iss-2" || s0.FormulaInputs.Positive[1].Value != 0.5 {
		t.Fatalf("unexpected positive[1]: %#v", s0.FormulaInputs.Positive[1])
	}
	if len(s0.FormulaInputs.Negative) != 1 || s0.FormulaInputs.Negative[0].IssueID != "iss-3" {
		t.Fatalf("unexpected negative contributions: %#v", s0.FormulaInputs.Negative)
	}
	if len(s0.ContributingIssueIDs) != 2 || len(s0.ContributingEvidenceIDs) != 1 {
		t.Fatalf("unexpected contributing IDs: issues=%v evidence=%v", s0.ContributingIssueIDs, s0.ContributingEvidenceIDs)
	}

	// Skill without formula inputs
	s1 := out.Skills[1]
	if s1.SkillID != "frontend" || s1.FormulaInputs != nil {
		t.Fatalf("unexpected skill 1: %#v", s1)
	}
}

// --- bridgeResumeInputArtifact with StronglySupportedClaims ---

func TestBridgeResumeInputArtifact_WithStronglySupportedClaims(t *testing.T) {
	in := artifactsv2.ResumeInputArtifact{
		SchemaVersion: "1.0.0",
		Profile: artifactsv2.ProfileArtifact{
			SchemaVersion: "1.0.0",
			Repository:    artifactsv2.ClaimRepositoryRef{Path: "/repo", Commit: "abc123"},
		},
		VerifiedClaims: []artifactsv2.ResumeClaimStub{
			{ClaimID: "c-1", Title: "Verified claim", SupportLevel: "verified", Confidence: 0.95},
		},
		StronglySupportedClaims: []artifactsv2.ResumeClaimStub{
			{ClaimID: "c-2", Title: "Strong claim", SupportLevel: "strongly_supported", Confidence: 0.80, SupportingEvidenceIDs: []string{"ev-1"}},
			{ClaimID: "c-3", Title: "Another strong", SupportLevel: "strongly_supported", Confidence: 0.75},
		},
		TechnologySummary: []string{"go"},
		EvidenceReferences: []artifactsv2.EvidenceReference{
			{EvidenceID: "ev-1", ClaimIDs: []string{"c-2"}, ContradictoryClaimIDs: []string{"c-bad"}},
		},
		SynthesisConstraints: artifactsv2.SynthesisConstraints{
			AllowUnsupportedClaims: true,
		},
	}

	out := bridgeResumeInputArtifact(in)
	if out.SchemaVersion != "1.0.0" {
		t.Fatalf("unexpected schema version %q", out.SchemaVersion)
	}
	if len(out.VerifiedClaims) != 1 || out.VerifiedClaims[0].ClaimID != "c-1" {
		t.Fatalf("unexpected verified claims: %#v", out.VerifiedClaims)
	}
	if len(out.StronglySupportedClaims) != 2 {
		t.Fatalf("expected 2 strongly supported claims, got %d", len(out.StronglySupportedClaims))
	}
	if out.StronglySupportedClaims[0].ClaimID != "c-2" || out.StronglySupportedClaims[0].Confidence != 0.80 {
		t.Fatalf("unexpected strongly supported[0]: %#v", out.StronglySupportedClaims[0])
	}
	if len(out.StronglySupportedClaims[0].SupportingEvidenceIDs) != 1 {
		t.Fatalf("expected supporting evidence IDs for strongly supported[0]")
	}
	if out.StronglySupportedClaims[1].ClaimID != "c-3" {
		t.Fatalf("unexpected strongly supported[1]: %#v", out.StronglySupportedClaims[1])
	}
	if len(out.EvidenceReferences) != 1 || len(out.EvidenceReferences[0].ContradictoryClaimIDs) != 1 {
		t.Fatalf("unexpected evidence references: %#v", out.EvidenceReferences)
	}
	if !out.SynthesisConstraints.AllowUnsupportedClaims {
		t.Fatal("expected AllowUnsupportedClaims to be true")
	}
}

// --- bridgeVerifiableBundle with ConfidenceBreakdown ---

func TestBridgeVerifiableBundle_WithConfidenceBreakdown(t *testing.T) {
	b := &artifactsv2.Bundle{
		Report: artifactsv2.ReportArtifact{
			SchemaVersion: "2.0.0",
			EngineVersion: "verabase@dev",
			Repo:          "github.com/acme/repo",
			Commit:        "abc123",
			Timestamp:     "2026-03-27T12:00:00Z",
			TraceID:       "trace-1",
			Summary:       artifactsv2.ReportSummary{OverallScore: 0.5, RiskLevel: "low"},
			Issues: []artifactsv2.Issue{{
				ID:       "iss-1",
				Category: "quality",
				Title:    "Test issue",
				Severity: "medium",
				ConfidenceBreakdown: &artifactsv2.ConfidenceBreakdown{
					RuleReliability:      0.95,
					EvidenceQuality:      0.80,
					BoundaryCompleteness: 0.70,
					ContextCompleteness:  0.60,
					SourceAgreement:      0.90,
					ContradictionPenalty: 0.05,
					LLMPenalty:           0.10,
					Final:                0.75,
				},
				SourceSummary: artifactsv2.IssueSourceSummary{RuleCount: 1, TotalSources: 1},
			}},
		},
		Evidence: artifactsv2.EvidenceArtifact{
			SchemaVersion: "2.0.0",
			EngineVersion: "verabase@dev",
			Repo:          "github.com/acme/repo",
			Commit:        "abc123",
			Timestamp:     "2026-03-27T12:00:00Z",
		},
		Skills: artifactsv2.SkillsArtifact{
			SchemaVersion: "2.0.0",
			EngineVersion: "verabase@dev",
			Repo:          "github.com/acme/repo",
			Commit:        "abc123",
			Timestamp:     "2026-03-27T12:00:00Z",
		},
		Trace: artifactsv2.TraceArtifact{
			SchemaVersion: "2.0.0",
			EngineVersion: "verabase@dev",
			TraceID:       "trace-1",
			Repo:          "github.com/acme/repo",
			Commit:        "abc123",
			Timestamp:     "2026-03-27T12:00:00Z",
			ScanBoundary:  artifactsv2.TraceScanBoundary{Mode: "repo", IncludedFiles: 5},
		},
		SummaryMD: "# Summary",
		Signature: artifactsv2.SignatureArtifact{
			Version:        "1.0.0",
			SignedBy:       "verabase",
			Timestamp:      "2026-03-27T12:00:00Z",
			ArtifactHashes: map[string]string{"report.json": "sha256:x"},
			BundleHash:     "sha256:y",
		},
	}

	out := bridgeVerifiableBundle(b)
	if out == nil {
		t.Fatal("expected non-nil output")
	}
	if len(out.Report.Issues) != 1 {
		t.Fatalf("expected 1 issue, got %d", len(out.Report.Issues))
	}
	issue := out.Report.Issues[0]
	if issue.ConfidenceBreakdown == nil {
		t.Fatal("expected confidence breakdown")
	}
	if issue.ConfidenceBreakdown.RuleReliability != 0.95 {
		t.Fatalf("unexpected rule reliability %f", issue.ConfidenceBreakdown.RuleReliability)
	}
	if issue.ConfidenceBreakdown.Final != 0.75 {
		t.Fatalf("unexpected final confidence %f", issue.ConfidenceBreakdown.Final)
	}
	if issue.ConfidenceBreakdown.LLMPenalty != 0.10 {
		t.Fatalf("unexpected LLM penalty %f", issue.ConfidenceBreakdown.LLMPenalty)
	}
}

func TestBridgeClaimsProjection(t *testing.T) {
	in := &artifactsv2.ClaimsProjectionArtifacts{
		Claims: artifactsv2.ClaimsArtifact{
			SchemaVersion: "1.0.0",
			Repository:    artifactsv2.ClaimRepositoryRef{Path: "/repo", Commit: "abc123"},
			Claims: []artifactsv2.ClaimRecord{
				{
					ClaimID:               "architecture.multi_agent_pipeline",
					Title:                 "Multi-agent pipeline exists",
					Category:              "architecture",
					ClaimType:             "architecture",
					Status:                "accepted",
					SupportLevel:          "verified",
					Confidence:            0.93,
					VerificationClass:     artifactsv2.VerificationStructuralInference,
					ScenarioApplicability: &artifactsv2.ScenarioApplicability{Hiring: true, OutsourceAcceptance: true},
					SourceOrigins:         []string{"code_inferred", "readme_extracted"},
					SupportingEvidenceIDs: []string{"src-1", "src-2"},
					Reason:                "code-backed by multiple sources",
					ProjectionEligible:    true,
				},
			},
			Summary: artifactsv2.ClaimSummary{Verified: 1},
		},
		Profile: artifactsv2.ProfileArtifact{
			SchemaVersion: "1.0.0",
			Repository:    artifactsv2.ClaimRepositoryRef{Path: "/repo", Commit: "abc123"},
			Highlights: []artifactsv2.CapabilityHighlight{
				{HighlightID: "hl-1", Title: "Built a multi-agent pipeline", SupportLevel: "verified", ClaimIDs: []string{"architecture.multi_agent_pipeline"}, SupportingEvidenceIDs: []string{"src-1"}},
			},
			CapabilityAreas: []artifactsv2.CapabilityArea{
				{AreaID: "architecture", Title: "Architecture", ClaimIDs: []string{"architecture.multi_agent_pipeline"}},
			},
			Technologies: []string{"go", "typescript"},
			ClaimIDs:     []string{"architecture.multi_agent_pipeline"},
		},
		ResumeInput: artifactsv2.ResumeInputArtifact{
			SchemaVersion:     "1.0.0",
			Profile:           artifactsv2.ProfileArtifact{SchemaVersion: "1.0.0", Repository: artifactsv2.ClaimRepositoryRef{Path: "/repo", Commit: "abc123"}},
			VerifiedClaims:    []artifactsv2.ResumeClaimStub{{ClaimID: "architecture.multi_agent_pipeline", Title: "Multi-agent pipeline exists", SupportLevel: "verified", Confidence: 0.93}},
			TechnologySummary: []string{"go", "typescript"},
			EvidenceReferences: []artifactsv2.EvidenceReference{
				{EvidenceID: "src-1", ClaimIDs: []string{"architecture.multi_agent_pipeline"}},
			},
			SynthesisConstraints: artifactsv2.SynthesisConstraints{
				AllowUnsupportedClaims:        false,
				AllowClaimInvention:           false,
				AllowContradictionSuppression: false,
			},
		},
	}

	out := bridgeClaimsProjection(in)
	if out == nil {
		t.Fatal("expected claims projection output")
	}
	if len(out.Claims.Claims) != 1 || out.Claims.Claims[0].ClaimID != "architecture.multi_agent_pipeline" {
		t.Fatalf("unexpected bridged claim records: %#v", out.Claims.Claims)
	}
	if out.Claims.Claims[0].VerificationClass != string(artifactsv2.VerificationStructuralInference) {
		t.Fatalf("unexpected bridged verification class: %#v", out.Claims.Claims[0].VerificationClass)
	}
	if out.Claims.Claims[0].ScenarioApplicability == nil || !out.Claims.Claims[0].ScenarioApplicability.Hiring {
		t.Fatalf("expected bridged scenario applicability, got %#v", out.Claims.Claims[0].ScenarioApplicability)
	}
	if len(out.Profile.Highlights) != 1 || out.Profile.Highlights[0].HighlightID != "hl-1" {
		t.Fatalf("unexpected bridged profile highlights: %#v", out.Profile.Highlights)
	}
	if len(out.ResumeInput.EvidenceReferences) != 1 || out.ResumeInput.EvidenceReferences[0].EvidenceID != "src-1" {
		t.Fatalf("unexpected bridged resume evidence refs: %#v", out.ResumeInput.EvidenceReferences)
	}
}
