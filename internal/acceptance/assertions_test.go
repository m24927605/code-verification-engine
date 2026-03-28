package acceptance

import (
	"testing"

	"github.com/verabase/code-verification-engine/internal/artifactsv2"
)

func TestAssertBundleAgainstFixture(t *testing.T) {
	t.Parallel()

	bundle := artifactsv2.Bundle{
		Report: artifactsv2.ReportArtifact{
			SchemaVersion: artifactsv2.ReportSchemaVersion,
			EngineVersion: "verabase@dev",
			Repo:          "github.com/acme/repo",
			Commit:        "abc123",
			Timestamp:     "2026-03-27T12:00:00Z",
			TraceID:       "trace-abc123",
			Summary: artifactsv2.ReportSummary{
				OverallScore: 0.8,
				RiskLevel:    "medium",
				IssueCounts:  artifactsv2.IssueCountSummary{High: 1},
			},
			Issues: []artifactsv2.Issue{{
				ID:              "iss-001",
				Fingerprint:     "fp-001",
				RuleFamily:      "sec_secret",
				MergeBasis:      "same_symbol",
				Category:        "security",
				Title:           "Missing null check",
				Severity:        "high",
				Confidence:      0.82,
				ConfidenceClass: "moderate",
				PolicyClass:     "advisory",
				Status:          "open",
				EvidenceIDs:     []string{"ev-001", "ev-002"},
				SourceSummary: artifactsv2.IssueSourceSummary{
					RuleCount:            1,
					DeterministicSources: 1,
					AgentSources:         1,
					TotalSources:         2,
					MultiSource:          true,
				},
			}},
		},
		Evidence: artifactsv2.EvidenceArtifact{
			SchemaVersion: artifactsv2.EvidenceSchemaVersion,
			EngineVersion: "verabase@dev",
			Repo:          "github.com/acme/repo",
			Commit:        "abc123",
			Timestamp:     "2026-03-27T12:00:00Z",
			Evidence: []artifactsv2.EvidenceRecord{
				{
					ID:              "ev-001",
					Kind:            "rule_assertion",
					Source:          "rule",
					ProducerID:      "rule:SEC-001",
					ProducerVersion: "1.0.0",
					Repo:            "github.com/acme/repo",
					Commit:          "abc123",
					BoundaryHash:    "sha256:test",
					FactQuality:     "proof",
					Locations:       []artifactsv2.LocationRef{{RepoRelPath: "service.ts", StartLine: 10, EndLine: 10}},
					Claims:          []string{"SEC-001"},
					Payload:         map[string]any{"title": "Missing null check"},
					CreatedAt:       "2026-03-27T12:00:00Z",
				},
				{
					ID:              "ev-002",
					Kind:            "agent_assertion",
					Source:          "agent",
					ProducerID:      "agent:security",
					ProducerVersion: "1.0.0",
					Repo:            "github.com/acme/repo",
					Commit:          "abc123",
					BoundaryHash:    "sha256:test",
					FactQuality:     "heuristic",
					Locations:       []artifactsv2.LocationRef{{RepoRelPath: "service.ts", StartLine: 10, EndLine: 10}},
					Claims:          []string{"security_review"},
					Payload:         map[string]any{"title": "Agent confirmation"},
					CreatedAt:       "2026-03-27T12:00:00Z",
				},
			},
		},
		Skills: artifactsv2.SkillsArtifact{
			SchemaVersion: artifactsv2.SkillsSchemaVersion,
			EngineVersion: "verabase@dev",
			Repo:          "github.com/acme/repo",
			Commit:        "abc123",
			Timestamp:     "2026-03-27T12:00:00Z",
			Skills: []artifactsv2.SkillScore{{
				SkillID:                 "backend",
				Score:                   0.8,
				Confidence:              0.8,
				ContributingIssueIDs:    []string{"iss-001"},
				ContributingEvidenceIDs: []string{"ev-001"},
			}},
		},
		Trace: artifactsv2.TraceArtifact{
			SchemaVersion: artifactsv2.TraceSchemaVersion,
			EngineVersion: "verabase@dev",
			TraceID:       "trace-abc123",
			Repo:          "github.com/acme/repo",
			Commit:        "abc123",
			Timestamp:     "2026-03-27T12:00:00Z",
			ScanBoundary:  artifactsv2.TraceScanBoundary{Mode: "repo", IncludedFiles: 1},
			ConfidenceCalibration: &artifactsv2.ConfidenceCalibration{
				Version:                 "v2-release-blocking-calibration-1",
				MachineTrustedThreshold: 0.85,
				UnknownCap:              0.55,
				AgentOnlyCap:            0.60,
				RuleFamilyBaselines: map[string]float64{
					"sec_secret":   0.94,
					"fe_dep":       0.92,
					"sec_strict":   0.72,
					"arch_layer":   0.78,
					"arch_pattern": 0.74,
					"test_auth":    0.62,
					"test_payment": 0.62,
				},
				OrderingRules: []string{
					"issue_native > seed_native > finding_bridged",
					"proof > structural > heuristic",
					"deterministic > agent_only",
				},
			},
			Rules: []artifactsv2.RuleRun{{
				ID:                 "SEC-001",
				Version:            "1.0.0",
				TriggeredIssueIDs:  []string{"iss-001"},
				EmittedEvidenceIDs: []string{"ev-001"},
			}},
			ContextSelections: []artifactsv2.ContextSelectionRecord{{
				ID:                  "ctx-001",
				TriggerType:         "issue",
				TriggerID:           "iss-001",
				SelectedEvidenceIDs: []string{"ev-001"},
				EntityIDs:           []string{"fn-1"},
				SelectedSpans:       []artifactsv2.LocationRef{{RepoRelPath: "service.ts", StartLine: 10, EndLine: 10}},
				MaxFiles:            2,
				MaxSpans:            4,
				MaxTokens:           1200,
				SelectionTrace:      []string{"trigger_reason:unknown_issue", "include_evidence:ev-001"},
			}},
			Agents: []artifactsv2.AgentRun{{
				ID:                 "agent-001",
				Kind:               "security",
				IssueType:          "security_review",
				Question:           "Assess whether the issue should remain unknown or can be confirmed with the selected bounded context.",
				IssueID:            "iss-001",
				ContextSelectionID: "ctx-001",
				TriggerReason:      "unknown_issue",
				InputEvidenceIDs:   []string{"ev-001"},
				OutputEvidenceIDs:  []string{"ev-002"},
				MaxFiles:           2,
				MaxTokens:          1200,
				AllowSpeculation:   false,
				Status:             "completed",
			}},
			Derivations: []artifactsv2.IssueDerivation{{
				IssueID:                "iss-001",
				IssueFingerprint:       "fp-001",
				DerivedFromEvidenceIDs: []string{"ev-001", "ev-002"},
			}},
		},
		SummaryMD: "# Verabase Report\n",
		Signature: artifactsv2.SignatureArtifact{
			Version: artifactsv2.SignatureSchemaVersion,
		},
	}
	if err := artifactsv2.FinalizeSignature(&bundle, "verabase"); err != nil {
		t.Fatalf("FinalizeSignature(): %v", err)
	}

	partial := false
	minConfidence := 0.8
	maxConfidence := 0.9
	if err := AssertBundleAgainstFixture(bundle, FixtureManifest{
		FixtureID:                          "fx-001",
		FixtureType:                        "micro",
		ExpectedIssueCount:                 1,
		ExpectedIssueIDs:                   []string{"iss-001"},
		ExpectedEvidenceIDs:                []string{"ev-001", "ev-002"},
		ExpectedRuleIDs:                    []string{"SEC-001"},
		ExpectedPartial:                    &partial,
		ExpectedContextSelectionCount:      func() *int { v := 1; return &v }(),
		ExpectedContextSelectionTriggerIDs: []string{"iss-001"},
		ExpectedAgentCount:                 func() *int { v := 1; return &v }(),
		ExpectedAgentKinds:                 []string{"security"},
		ExpectedAgentIssueTypes:            []string{"security_review"},
		ExpectedAgentTriggerReasons:        []string{"unknown_issue"},
		ExpectedAgentContracts: []PlannedAgentConstraint{{
			IssueID:           "iss-001",
			Kind:              "security",
			TriggerReason:     "unknown_issue",
			Status:            "completed",
			OutputEvidenceIDs: []string{"ev-002"},
		}},
		ExpectedBundleHashStable: true,
		ExpectedIssuePolicyClasses: map[string]string{
			"iss-001": "advisory",
		},
		ExpectedIssueConfidenceClasses: map[string]string{
			"iss-001": "moderate",
		},
		ExpectedConfidenceConstraints: []ConfidenceConstraint{{
			IssueID:     "iss-001",
			Min:         &minConfidence,
			Max:         &maxConfidence,
			Class:       "moderate",
			PolicyClass: "advisory",
		}},
	}); err != nil {
		t.Fatalf("AssertBundleAgainstFixture(): %v", err)
	}
}

func TestAssertBundleDeterministic(t *testing.T) {
	t.Parallel()

	a := sampleBundle(t)
	b := sampleBundle(t)

	if err := AssertBundleDeterministic(a, b); err != nil {
		t.Fatalf("AssertBundleDeterministic(): %v", err)
	}
}

func sampleBundle(t *testing.T) artifactsv2.Bundle {
	t.Helper()

	bundle := artifactsv2.Bundle{
		Report: artifactsv2.ReportArtifact{
			SchemaVersion: artifactsv2.ReportSchemaVersion,
			EngineVersion: "verabase@dev",
			Repo:          "github.com/acme/repo",
			Commit:        "abc123",
			Timestamp:     "2026-03-27T12:00:00Z",
			TraceID:       "trace-abc123",
			Summary: artifactsv2.ReportSummary{
				OverallScore: 0.8,
				RiskLevel:    "medium",
				IssueCounts:  artifactsv2.IssueCountSummary{High: 1},
			},
			Issues: []artifactsv2.Issue{{
				ID:              "iss-001",
				Fingerprint:     "fp-001",
				RuleFamily:      "sec_secret",
				MergeBasis:      "same_symbol",
				Category:        "security",
				Title:           "Missing null check",
				Severity:        "high",
				Confidence:      0.82,
				ConfidenceClass: "moderate",
				PolicyClass:     "advisory",
				Status:          "open",
				EvidenceIDs:     []string{"ev-001"},
				SourceSummary: artifactsv2.IssueSourceSummary{
					RuleCount:            1,
					DeterministicSources: 1,
					AgentSources:         0,
					TotalSources:         1,
					MultiSource:          false,
				},
			}},
		},
		Evidence: artifactsv2.EvidenceArtifact{
			SchemaVersion: artifactsv2.EvidenceSchemaVersion,
			EngineVersion: "verabase@dev",
			Repo:          "github.com/acme/repo",
			Commit:        "abc123",
			Timestamp:     "2026-03-27T12:00:00Z",
			Evidence: []artifactsv2.EvidenceRecord{{
				ID:              "ev-001",
				Kind:            "rule_assertion",
				Source:          "rule",
				ProducerID:      "rule:SEC-001",
				ProducerVersion: "1.0.0",
				Repo:            "github.com/acme/repo",
				Commit:          "abc123",
				BoundaryHash:    "sha256:test",
				FactQuality:     "proof",
				Locations:       []artifactsv2.LocationRef{{RepoRelPath: "service.ts", StartLine: 10, EndLine: 10}},
				Claims:          []string{"SEC-001"},
				Payload:         map[string]any{"title": "Missing null check"},
				CreatedAt:       "2026-03-27T12:00:00Z",
			}},
		},
		Skills: artifactsv2.SkillsArtifact{
			SchemaVersion: artifactsv2.SkillsSchemaVersion,
			EngineVersion: "verabase@dev",
			Repo:          "github.com/acme/repo",
			Commit:        "abc123",
			Timestamp:     "2026-03-27T12:00:00Z",
			Skills: []artifactsv2.SkillScore{{
				SkillID:                 "backend",
				Score:                   0.8,
				Confidence:              0.8,
				ContributingIssueIDs:    []string{"iss-001"},
				ContributingEvidenceIDs: []string{"ev-001"},
			}},
		},
		Trace: artifactsv2.TraceArtifact{
			SchemaVersion: artifactsv2.TraceSchemaVersion,
			EngineVersion: "verabase@dev",
			TraceID:       "trace-abc123",
			Repo:          "github.com/acme/repo",
			Commit:        "abc123",
			Timestamp:     "2026-03-27T12:00:00Z",
			ScanBoundary:  artifactsv2.TraceScanBoundary{Mode: "repo", IncludedFiles: 1},
			ConfidenceCalibration: &artifactsv2.ConfidenceCalibration{
				Version:                 "v2-release-blocking-calibration-1",
				MachineTrustedThreshold: 0.85,
				UnknownCap:              0.55,
				AgentOnlyCap:            0.60,
				RuleFamilyBaselines: map[string]float64{
					"sec_secret":   0.94,
					"fe_dep":       0.92,
					"sec_strict":   0.72,
					"arch_layer":   0.78,
					"arch_pattern": 0.74,
					"test_auth":    0.62,
					"test_payment": 0.62,
				},
				OrderingRules: []string{
					"issue_native > seed_native > finding_bridged",
					"proof > structural > heuristic",
					"deterministic > agent_only",
				},
			},
			Rules: []artifactsv2.RuleRun{{
				ID:                 "SEC-001",
				Version:            "1.0.0",
				TriggeredIssueIDs:  []string{"iss-001"},
				EmittedEvidenceIDs: []string{"ev-001"},
			}},
			Derivations: []artifactsv2.IssueDerivation{{
				IssueID:                "iss-001",
				IssueFingerprint:       "fp-001",
				DerivedFromEvidenceIDs: []string{"ev-001"},
			}},
		},
		SummaryMD: "# Verabase Report\n",
		Signature: artifactsv2.SignatureArtifact{
			Version: artifactsv2.SignatureSchemaVersion,
		},
	}
	if err := artifactsv2.FinalizeSignature(&bundle, "verabase"); err != nil {
		t.Fatalf("FinalizeSignature(): %v", err)
	}
	return bundle
}
