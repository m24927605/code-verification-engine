package acceptance

import (
	"strings"
	"testing"

	"github.com/verabase/code-verification-engine/internal/artifactsv2"
)

// validBundle returns a minimal valid Bundle suitable for assertion tests.
func validBundle(t *testing.T) artifactsv2.Bundle {
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
					TotalSources:         1,
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
				Version:                 "release-blocking-calibration-1",
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

func intPtr(v int) *int             { return &v }
func boolPtr(v bool) *bool          { return &v }
func float64Ptr(v float64) *float64 { return &v }

func TestAssertBundleAgainstFixture_ErrorPaths(t *testing.T) {
	t.Parallel()

	bundle := validBundle(t)

	tests := []struct {
		name     string
		manifest FixtureManifest
		wantErr  string
	}{
		{
			name: "issue_count_mismatch",
			manifest: FixtureManifest{
				ExpectedIssueCount: 99,
			},
			wantErr: "issue count mismatch",
		},
		{
			name: "partial_mismatch",
			manifest: FixtureManifest{
				ExpectedIssueCount: 1,
				ExpectedPartial:    boolPtr(true),
			},
			wantErr: "partial mismatch",
		},
		{
			name: "degraded_mismatch",
			manifest: FixtureManifest{
				ExpectedIssueCount: 1,
				ExpectedDegraded:   boolPtr(true),
			},
			wantErr: "degraded mismatch",
		},
		{
			name: "issue_native_count_mismatch_nil_summary",
			manifest: FixtureManifest{
				ExpectedIssueCount:       1,
				ExpectedIssueNativeCount: intPtr(5),
			},
			wantErr: "issue_native_count mismatch",
		},
		{
			name: "seed_native_count_mismatch_nil_summary",
			manifest: FixtureManifest{
				ExpectedIssueCount:      1,
				ExpectedSeedNativeCount: intPtr(5),
			},
			wantErr: "seed_native_count mismatch",
		},
		{
			name: "finding_bridged_count_mismatch_nil_summary",
			manifest: FixtureManifest{
				ExpectedIssueCount:          1,
				ExpectedFindingBridgedCount: intPtr(5),
			},
			wantErr: "finding_bridged_count mismatch",
		},
		{
			name: "context_selection_count_mismatch",
			manifest: FixtureManifest{
				ExpectedIssueCount:            1,
				ExpectedContextSelectionCount: intPtr(99),
			},
			wantErr: "context selection count mismatch",
		},
		{
			name: "missing_context_selection_trigger_id",
			manifest: FixtureManifest{
				ExpectedIssueCount:                 1,
				ExpectedContextSelectionTriggerIDs: []string{"nonexistent-trigger"},
			},
			wantErr: "missing expected context selection trigger id",
		},
		{
			name: "missing_context_selection_trigger_rule_id",
			manifest: FixtureManifest{
				ExpectedIssueCount:                     1,
				ExpectedContextSelectionTriggerRuleIDs: []string{"nonexistent-rule"},
			},
			wantErr: "missing expected context selection trigger rule id",
		},
		{
			name: "agent_count_mismatch",
			manifest: FixtureManifest{
				ExpectedIssueCount: 1,
				ExpectedAgentCount: intPtr(99),
			},
			wantErr: "agent count mismatch",
		},
		{
			name: "missing_agent_kind",
			manifest: FixtureManifest{
				ExpectedIssueCount: 1,
				ExpectedAgentKinds: []string{"nonexistent-kind"},
			},
			wantErr: "missing expected agent kind",
		},
		{
			name: "missing_agent_issue_type",
			manifest: FixtureManifest{
				ExpectedIssueCount:      1,
				ExpectedAgentIssueTypes: []string{"nonexistent-type"},
			},
			wantErr: "missing expected agent issue_type",
		},
		{
			name: "missing_agent_trigger_reason",
			manifest: FixtureManifest{
				ExpectedIssueCount:          1,
				ExpectedAgentTriggerReasons: []string{"nonexistent-reason"},
			},
			wantErr: "missing expected agent trigger_reason",
		},
		{
			name: "missing_agent_contract_by_issue_id",
			manifest: FixtureManifest{
				ExpectedIssueCount: 1,
				ExpectedAgentContracts: []PlannedAgentConstraint{{
					IssueID: "nonexistent-issue",
					Kind:    "security",
				}},
			},
			wantErr: "missing expected planned agent contract",
		},
		{
			name: "missing_agent_contract_by_rule_id",
			manifest: FixtureManifest{
				ExpectedIssueCount: 1,
				ExpectedAgentContracts: []PlannedAgentConstraint{{
					RuleID: "nonexistent-rule",
					Kind:   "security",
				}},
			},
			wantErr: "missing expected planned agent contract",
		},
		{
			name: "rule_migration_state_nil_summary",
			manifest: FixtureManifest{
				ExpectedIssueCount: 1,
				ExpectedRuleMigrationStates: map[string]string{
					"SEC-001": "issue_native",
				},
			},
			wantErr: "missing migration_summary",
		},
		{
			name: "issue_policy_class_mismatch",
			manifest: FixtureManifest{
				ExpectedIssueCount: 1,
				ExpectedIssuePolicyClasses: map[string]string{
					"iss-001": "blocking",
				},
			},
			wantErr: "issue policy class mismatch",
		},
		{
			name: "issue_policy_class_missing_issue",
			manifest: FixtureManifest{
				ExpectedIssueCount: 1,
				ExpectedIssuePolicyClasses: map[string]string{
					"nonexistent": "advisory",
				},
			},
			wantErr: "missing issue",
		},
		{
			name: "issue_confidence_class_mismatch",
			manifest: FixtureManifest{
				ExpectedIssueCount: 1,
				ExpectedIssueConfidenceClasses: map[string]string{
					"iss-001": "high",
				},
			},
			wantErr: "issue confidence class mismatch",
		},
		{
			name: "issue_confidence_class_missing_issue",
			manifest: FixtureManifest{
				ExpectedIssueCount: 1,
				ExpectedIssueConfidenceClasses: map[string]string{
					"nonexistent": "moderate",
				},
			},
			wantErr: "missing issue",
		},
		{
			name: "confidence_constraint_missing_issue",
			manifest: FixtureManifest{
				ExpectedIssueCount: 1,
				ExpectedConfidenceConstraints: []ConfidenceConstraint{{
					IssueID: "nonexistent",
				}},
			},
			wantErr: "missing issue while checking confidence constraints",
		},
		{
			name: "confidence_constraint_min_violation",
			manifest: FixtureManifest{
				ExpectedIssueCount: 1,
				ExpectedConfidenceConstraints: []ConfidenceConstraint{{
					IssueID: "iss-001",
					Min:     float64Ptr(0.99),
				}},
			},
			wantErr: "issue confidence below minimum",
		},
		{
			name: "confidence_constraint_max_violation",
			manifest: FixtureManifest{
				ExpectedIssueCount: 1,
				ExpectedConfidenceConstraints: []ConfidenceConstraint{{
					IssueID: "iss-001",
					Max:     float64Ptr(0.01),
				}},
			},
			wantErr: "issue confidence above maximum",
		},
		{
			name: "confidence_constraint_class_mismatch",
			manifest: FixtureManifest{
				ExpectedIssueCount: 1,
				ExpectedConfidenceConstraints: []ConfidenceConstraint{{
					IssueID: "iss-001",
					Class:   "high",
				}},
			},
			wantErr: "issue confidence class mismatch",
		},
		{
			name: "confidence_constraint_policy_class_mismatch",
			manifest: FixtureManifest{
				ExpectedIssueCount: 1,
				ExpectedConfidenceConstraints: []ConfidenceConstraint{{
					IssueID:     "iss-001",
					PolicyClass: "blocking",
				}},
			},
			wantErr: "issue policy class mismatch",
		},
		{
			name: "missing_issue_id",
			manifest: FixtureManifest{
				ExpectedIssueCount: 1,
				ExpectedIssueIDs:   []string{"nonexistent"},
			},
			wantErr: "missing expected issue id",
		},
		{
			name: "missing_evidence_id",
			manifest: FixtureManifest{
				ExpectedIssueCount:  1,
				ExpectedEvidenceIDs: []string{"nonexistent"},
			},
			wantErr: "missing expected evidence id",
		},
		{
			name: "missing_rule_id",
			manifest: FixtureManifest{
				ExpectedIssueCount: 1,
				ExpectedRuleIDs:    []string{"nonexistent"},
			},
			wantErr: "missing expected trace rule id",
		},
		{
			name: "missing_non_merge_issue_id",
			manifest: FixtureManifest{
				ExpectedIssueCount:       1,
				ExpectedNonMergeIssueIDs: []string{"nonexistent"},
			},
			wantErr: "expected non-merged issue id",
		},
		{
			name: "missing_merge_representative_id",
			manifest: FixtureManifest{
				ExpectedIssueCount:            1,
				ExpectedMergeRepresentativeID: "nonexistent",
			},
			wantErr: "missing merge representative issue id",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := AssertBundleAgainstFixture(bundle, tc.manifest)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("expected error containing %q, got %q", tc.wantErr, err.Error())
			}
		})
	}
}

func TestAssertBundleAgainstFixture_AgentContractOutputEvidenceMismatch(t *testing.T) {
	t.Parallel()

	bundle := validBundle(t)
	// Use ev-001 which exists in the bundle evidence, so bundle validation passes
	// but the expected output evidence IDs differ.
	bundle.Trace.Agents = []artifactsv2.AgentRun{{
		ID:                "agent-001",
		Kind:              "security",
		IssueType:         "security_review",
		Question:          "test",
		IssueID:           "iss-001",
		TriggerReason:     "unknown_issue",
		InputEvidenceIDs:  []string{"ev-001"},
		OutputEvidenceIDs: []string{"ev-001"},
		Status:            "completed",
	}}

	err := AssertBundleAgainstFixture(bundle, FixtureManifest{
		ExpectedIssueCount: 1,
		ExpectedAgentContracts: []PlannedAgentConstraint{{
			IssueID:           "iss-001",
			Kind:              "security",
			TriggerReason:     "unknown_issue",
			Status:            "completed",
			OutputEvidenceIDs: []string{"ev-expected"},
		}},
	})
	if err == nil {
		t.Fatal("expected error for output evidence mismatch")
	}
	if !strings.Contains(err.Error(), "agent output evidence mismatch") {
		t.Fatalf("expected agent output evidence mismatch error, got %q", err.Error())
	}
}

func TestAssertBundleAgainstFixture_RuleMigrationStateMismatchWithSummary(t *testing.T) {
	t.Parallel()

	bundle := validBundle(t)
	bundle.Trace.MigrationSummary = &artifactsv2.RuleMigrationSummary{
		RuleStates: map[string]string{
			"SEC-001": "seed_native",
		},
	}

	err := AssertBundleAgainstFixture(bundle, FixtureManifest{
		ExpectedIssueCount: 1,
		ExpectedRuleMigrationStates: map[string]string{
			"SEC-001": "issue_native",
		},
	})
	if err == nil {
		t.Fatal("expected error for rule migration state mismatch")
	}
	if !strings.Contains(err.Error(), "rule migration state mismatch") {
		t.Fatalf("expected rule migration state mismatch error, got %q", err.Error())
	}
}

func TestAssertBundleAgainstFixture_MigrationCountWithSummary(t *testing.T) {
	t.Parallel()

	bundle := validBundle(t)
	bundle.Trace.MigrationSummary = &artifactsv2.RuleMigrationSummary{
		IssueNativeCount:    1,
		SeedNativeCount:     2,
		FindingBridgedCount: 3,
		RuleStates:          map[string]string{},
	}

	tests := []struct {
		name     string
		manifest FixtureManifest
		wantErr  string
	}{
		{
			name: "issue_native_count_mismatch_with_summary",
			manifest: FixtureManifest{
				ExpectedIssueCount:       1,
				ExpectedIssueNativeCount: intPtr(99),
			},
			wantErr: "issue_native_count mismatch",
		},
		{
			name: "seed_native_count_mismatch_with_summary",
			manifest: FixtureManifest{
				ExpectedIssueCount:      1,
				ExpectedSeedNativeCount: intPtr(99),
			},
			wantErr: "seed_native_count mismatch",
		},
		{
			name: "finding_bridged_count_mismatch_with_summary",
			manifest: FixtureManifest{
				ExpectedIssueCount:          1,
				ExpectedFindingBridgedCount: intPtr(99),
			},
			wantErr: "finding_bridged_count mismatch",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := AssertBundleAgainstFixture(bundle, tc.manifest)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("expected error containing %q, got %q", tc.wantErr, err.Error())
			}
		})
	}
}

func TestAssertBundleAgainstFixture_ConfidenceConstraintByRuleID(t *testing.T) {
	t.Parallel()

	bundle := validBundle(t)

	// Lookup by RuleID should resolve through rulesRun -> triggeredIssueIDs
	err := AssertBundleAgainstFixture(bundle, FixtureManifest{
		ExpectedIssueCount: 1,
		ExpectedConfidenceConstraints: []ConfidenceConstraint{{
			RuleID: "SEC-001",
			Min:    float64Ptr(0.80),
			Max:    float64Ptr(0.85),
		}},
	})
	if err != nil {
		t.Fatalf("expected no error for valid rule-based confidence constraint, got %v", err)
	}

	// Lookup by RuleID that doesn't exist
	err = AssertBundleAgainstFixture(bundle, FixtureManifest{
		ExpectedIssueCount: 1,
		ExpectedConfidenceConstraints: []ConfidenceConstraint{{
			RuleID: "nonexistent-rule",
		}},
	})
	if err == nil {
		t.Fatal("expected error for nonexistent rule-based confidence constraint")
	}
}

func TestAssertBundleAgainstFixture_ConfidenceConstraintNoIDNoRule(t *testing.T) {
	t.Parallel()

	bundle := validBundle(t)

	err := AssertBundleAgainstFixture(bundle, FixtureManifest{
		ExpectedIssueCount: 1,
		ExpectedConfidenceConstraints: []ConfidenceConstraint{{
			Min: float64Ptr(0.5),
		}},
	})
	if err == nil {
		t.Fatal("expected error when neither IssueID nor RuleID set")
	}
}

func TestAssertBundleDeterministic_InvalidBundles(t *testing.T) {
	t.Parallel()

	valid := validBundle(t)
	invalid := artifactsv2.Bundle{}

	t.Run("first_bundle_invalid", func(t *testing.T) {
		t.Parallel()
		err := AssertBundleDeterministic(invalid, valid)
		if err == nil {
			t.Fatal("expected error for invalid first bundle")
		}
		if !strings.Contains(err.Error(), "first bundle invalid") {
			t.Fatalf("expected 'first bundle invalid' error, got %q", err.Error())
		}
	})

	t.Run("second_bundle_invalid", func(t *testing.T) {
		t.Parallel()
		err := AssertBundleDeterministic(valid, invalid)
		if err == nil {
			t.Fatal("expected error for invalid second bundle")
		}
		if !strings.Contains(err.Error(), "second bundle invalid") {
			t.Fatalf("expected 'second bundle invalid' error, got %q", err.Error())
		}
	})
}

func TestAssertBundleDeterministic_DifferentBundles(t *testing.T) {
	t.Parallel()

	a := validBundle(t)
	b := validBundle(t)
	b.Report.Issues[0].Title = "Different title"
	b.Report.Summary.OverallScore = 0.5
	if err := artifactsv2.FinalizeSignature(&b, "verabase"); err != nil {
		t.Fatalf("FinalizeSignature(): %v", err)
	}

	err := AssertBundleDeterministic(a, b)
	if err == nil {
		t.Fatal("expected error for different bundles")
	}
	if !strings.Contains(err.Error(), "hashes differ") {
		t.Fatalf("expected hashes differ error, got %q", err.Error())
	}
}

func TestMigrationCountOrNil(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		summary *artifactsv2.RuleMigrationSummary
		kind    string
		want    any
	}{
		{
			name:    "nil_summary",
			summary: nil,
			kind:    "issue_native",
			want:    nil,
		},
		{
			name: "issue_native",
			summary: &artifactsv2.RuleMigrationSummary{
				IssueNativeCount: 5,
			},
			kind: "issue_native",
			want: 5,
		},
		{
			name: "seed_native",
			summary: &artifactsv2.RuleMigrationSummary{
				SeedNativeCount: 3,
			},
			kind: "seed_native",
			want: 3,
		},
		{
			name: "finding_bridged",
			summary: &artifactsv2.RuleMigrationSummary{
				FindingBridgedCount: 7,
			},
			kind: "finding_bridged",
			want: 7,
		},
		{
			name: "unknown_kind",
			summary: &artifactsv2.RuleMigrationSummary{
				IssueNativeCount: 1,
			},
			kind: "unknown_kind",
			want: nil,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := migrationCountOrNil(tc.summary, tc.kind)
			if got != tc.want {
				t.Fatalf("migrationCountOrNil(%v, %q) = %v, want %v", tc.summary, tc.kind, got, tc.want)
			}
		})
	}
}

func TestHasHelpers_NegativePaths(t *testing.T) {
	t.Parallel()

	t.Run("hasIssueID_not_found", func(t *testing.T) {
		t.Parallel()
		if hasIssueID(nil, "x") {
			t.Fatal("expected false for nil slice")
		}
		if hasIssueID([]artifactsv2.Issue{{ID: "a"}}, "b") {
			t.Fatal("expected false for non-matching ID")
		}
	})

	t.Run("findIssueByID_not_found", func(t *testing.T) {
		t.Parallel()
		_, ok := findIssueByID(nil, "x")
		if ok {
			t.Fatal("expected false for nil slice")
		}
		_, ok = findIssueByID([]artifactsv2.Issue{{ID: "a"}}, "b")
		if ok {
			t.Fatal("expected false for non-matching ID")
		}
	})

	t.Run("hasEvidenceID_not_found", func(t *testing.T) {
		t.Parallel()
		if hasEvidenceID(nil, "x") {
			t.Fatal("expected false for nil slice")
		}
		if hasEvidenceID([]artifactsv2.EvidenceRecord{{ID: "a"}}, "b") {
			t.Fatal("expected false for non-matching ID")
		}
	})

	t.Run("hasRuleID_not_found", func(t *testing.T) {
		t.Parallel()
		if hasRuleID(nil, "x") {
			t.Fatal("expected false for nil slice")
		}
		if hasRuleID([]artifactsv2.RuleRun{{ID: "a"}}, "b") {
			t.Fatal("expected false for non-matching ID")
		}
	})

	t.Run("hasContextSelectionTriggerID_not_found", func(t *testing.T) {
		t.Parallel()
		if hasContextSelectionTriggerID(nil, "x") {
			t.Fatal("expected false for nil slice")
		}
		if hasContextSelectionTriggerID([]artifactsv2.ContextSelectionRecord{{TriggerID: "a"}}, "b") {
			t.Fatal("expected false for non-matching ID")
		}
	})

	t.Run("hasContextSelectionTriggerRuleID_not_found", func(t *testing.T) {
		t.Parallel()
		if hasContextSelectionTriggerRuleID(
			[]artifactsv2.ContextSelectionRecord{{TriggerID: "iss-1"}},
			nil,
			"RULE-001",
		) {
			t.Fatal("expected false when no rules match")
		}
		if hasContextSelectionTriggerRuleID(
			[]artifactsv2.ContextSelectionRecord{{TriggerID: "iss-other"}},
			[]artifactsv2.RuleRun{{ID: "RULE-001", TriggeredIssueIDs: []string{"iss-1"}}},
			"RULE-001",
		) {
			t.Fatal("expected false when trigger IDs don't match selections")
		}
	})

	t.Run("hasAgentKind_not_found", func(t *testing.T) {
		t.Parallel()
		if hasAgentKind(nil, "x") {
			t.Fatal("expected false for nil slice")
		}
		if hasAgentKind([]artifactsv2.AgentRun{{Kind: "a"}}, "b") {
			t.Fatal("expected false for non-matching kind")
		}
	})

	t.Run("hasAgentIssueType_not_found", func(t *testing.T) {
		t.Parallel()
		if hasAgentIssueType(nil, "x") {
			t.Fatal("expected false for nil slice")
		}
		if hasAgentIssueType([]artifactsv2.AgentRun{{IssueType: "a"}}, "b") {
			t.Fatal("expected false for non-matching type")
		}
	})

	t.Run("hasAgentTriggerReason_not_found", func(t *testing.T) {
		t.Parallel()
		if hasAgentTriggerReason(nil, "x") {
			t.Fatal("expected false for nil slice")
		}
		if hasAgentTriggerReason([]artifactsv2.AgentRun{{TriggerReason: "a"}}, "b") {
			t.Fatal("expected false for non-matching reason")
		}
	})
}

func TestFindAgentByConstraint(t *testing.T) {
	t.Parallel()

	agents := []artifactsv2.AgentRun{
		{
			ID:            "agent-001",
			Kind:          "security",
			IssueType:     "security_review",
			IssueID:       "iss-001",
			TriggerReason: "unknown_issue",
			Status:        "completed",
		},
		{
			ID:            "agent-002",
			Kind:          "quality",
			IssueType:     "quality_review",
			IssueID:       "iss-002",
			TriggerReason: "new_issue",
			Status:        "completed",
		},
	}

	rules := []artifactsv2.RuleRun{
		{ID: "SEC-001", TriggeredIssueIDs: []string{"iss-001"}},
		{ID: "QUAL-001", TriggeredIssueIDs: []string{"iss-002"}},
	}

	tests := []struct {
		name       string
		constraint PlannedAgentConstraint
		wantFound  bool
		wantID     string
	}{
		{
			name:       "by_issue_id",
			constraint: PlannedAgentConstraint{IssueID: "iss-001", Kind: "security"},
			wantFound:  true,
			wantID:     "agent-001",
		},
		{
			name:       "by_issue_id_kind_mismatch",
			constraint: PlannedAgentConstraint{IssueID: "iss-001", Kind: "quality"},
			wantFound:  false,
		},
		{
			name:       "by_issue_id_trigger_reason_mismatch",
			constraint: PlannedAgentConstraint{IssueID: "iss-001", TriggerReason: "wrong"},
			wantFound:  false,
		},
		{
			name:       "by_issue_id_status_mismatch",
			constraint: PlannedAgentConstraint{IssueID: "iss-001", Status: "failed"},
			wantFound:  false,
		},
		{
			name:       "by_issue_id_not_found",
			constraint: PlannedAgentConstraint{IssueID: "nonexistent"},
			wantFound:  false,
		},
		{
			name:       "by_rule_id",
			constraint: PlannedAgentConstraint{RuleID: "SEC-001", Kind: "security"},
			wantFound:  true,
			wantID:     "agent-001",
		},
		{
			name:       "by_rule_id_not_found",
			constraint: PlannedAgentConstraint{RuleID: "nonexistent"},
			wantFound:  false,
		},
		{
			name:       "by_rule_id_candidate_not_matching",
			constraint: PlannedAgentConstraint{RuleID: "SEC-001", Kind: "quality"},
			wantFound:  false,
		},
		{
			name:       "no_issue_id_no_rule_id",
			constraint: PlannedAgentConstraint{Kind: "security"},
			wantFound:  false,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			agent, ok := findAgentByConstraint(agents, rules, tc.constraint)
			if ok != tc.wantFound {
				t.Fatalf("findAgentByConstraint() found=%v, want found=%v", ok, tc.wantFound)
			}
			if tc.wantFound && agent.ID != tc.wantID {
				t.Fatalf("findAgentByConstraint() agent.ID=%q, want %q", agent.ID, tc.wantID)
			}
		})
	}
}

func TestFindIssueByConstraint(t *testing.T) {
	t.Parallel()

	issues := []artifactsv2.Issue{
		{ID: "iss-001", Confidence: 0.82, ConfidenceClass: "moderate"},
		{ID: "iss-002", Confidence: 0.95, ConfidenceClass: "high"},
	}
	rules := []artifactsv2.RuleRun{
		{ID: "SEC-001", TriggeredIssueIDs: []string{"iss-001"}},
	}

	tests := []struct {
		name       string
		constraint ConfidenceConstraint
		wantFound  bool
		wantID     string
	}{
		{
			name:       "by_issue_id",
			constraint: ConfidenceConstraint{IssueID: "iss-001"},
			wantFound:  true,
			wantID:     "iss-001",
		},
		{
			name:       "by_issue_id_not_found",
			constraint: ConfidenceConstraint{IssueID: "nonexistent"},
			wantFound:  false,
		},
		{
			name:       "by_rule_id",
			constraint: ConfidenceConstraint{RuleID: "SEC-001"},
			wantFound:  true,
			wantID:     "iss-001",
		},
		{
			name:       "by_rule_id_not_found",
			constraint: ConfidenceConstraint{RuleID: "nonexistent"},
			wantFound:  false,
		},
		{
			name:       "no_id_no_rule",
			constraint: ConfidenceConstraint{},
			wantFound:  false,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			issue, ok := findIssueByConstraint(issues, rules, tc.constraint)
			if ok != tc.wantFound {
				t.Fatalf("findIssueByConstraint() found=%v, want found=%v", ok, tc.wantFound)
			}
			if tc.wantFound && issue.ID != tc.wantID {
				t.Fatalf("findIssueByConstraint() issue.ID=%q, want %q", issue.ID, tc.wantID)
			}
		})
	}
}

func TestSortedMapEntries(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		m    map[string]string
		want []string
	}{
		{
			name: "nil_map",
			m:    nil,
			want: nil,
		},
		{
			name: "empty_map",
			m:    map[string]string{},
			want: nil,
		},
		{
			name: "single_entry",
			m:    map[string]string{"a": "1"},
			want: []string{"a=1"},
		},
		{
			name: "multiple_entries_sorted",
			m:    map[string]string{"c": "3", "a": "1", "b": "2"},
			want: []string{"a=1", "b=2", "c=3"},
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := sortedMapEntries(tc.m)
			if len(got) != len(tc.want) {
				t.Fatalf("sortedMapEntries() len=%d, want len=%d", len(got), len(tc.want))
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("sortedMapEntries()[%d]=%q, want %q", i, got[i], tc.want[i])
				}
			}
		})
	}
}
