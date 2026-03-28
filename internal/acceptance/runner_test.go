package acceptance

import (
	"testing"

	"github.com/verabase/code-verification-engine/internal/artifactsv2"
	"github.com/verabase/code-verification-engine/internal/report"
)

func floatPtr(v float64) *float64 {
	return &v
}

func TestRunCompatFixture_NativeSeedDeterministicPath(t *testing.T) {
	t.Parallel()

	partial := false
	issueNativeCount := 1
	fixture := CompatFixture{
		Input: artifactsv2.CompatBuildInput{
			Scan: report.ScanReport{
				ScanSchemaVersion: "1.0.0",
				RepoPath:          "/tmp/repo",
				RepoName:          "github.com/acme/repo",
				CommitSHA:         "abc123def456",
				ScannedAt:         "2026-03-27T12:00:00Z",
				FileCount:         3,
				BoundaryMode:      "repo",
			},
			Verification: artifactsv2.VerificationSource{
				ReportSchemaVersion: "1.0.0",
				RuleMetadata: map[string]artifactsv2.RuleMetadata{
					"SEC-001": {RuleID: "SEC-001", MigrationState: "issue_native"},
				},
				IssueSeeds: []artifactsv2.IssueSeed{{
					RuleID:     "SEC-001",
					Title:      "Missing null check",
					Source:     "rule",
					Category:   "security",
					Severity:   "high",
					Status:     "open",
					Confidence: 0.9,
					Quality:    1.0,
					File:       "service.ts",
					Symbol:     "getUser",
					StartLine:  10,
					EndLine:    10,
				}},
			},
			EngineVersion: "verabase@dev",
		},
		Manifest: FixtureManifest{
			FixtureID:                "native-seed-deterministic",
			FixtureType:              "micro",
			ExpectedIssueCount:       1,
			ExpectedRuleIDs:          []string{"SEC-001"},
			ExpectedPartial:          &partial,
			ExpectedIssueNativeCount: &issueNativeCount,
			ExpectedBundleHashStable: true,
			ExpectedConfidenceConstraints: []ConfidenceConstraint{{
				RuleID:      "SEC-001",
				Min:         floatPtr(0.80),
				Max:         floatPtr(0.85),
				Class:       "moderate",
				PolicyClass: "advisory",
			}},
		},
	}

	result, err := RunCompatFixture(fixture)
	if err != nil {
		t.Fatalf("RunCompatFixture(): %v", err)
	}
	if len(result.IssueCandidates) != 1 {
		t.Fatalf("expected 1 issue candidate, got %d", len(result.IssueCandidates))
	}
	if result.IssueCandidates[0].ConfidenceBreakdown == nil {
		t.Fatalf("expected confidence breakdown on issue candidate")
	}
	if result.Bundle.Report.Issues[0].Category != "security" {
		t.Fatalf("expected security category, got %q", result.Bundle.Report.Issues[0].Category)
	}
	if result.Bundle.Trace.MigrationSummary == nil || result.Bundle.Trace.MigrationSummary.IssueNativeCount != 1 {
		t.Fatalf("expected migration summary to report issue_native progress, got %#v", result.Bundle.Trace.MigrationSummary)
	}
	if result.Bundle.Report.Issues[0].PolicyClass != "advisory" {
		t.Fatalf("expected advisory policy class, got %q", result.Bundle.Report.Issues[0].PolicyClass)
	}
	if result.Bundle.Report.Issues[0].ConfidenceClass != "moderate" {
		t.Fatalf("expected moderate confidence class, got %q", result.Bundle.Report.Issues[0].ConfidenceClass)
	}
}

func TestRunCompatFixture_AggregationMergeAndNonMerge(t *testing.T) {
	t.Parallel()

	partial := false

	mergeFixture := CompatFixture{
		Input: artifactsv2.CompatBuildInput{
			Scan: report.ScanReport{
				ScanSchemaVersion: "1.0.0",
				RepoPath:          "/tmp/repo",
				RepoName:          "github.com/acme/repo",
				CommitSHA:         "abc123def456",
				ScannedAt:         "2026-03-27T12:00:00Z",
				FileCount:         3,
				BoundaryMode:      "repo",
			},
			Verification: artifactsv2.VerificationSource{
				ReportSchemaVersion: "1.0.0",
				IssueSeeds: []artifactsv2.IssueSeed{
					{
						RuleID:     "QUAL-001",
						Title:      "Null check missing",
						Source:     "rule",
						Category:   "bug",
						Severity:   "medium",
						Status:     "open",
						Confidence: 0.7,
						Quality:    0.7,
						File:       "service.ts",
						Symbol:     "getUser",
						StartLine:  10,
						EndLine:    11,
					},
					{
						RuleID:     "SEC-001",
						Title:      "Nil dereference risk",
						Source:     "rule",
						Category:   "bug",
						Severity:   "high",
						Status:     "open",
						Confidence: 0.9,
						Quality:    1.0,
						File:       "service.ts",
						Symbol:     "getUser",
						StartLine:  11,
						EndLine:    12,
					},
				},
			},
			EngineVersion: "verabase@dev",
		},
		Manifest: FixtureManifest{
			FixtureID:                "aggregation-merge",
			FixtureType:              "aggregation",
			ExpectedIssueCount:       1,
			ExpectedRuleIDs:          []string{"QUAL-001", "SEC-001"},
			ExpectedPartial:          &partial,
			ExpectedBundleHashStable: true,
		},
	}

	mergeResult, err := RunCompatFixture(mergeFixture)
	if err != nil {
		t.Fatalf("RunCompatFixture(merge): %v", err)
	}
	if got := len(mergeResult.Bundle.Report.Issues[0].EvidenceIDs); got != 2 {
		t.Fatalf("expected merged issue to carry 2 evidence ids, got %d", got)
	}
	if got := mergeResult.Bundle.Report.Issues[0].Severity; got != "high" {
		t.Fatalf("expected merged issue to keep highest severity, got %q", got)
	}

	nonMergeFixture := CompatFixture{
		Input: artifactsv2.CompatBuildInput{
			Scan: mergeFixture.Input.Scan,
			Verification: artifactsv2.VerificationSource{
				ReportSchemaVersion: "1.0.0",
				IssueSeeds: []artifactsv2.IssueSeed{
					{
						RuleID:     "QUAL-001",
						Title:      "Null check missing",
						Source:     "rule",
						Category:   "bug",
						Severity:   "medium",
						Status:     "open",
						Confidence: 0.7,
						Quality:    0.7,
						File:       "service.ts",
						Symbol:     "getUser",
						StartLine:  10,
						EndLine:    11,
					},
					{
						RuleID:     "SEC-002",
						Title:      "Missing validation",
						Source:     "rule",
						Category:   "security",
						Severity:   "high",
						Status:     "open",
						Confidence: 0.9,
						Quality:    1.0,
						File:       "controller.ts",
						Symbol:     "getUser",
						StartLine:  10,
						EndLine:    12,
					},
				},
			},
			EngineVersion: "verabase@dev",
		},
		Manifest: FixtureManifest{
			FixtureID:                "aggregation-non-merge",
			FixtureType:              "aggregation",
			ExpectedIssueCount:       2,
			ExpectedRuleIDs:          []string{"QUAL-001", "SEC-002"},
			ExpectedPartial:          &partial,
			ExpectedBundleHashStable: true,
		},
	}

	nonMergeResult, err := RunCompatFixture(nonMergeFixture)
	if err != nil {
		t.Fatalf("RunCompatFixture(non-merge): %v", err)
	}
	if got := len(nonMergeResult.Bundle.Report.Issues); got != 2 {
		t.Fatalf("expected 2 issues for non-merge fixture, got %d", got)
	}
}

func TestRunCompatFixture_AggregationDoesNotMergeDifferentArchitectureFamilies(t *testing.T) {
	t.Parallel()

	partial := false
	fixture := CompatFixture{
		Input: artifactsv2.CompatBuildInput{
			Scan: report.ScanReport{
				ScanSchemaVersion: "1.0.0",
				RepoPath:          "/tmp/repo",
				RepoName:          "github.com/acme/repo",
				CommitSHA:         "abc123def456",
				ScannedAt:         "2026-03-27T12:00:00Z",
				FileCount:         3,
				BoundaryMode:      "repo",
			},
			Verification: artifactsv2.VerificationSource{
				ReportSchemaVersion: "1.0.0",
				RuleMetadata: map[string]artifactsv2.RuleMetadata{
					"ARCH-LAYER-001":   {RuleID: "ARCH-LAYER-001", MigrationState: "issue_native", MigrationReason: "audited issue-native"},
					"ARCH-PATTERN-001": {RuleID: "ARCH-PATTERN-001", MigrationState: "seed_native", MigrationReason: "audited seed-native"},
				},
				IssueSeeds: []artifactsv2.IssueSeed{
					{
						RuleID:     "ARCH-LAYER-001",
						Title:      "Controller DB access",
						Source:     "rule",
						Category:   "architecture",
						Severity:   "high",
						Status:     "open",
						Confidence: 0.9,
						Quality:    1.0,
						File:       "service.ts",
						StartLine:  20,
						EndLine:    24,
					},
					{
						RuleID:     "ARCH-PATTERN-001",
						Title:      "Repository pattern violation",
						Source:     "rule",
						Category:   "architecture",
						Severity:   "medium",
						Status:     "open",
						Confidence: 0.82,
						Quality:    0.8,
						File:       "service.ts",
						StartLine:  22,
						EndLine:    25,
					},
				},
			},
			EngineVersion: "verabase@dev",
		},
		Manifest: FixtureManifest{
			FixtureID:                "aggregation-arch-family-boundary",
			FixtureType:              "aggregation",
			ExpectedIssueCount:       2,
			ExpectedRuleIDs:          []string{"ARCH-LAYER-001", "ARCH-PATTERN-001"},
			ExpectedPartial:          &partial,
			ExpectedBundleHashStable: true,
		},
	}

	result, err := RunCompatFixture(fixture)
	if err != nil {
		t.Fatalf("RunCompatFixture(): %v", err)
	}
	if len(result.IssueCandidates) != 2 {
		t.Fatalf("expected 2 issue candidates, got %d", len(result.IssueCandidates))
	}
	seen := make(map[string]string)
	for _, candidate := range result.IssueCandidates {
		for _, ruleID := range candidate.RuleIDs {
			seen[ruleID] = candidate.ID
		}
	}
	if seen["ARCH-LAYER-001"] == "" || seen["ARCH-PATTERN-001"] == "" {
		t.Fatalf("expected both architecture families to be present, got %#v", seen)
	}
	if seen["ARCH-LAYER-001"] == seen["ARCH-PATTERN-001"] {
		t.Fatalf("expected architecture families to remain separate, got %#v", seen)
	}
}

func TestRunCompatFixture_ConfidencePenaltyForPartialDegradedScan(t *testing.T) {
	t.Parallel()

	baseSeed := artifactsv2.IssueSeed{
		RuleID:     "SEC-001",
		Title:      "Missing null check",
		Source:     "rule",
		Category:   "security",
		Severity:   "high",
		Status:     "open",
		Confidence: 0.9,
		Quality:    1.0,
		File:       "service.ts",
		Symbol:     "getUser",
		StartLine:  10,
		EndLine:    10,
	}
	partialFalse := false
	partialTrue := true
	degradedTrue := true

	fullFixture := CompatFixture{
		Input: artifactsv2.CompatBuildInput{
			Scan: report.ScanReport{
				ScanSchemaVersion: "1.0.0",
				RepoPath:          "/tmp/repo",
				RepoName:          "github.com/acme/repo",
				CommitSHA:         "abc123def456",
				ScannedAt:         "2026-03-27T12:00:00Z",
				FileCount:         3,
				BoundaryMode:      "repo",
			},
			Verification: artifactsv2.VerificationSource{
				ReportSchemaVersion: "1.0.0",
				IssueSeeds:          []artifactsv2.IssueSeed{baseSeed},
			},
			EngineVersion: "verabase@dev",
		},
		Manifest: FixtureManifest{
			FixtureID:                "confidence-full",
			FixtureType:              "confidence",
			ExpectedIssueCount:       1,
			ExpectedRuleIDs:          []string{"SEC-001"},
			ExpectedPartial:          &partialFalse,
			ExpectedBundleHashStable: true,
		},
	}
	penalizedFixture := CompatFixture{
		Input: artifactsv2.CompatBuildInput{
			Scan: fullFixture.Input.Scan,
			Verification: artifactsv2.VerificationSource{
				ReportSchemaVersion: "1.0.0",
				IssueSeeds:          []artifactsv2.IssueSeed{baseSeed},
				Partial:             true,
				Degraded:            true,
				Errors:              []string{"analyzer degraded"},
			},
			EngineVersion: "verabase@dev",
		},
		Manifest: FixtureManifest{
			FixtureID:                "confidence-partial-degraded",
			FixtureType:              "confidence",
			ExpectedIssueCount:       1,
			ExpectedRuleIDs:          []string{"SEC-001"},
			ExpectedPartial:          &partialTrue,
			ExpectedDegraded:         &degradedTrue,
			ExpectedBundleHashStable: true,
		},
	}

	fullResult, err := RunCompatFixture(fullFixture)
	if err != nil {
		t.Fatalf("RunCompatFixture(full): %v", err)
	}
	penalizedResult, err := RunCompatFixture(penalizedFixture)
	if err != nil {
		t.Fatalf("RunCompatFixture(penalized): %v", err)
	}

	fullConfidence := fullResult.IssueCandidates[0].Confidence
	penalizedConfidence := penalizedResult.IssueCandidates[0].Confidence
	if penalizedConfidence >= fullConfidence {
		t.Fatalf("expected penalized confidence %f to be lower than full confidence %f", penalizedConfidence, fullConfidence)
	}
	if penalizedResult.IssueCandidates[0].ConfidenceBreakdown.BoundaryCompleteness >= fullResult.IssueCandidates[0].ConfidenceBreakdown.BoundaryCompleteness {
		t.Fatalf("expected boundary completeness to drop under partial/degraded conditions")
	}
}

func TestRunCompatFixture_ConfidencePenaltyForAgentOnlySupport(t *testing.T) {
	t.Parallel()

	partial := false
	ruleFixture := CompatFixture{
		Input: artifactsv2.CompatBuildInput{
			Scan: report.ScanReport{
				ScanSchemaVersion: "1.0.0",
				RepoPath:          "/tmp/repo",
				RepoName:          "github.com/acme/repo",
				CommitSHA:         "abc123def456",
				ScannedAt:         "2026-03-27T12:00:00Z",
				FileCount:         3,
				BoundaryMode:      "repo",
			},
			Verification: artifactsv2.VerificationSource{
				ReportSchemaVersion: "1.0.0",
				IssueSeeds: []artifactsv2.IssueSeed{{
					RuleID:     "SEC-001",
					Title:      "Missing null check",
					Source:     "rule",
					Category:   "security",
					Severity:   "high",
					Status:     "open",
					Confidence: 0.9,
					Quality:    1.0,
					File:       "service.ts",
					Symbol:     "getUser",
					StartLine:  10,
					EndLine:    10,
				}},
			},
			EngineVersion: "verabase@dev",
		},
		Manifest: FixtureManifest{
			FixtureID:                "confidence-rule-only",
			FixtureType:              "confidence",
			ExpectedIssueCount:       1,
			ExpectedRuleIDs:          []string{"SEC-001"},
			ExpectedPartial:          &partial,
			ExpectedBundleHashStable: true,
		},
	}
	agentFixture := CompatFixture{
		Input: artifactsv2.CompatBuildInput{
			Scan: ruleFixture.Input.Scan,
			Verification: artifactsv2.VerificationSource{
				ReportSchemaVersion: "1.0.0",
				IssueSeeds: []artifactsv2.IssueSeed{{
					RuleID:     "SEC-001",
					Title:      "Missing null check",
					Source:     "agent",
					Category:   "security",
					Severity:   "high",
					Status:     "open",
					Confidence: 0.9,
					Quality:    1.0,
					File:       "service.ts",
					Symbol:     "getUser",
					StartLine:  10,
					EndLine:    10,
				}},
			},
			EngineVersion: "verabase@dev",
		},
		Manifest: FixtureManifest{
			FixtureID:                "confidence-agent-only",
			FixtureType:              "confidence",
			ExpectedIssueCount:       1,
			ExpectedRuleIDs:          []string{"SEC-001"},
			ExpectedPartial:          &partial,
			ExpectedBundleHashStable: true,
		},
	}

	ruleResult, err := RunCompatFixture(ruleFixture)
	if err != nil {
		t.Fatalf("RunCompatFixture(rule): %v", err)
	}
	agentResult, err := RunCompatFixture(agentFixture)
	if err != nil {
		t.Fatalf("RunCompatFixture(agent): %v", err)
	}

	ruleConfidence := ruleResult.IssueCandidates[0].Confidence
	agentConfidence := agentResult.IssueCandidates[0].Confidence
	if agentConfidence >= ruleConfidence {
		t.Fatalf("expected agent-only confidence %f to be lower than rule-only confidence %f", agentConfidence, ruleConfidence)
	}
	if agentResult.IssueCandidates[0].ConfidenceBreakdown.LLMPenalty <= ruleResult.IssueCandidates[0].ConfidenceBreakdown.LLMPenalty {
		t.Fatalf("expected agent-only path to carry higher llm penalty")
	}
}

func TestRunCompatFixture_ConfidenceCapForUnknownStatus(t *testing.T) {
	t.Parallel()

	partial := false
	fixture := CompatFixture{
		Input: artifactsv2.CompatBuildInput{
			Scan: report.ScanReport{
				ScanSchemaVersion: "1.0.0",
				RepoPath:          "/tmp/repo",
				RepoName:          "github.com/acme/repo",
				CommitSHA:         "abc123def456",
				ScannedAt:         "2026-03-27T12:00:00Z",
				FileCount:         3,
				BoundaryMode:      "repo",
			},
			Verification: artifactsv2.VerificationSource{
				ReportSchemaVersion: "1.0.0",
				IssueSeeds: []artifactsv2.IssueSeed{{
					RuleID:     "SEC-001",
					Title:      "Missing null check",
					Source:     "rule",
					Category:   "security",
					Severity:   "high",
					Status:     "unknown",
					Confidence: 0.9,
					Quality:    1.0,
					File:       "service.ts",
					Symbol:     "getUser",
					StartLine:  10,
					EndLine:    10,
				}},
			},
			EngineVersion: "verabase@dev",
		},
		Manifest: FixtureManifest{
			FixtureID:                "confidence-unknown-cap",
			FixtureType:              "confidence",
			ExpectedIssueCount:       1,
			ExpectedRuleIDs:          []string{"SEC-001"},
			ExpectedPartial:          &partial,
			ExpectedBundleHashStable: true,
		},
	}

	result, err := RunCompatFixture(fixture)
	if err != nil {
		t.Fatalf("RunCompatFixture(): %v", err)
	}
	if result.IssueCandidates[0].Confidence > 0.55 {
		t.Fatalf("expected unknown issue confidence to be capped at 0.55, got %f", result.IssueCandidates[0].Confidence)
	}
	if result.IssueCandidates[0].ConfidenceBreakdown.Final > 0.55 {
		t.Fatalf("expected unknown issue breakdown final to be capped at 0.55, got %f", result.IssueCandidates[0].ConfidenceBreakdown.Final)
	}
}

func TestRunCompatFixture_ArchitectureRulePromotedToIssueNative(t *testing.T) {
	t.Parallel()

	partial := false
	issueNativeCount := 1
	fixture := CompatFixture{
		Input: artifactsv2.CompatBuildInput{
			Scan: report.ScanReport{
				ScanSchemaVersion: "1.0.0",
				RepoPath:          "/tmp/repo",
				RepoName:          "github.com/acme/repo",
				CommitSHA:         "abc123def456",
				ScannedAt:         "2026-03-27T12:00:00Z",
				FileCount:         3,
				BoundaryMode:      "repo",
			},
			Verification: artifactsv2.VerificationSource{
				ReportSchemaVersion: "1.0.0",
				RuleMetadata: map[string]artifactsv2.RuleMetadata{
					"ARCH-LAYER-001": {
						RuleID:          "ARCH-LAYER-001",
						MigrationState:  "issue_native",
						MigrationReason: "controller DB-access violations are grounded in FileRole and route-binding evidence, with explicit service/test/repository false-positive guards",
					},
				},
				IssueSeeds: []artifactsv2.IssueSeed{{
					RuleID:     "ARCH-LAYER-001",
					Title:      "Controllers must not access database directly",
					Source:     "rule",
					Category:   "architecture",
					Severity:   "high",
					Status:     "open",
					Confidence: 0.9,
					Quality:    0.7,
					File:       "users/controller.ts",
					Symbol:     "UsersController",
					StartLine:  10,
					EndLine:    12,
				}},
			},
			EngineVersion: "verabase@dev",
		},
		Manifest: FixtureManifest{
			FixtureID:                "architecture-issue-native",
			FixtureType:              "migration",
			ExpectedIssueCount:       1,
			ExpectedRuleIDs:          []string{"ARCH-LAYER-001"},
			ExpectedPartial:          &partial,
			ExpectedIssueNativeCount: &issueNativeCount,
			ExpectedRuleMigrationStates: map[string]string{
				"ARCH-LAYER-001": "issue_native",
			},
			ExpectedBundleHashStable: true,
		},
	}

	result, err := RunCompatFixture(fixture)
	if err != nil {
		t.Fatalf("RunCompatFixture(): %v", err)
	}
	if result.Bundle.Trace.MigrationSummary == nil {
		t.Fatal("expected migration summary")
	}
	if got := result.Bundle.Trace.MigrationSummary.RuleStates["ARCH-LAYER-001"]; got != "issue_native" {
		t.Fatalf("expected ARCH-LAYER-001 to be issue_native, got %q", got)
	}
	if result.Bundle.Trace.MigrationSummary.RuleReasons["ARCH-LAYER-001"] == "" {
		t.Fatalf("expected ARCH-LAYER-001 migration reason, got %#v", result.Bundle.Trace.MigrationSummary.RuleReasons)
	}
}

func TestRunCompatFixture_AggregationNonMergeOnStatusMismatch(t *testing.T) {
	t.Parallel()

	partial := false
	fixture := CompatFixture{
		Input: artifactsv2.CompatBuildInput{
			Scan: report.ScanReport{
				ScanSchemaVersion: "1.0.0",
				RepoPath:          "/tmp/repo",
				RepoName:          "github.com/acme/repo",
				CommitSHA:         "abc123def456",
				ScannedAt:         "2026-03-27T12:00:00Z",
				FileCount:         3,
				BoundaryMode:      "repo",
			},
			Verification: artifactsv2.VerificationSource{
				ReportSchemaVersion: "1.0.0",
				IssueSeeds: []artifactsv2.IssueSeed{
					{
						RuleID:     "QUAL-001",
						Title:      "Null check missing",
						Source:     "rule",
						Category:   "bug",
						Severity:   "medium",
						Status:     "open",
						Confidence: 0.7,
						Quality:    0.7,
						File:       "service.ts",
						Symbol:     "getUser",
						StartLine:  10,
						EndLine:    11,
					},
					{
						RuleID:     "QUAL-002",
						Title:      "Null check restored",
						Source:     "rule",
						Category:   "bug",
						Severity:   "medium",
						Status:     "resolved",
						Confidence: 0.7,
						Quality:    0.7,
						File:       "service.ts",
						Symbol:     "getUser",
						StartLine:  10,
						EndLine:    11,
					},
				},
			},
			EngineVersion: "verabase@dev",
		},
		Manifest: FixtureManifest{
			FixtureID:                "aggregation-status-non-merge",
			FixtureType:              "aggregation",
			ExpectedIssueCount:       2,
			ExpectedRuleIDs:          []string{"QUAL-001", "QUAL-002"},
			ExpectedPartial:          &partial,
			ExpectedBundleHashStable: true,
		},
	}

	result, err := RunCompatFixture(fixture)
	if err != nil {
		t.Fatalf("RunCompatFixture(): %v", err)
	}
	if len(result.Bundle.Report.Issues) != 2 {
		t.Fatalf("expected 2 issues for status mismatch fixture, got %d", len(result.Bundle.Report.Issues))
	}
}

func TestRunCompatFixture_AggregationMergeByNearbyLinesWithoutSymbol(t *testing.T) {
	t.Parallel()

	partial := false
	fixture := CompatFixture{
		Input: artifactsv2.CompatBuildInput{
			Scan: report.ScanReport{
				ScanSchemaVersion: "1.0.0",
				RepoPath:          "/tmp/repo",
				RepoName:          "github.com/acme/repo",
				CommitSHA:         "abc123def456",
				ScannedAt:         "2026-03-27T12:00:00Z",
				FileCount:         3,
				BoundaryMode:      "repo",
			},
			Verification: artifactsv2.VerificationSource{
				ReportSchemaVersion: "1.0.0",
				IssueSeeds: []artifactsv2.IssueSeed{
					{
						RuleID:     "QUAL-001",
						Title:      "Null check missing",
						Source:     "rule",
						Category:   "bug",
						Severity:   "medium",
						Status:     "open",
						Confidence: 0.7,
						Quality:    0.7,
						File:       "service.ts",
						StartLine:  10,
						EndLine:    11,
					},
					{
						RuleID:     "SEC-001",
						Title:      "Nil dereference risk",
						Source:     "rule",
						Category:   "bug",
						Severity:   "high",
						Status:     "open",
						Confidence: 0.9,
						Quality:    1.0,
						File:       "service.ts",
						StartLine:  13,
						EndLine:    14,
					},
				},
			},
			EngineVersion: "verabase@dev",
		},
		Manifest: FixtureManifest{
			FixtureID:                "aggregation-nearby-line-merge",
			FixtureType:              "aggregation",
			ExpectedIssueCount:       1,
			ExpectedRuleIDs:          []string{"QUAL-001", "SEC-001"},
			ExpectedPartial:          &partial,
			ExpectedBundleHashStable: true,
		},
	}

	result, err := RunCompatFixture(fixture)
	if err != nil {
		t.Fatalf("RunCompatFixture(): %v", err)
	}
	if got := result.Bundle.Report.Issues[0].MergeBasis; got != "line_overlap" {
		t.Fatalf("expected line_overlap merge basis, got %q", got)
	}
}

func TestRunCompatFixture_PreservesExplicitEvidenceIDs(t *testing.T) {
	t.Parallel()

	partial := false
	fixture := CompatFixture{
		Input: artifactsv2.CompatBuildInput{
			Scan: report.ScanReport{
				ScanSchemaVersion: "1.0.0",
				RepoPath:          "/tmp/repo",
				RepoName:          "github.com/acme/repo",
				CommitSHA:         "abc123def456",
				ScannedAt:         "2026-03-27T12:00:00Z",
				FileCount:         3,
				BoundaryMode:      "repo",
			},
			Verification: artifactsv2.VerificationSource{
				ReportSchemaVersion: "1.0.0",
				IssueSeeds: []artifactsv2.IssueSeed{{
					RuleID:      "SEC-001",
					Title:       "Missing null check",
					Source:      "rule",
					Category:    "security",
					Severity:    "high",
					Status:      "open",
					Confidence:  0.9,
					Quality:     1.0,
					File:        "service.ts",
					Symbol:      "getUser",
					StartLine:   10,
					EndLine:     10,
					EvidenceIDs: []string{"ev-explicit-1"},
				}},
			},
			EngineVersion: "verabase@dev",
		},
		Manifest: FixtureManifest{
			FixtureID:                "evidence-explicit-id",
			FixtureType:              "evidence",
			ExpectedIssueCount:       1,
			ExpectedRuleIDs:          []string{"SEC-001"},
			ExpectedEvidenceIDs:      []string{"ev-explicit-1"},
			ExpectedPartial:          &partial,
			ExpectedBundleHashStable: true,
		},
	}

	result, err := RunCompatFixture(fixture)
	if err != nil {
		t.Fatalf("RunCompatFixture(): %v", err)
	}
	if got := result.Bundle.Report.Issues[0].EvidenceIDs; len(got) != 1 || got[0] != "ev-explicit-1" {
		t.Fatalf("expected explicit evidence id to be preserved, got %#v", got)
	}
	if got := result.Bundle.Evidence.Evidence[0].ID; got != "ev-explicit-1" {
		t.Fatalf("expected evidence artifact to preserve explicit id, got %q", got)
	}
}

func TestRunCompatFixture_SynthesizesEvidenceAndCrossReferences(t *testing.T) {
	t.Parallel()

	partial := false
	fixture := CompatFixture{
		Input: artifactsv2.CompatBuildInput{
			Scan: report.ScanReport{
				ScanSchemaVersion: "1.0.0",
				RepoPath:          "/tmp/repo",
				RepoName:          "github.com/acme/repo",
				CommitSHA:         "abc123def456",
				ScannedAt:         "2026-03-27T12:00:00Z",
				FileCount:         3,
				BoundaryMode:      "repo",
			},
			Verification: artifactsv2.VerificationSource{
				ReportSchemaVersion: "1.0.0",
				IssueSeeds: []artifactsv2.IssueSeed{{
					RuleID:     "SEC-001",
					Title:      "Missing null check",
					Source:     "rule",
					Category:   "security",
					Severity:   "high",
					Status:     "open",
					Confidence: 0.9,
					Quality:    1.0,
					File:       "service.ts",
					Symbol:     "getUser",
					StartLine:  10,
					EndLine:    10,
				}},
			},
			EngineVersion: "verabase@dev",
		},
		Manifest: FixtureManifest{
			FixtureID:                "evidence-synthetic",
			FixtureType:              "evidence",
			ExpectedIssueCount:       1,
			ExpectedRuleIDs:          []string{"SEC-001"},
			ExpectedPartial:          &partial,
			ExpectedBundleHashStable: true,
		},
	}

	result, err := RunCompatFixture(fixture)
	if err != nil {
		t.Fatalf("RunCompatFixture(): %v", err)
	}
	if len(result.Bundle.Evidence.Evidence) != 1 {
		t.Fatalf("expected single synthetic evidence record, got %d", len(result.Bundle.Evidence.Evidence))
	}
	ev := result.Bundle.Evidence.Evidence[0]
	if synthetic, _ := ev.Payload["synthetic"].(bool); !synthetic {
		t.Fatalf("expected synthetic evidence payload marker, got %#v", ev.Payload)
	}
	if got := result.Bundle.Report.Issues[0].EvidenceIDs; len(got) != 1 || got[0] != ev.ID {
		t.Fatalf("expected report issue evidence ids to match synthetic evidence id, got %#v vs %q", got, ev.ID)
	}
	if got := result.Bundle.Trace.Derivations[0].DerivedFromEvidenceIDs; len(got) != 1 || got[0] != ev.ID {
		t.Fatalf("expected trace derivation evidence ids to match synthetic evidence id, got %#v vs %q", got, ev.ID)
	}
}

func TestRunCompatFixture_RepeatedBuildPreservesStableIssueAndEvidenceIDs(t *testing.T) {
	t.Parallel()

	input := artifactsv2.CompatBuildInput{
		Scan: report.ScanReport{
			ScanSchemaVersion: "1.0.0",
			RepoPath:          "/tmp/repo",
			RepoName:          "github.com/acme/repo",
			CommitSHA:         "abc123def456",
			ScannedAt:         "2026-03-27T12:00:00Z",
			FileCount:         3,
			BoundaryMode:      "repo",
		},
		Verification: artifactsv2.VerificationSource{
			ReportSchemaVersion: "1.0.0",
			IssueSeeds: []artifactsv2.IssueSeed{{
				RuleID:     "SEC-001",
				Title:      "Missing null check",
				Source:     "rule",
				Category:   "security",
				Severity:   "high",
				Status:     "open",
				Confidence: 0.9,
				Quality:    1.0,
				File:       "service.ts",
				Symbol:     "getUser",
				StartLine:  10,
				EndLine:    10,
			}},
		},
		EngineVersion: "verabase@dev",
	}

	first, err := artifactsv2.BuildCompatArtifacts(input)
	if err != nil {
		t.Fatalf("BuildCompatArtifacts(first): %v", err)
	}
	second, err := artifactsv2.BuildCompatArtifacts(input)
	if err != nil {
		t.Fatalf("BuildCompatArtifacts(second): %v", err)
	}

	if len(first.Bundle.Report.Issues) != 1 || len(second.Bundle.Report.Issues) != 1 {
		t.Fatalf("expected exactly one issue from repeated builds")
	}
	if first.Bundle.Report.Issues[0].ID != second.Bundle.Report.Issues[0].ID {
		t.Fatalf("expected stable issue ids across repeated builds, got %q vs %q", first.Bundle.Report.Issues[0].ID, second.Bundle.Report.Issues[0].ID)
	}
	if first.Bundle.Report.Issues[0].Fingerprint != second.Bundle.Report.Issues[0].Fingerprint {
		t.Fatalf("expected stable issue fingerprints across repeated builds, got %q vs %q", first.Bundle.Report.Issues[0].Fingerprint, second.Bundle.Report.Issues[0].Fingerprint)
	}
	if len(first.Bundle.Evidence.Evidence) != 1 || len(second.Bundle.Evidence.Evidence) != 1 {
		t.Fatalf("expected exactly one evidence record from repeated builds")
	}
	if first.Bundle.Evidence.Evidence[0].ID != second.Bundle.Evidence.Evidence[0].ID {
		t.Fatalf("expected stable evidence ids across repeated builds, got %q vs %q", first.Bundle.Evidence.Evidence[0].ID, second.Bundle.Evidence.Evidence[0].ID)
	}
}

func TestRunCompatFixture_ConfidenceBoostForMultiRuleSupport(t *testing.T) {
	t.Parallel()

	partial := false
	baseScan := report.ScanReport{
		ScanSchemaVersion: "1.0.0",
		RepoPath:          "/tmp/repo",
		RepoName:          "github.com/acme/repo",
		CommitSHA:         "abc123def456",
		ScannedAt:         "2026-03-27T12:00:00Z",
		FileCount:         3,
		BoundaryMode:      "repo",
	}
	singleFixture := CompatFixture{
		Input: artifactsv2.CompatBuildInput{
			Scan: baseScan,
			Verification: artifactsv2.VerificationSource{
				ReportSchemaVersion: "1.0.0",
				RuleMetadata: map[string]artifactsv2.RuleMetadata{
					"SEC-001": {RuleID: "SEC-001", MigrationState: "issue_native"},
				},
				IssueSeeds: []artifactsv2.IssueSeed{{
					RuleID:     "SEC-001",
					Title:      "Missing null check",
					Source:     "rule",
					Category:   "security",
					Severity:   "high",
					Status:     "open",
					Confidence: 0.9,
					Quality:    1.0,
					File:       "service.ts",
					Symbol:     "getUser",
					StartLine:  10,
					EndLine:    10,
				}},
			},
			EngineVersion: "verabase@dev",
		},
		Manifest: FixtureManifest{
			FixtureID:                "confidence-single-rule",
			FixtureType:              "confidence",
			ExpectedIssueCount:       1,
			ExpectedRuleIDs:          []string{"SEC-001"},
			ExpectedPartial:          &partial,
			ExpectedBundleHashStable: true,
		},
	}
	multiFixture := CompatFixture{
		Input: artifactsv2.CompatBuildInput{
			Scan: baseScan,
			Verification: artifactsv2.VerificationSource{
				ReportSchemaVersion: "1.0.0",
				RuleMetadata: map[string]artifactsv2.RuleMetadata{
					"SEC-001":  {RuleID: "SEC-001", MigrationState: "issue_native"},
					"QUAL-001": {RuleID: "QUAL-001", MigrationState: "issue_native"},
				},
				IssueSeeds: []artifactsv2.IssueSeed{
					{
						RuleID:     "SEC-001",
						Title:      "Missing null check",
						Source:     "rule",
						Category:   "security",
						Severity:   "high",
						Status:     "open",
						Confidence: 0.9,
						Quality:    1.0,
						File:       "service.ts",
						Symbol:     "getUser",
						StartLine:  10,
						EndLine:    10,
					},
					{
						RuleID:     "QUAL-001",
						Title:      "Potential nil dereference",
						Source:     "rule",
						Category:   "bug",
						Severity:   "high",
						Status:     "open",
						Confidence: 0.9,
						Quality:    1.0,
						File:       "service.ts",
						Symbol:     "getUser",
						StartLine:  10,
						EndLine:    10,
					},
				},
			},
			EngineVersion: "verabase@dev",
		},
		Manifest: FixtureManifest{
			FixtureID:                "confidence-multi-rule",
			FixtureType:              "confidence",
			ExpectedIssueCount:       1,
			ExpectedRuleIDs:          []string{"SEC-001", "QUAL-001"},
			ExpectedPartial:          &partial,
			ExpectedBundleHashStable: true,
		},
	}

	single, err := RunCompatFixture(singleFixture)
	if err != nil {
		t.Fatalf("RunCompatFixture(single): %v", err)
	}
	multi, err := RunCompatFixture(multiFixture)
	if err != nil {
		t.Fatalf("RunCompatFixture(multi): %v", err)
	}
	if multi.IssueCandidates[0].ConfidenceBreakdown.RuleReliability <= single.IssueCandidates[0].ConfidenceBreakdown.RuleReliability {
		t.Fatalf("expected multi-rule support boost, got %f vs %f", multi.IssueCandidates[0].ConfidenceBreakdown.RuleReliability, single.IssueCandidates[0].ConfidenceBreakdown.RuleReliability)
	}
}

func TestRunCompatFixture_MigrationProgressImprovesConfidenceOrdering(t *testing.T) {
	t.Parallel()

	partial := false
	baseScan := report.ScanReport{
		ScanSchemaVersion: "1.0.0",
		RepoPath:          "/tmp/repo",
		RepoName:          "github.com/acme/repo",
		CommitSHA:         "abc123def456",
		ScannedAt:         "2026-03-27T12:00:00Z",
		FileCount:         3,
		BoundaryMode:      "repo",
	}
	baseSeed := artifactsv2.IssueSeed{
		RuleID:     "MIG-001",
		Title:      "Deterministic issue seed",
		Source:     "rule",
		Category:   "security",
		Severity:   "high",
		Status:     "open",
		Confidence: 0.9,
		Quality:    1.0,
		File:       "service.ts",
		Symbol:     "getUser",
		StartLine:  10,
		EndLine:    10,
	}

	issueNativeFixture := CompatFixture{
		Input: artifactsv2.CompatBuildInput{
			Scan: baseScan,
			Verification: artifactsv2.VerificationSource{
				ReportSchemaVersion: "1.0.0",
				RuleMetadata: map[string]artifactsv2.RuleMetadata{
					"MIG-001": {RuleID: "MIG-001", MigrationState: "issue_native", MigrationReason: "native issue semantics"},
				},
				IssueSeeds: []artifactsv2.IssueSeed{baseSeed},
			},
			EngineVersion: "verabase@dev",
		},
		Manifest: FixtureManifest{
			FixtureID:                "migration-issue-native",
			FixtureType:              "migration",
			ExpectedIssueCount:       1,
			ExpectedRuleIDs:          []string{"MIG-001"},
			ExpectedPartial:          &partial,
			ExpectedIssueNativeCount: func() *int { v := 1; return &v }(),
			ExpectedSeedNativeCount:  func() *int { v := 0; return &v }(),
			ExpectedBundleHashStable: true,
			ExpectedConfidenceConstraints: []ConfidenceConstraint{{
				RuleID:      "MIG-001",
				Min:         floatPtr(0.80),
				Max:         floatPtr(0.85),
				Class:       "moderate",
				PolicyClass: "advisory",
			}},
		},
	}

	seedNativeFixture := CompatFixture{
		Input: artifactsv2.CompatBuildInput{
			Scan: baseScan,
			Verification: artifactsv2.VerificationSource{
				ReportSchemaVersion: "1.0.0",
				RuleMetadata: map[string]artifactsv2.RuleMetadata{
					"MIG-001": {RuleID: "MIG-001", MigrationState: "seed_native", MigrationReason: "deterministic issue seeds exist, but issue-native audit is incomplete"},
				},
				IssueSeeds: []artifactsv2.IssueSeed{baseSeed},
			},
			EngineVersion: "verabase@dev",
		},
		Manifest: FixtureManifest{
			FixtureID:                "migration-seed-native",
			FixtureType:              "migration",
			ExpectedIssueCount:       1,
			ExpectedRuleIDs:          []string{"MIG-001"},
			ExpectedPartial:          &partial,
			ExpectedIssueNativeCount: func() *int { v := 0; return &v }(),
			ExpectedSeedNativeCount:  func() *int { v := 1; return &v }(),
			ExpectedBundleHashStable: true,
			ExpectedConfidenceConstraints: []ConfidenceConstraint{{
				RuleID:      "MIG-001",
				Min:         floatPtr(0.75),
				Max:         floatPtr(0.82),
				Class:       "moderate",
				PolicyClass: "advisory",
			}},
		},
	}

	issueNativeResult, err := RunCompatFixture(issueNativeFixture)
	if err != nil {
		t.Fatalf("RunCompatFixture(issue-native): %v", err)
	}
	seedNativeResult, err := RunCompatFixture(seedNativeFixture)
	if err != nil {
		t.Fatalf("RunCompatFixture(seed-native): %v", err)
	}

	if issueNativeResult.IssueCandidates[0].Confidence <= seedNativeResult.IssueCandidates[0].Confidence {
		t.Fatalf("expected issue_native confidence %f to exceed seed_native confidence %f", issueNativeResult.IssueCandidates[0].Confidence, seedNativeResult.IssueCandidates[0].Confidence)
	}
	if issueNativeResult.Bundle.Report.Issues[0].PolicyClass != "advisory" {
		t.Fatalf("expected issue_native policy class advisory, got %q", issueNativeResult.Bundle.Report.Issues[0].PolicyClass)
	}
	if seedNativeResult.Bundle.Report.Issues[0].PolicyClass != "advisory" {
		t.Fatalf("expected seed_native policy class advisory, got %q", seedNativeResult.Bundle.Report.Issues[0].PolicyClass)
	}
}

func TestRunCompatFixture_ContextSelectionAndPlannedAgentsStayBounded(t *testing.T) {
	t.Parallel()

	partial := false
	contextSelectionCount := 3
	agentCount := 3
	fixture := CompatFixture{
		Input: artifactsv2.CompatBuildInput{
			Scan: report.ScanReport{
				ScanSchemaVersion: "1.0.0",
				RepoPath:          "/tmp/repo",
				RepoName:          "github.com/acme/repo",
				CommitSHA:         "abc123def456",
				ScannedAt:         "2026-03-27T12:00:00Z",
				FileCount:         3,
				BoundaryMode:      "repo",
			},
			Verification: artifactsv2.VerificationSource{
				ReportSchemaVersion: "1.0.0",
				RuleMetadata: map[string]artifactsv2.RuleMetadata{
					"CTX-TRUST-001": {RuleID: "CTX-TRUST-001", MigrationState: "issue_native", MigrationReason: "trusted static issue semantics"},
					"CTX-DES-001":   {RuleID: "CTX-DES-001", MigrationState: "seed_native", MigrationReason: "semantic issue seed exists but planned agent support is still required"},
					"CTX-UNK-001":   {RuleID: "CTX-UNK-001", MigrationState: "finding_bridged", MigrationReason: "unknown path still depends on compatibility finding semantics"},
				},
				IssueSeeds: []artifactsv2.IssueSeed{
					{
						RuleID:     "CTX-TRUST-001",
						Title:      "Strongly evidenced security check",
						Source:     "rule",
						Category:   "security",
						Severity:   "high",
						Status:     "resolved",
						Confidence: 0.95,
						Quality:    1.0,
						File:       "storage/security.ts",
						Symbol:     "verifyPermissions",
						StartLine:  40,
						EndLine:    44,
					},
					{
						RuleID:     "CTX-DES-001",
						Title:      "Layering violation across UI and domain",
						Source:     "agent",
						Category:   "design",
						Severity:   "high",
						Status:     "open",
						Confidence: 0.9,
						Quality:    1.0,
						File:       "checkout/design.ts",
						Symbol:     "composeCheckout",
						StartLine:  22,
						EndLine:    28,
					},
					{
						RuleID:     "CTX-UNK-001",
						Title:      "Missing access control check",
						Source:     "rule",
						Category:   "bug",
						Severity:   "medium",
						Status:     "unknown",
						Confidence: 0.8,
						Quality:    0.7,
						File:       "auth/service.ts",
						Symbol:     "AuthorizeUser",
						StartLine:  10,
						EndLine:    12,
					},
				},
			},
			EngineVersion: "verabase@dev",
		},
		Manifest: FixtureManifest{
			FixtureID:                              "context-agent-contract-boundary",
			FixtureType:                            "context",
			ExpectedIssueCount:                     3,
			ExpectedRuleIDs:                        []string{"CTX-TRUST-001", "CTX-DES-001", "CTX-UNK-001"},
			ExpectedPartial:                        &partial,
			ExpectedContextSelectionCount:          &contextSelectionCount,
			ExpectedContextSelectionTriggerRuleIDs: []string{"CTX-TRUST-001", "CTX-DES-001", "CTX-UNK-001"},
			ExpectedAgentCount:                     &agentCount,
			ExpectedAgentKinds:                     []string{"bug", "design", "security"},
			ExpectedAgentIssueTypes:                []string{"bug_review", "design_review", "security_review"},
			ExpectedAgentTriggerReasons:            []string{"high_severity_review", "unknown_issue"},
			ExpectedAgentContracts: []PlannedAgentConstraint{
				{RuleID: "CTX-TRUST-001", Kind: "security", TriggerReason: "high_severity_review", Status: "planned"},
				{RuleID: "CTX-DES-001", Kind: "design", TriggerReason: "high_severity_review", Status: "planned"},
				{RuleID: "CTX-UNK-001", Kind: "bug", TriggerReason: "unknown_issue", Status: "planned"},
			},
			ExpectedBundleHashStable: true,
			ExpectedConfidenceConstraints: []ConfidenceConstraint{
				{
					RuleID:      "CTX-TRUST-001",
					Min:         floatPtr(0.82),
					Max:         floatPtr(0.84),
					Class:       "moderate",
					PolicyClass: "advisory",
				},
				{
					RuleID:      "CTX-DES-001",
					Min:         floatPtr(0.40),
					Max:         floatPtr(0.60),
					Class:       "low",
					PolicyClass: "advisory",
				},
				{
					RuleID:      "CTX-UNK-001",
					Min:         floatPtr(0.40),
					Max:         floatPtr(0.55),
					Class:       "low",
					PolicyClass: "unknown_retained",
				},
			},
		},
	}

	result, err := RunCompatFixture(fixture)
	if err != nil {
		t.Fatalf("RunCompatFixture(): %v", err)
	}
	if len(result.Bundle.Trace.ContextSelections) != 3 {
		t.Fatalf("expected 3 context selections, got %d", len(result.Bundle.Trace.ContextSelections))
	}
	if len(result.Bundle.Trace.Agents) != 3 {
		t.Fatalf("expected 3 planned agents, got %d", len(result.Bundle.Trace.Agents))
	}

	issuesByRule := make(map[string]artifactsv2.IssueCandidate)
	for _, candidate := range result.IssueCandidates {
		for _, ruleID := range candidate.RuleIDs {
			issuesByRule[ruleID] = candidate
		}
	}
	trustedIssue := issuesByRule["CTX-TRUST-001"]
	designIssue := issuesByRule["CTX-DES-001"]
	unknownIssue := issuesByRule["CTX-UNK-001"]
	if trustedIssue.ID == "" || designIssue.ID == "" || unknownIssue.ID == "" {
		t.Fatal("expected all issue candidates to be present")
	}
	if trustedIssue.Confidence <= designIssue.Confidence || designIssue.Confidence <= unknownIssue.Confidence {
		t.Fatalf("expected confidence ordering trusted > design > unknown, got %f > %f > %f", trustedIssue.Confidence, designIssue.Confidence, unknownIssue.Confidence)
	}
	if trustedIssue.PolicyClass != "advisory" || designIssue.PolicyClass != "advisory" || unknownIssue.PolicyClass != "unknown_retained" {
		t.Fatalf("unexpected policy classes: trusted=%q design=%q unknown=%q", trustedIssue.PolicyClass, designIssue.PolicyClass, unknownIssue.PolicyClass)
	}
	selectionByTrigger := make(map[string]artifactsv2.ContextSelectionRecord)
	for _, selection := range result.Bundle.Trace.ContextSelections {
		selectionByTrigger[selection.TriggerID] = selection
		if len(selection.SelectionTrace) == 0 {
			t.Fatalf("expected selection trace for trigger %q", selection.TriggerID)
		}
	}
	if _, ok := selectionByTrigger[trustedIssue.ID]; !ok {
		t.Fatalf("expected trusted issue %q to trigger context selection", trustedIssue.ID)
	}
	if _, ok := selectionByTrigger[designIssue.ID]; !ok {
		t.Fatalf("expected design issue %q to trigger context selection", designIssue.ID)
	}
	if _, ok := selectionByTrigger[unknownIssue.ID]; !ok {
		t.Fatalf("expected unknown issue %q to trigger context selection", unknownIssue.ID)
	}
	if selectionByTrigger[designIssue.ID].SelectionTrace[0] != "trigger_reason:high_severity_review" {
		t.Fatalf("expected design issue to record review trigger, got %#v", selectionByTrigger[designIssue.ID].SelectionTrace)
	}
	if selectionByTrigger[unknownIssue.ID].SelectionTrace[0] != "trigger_reason:unknown_issue" {
		t.Fatalf("expected unknown issue to record unknown trigger, got %#v", selectionByTrigger[unknownIssue.ID].SelectionTrace)
	}
}

func TestRunCompatFixture_BoundedContextSelectionAndPlannedAgents(t *testing.T) {
	t.Parallel()

	partial := false
	contextSelectionCount := 3
	agentCount := 3
	fixture := CompatFixture{
		Input: artifactsv2.CompatBuildInput{
			Scan: report.ScanReport{
				ScanSchemaVersion: "1.0.0",
				RepoPath:          "/tmp/repo",
				RepoName:          "github.com/acme/repo",
				CommitSHA:         "abc123def456",
				ScannedAt:         "2026-03-27T12:00:00Z",
				FileCount:         3,
				BoundaryMode:      "repo",
			},
			Verification: artifactsv2.VerificationSource{
				ReportSchemaVersion: "1.0.0",
				RuleMetadata: map[string]artifactsv2.RuleMetadata{
					"CTX-UNK-001":   {RuleID: "CTX-UNK-001", MigrationState: "issue_native", MigrationReason: "native issue semantics"},
					"CTX-DES-001":   {RuleID: "CTX-DES-001", MigrationState: "issue_native", MigrationReason: "native issue semantics"},
					"CTX-TRUST-001": {RuleID: "CTX-TRUST-001", MigrationState: "issue_native", MigrationReason: "native issue semantics"},
				},
				IssueSeeds: []artifactsv2.IssueSeed{
					{
						RuleID:     "CTX-UNK-001",
						Title:      "Missing access control check",
						Source:     "rule",
						Category:   "bug",
						Severity:   "medium",
						Status:     "unknown",
						Confidence: 0.9,
						Quality:    1.0,
						File:       "auth/service.ts",
						Symbol:     "AuthorizeUser",
						StartLine:  10,
						EndLine:    12,
					},
					{
						RuleID:     "CTX-DES-001",
						Title:      "Layering violation across UI and domain",
						Source:     "agent",
						Category:   "design",
						Severity:   "high",
						Status:     "open",
						Confidence: 0.9,
						Quality:    1.0,
						File:       "checkout/design.ts",
						Symbol:     "composeCheckout",
						StartLine:  22,
						EndLine:    28,
					},
					{
						RuleID:     "CTX-TRUST-001",
						Title:      "Strongly evidenced security check",
						Source:     "rule",
						Category:   "security",
						Severity:   "high",
						Status:     "open",
						Confidence: 0.95,
						Quality:    1.0,
						File:       "storage/security.ts",
						Symbol:     "verifyPermissions",
						StartLine:  40,
						EndLine:    44,
					},
				},
			},
			EngineVersion: "verabase@dev",
		},
		Manifest: FixtureManifest{
			FixtureID:                     "context-selection-bounded",
			FixtureType:                   "context",
			ExpectedIssueCount:            3,
			ExpectedRuleIDs:               []string{"CTX-UNK-001", "CTX-DES-001", "CTX-TRUST-001"},
			ExpectedPartial:               &partial,
			ExpectedContextSelectionCount: &contextSelectionCount,
			ExpectedAgentCount:            &agentCount,
			ExpectedAgentKinds:            []string{"bug", "design", "security"},
			ExpectedBundleHashStable:      true,
		},
	}

	result, err := RunCompatFixture(fixture)
	if err != nil {
		t.Fatalf("RunCompatFixture(): %v", err)
	}
	if len(result.Bundle.Trace.ContextSelections) != 3 {
		t.Fatalf("expected 3 context selections, got %d", len(result.Bundle.Trace.ContextSelections))
	}
	if len(result.Bundle.Trace.Agents) != 3 {
		t.Fatalf("expected 3 planned agents, got %d", len(result.Bundle.Trace.Agents))
	}

	issuesByRule := make(map[string]artifactsv2.IssueCandidate)
	for _, candidate := range result.IssueCandidates {
		for _, ruleID := range candidate.RuleIDs {
			issuesByRule[ruleID] = candidate
		}
	}
	unknownIssue, ok := issuesByRule["CTX-UNK-001"]
	if !ok {
		t.Fatal("expected unknown issue candidate")
	}
	designIssue, ok := issuesByRule["CTX-DES-001"]
	if !ok {
		t.Fatal("expected design issue candidate")
	}
	trustedIssue, ok := issuesByRule["CTX-TRUST-001"]
	if !ok {
		t.Fatal("expected trusted issue candidate")
	}

	selectionByTrigger := make(map[string]artifactsv2.ContextSelectionRecord)
	for _, selection := range result.Bundle.Trace.ContextSelections {
		selectionByTrigger[selection.TriggerID] = selection
		if len(selection.SelectionTrace) == 0 {
			t.Fatalf("expected selection trace for trigger %q", selection.TriggerID)
		}
	}
	if _, ok := selectionByTrigger[unknownIssue.ID]; !ok {
		t.Fatalf("expected unknown issue %q to trigger bounded context selection", unknownIssue.ID)
	}
	if _, ok := selectionByTrigger[designIssue.ID]; !ok {
		t.Fatalf("expected design issue %q to trigger bounded context selection", designIssue.ID)
	}
	if _, ok := selectionByTrigger[trustedIssue.ID]; !ok {
		t.Fatalf("expected high-severity advisory issue %q to trigger bounded context selection", trustedIssue.ID)
	}
	if selectionByTrigger[unknownIssue.ID].SelectionTrace[0] != "trigger_reason:unknown_issue" {
		t.Fatalf("expected unknown issue to record trigger reason, got %#v", selectionByTrigger[unknownIssue.ID].SelectionTrace)
	}
	if selectionByTrigger[designIssue.ID].SelectionTrace[0] != "trigger_reason:high_severity_review" {
		t.Fatalf("expected design issue to record trigger reason, got %#v", selectionByTrigger[designIssue.ID].SelectionTrace)
	}
	if selectionByTrigger[trustedIssue.ID].SelectionTrace[0] != "trigger_reason:high_severity_review" {
		t.Fatalf("expected trusted issue to record high severity review trigger, got %#v", selectionByTrigger[trustedIssue.ID].SelectionTrace)
	}
}

func TestRunCompatFixture_CompletedAgentResultFeedsEvidenceAndTrace(t *testing.T) {
	t.Parallel()

	partial := false
	contextSelectionCount := 1
	agentCount := 1

	baseFixture := CompatFixture{
		Input: artifactsv2.CompatBuildInput{
			Scan: report.ScanReport{
				ScanSchemaVersion: "1.0.0",
				RepoPath:          "/tmp/repo",
				RepoName:          "github.com/acme/repo",
				CommitSHA:         "abc123def456",
				ScannedAt:         "2026-03-27T12:00:00Z",
				FileCount:         3,
				BoundaryMode:      "repo",
			},
			Verification: artifactsv2.VerificationSource{
				ReportSchemaVersion: "1.0.0",
				RuleMetadata: map[string]artifactsv2.RuleMetadata{
					"AGENT-SEC-001": {RuleID: "AGENT-SEC-001", MigrationState: "issue_native", MigrationReason: "native issue semantics"},
				},
				IssueSeeds: []artifactsv2.IssueSeed{{
					RuleID:     "AGENT-SEC-001",
					Title:      "Authorization gap in checkout flow",
					Source:     "rule",
					Category:   "security",
					Severity:   "high",
					Status:     "open",
					Confidence: 0.9,
					Quality:    1.0,
					File:       "checkout/auth.ts",
					Symbol:     "AuthorizeCheckout",
					StartLine:  15,
					EndLine:    22,
				}},
			},
			EngineVersion: "verabase@dev",
		},
		Manifest: FixtureManifest{
			FixtureID:                              "completed-agent-result",
			FixtureType:                            "context",
			ExpectedIssueCount:                     1,
			ExpectedRuleIDs:                        []string{"AGENT-SEC-001"},
			ExpectedPartial:                        &partial,
			ExpectedContextSelectionCount:          &contextSelectionCount,
			ExpectedContextSelectionTriggerRuleIDs: []string{"AGENT-SEC-001"},
			ExpectedAgentCount:                     &agentCount,
			ExpectedAgentKinds:                     []string{"security"},
			ExpectedAgentIssueTypes:                []string{"security_review"},
			ExpectedAgentTriggerReasons:            []string{"high_severity_review"},
			ExpectedAgentContracts: []PlannedAgentConstraint{
				{
					RuleID:        "AGENT-SEC-001",
					Kind:          "security",
					TriggerReason: "high_severity_review",
					Status:        "planned",
				},
			},
			ExpectedConfidenceConstraints: []ConfidenceConstraint{{
				RuleID:      "AGENT-SEC-001",
				Min:         floatPtr(0.75),
				Max:         floatPtr(0.90),
				Class:       "moderate",
				PolicyClass: "advisory",
			}},
			ExpectedBundleHashStable: true,
		},
	}

	initial, err := RunCompatFixture(baseFixture)
	if err != nil {
		t.Fatalf("RunCompatFixture(initial): %v", err)
	}
	if len(initial.Bundle.Trace.Agents) != 1 {
		t.Fatalf("expected 1 planned agent, got %#v", initial.Bundle.Trace.Agents)
	}

	taskID := initial.Bundle.Trace.Agents[0].ID
	withResult := baseFixture
	withResult.Manifest.ExpectedAgentContracts = []PlannedAgentConstraint{{
		RuleID:            "AGENT-SEC-001",
		Kind:              "security",
		TriggerReason:     "high_severity_review",
		Status:            "completed",
		OutputEvidenceIDs: []string{"ev-agent-completed-1"},
	}}
	withResult.Manifest.ExpectedConfidenceConstraints = []ConfidenceConstraint{{
		RuleID:      "AGENT-SEC-001",
		Min:         floatPtr(0.85),
		Max:         floatPtr(0.95),
		Class:       "high",
		PolicyClass: "advisory",
	}}
	withResult.Input.Verification.AgentResults = []artifactsv2.AgentResult{{
		TaskID:  taskID,
		Kind:    "security",
		Status:  "completed",
		IssueID: initial.Bundle.Trace.Agents[0].IssueID,
		EmittedEvidence: []artifactsv2.EvidenceRecord{{
			ID:              "ev-agent-completed-1",
			Kind:            "agent_assertion",
			Source:          "agent",
			ProducerID:      "agent:security",
			ProducerVersion: "1.0.0",
			FactQuality:     "heuristic",
			Locations:       []artifactsv2.LocationRef{{RepoRelPath: "checkout/auth.ts", StartLine: 15, EndLine: 22, SymbolID: "AuthorizeCheckout"}},
			Claims:          []string{"AGENT-SEC-001"},
		}},
	}}

	result, err := RunCompatFixture(withResult)
	if err != nil {
		t.Fatalf("RunCompatFixture(withResult): %v", err)
	}
	if len(result.Bundle.Trace.Agents) != 1 {
		t.Fatalf("expected 1 agent after overlay, got %#v", result.Bundle.Trace.Agents)
	}
	if result.Bundle.Trace.Agents[0].Status != "completed" {
		t.Fatalf("expected completed agent status, got %#v", result.Bundle.Trace.Agents[0])
	}
	if result.Bundle.Trace.Agents[0].Kind != "security" || result.Bundle.Trace.Agents[0].TriggerReason != "high_severity_review" {
		t.Fatalf("expected completed agent runtime contract to remain security/high_severity_review, got %#v", result.Bundle.Trace.Agents[0])
	}
	if len(result.Bundle.Trace.Agents[0].OutputEvidenceIDs) != 1 || result.Bundle.Trace.Agents[0].OutputEvidenceIDs[0] != "ev-agent-completed-1" {
		t.Fatalf("expected completed agent output evidence ids, got %#v", result.Bundle.Trace.Agents[0])
	}
	if len(result.Bundle.Report.Issues) != 1 || result.Bundle.Report.Issues[0].SourceSummary.AgentSources != 1 || !result.Bundle.Report.Issues[0].SourceSummary.MultiSource {
		t.Fatalf("expected completed agent result to affect issue source summary, got %#v", result.Bundle.Report.Issues)
	}
	if result.Bundle.Report.Issues[0].PolicyClass != "advisory" || result.Bundle.Report.Issues[0].ConfidenceClass != "high" {
		t.Fatalf("expected completed agent result to preserve advisory/high confidence contract, got %#v", result.Bundle.Report.Issues[0])
	}
	if len(result.Bundle.Trace.Derivations) != 1 {
		t.Fatalf("expected 1 derivation after completed agent overlay, got %#v", result.Bundle.Trace.Derivations)
	}
	found := false
	for _, record := range result.Bundle.Evidence.Evidence {
		if record.ID == "ev-agent-completed-1" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected completed agent evidence to appear in evidence artifact")
	}
	found = false
	for _, evID := range result.Bundle.Trace.Derivations[0].DerivedFromEvidenceIDs {
		if evID == "ev-agent-completed-1" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected derivation to include completed agent evidence, got %#v", result.Bundle.Trace.Derivations[0])
	}
}

func TestRunCompatFixture_FamilyBoundariesConfidenceAndAgentContract(t *testing.T) {
	t.Parallel()

	partial := false
	contextSelectionCount := 3
	agentCount := 3
	issueNativeCount := 1
	seedNativeCount := 1
	findingBridgedCount := 1

	fixture := CompatFixture{
		Input: artifactsv2.CompatBuildInput{
			Scan: report.ScanReport{
				ScanSchemaVersion: "1.0.0",
				RepoPath:          "/tmp/repo",
				RepoName:          "github.com/acme/repo",
				CommitSHA:         "abc123def456",
				ScannedAt:         "2026-03-27T12:00:00Z",
				FileCount:         3,
				BoundaryMode:      "repo",
			},
			Verification: artifactsv2.VerificationSource{
				ReportSchemaVersion: "1.0.0",
				RuleMetadata: map[string]artifactsv2.RuleMetadata{
					"FAM-SEC-001": {RuleID: "FAM-SEC-001", MigrationState: "issue_native", MigrationReason: "native issue semantics"},
					"FAM-DES-001": {RuleID: "FAM-DES-001", MigrationState: "seed_native", MigrationReason: "deterministic seed boundary remains under review"},
					"FAM-BUG-001": {RuleID: "FAM-BUG-001", MigrationState: "finding_bridged", MigrationReason: "compatibility finding boundary remains bridged"},
				},
				IssueSeeds: []artifactsv2.IssueSeed{
					{
						RuleID:     "FAM-SEC-001",
						Title:      "Authorization gap in security boundary",
						Source:     "rule",
						Category:   "security",
						Severity:   "high",
						Status:     "open",
						Confidence: 0.95,
						Quality:    1.0,
						File:       "core/security.ts",
						Symbol:     "authorizeAdmin",
						StartLine:  14,
						EndLine:    18,
					},
					{
						RuleID:     "FAM-DES-001",
						Title:      "Cross-layer dependency boundary",
						Source:     "rule",
						Category:   "design",
						Severity:   "high",
						Status:     "open",
						Confidence: 0.88,
						Quality:    1.0,
						File:       "core/design.ts",
						Symbol:     "composeLayers",
						StartLine:  32,
						EndLine:    38,
					},
					{
						RuleID:     "FAM-BUG-001",
						Title:      "Unchecked access at runtime boundary",
						Source:     "rule",
						Category:   "bug",
						Severity:   "medium",
						Status:     "unknown",
						Confidence: 0.8,
						Quality:    0.7,
						File:       "core/auth.ts",
						Symbol:     "checkAccess",
						StartLine:  51,
						EndLine:    54,
					},
				},
			},
			EngineVersion: "verabase@dev",
		},
		Manifest: FixtureManifest{
			FixtureID:                              "family-boundaries-confidence-agent-contract",
			FixtureType:                            "regression",
			ExpectedIssueCount:                     3,
			ExpectedRuleIDs:                        []string{"FAM-SEC-001", "FAM-DES-001", "FAM-BUG-001"},
			ExpectedPartial:                        &partial,
			ExpectedIssueNativeCount:               &issueNativeCount,
			ExpectedSeedNativeCount:                &seedNativeCount,
			ExpectedFindingBridgedCount:            &findingBridgedCount,
			ExpectedContextSelectionCount:          &contextSelectionCount,
			ExpectedContextSelectionTriggerRuleIDs: []string{"FAM-SEC-001", "FAM-DES-001", "FAM-BUG-001"},
			ExpectedAgentCount:                     &agentCount,
			ExpectedAgentKinds:                     []string{"bug", "design", "security"},
			ExpectedAgentIssueTypes:                []string{"bug_review", "design_review", "security_review"},
			ExpectedAgentTriggerReasons:            []string{"high_severity_review", "unknown_issue"},
			ExpectedAgentContracts: []PlannedAgentConstraint{
				{RuleID: "FAM-SEC-001", Kind: "security", TriggerReason: "high_severity_review", Status: "planned"},
				{RuleID: "FAM-DES-001", Kind: "design", TriggerReason: "high_severity_review", Status: "planned"},
				{RuleID: "FAM-BUG-001", Kind: "bug", TriggerReason: "unknown_issue", Status: "planned"},
			},
			ExpectedConfidenceConstraints: []ConfidenceConstraint{
				{RuleID: "FAM-SEC-001", Min: floatPtr(0.80), Max: floatPtr(0.86), Class: "moderate", PolicyClass: "advisory"},
				{RuleID: "FAM-DES-001", Min: floatPtr(0.75), Max: floatPtr(0.83), Class: "moderate", PolicyClass: "advisory"},
				{RuleID: "FAM-BUG-001", Min: floatPtr(0.40), Max: floatPtr(0.55), Class: "low", PolicyClass: "unknown_retained"},
			},
			ExpectedBundleHashStable: true,
		},
	}

	result, err := RunCompatFixture(fixture)
	if err != nil {
		t.Fatalf("RunCompatFixture(): %v", err)
	}
	if len(result.Bundle.Trace.ContextSelections) != 3 {
		t.Fatalf("expected 3 context selections, got %d", len(result.Bundle.Trace.ContextSelections))
	}
	if len(result.Bundle.Trace.Agents) != 3 {
		t.Fatalf("expected 3 planned agents, got %d", len(result.Bundle.Trace.Agents))
	}
	if len(result.IssueCandidates) != 3 {
		t.Fatalf("expected 3 issue candidates, got %d", len(result.IssueCandidates))
	}

	issuesByRule := make(map[string]artifactsv2.IssueCandidate)
	for _, candidate := range result.IssueCandidates {
		for _, ruleID := range candidate.RuleIDs {
			if existing, ok := issuesByRule[ruleID]; ok && existing.ID != candidate.ID {
				t.Fatalf("expected rule %q to remain in a single family boundary, got candidates %q and %q", ruleID, existing.ID, candidate.ID)
			}
			issuesByRule[ruleID] = candidate
		}
	}

	securityIssue, ok := issuesByRule["FAM-SEC-001"]
	if !ok {
		t.Fatal("expected security issue candidate")
	}
	designIssue, ok := issuesByRule["FAM-DES-001"]
	if !ok {
		t.Fatal("expected design issue candidate")
	}
	bugIssue, ok := issuesByRule["FAM-BUG-001"]
	if !ok {
		t.Fatal("expected bug issue candidate")
	}

	if securityIssue.Confidence <= designIssue.Confidence || designIssue.Confidence <= bugIssue.Confidence {
		t.Fatalf("expected confidence ordering security > design > bug, got %f > %f > %f", securityIssue.Confidence, designIssue.Confidence, bugIssue.Confidence)
	}
	if securityIssue.PolicyClass != "advisory" || designIssue.PolicyClass != "advisory" || bugIssue.PolicyClass != "unknown_retained" {
		t.Fatalf("unexpected policy classes: security=%q design=%q bug=%q", securityIssue.PolicyClass, designIssue.PolicyClass, bugIssue.PolicyClass)
	}
	if issue, ok := findIssueByID(result.Bundle.Report.Issues, securityIssue.ID); !ok || issue.ConfidenceClass != "moderate" {
		t.Fatalf("expected security issue confidence class moderate, got %#v", issue)
	}
	if issue, ok := findIssueByID(result.Bundle.Report.Issues, designIssue.ID); !ok || issue.ConfidenceClass != "moderate" {
		t.Fatalf("expected design issue confidence class moderate, got %#v", issue)
	}
	if issue, ok := findIssueByID(result.Bundle.Report.Issues, bugIssue.ID); !ok || issue.ConfidenceClass != "low" {
		t.Fatalf("expected bug issue confidence class low, got %#v", issue)
	}

	selectionByTrigger := make(map[string]artifactsv2.ContextSelectionRecord)
	for _, selection := range result.Bundle.Trace.ContextSelections {
		selectionByTrigger[selection.TriggerID] = selection
		if len(selection.SelectionTrace) == 0 {
			t.Fatalf("expected selection trace for trigger %q", selection.TriggerID)
		}
	}
	for _, issueID := range []string{securityIssue.ID, designIssue.ID, bugIssue.ID} {
		if _, ok := selectionByTrigger[issueID]; !ok {
			t.Fatalf("expected issue %q to trigger bounded context selection", issueID)
		}
	}
	if selectionByTrigger[securityIssue.ID].SelectionTrace[0] != "trigger_reason:high_severity_review" {
		t.Fatalf("expected security issue to record high severity trigger, got %#v", selectionByTrigger[securityIssue.ID].SelectionTrace)
	}
	if selectionByTrigger[designIssue.ID].SelectionTrace[0] != "trigger_reason:high_severity_review" {
		t.Fatalf("expected design issue to record high severity trigger, got %#v", selectionByTrigger[designIssue.ID].SelectionTrace)
	}
	if selectionByTrigger[bugIssue.ID].SelectionTrace[0] != "trigger_reason:unknown_issue" {
		t.Fatalf("expected bug issue to record unknown trigger, got %#v", selectionByTrigger[bugIssue.ID].SelectionTrace)
	}

	for _, agent := range result.Bundle.Trace.Agents {
		if agent.Status != "planned" {
			t.Fatalf("expected planned agent status, got %#v", agent)
		}
	}
}
