package artifactsv2

import (
	"slices"
	"testing"

	"github.com/verabase/code-verification-engine/internal/report"
)

func TestComputeConfidenceBreakdownPenalizesPartialAndDegradedScans(t *testing.T) {
	t.Parallel()

	cluster := compatIssueCluster{
		File:       "service.ts",
		Symbol:     "getUser",
		Confidence: 0.9,
		Quality:    1.0,
		Sources:    []string{"rule"},
	}

	full := computeConfidenceBreakdown(cluster, report.ScanReport{BoundaryMode: "repo"}, VerificationSource{})
	partial := computeConfidenceBreakdown(cluster, report.ScanReport{BoundaryMode: "repo"}, VerificationSource{
		Partial:  true,
		Degraded: true,
		Errors:   []string{"analyzer degraded"},
	})

	if partial.Final >= full.Final {
		t.Fatalf("expected partial/degraded score %f to be lower than full score %f", partial.Final, full.Final)
	}
	if partial.BoundaryCompleteness >= full.BoundaryCompleteness {
		t.Fatalf("expected boundary completeness to drop under partial/degraded conditions")
	}
}

func TestComputeConfidenceBreakdownPenalizesAgentOnlySupport(t *testing.T) {
	t.Parallel()

	cluster := compatIssueCluster{
		File:       "service.ts",
		Symbol:     "getUser",
		Confidence: 0.9,
		Quality:    1.0,
		Sources:    []string{"agent"},
	}
	ruleCluster := cluster
	ruleCluster.Sources = []string{"rule"}

	agentOnly := computeConfidenceBreakdown(cluster, report.ScanReport{BoundaryMode: "repo"}, VerificationSource{})
	ruleOnly := computeConfidenceBreakdown(ruleCluster, report.ScanReport{BoundaryMode: "repo"}, VerificationSource{})

	if agentOnly.LLMPenalty <= ruleOnly.LLMPenalty {
		t.Fatalf("expected higher llm penalty for agent-only support")
	}
	if agentOnly.Final >= ruleOnly.Final {
		t.Fatalf("expected agent-only confidence %f to be lower than rule-only confidence %f", agentOnly.Final, ruleOnly.Final)
	}
	if agentOnly.RuleReliability >= ruleOnly.RuleReliability {
		t.Fatalf("expected agent-only rule reliability %f to be lower than rule-only %f", agentOnly.RuleReliability, ruleOnly.RuleReliability)
	}
}

func TestComputeConfidenceBreakdownRewardsMultiRuleSupport(t *testing.T) {
	t.Parallel()

	singleRule := compatIssueCluster{
		File:       "service.ts",
		Symbol:     "getUser",
		Confidence: 0.9,
		Quality:    1.0,
		Sources:    []string{"rule"},
		RuleIDs:    []string{"SEC-001"},
	}
	multiRule := singleRule
	multiRule.RuleIDs = []string{"SEC-001", "QUAL-001"}

	verification := VerificationSource{
		RuleMetadata: map[string]RuleMetadata{
			"SEC-001":  {RuleID: "SEC-001", MatcherClass: "proof_matcher", TrustClass: "machine_trusted", MigrationState: "issue_native"},
			"QUAL-001": {RuleID: "QUAL-001", MatcherClass: "proof_matcher", TrustClass: "machine_trusted", MigrationState: "issue_native"},
		},
	}

	single := computeConfidenceBreakdown(singleRule, report.ScanReport{BoundaryMode: "repo"}, verification)
	multi := computeConfidenceBreakdown(multiRule, report.ScanReport{BoundaryMode: "repo"}, verification)

	if multi.RuleReliability <= single.RuleReliability {
		t.Fatalf("expected multi-rule support reliability %f to be greater than single-rule %f", multi.RuleReliability, single.RuleReliability)
	}
}

func TestComputeConfidenceBreakdownUsesMigrationStateReliabilityOrdering(t *testing.T) {
	t.Parallel()

	cluster := compatIssueCluster{
		File:       "service.ts",
		Symbol:     "getUser",
		Confidence: 0.85,
		Quality:    0.95,
		Sources:    []string{"rule"},
	}
	verification := VerificationSource{
		RuleMetadata: map[string]RuleMetadata{
			"SEC-001":  {RuleID: "SEC-001", MatcherClass: "proof_matcher", TrustClass: "machine_trusted", MigrationState: "issue_native"},
			"ARCH-001": {RuleID: "ARCH-001", MatcherClass: "structural_matcher", TrustClass: "advisory", MigrationState: "seed_native"},
			"QUAL-001": {RuleID: "QUAL-001", MatcherClass: "heuristic_matcher", TrustClass: "advisory", MigrationState: "finding_bridged"},
		},
	}

	issueNative := cluster
	issueNative.RuleIDs = []string{"SEC-001"}

	seedNative := cluster
	seedNative.RuleIDs = []string{"ARCH-001"}

	findingBridged := cluster
	findingBridged.RuleIDs = []string{"QUAL-001"}

	issueNativeBreakdown := computeConfidenceBreakdown(issueNative, report.ScanReport{BoundaryMode: "repo"}, verification)
	seedNativeBreakdown := computeConfidenceBreakdown(seedNative, report.ScanReport{BoundaryMode: "repo"}, verification)
	findingBridgedBreakdown := computeConfidenceBreakdown(findingBridged, report.ScanReport{BoundaryMode: "repo"}, verification)

	if issueNativeBreakdown.RuleReliability <= seedNativeBreakdown.RuleReliability {
		t.Fatalf("expected issue_native reliability %f to be greater than seed_native %f", issueNativeBreakdown.RuleReliability, seedNativeBreakdown.RuleReliability)
	}
	if seedNativeBreakdown.RuleReliability <= findingBridgedBreakdown.RuleReliability {
		t.Fatalf("expected seed_native reliability %f to be greater than finding_bridged %f", seedNativeBreakdown.RuleReliability, findingBridgedBreakdown.RuleReliability)
	}
}

func TestCurrentConfidenceCalibrationExposesReleaseBlockingPolicy(t *testing.T) {
	t.Parallel()

	calibration := currentConfidenceCalibration()
	if calibration == nil {
		t.Fatal("expected calibration metadata")
	}
	if calibration.Version == "" {
		t.Fatal("expected calibration version")
	}
	if calibration.RuleFamilyBaselines["sec_secret"] <= calibration.RuleFamilyBaselines["arch_pattern"] {
		t.Fatalf("expected sec_secret baseline to exceed arch_pattern baseline, got %#v", calibration.RuleFamilyBaselines)
	}
	if !slices.Contains(calibration.OrderingRules, "issue_native > seed_native > finding_bridged") {
		t.Fatalf("expected migration ordering rule in calibration metadata, got %#v", calibration.OrderingRules)
	}
}

func TestCurrentConfidenceCalibrationCoversAllReleaseBlockingFamilies(t *testing.T) {
	t.Parallel()

	calibration := currentConfidenceCalibration()
	for _, family := range releaseBlockingRuleFamilies() {
		if _, ok := calibration.RuleFamilyBaselines[family]; !ok {
			t.Fatalf("expected calibration to include release-blocking family %q, got %#v", family, calibration.RuleFamilyBaselines)
		}
	}
}

func TestBuildArtifactsSetsComputedConfidenceBreakdown(t *testing.T) {
	t.Parallel()

	input := BuildInput{
		Scan: report.ScanReport{
			RepoName:     "github.com/acme/repo",
			CommitSHA:    "abc123",
			ScannedAt:    "2026-03-27T12:00:00Z",
			FileCount:    3,
			BoundaryMode: "repo",
		},
		Verification: VerificationSource{
			ReportSchemaVersion: "1.0.0",
			IssueSeeds: []IssueSeed{{
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
			Partial: true,
		},
		EngineVersion: "verabase@dev",
	}

	result, err := BuildArtifacts(input)
	if err != nil {
		t.Fatalf("BuildArtifacts(): %v", err)
	}
	if len(result.IssueCandidates) != 1 {
		t.Fatalf("expected 1 issue candidate, got %d", len(result.IssueCandidates))
	}
	breakdown := result.IssueCandidates[0].ConfidenceBreakdown
	if breakdown == nil {
		t.Fatalf("expected confidence breakdown")
	}
	if breakdown.BoundaryCompleteness >= 1.0 {
		t.Fatalf("expected partial scan to reduce boundary completeness, got %f", breakdown.BoundaryCompleteness)
	}
	if result.IssueCandidates[0].Confidence != breakdown.Final {
		t.Fatalf("expected issue confidence to equal breakdown final, got %f vs %f", result.IssueCandidates[0].Confidence, breakdown.Final)
	}
	if result.IssueCandidates[0].ConfidenceClass == "" || result.IssueCandidates[0].PolicyClass == "" {
		t.Fatalf("expected computed confidence/policy classes, got %q/%q", result.IssueCandidates[0].ConfidenceClass, result.IssueCandidates[0].PolicyClass)
	}
}

func TestComputeRuleMetadataReliabilityUsesRuleFamilyBaselineAndMigrationCap(t *testing.T) {
	t.Parallel()

	proofIssueNative := reliabilityForRuleMetadata(RuleMetadata{
		RuleID:         "SEC-001",
		MatcherClass:   "proof_matcher",
		TrustClass:     "machine_trusted",
		MigrationState: "issue_native",
	})
	proofSeedNative := reliabilityForRuleMetadata(RuleMetadata{
		RuleID:         "SEC-002",
		MatcherClass:   "proof_matcher",
		TrustClass:     "machine_trusted",
		MigrationState: "seed_native",
	})
	structuralSeedNative := reliabilityForRuleMetadata(RuleMetadata{
		RuleID:         "ARCH-001",
		MatcherClass:   "structural_matcher",
		TrustClass:     "advisory",
		MigrationState: "seed_native",
	})
	heuristicFindingBridged := reliabilityForRuleMetadata(RuleMetadata{
		RuleID:         "QUAL-001",
		MatcherClass:   "heuristic_matcher",
		TrustClass:     "advisory",
		MigrationState: "finding_bridged",
	})
	runtimeRequired := reliabilityForRuleMetadata(RuleMetadata{
		RuleID:         "AUTH-001",
		MatcherClass:   "attestation_matcher",
		TrustClass:     "human_or_runtime_required",
		MigrationState: "finding_bridged",
	})

	if proofIssueNative <= proofSeedNative {
		t.Fatalf("expected issue_native proof reliability %f to exceed seed_native proof %f", proofIssueNative, proofSeedNative)
	}
	if proofSeedNative <= structuralSeedNative {
		t.Fatalf("expected proof seed_native reliability %f to exceed structural seed_native %f", proofSeedNative, structuralSeedNative)
	}
	if structuralSeedNative <= heuristicFindingBridged {
		t.Fatalf("expected structural seed_native reliability %f to exceed heuristic finding_bridged %f", structuralSeedNative, heuristicFindingBridged)
	}
	if heuristicFindingBridged <= runtimeRequired {
		t.Fatalf("expected heuristic finding_bridged reliability %f to exceed runtime-required %f", heuristicFindingBridged, runtimeRequired)
	}
}

func TestComputeRuleMetadataReliabilityUsesCategoryFamilyBaseline(t *testing.T) {
	t.Parallel()

	security := reliabilityForRuleMetadata(RuleMetadata{
		RuleID:         "SEC-001",
		MatcherClass:   "proof_matcher",
		TrustClass:     "machine_trusted",
		MigrationState: "issue_native",
		Category:       "security",
	})
	architecture := reliabilityForRuleMetadata(RuleMetadata{
		RuleID:         "ARCH-001",
		MatcherClass:   "proof_matcher",
		TrustClass:     "machine_trusted",
		MigrationState: "issue_native",
		Category:       "architecture",
	})
	quality := reliabilityForRuleMetadata(RuleMetadata{
		RuleID:         "QUAL-001",
		MatcherClass:   "proof_matcher",
		TrustClass:     "machine_trusted",
		MigrationState: "issue_native",
		Category:       "quality",
	})

	if security <= architecture {
		t.Fatalf("expected security category reliability %f to exceed architecture %f", security, architecture)
	}
	if architecture <= quality {
		t.Fatalf("expected architecture category reliability %f to exceed quality %f", architecture, quality)
	}
}

func TestComputeRuleMetadataReliabilityUsesExplicitRuleFamilyBaselines(t *testing.T) {
	t.Parallel()

	secret := reliabilityForRuleMetadata(RuleMetadata{
		RuleID:         "SEC-SECRET-001",
		MatcherClass:   "proof_matcher",
		TrustClass:     "machine_trusted",
		MigrationState: "issue_native",
		Category:       "security",
	})
	strict := reliabilityForRuleMetadata(RuleMetadata{
		RuleID:         "SEC-STRICT-001",
		MatcherClass:   "structural_matcher",
		TrustClass:     "advisory",
		MigrationState: "seed_native",
		Category:       "security",
	})
	layer := reliabilityForRuleMetadata(RuleMetadata{
		RuleID:         "ARCH-LAYER-001",
		MatcherClass:   "structural_matcher",
		TrustClass:     "advisory",
		MigrationState: "issue_native",
		Category:       "architecture",
	})
	pattern := reliabilityForRuleMetadata(RuleMetadata{
		RuleID:         "ARCH-PATTERN-001",
		MatcherClass:   "structural_matcher",
		TrustClass:     "advisory",
		MigrationState: "seed_native",
		Category:       "architecture",
	})

	if secret <= strict {
		t.Fatalf("expected SEC-SECRET reliability %f to exceed SEC-STRICT %f", secret, strict)
	}
	if layer <= pattern {
		t.Fatalf("expected ARCH-LAYER reliability %f to exceed ARCH-PATTERN %f", layer, pattern)
	}
}

func TestComputeConfidenceBreakdownCapsUnknownConfidence(t *testing.T) {
	t.Parallel()

	cluster := compatIssueCluster{
		Status:     "unknown",
		File:       "service.ts",
		Symbol:     "getUser",
		Confidence: 0.9,
		Quality:    1.0,
		Sources:    []string{"rule"},
		RuleIDs:    []string{"SEC-001", "QUAL-001"},
	}

	breakdown := computeConfidenceBreakdown(cluster, report.ScanReport{BoundaryMode: "repo"}, VerificationSource{})
	if breakdown.Final > 0.55 {
		t.Fatalf("expected unknown issue confidence to be capped at 0.55, got %f", breakdown.Final)
	}
}

func TestComputeConfidenceBreakdownCapsAgentOnlyConfidence(t *testing.T) {
	t.Parallel()

	cluster := compatIssueCluster{
		Status:     "open",
		File:       "service.ts",
		Symbol:     "getUser",
		Confidence: 0.9,
		Quality:    1.0,
		Sources:    []string{"agent"},
		RuleIDs:    []string{"SEC-001", "QUAL-001"},
	}

	breakdown := computeConfidenceBreakdown(cluster, report.ScanReport{BoundaryMode: "repo"}, VerificationSource{})
	if breakdown.Final > 0.60 {
		t.Fatalf("expected agent-only confidence to be capped at 0.60, got %f", breakdown.Final)
	}
}

func TestComputeConfidenceBreakdownPenalizesContradictingEvidence(t *testing.T) {
	t.Parallel()

	cluster := compatIssueCluster{
		Status:             "open",
		File:               "service.ts",
		Symbol:             "getUser",
		Confidence:         0.9,
		Quality:            1.0,
		Sources:            []string{"rule"},
		RuleIDs:            []string{"SEC-001"},
		CounterEvidenceIDs: []string{"ev-counter-1", "ev-counter-2"},
	}

	breakdown := computeConfidenceBreakdown(cluster, report.ScanReport{BoundaryMode: "repo"}, VerificationSource{})
	if breakdown.ContradictionPenalty <= 0 {
		t.Fatalf("expected contradiction penalty to be applied")
	}
	if breakdown.Final >= 0.90 {
		t.Fatalf("expected contradiction penalty to reduce final confidence, got %f", breakdown.Final)
	}
}

func TestDeriveIssuePolicyClassMachineTrustedAndAdvisory(t *testing.T) {
	t.Parallel()

	machineTrusted := deriveIssuePolicyClass(compatIssueCluster{Status: "open"}, &ConfidenceBreakdown{
		RuleReliability:      0.90,
		EvidenceQuality:      1.00,
		BoundaryCompleteness: 1.00,
		ContextCompleteness:  1.00,
		SourceAgreement:      0.70,
		ContradictionPenalty: 0.00,
		LLMPenalty:           0.00,
		Final:                0.91,
	})
	if machineTrusted != "machine_trusted" {
		t.Fatalf("expected machine_trusted policy class, got %q", machineTrusted)
	}

	advisory := deriveIssuePolicyClass(compatIssueCluster{Status: "open"}, &ConfidenceBreakdown{
		RuleReliability:      0.68,
		EvidenceQuality:      0.70,
		BoundaryCompleteness: 1.00,
		ContextCompleteness:  0.75,
		SourceAgreement:      0.45,
		ContradictionPenalty: 0.00,
		LLMPenalty:           0.00,
		Final:                0.66,
	})
	if advisory != "advisory" {
		t.Fatalf("expected advisory policy class, got %q", advisory)
	}
}

func TestDeriveIssuePolicyClassRetainsUnknown(t *testing.T) {
	t.Parallel()

	policyClass := deriveIssuePolicyClass(compatIssueCluster{Status: "unknown"}, &ConfidenceBreakdown{
		RuleReliability:      0.90,
		EvidenceQuality:      1.00,
		BoundaryCompleteness: 1.00,
		ContextCompleteness:  1.00,
		SourceAgreement:      0.70,
		ContradictionPenalty: 0.00,
		LLMPenalty:           0.00,
		Final:                0.55,
	})
	if policyClass != "unknown_retained" {
		t.Fatalf("expected unknown_retained policy class, got %q", policyClass)
	}
}

func TestClassifyConfidenceThresholdBoundaries(t *testing.T) {
	t.Parallel()

	cases := []struct {
		score    float64
		expected string
	}{
		{score: 0.85, expected: "high"},
		{score: 0.84, expected: "moderate"},
		{score: 0.65, expected: "moderate"},
		{score: 0.64, expected: "low"},
		{score: 0.40, expected: "low"},
		{score: 0.39, expected: "weak"},
	}

	for _, tc := range cases {
		if got := classifyConfidence(tc.score); got != tc.expected {
			t.Fatalf("classifyConfidence(%0.2f) = %q, want %q", tc.score, got, tc.expected)
		}
	}
}
