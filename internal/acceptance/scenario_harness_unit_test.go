package acceptance

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/verabase/code-verification-engine/internal/artifactsv2"
	"github.com/verabase/code-verification-engine/internal/report"
)

func TestRunScenarioFixture_Success(t *testing.T) {
	t.Parallel()

	fixtureDir := filepath.Clean(filepath.Join("..", "..", "testdata", "acceptance", "proof_grade_scenarios", "hiring-proof-backed"))
	golden, err := loadScenarioFixtureGolden(fixtureDir)
	if err != nil {
		t.Fatalf("loadScenarioFixtureGolden(): %v", err)
	}

	result, err := runScenarioFixture(t.Context(), fixtureDir, golden)
	if err != nil {
		t.Fatalf("runScenarioFixture(): %v", err)
	}
	if result == nil {
		t.Fatal("expected scenario fixture result")
	}
	if result.Bundle.Claims == nil || result.Bundle.ResumeInput == nil {
		t.Fatal("expected hiring scenario fixture to project claims and resume artifacts")
	}
}

func TestLoadScenarioFixtureGolden_ErrorPaths(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	if _, err := loadScenarioFixtureGolden(dir); err == nil {
		t.Fatal("expected missing golden file error")
	}

	bad := filepath.Join(dir, "scenario_golden.json")
	if err := os.WriteFile(bad, []byte("{"), 0o644); err != nil {
		t.Fatalf("WriteFile(): %v", err)
	}
	if _, err := loadScenarioFixtureGolden(dir); err == nil {
		t.Fatal("expected invalid json error")
	}

	if err := os.WriteFile(bad, []byte(`{"fixture_id":"   "}`), 0o644); err != nil {
		t.Fatalf("WriteFile(): %v", err)
	}
	if _, err := loadScenarioFixtureGolden(dir); err == nil {
		t.Fatal("expected missing fixture id error")
	}
}

func TestScenarioHarnessHelpers(t *testing.T) {
	t.Parallel()

	if !hasResumeVerifiedClaim([]artifactsv2.ResumeClaimStub{{ClaimID: "c-1"}}, "c-1") {
		t.Fatal("expected verified claim lookup to succeed")
	}
	if hasResumeVerifiedClaim([]artifactsv2.ResumeClaimStub{{ClaimID: "c-1"}}, "c-2") {
		t.Fatal("unexpected verified claim lookup hit")
	}

	bundle := artifactsv2.Bundle{
		OutsourceAcceptance: &artifactsv2.OutsourceAcceptanceArtifact{
			Requirements: []artifactsv2.OutsourceRequirementRow{{
				RequirementID:            "oa-1",
				VerificationClass:        artifactsv2.VerificationProofGrade,
				TrustClass:               artifactsv2.TrustClassMachineTrusted,
				ClaimIDs:                 []string{"claim-1"},
				SupportingEvidenceIDs:    []string{"ev-1"},
				ContradictoryEvidenceIDs: []string{"ev-x"},
			}},
		},
		PMAcceptance: &artifactsv2.PMAcceptanceArtifact{
			EngineeringRequirements: []artifactsv2.PMEngineeringRequirement{{
				RequirementID:            "pm-1",
				VerificationClass:        artifactsv2.VerificationStructuralInference,
				TrustClass:               artifactsv2.TrustClassAdvisory,
				ClaimIDs:                 []string{"claim-2"},
				SupportingEvidenceIDs:    []string{"ev-2"},
				ContradictoryEvidenceIDs: []string{"ev-y"},
			}},
		},
	}
	if !bundleHasContradictionEvidence(bundle) {
		t.Fatal("expected contradiction detection")
	}
	if !bundleHasProofGradeScenarioRows(bundle) {
		t.Fatal("expected proof-grade row detection")
	}
	if err := assertExpectedRuleClaimFamilies(bundle, map[string][]string{}); err != nil {
		t.Fatalf("assertExpectedRuleClaimFamilies(empty): %v", err)
	}
	if err := assertScenarioTrustSemantics(bundle); err != nil {
		t.Fatalf("assertScenarioTrustSemantics(valid): %v", err)
	}
}

func TestScenarioHarnessEvidenceAndProofRowDetectors(t *testing.T) {
	t.Parallel()

	if !bundleHasContradictionEvidence(artifactsv2.Bundle{
		Claims: &artifactsv2.ClaimsArtifact{
			Claims: []artifactsv2.ClaimRecord{{ContradictoryEvidenceIDs: []string{"ev-1"}}},
		},
	}) {
		t.Fatal("expected contradiction detection from claims")
	}
	if !bundleHasContradictionEvidence(artifactsv2.Bundle{
		PMAcceptance: &artifactsv2.PMAcceptanceArtifact{
			EngineeringRequirements: []artifactsv2.PMEngineeringRequirement{{ContradictoryEvidenceIDs: []string{"ev-1"}}},
		},
	}) {
		t.Fatal("expected contradiction detection from PM rows")
	}
	if !bundleHasProofGradeScenarioRows(artifactsv2.Bundle{
		PMAcceptance: &artifactsv2.PMAcceptanceArtifact{
			EngineeringRequirements: []artifactsv2.PMEngineeringRequirement{{VerificationClass: artifactsv2.VerificationProofGrade}},
		},
	}) {
		t.Fatal("expected proof-grade detection from PM rows")
	}
	if bundleHasProofGradeScenarioRows(artifactsv2.Bundle{
		PMAcceptance: &artifactsv2.PMAcceptanceArtifact{
			EngineeringRequirements: []artifactsv2.PMEngineeringRequirement{{VerificationClass: artifactsv2.VerificationStructuralInference}},
		},
	}) {
		t.Fatal("did not expect proof-grade detection from structural row")
	}
}

func TestScenarioHarnessRequirementAssertions(t *testing.T) {
	t.Parallel()

	outsource := artifactsv2.OutsourceAcceptanceArtifact{
		Requirements: []artifactsv2.OutsourceRequirementRow{{
			RequirementID:            "oa-1",
			Status:                   "failed",
			VerificationClass:        artifactsv2.VerificationStructuralInference,
			TrustClass:               artifactsv2.TrustClassAdvisory,
			ClaimIDs:                 []string{"claim-1"},
			SupportingEvidenceIDs:    []string{"ev-1"},
			ContradictoryEvidenceIDs: []string{"ev-x"},
		}},
	}
	if err := assertOutsourceRequirement(outsource, ScenarioRequirementExpectation{
		RequirementID:            "oa-1",
		Status:                   "failed",
		VerificationClass:        string(artifactsv2.VerificationStructuralInference),
		TrustClass:               string(artifactsv2.TrustClassAdvisory),
		RequireClaimIDs:          []string{"claim-1"},
		MinSupportingEvidence:    1,
		MinContradictoryEvidence: 1,
	}); err != nil {
		t.Fatalf("assertOutsourceRequirement(valid): %v", err)
	}
	if err := assertOutsourceRequirement(outsource, ScenarioRequirementExpectation{RequirementID: "oa-1", Status: "passed"}); err == nil {
		t.Fatal("expected outsource status mismatch")
	}

	pm := artifactsv2.PMAcceptanceArtifact{
		EngineeringRequirements: []artifactsv2.PMEngineeringRequirement{{
			RequirementID:            "pm-1",
			Status:                   "partial",
			VerificationClass:        artifactsv2.VerificationStructuralInference,
			TrustClass:               artifactsv2.TrustClassAdvisory,
			ClaimIDs:                 []string{"claim-2"},
			SupportingEvidenceIDs:    []string{"ev-2"},
			ContradictoryEvidenceIDs: []string{"ev-y"},
		}},
	}
	if err := assertPMRequirement(pm, ScenarioRequirementExpectation{
		RequirementID:            "pm-1",
		Status:                   "partial",
		VerificationClass:        string(artifactsv2.VerificationStructuralInference),
		TrustClass:               string(artifactsv2.TrustClassAdvisory),
		RequireClaimIDs:          []string{"claim-2"},
		MinSupportingEvidence:    1,
		MinContradictoryEvidence: 1,
	}); err != nil {
		t.Fatalf("assertPMRequirement(valid): %v", err)
	}
	if err := assertPMRequirement(pm, ScenarioRequirementExpectation{RequirementID: "pm-missing", Status: "partial"}); err == nil {
		t.Fatal("expected missing PM requirement")
	}
}

func TestScenarioHarnessBundleAssertions(t *testing.T) {
	t.Parallel()

	maxVerified := 0
	bundle := artifactsv2.Bundle{
		Claims: &artifactsv2.ClaimsArtifact{
			SchemaVersion: artifactsv2.ClaimsSchemaVersion,
			Repository:    artifactsv2.ClaimRepositoryRef{Path: "/repo", Commit: "abc123"},
			Claims: []artifactsv2.ClaimRecord{{
				ClaimID:               "claim-1",
				Title:                 "Claim 1",
				Category:              "security",
				ClaimType:             "implementation",
				Status:                "accepted",
				SupportLevel:          "verified",
				Confidence:            0.9,
				VerificationClass:     artifactsv2.VerificationProofGrade,
				SourceOrigins:         []string{"code_inferred"},
				SupportingEvidenceIDs: []string{"ev-1"},
				Reason:                "ok",
				ProjectionEligible:    true,
			}},
			Summary: artifactsv2.ClaimSummary{Verified: 1},
		},
		Profile: &artifactsv2.ProfileArtifact{
			SchemaVersion: "1.0.0",
			Repository:    artifactsv2.ClaimRepositoryRef{Path: "/repo", Commit: "abc123"},
			Highlights: []artifactsv2.CapabilityHighlight{{
				HighlightID:           "hl-1",
				Title:                 "Claim 1",
				SupportLevel:          "verified",
				ClaimIDs:              []string{"claim-1"},
				SupportingEvidenceIDs: []string{"ev-1"},
			}},
			ClaimIDs: []string{"claim-1"},
		},
		ResumeInput: &artifactsv2.ResumeInputArtifact{
			SchemaVersion: artifactsv2.ResumeInputSchemaVersion,
			Profile: artifactsv2.ProfileArtifact{
				SchemaVersion: "1.0.0",
				Repository:    artifactsv2.ClaimRepositoryRef{Path: "/repo", Commit: "abc123"},
				ClaimIDs:      []string{"claim-1"},
			},
			VerifiedClaims: []artifactsv2.ResumeClaimStub{{
				ClaimID:               "claim-1",
				Title:                 "Claim 1",
				SupportLevel:          "verified",
				Confidence:            0.9,
				SupportingEvidenceIDs: []string{"ev-1"},
			}},
			EvidenceReferences: []artifactsv2.EvidenceReference{{EvidenceID: "ev-1", ClaimIDs: []string{"claim-1"}}},
			SynthesisConstraints: artifactsv2.SynthesisConstraints{
				AllowUnsupportedClaims:        false,
				AllowClaimInvention:           false,
				AllowContradictionSuppression: false,
			},
		},
		OutsourceAcceptance: &artifactsv2.OutsourceAcceptanceArtifact{
			SchemaVersion:     artifactsv2.OutsourceAcceptanceSchemaVersion,
			Repository:        artifactsv2.AcceptanceRepositoryRef{Path: "/repo", Commit: "abc123"},
			TraceID:           "trace-1",
			AcceptanceProfile: "outsource-default",
			Summary:           artifactsv2.OutsourceAcceptanceSummary{Passed: 1, ProofGradeRows: 1},
			Requirements: []artifactsv2.OutsourceRequirementRow{{
				RequirementID:         "oa-1",
				Title:                 "Requirement",
				Category:              "security",
				Status:                "passed",
				VerificationClass:     artifactsv2.VerificationProofGrade,
				TrustClass:            artifactsv2.TrustClassMachineTrusted,
				Blocking:              true,
				AcceptanceIntent:      artifactsv2.AcceptanceIntentBinding,
				ClaimIDs:              []string{"claim-1"},
				SupportingEvidenceIDs: []string{"ev-1"},
				Reason:                "ok",
			}},
		},
		PMAcceptance: &artifactsv2.PMAcceptanceArtifact{
			SchemaVersion:     artifactsv2.PMAcceptanceSchemaVersion,
			Repository:        artifactsv2.AcceptanceRepositoryRef{Path: "/repo", Commit: "abc123"},
			TraceID:           "trace-1",
			AcceptanceProfile: "pm-default",
			Summary:           artifactsv2.PMAcceptanceSummary{Implemented: 1, ProofGradeRows: 1},
			EngineeringRequirements: []artifactsv2.PMEngineeringRequirement{{
				RequirementID:         "pm-1",
				Title:                 "Requirement",
				Category:              "security",
				Status:                "implemented",
				VerificationClass:     artifactsv2.VerificationProofGrade,
				TrustClass:            artifactsv2.TrustClassMachineTrusted,
				DeliveryScope:         "implemented",
				ClaimIDs:              []string{"claim-1"},
				SupportingEvidenceIDs: []string{"ev-1"},
				Reason:                "ok",
				FollowUpAction:        "none",
			}},
		},
		Trace: artifactsv2.TraceArtifact{
			SchemaVersion: artifactsv2.TraceSchemaVersion,
			EngineVersion: "verabase@dev",
			TraceID:       "trace-1",
			Repo:          "/repo",
			Commit:        "abc123",
			Timestamp:     "2026-03-28T00:00:00Z",
			ScanBoundary:  artifactsv2.TraceScanBoundary{Mode: "repo", IncludedFiles: 1},
			ConfidenceCalibration: &artifactsv2.ConfidenceCalibration{
				Version:                 "1.0.0",
				MachineTrustedThreshold: 0.85,
				UnknownCap:              0.5,
				AgentOnlyCap:            0.4,
				RuleFamilyBaselines: map[string]float64{
					"arch_layer":   0.9,
					"arch_pattern": 0.9,
					"fe_dep":       0.9,
					"sec_secret":   0.9,
					"sec_strict":   0.9,
					"test_auth":    0.9,
					"test_payment": 0.9,
				},
				OrderingRules: []string{"machine_trusted > advisory"},
			},
			MigrationSummary: &artifactsv2.RuleMigrationSummary{
				RuleClaimFamilies: map[string][]string{
					"SEC-001": {"security.hardcoded_secret_present"},
				},
			},
		},
		Report: artifactsv2.ReportArtifact{
			SchemaVersion: artifactsv2.ReportSchemaVersion,
			EngineVersion: "verabase@dev",
			Repo:          "/repo",
			Commit:        "abc123",
			Timestamp:     "2026-03-28T00:00:00Z",
			TraceID:       "trace-1",
			Summary:       artifactsv2.ReportSummary{OverallScore: 0.9, RiskLevel: "low"},
		},
		Evidence: artifactsv2.EvidenceArtifact{
			SchemaVersion: artifactsv2.EvidenceSchemaVersion,
			EngineVersion: "verabase@dev",
			Repo:          "/repo",
			Commit:        "abc123",
			Timestamp:     "2026-03-28T00:00:00Z",
			Evidence: []artifactsv2.EvidenceRecord{{
				ID:              "ev-1",
				Kind:            "rule_assertion",
				Source:          "rule",
				ProducerID:      "rule:SEC-001",
				ProducerVersion: "1.0.0",
				Repo:            "/repo",
				Commit:          "abc123",
				BoundaryHash:    "sha256:test",
				FactQuality:     "proof",
				Locations:       []artifactsv2.LocationRef{{RepoRelPath: "a.go", StartLine: 1, EndLine: 1}},
				Claims:          []string{"claim-1"},
				Payload:         map[string]any{"status": "pass"},
				CreatedAt:       "2026-03-28T00:00:00Z",
			}},
		},
		Skills: artifactsv2.SkillsArtifact{
			SchemaVersion: artifactsv2.SkillsSchemaVersion,
			EngineVersion: "verabase@dev",
			Repo:          "/repo",
			Commit:        "abc123",
			Timestamp:     "2026-03-28T00:00:00Z",
		},
		SummaryMD: "# Summary\n",
	}

	if err := assertScenarioFixtureGolden(bundle, ScenarioFixtureGolden{
		MinVerifiedClaims:         1,
		MinHighlights:             1,
		RequiredVerifiedClaimIDs:  []string{"claim-1"},
		RequireOutsourceArtifact:  true,
		RequirePMArtifact:         true,
		ExpectedRuleClaimFamilies: map[string][]string{"SEC-001": {"security.hardcoded_secret_present"}},
	}); err != nil {
		t.Fatalf("assertScenarioFixtureGolden(valid): %v", err)
	}

	if err := assertScenarioFixtureGolden(bundle, ScenarioFixtureGolden{MaxVerifiedClaims: &maxVerified}); err == nil {
		t.Fatal("expected max verified claims failure")
	}
}

func TestScenarioHarnessErrorBranches(t *testing.T) {
	t.Parallel()

	if _, err := initScenarioFixtureRepo(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("expected initScenarioFixtureRepo missing dir error")
	}
	if _, err := runScenarioFixture(t.Context(), filepath.Join(t.TempDir(), "missing"), ScenarioFixtureGolden{FixtureID: "missing"}); err == nil {
		t.Fatal("expected runScenarioFixture missing dir error")
	}

	outsource := artifactsv2.OutsourceAcceptanceArtifact{
		Requirements: []artifactsv2.OutsourceRequirementRow{{
			RequirementID:         "oa-1",
			Status:                "passed",
			VerificationClass:     artifactsv2.VerificationProofGrade,
			TrustClass:            artifactsv2.TrustClassMachineTrusted,
			ClaimIDs:              []string{"claim-1"},
			SupportingEvidenceIDs: []string{"ev-1"},
			Reason:                "ok",
		}},
	}
	for _, tc := range []ScenarioRequirementExpectation{
		{RequirementID: "missing", Status: "passed"},
		{RequirementID: "oa-1", Status: "failed"},
		{RequirementID: "oa-1", Status: "passed", VerificationClass: string(artifactsv2.VerificationStructuralInference)},
		{RequirementID: "oa-1", Status: "passed", TrustClass: string(artifactsv2.TrustClassAdvisory)},
		{RequirementID: "oa-1", Status: "passed", RequireClaimIDs: []string{"claim-x"}},
		{RequirementID: "oa-1", Status: "passed", MinSupportingEvidence: 2},
		{RequirementID: "oa-1", Status: "passed", MinContradictoryEvidence: 1},
	} {
		if err := assertOutsourceRequirement(outsource, tc); err == nil {
			t.Fatalf("expected outsource assertion error for %#v", tc)
		}
	}

	pm := artifactsv2.PMAcceptanceArtifact{
		EngineeringRequirements: []artifactsv2.PMEngineeringRequirement{{
			RequirementID:         "pm-1",
			Status:                "implemented",
			VerificationClass:     artifactsv2.VerificationProofGrade,
			TrustClass:            artifactsv2.TrustClassMachineTrusted,
			ClaimIDs:              []string{"claim-1"},
			SupportingEvidenceIDs: []string{"ev-1"},
			Reason:                "ok",
			FollowUpAction:        "none",
		}},
	}
	for _, tc := range []ScenarioRequirementExpectation{
		{RequirementID: "missing", Status: "implemented"},
		{RequirementID: "pm-1", Status: "partial"},
		{RequirementID: "pm-1", Status: "implemented", VerificationClass: string(artifactsv2.VerificationStructuralInference)},
		{RequirementID: "pm-1", Status: "implemented", TrustClass: string(artifactsv2.TrustClassAdvisory)},
		{RequirementID: "pm-1", Status: "implemented", RequireClaimIDs: []string{"claim-x"}},
		{RequirementID: "pm-1", Status: "implemented", MinSupportingEvidence: 2},
		{RequirementID: "pm-1", Status: "implemented", MinContradictoryEvidence: 1},
	} {
		if err := assertPMRequirement(pm, tc); err == nil {
			t.Fatalf("expected PM assertion error for %#v", tc)
		}
	}

	if bundleHasContradictionEvidence(artifactsv2.Bundle{}) {
		t.Fatal("expected no contradiction evidence in empty bundle")
	}
	if bundleHasProofGradeScenarioRows(artifactsv2.Bundle{}) {
		t.Fatal("expected no proof-grade rows in empty bundle")
	}

	if err := assertExpectedRuleClaimFamilies(artifactsv2.Bundle{}, map[string][]string{"SEC-001": {"claim"}}); err == nil {
		t.Fatal("expected missing migration summary error")
	}
	if err := assertExpectedRuleClaimFamilies(artifactsv2.Bundle{
		Trace: artifactsv2.TraceArtifact{
			MigrationSummary: &artifactsv2.RuleMigrationSummary{
				RuleClaimFamilies: map[string][]string{"SEC-001": {"other"}},
			},
		},
	}, map[string][]string{"SEC-001": {"claim"}}); err == nil {
		t.Fatal("expected migration summary mismatch")
	}

	if err := assertScenarioTrustSemantics(artifactsv2.Bundle{
		OutsourceAcceptance: &artifactsv2.OutsourceAcceptanceArtifact{
			Requirements: []artifactsv2.OutsourceRequirementRow{{
				RequirementID:     "oa-1",
				VerificationClass: artifactsv2.VerificationStructuralInference,
				TrustClass:        artifactsv2.TrustClassMachineTrusted,
			}},
		},
	}); err == nil {
		t.Fatal("expected outsource trust semantics error")
	}
	if err := assertScenarioTrustSemantics(artifactsv2.Bundle{
		PMAcceptance: &artifactsv2.PMAcceptanceArtifact{
			EngineeringRequirements: []artifactsv2.PMEngineeringRequirement{{
				RequirementID:     "pm-1",
				VerificationClass: artifactsv2.VerificationStructuralInference,
				TrustClass:        artifactsv2.TrustClassMachineTrusted,
			}},
		},
	}); err == nil {
		t.Fatal("expected PM trust semantics error")
	}
}

func TestInitScenarioFixtureRepo_SuccessCopiesFixtureContent(t *testing.T) {
	t.Parallel()

	fixtureDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(fixtureDir, "main.go"), []byte("package main\n"), 0o644); err != nil {
		t.Fatalf("WriteFile(main.go): %v", err)
	}
	if err := os.WriteFile(filepath.Join(fixtureDir, "scenario_golden.json"), []byte(`{"fixture_id":"fixture-a"}`), 0o644); err != nil {
		t.Fatalf("WriteFile(scenario_golden.json): %v", err)
	}

	repoDir, err := initScenarioFixtureRepo(fixtureDir)
	if err != nil {
		t.Fatalf("initScenarioFixtureRepo(): %v", err)
	}
	if _, err := os.Stat(filepath.Join(repoDir, "main.go")); err != nil {
		t.Fatalf("expected copied source file: %v", err)
	}
	if _, err := os.Stat(filepath.Join(repoDir, "scenario_golden.json")); !os.IsNotExist(err) {
		t.Fatalf("expected scenario_golden.json to be skipped, err=%v", err)
	}
	if _, err := os.Stat(filepath.Join(repoDir, ".git")); err != nil {
		t.Fatalf("expected initialized git repo: %v", err)
	}
}

func TestCompatRunnerAndDeterminismErrorBranches(t *testing.T) {
	t.Parallel()

	if _, err := RunFixture(Fixture{}); err == nil {
		t.Fatal("expected build failure for empty fixture")
	}

	fixture := Fixture{
		Input: artifactsv2.BuildInput{
			Scan: report.ScanReport{
				ScanSchemaVersion: "1.0.0",
				RepoPath:          "/tmp/repo",
				RepoName:          "github.com/acme/repo",
				CommitSHA:         "abc123def456",
				ScannedAt:         "2026-03-27T12:00:00Z",
				FileCount:         1,
				BoundaryMode:      "repo",
			},
			Verification: artifactsv2.VerificationSource{
				ReportSchemaVersion: "1.0.0",
				RuleMetadata: map[string]artifactsv2.RuleMetadata{
					"SEC-001": {RuleID: "SEC-001", MigrationState: "issue_native"},
				},
				IssueSeeds: []artifactsv2.IssueSeed{{
					RuleID:     "SEC-001",
					Title:      "Missing secret boundary",
					Source:     "rule",
					Category:   "security",
					Severity:   "high",
					Status:     "open",
					Confidence: 0.9,
					Quality:    1.0,
					File:       "service.ts",
					StartLine:  5,
					EndLine:    5,
				}},
			},
			EngineVersion: "verabase@dev",
		},
		Manifest: FixtureManifest{
			FixtureID:          "fixture-mismatch",
			FixtureType:        "micro",
			ExpectedIssueCount: 2,
		},
	}
	if _, err := RunFixture(fixture); err == nil {
		t.Fatal("expected manifest mismatch from fixture runner")
	}

	validFixture := fixture
	validFixture.Manifest.ExpectedIssueCount = 1
	result, err := RunFixture(validFixture)
	if err != nil {
		t.Fatalf("RunFixture(valid): %v", err)
	}

	invalidFirst := result.Bundle
	invalidFirst.Report.SchemaVersion = ""
	if err := AssertBundleDeterministic(invalidFirst, result.Bundle); err == nil {
		t.Fatal("expected invalid first bundle error")
	}

	invalidSecond := result.Bundle
	invalidSecond.Trace.SchemaVersion = ""
	if err := AssertBundleDeterministic(result.Bundle, invalidSecond); err == nil {
		t.Fatal("expected invalid second bundle error")
	}

	different := result.Bundle
	different.SummaryMD = "# changed\n"
	if err := AssertBundleDeterministic(result.Bundle, different); err == nil {
		t.Fatal("expected differing bundle hash error")
	}
}

func TestAssertScenarioFixtureGolden_ErrorBranches(t *testing.T) {
	t.Parallel()

	base := artifactsv2.Bundle{
		Report: artifactsv2.ReportArtifact{
			SchemaVersion: artifactsv2.ReportSchemaVersion,
			EngineVersion: "verabase@dev",
			Repo:          "/repo",
			Commit:        "abc123",
			Timestamp:     "2026-03-28T00:00:00Z",
			TraceID:       "trace-1",
			Summary:       artifactsv2.ReportSummary{OverallScore: 0.9, RiskLevel: "low"},
		},
		Evidence: artifactsv2.EvidenceArtifact{
			SchemaVersion: artifactsv2.EvidenceSchemaVersion,
			EngineVersion: "verabase@dev",
			Repo:          "/repo",
			Commit:        "abc123",
			Timestamp:     "2026-03-28T00:00:00Z",
			Evidence: []artifactsv2.EvidenceRecord{{
				ID:              "ev-1",
				Kind:            "rule_assertion",
				Source:          "rule",
				ProducerID:      "rule:SEC-001",
				ProducerVersion: "1.0.0",
				Repo:            "/repo",
				Commit:          "abc123",
				BoundaryHash:    "sha256:test",
				FactQuality:     "proof",
				Locations:       []artifactsv2.LocationRef{{RepoRelPath: "a.go", StartLine: 1, EndLine: 1}},
				Claims:          []string{"claim-1"},
				Payload:         map[string]any{"status": "pass"},
				CreatedAt:       "2026-03-28T00:00:00Z",
			}},
		},
		Skills: artifactsv2.SkillsArtifact{
			SchemaVersion: artifactsv2.SkillsSchemaVersion,
			EngineVersion: "verabase@dev",
			Repo:          "/repo",
			Commit:        "abc123",
			Timestamp:     "2026-03-28T00:00:00Z",
		},
		Trace: artifactsv2.TraceArtifact{
			SchemaVersion: artifactsv2.TraceSchemaVersion,
			EngineVersion: "verabase@dev",
			TraceID:       "trace-1",
			Repo:          "/repo",
			Commit:        "abc123",
			Timestamp:     "2026-03-28T00:00:00Z",
			ScanBoundary:  artifactsv2.TraceScanBoundary{Mode: "repo", IncludedFiles: 1},
			ConfidenceCalibration: &artifactsv2.ConfidenceCalibration{
				Version:                 "1.0.0",
				MachineTrustedThreshold: 0.85,
				UnknownCap:              0.5,
				AgentOnlyCap:            0.4,
				RuleFamilyBaselines: map[string]float64{
					"arch_layer": 0.9, "arch_pattern": 0.9, "fe_dep": 0.9, "sec_secret": 0.9, "sec_strict": 0.9, "test_auth": 0.9, "test_payment": 0.9,
				},
				OrderingRules: []string{"machine_trusted > advisory"},
			},
		},
		SummaryMD: "# Summary\n",
	}

	if err := assertScenarioFixtureGolden(base, ScenarioFixtureGolden{MinVerifiedClaims: 1}); err == nil {
		t.Fatal("expected missing claims/profile/resume error")
	}

	base.Claims = &artifactsv2.ClaimsArtifact{SchemaVersion: artifactsv2.ClaimsSchemaVersion, Repository: artifactsv2.ClaimRepositoryRef{Path: "/repo", Commit: "abc123"}}
	base.Profile = &artifactsv2.ProfileArtifact{SchemaVersion: "1.0.0", Repository: artifactsv2.ClaimRepositoryRef{Path: "/repo", Commit: "abc123"}}
	base.ResumeInput = &artifactsv2.ResumeInputArtifact{
		SchemaVersion: artifactsv2.ResumeInputSchemaVersion,
		Profile:       artifactsv2.ProfileArtifact{SchemaVersion: "1.0.0", Repository: artifactsv2.ClaimRepositoryRef{Path: "/repo", Commit: "abc123"}},
		SynthesisConstraints: artifactsv2.SynthesisConstraints{
			AllowUnsupportedClaims:        false,
			AllowClaimInvention:           false,
			AllowContradictionSuppression: false,
		},
	}
	if err := assertScenarioFixtureGolden(base, ScenarioFixtureGolden{RequireOutsourceArtifact: true}); err == nil {
		t.Fatal("expected missing outsource artifact error")
	}
	base.OutsourceAcceptance = &artifactsv2.OutsourceAcceptanceArtifact{
		SchemaVersion:     artifactsv2.OutsourceAcceptanceSchemaVersion,
		Repository:        artifactsv2.AcceptanceRepositoryRef{Path: "/repo", Commit: "abc123"},
		TraceID:           "trace-1",
		AcceptanceProfile: "outsource-default",
		Summary:           artifactsv2.OutsourceAcceptanceSummary{},
		Requirements:      []artifactsv2.OutsourceRequirementRow{},
	}
	if err := assertScenarioFixtureGolden(base, ScenarioFixtureGolden{RequirePMArtifact: true}); err == nil {
		t.Fatal("expected missing PM artifact error")
	}
	base.PMAcceptance = &artifactsv2.PMAcceptanceArtifact{
		SchemaVersion:           artifactsv2.PMAcceptanceSchemaVersion,
		Repository:              artifactsv2.AcceptanceRepositoryRef{Path: "/repo", Commit: "abc123"},
		TraceID:                 "trace-1",
		AcceptanceProfile:       "pm-default",
		Summary:                 artifactsv2.PMAcceptanceSummary{},
		EngineeringRequirements: []artifactsv2.PMEngineeringRequirement{},
	}
	if err := assertScenarioFixtureGolden(base, ScenarioFixtureGolden{RequireContradictionEvidence: true}); err == nil {
		t.Fatal("expected contradiction requirement error")
	}
	base.OutsourceAcceptance.Requirements = []artifactsv2.OutsourceRequirementRow{{
		RequirementID:         "oa-1",
		Title:                 "Requirement",
		Category:              "security",
		Status:                "passed",
		VerificationClass:     artifactsv2.VerificationProofGrade,
		TrustClass:            artifactsv2.TrustClassMachineTrusted,
		Blocking:              true,
		AcceptanceIntent:      artifactsv2.AcceptanceIntentBinding,
		ClaimIDs:              []string{"claim-1"},
		SupportingEvidenceIDs: []string{"ev-1"},
		Reason:                "ok",
	}}
	base.OutsourceAcceptance.Summary = artifactsv2.OutsourceAcceptanceSummary{Passed: 1, ProofGradeRows: 1}
	if err := assertScenarioFixtureGolden(base, ScenarioFixtureGolden{ForbidProofGradeScenarioRows: true}); err == nil {
		t.Fatal("expected forbid proof-grade rows error")
	}
}

func TestAssertScenarioFixtureGolden_AdditionalBranchCoverage(t *testing.T) {
	t.Parallel()

	bundle := artifactsv2.Bundle{
		Report: artifactsv2.ReportArtifact{
			SchemaVersion: artifactsv2.ReportSchemaVersion,
			EngineVersion: "verabase@dev",
			Repo:          "/repo",
			Commit:        "abc123",
			Timestamp:     "2026-03-28T00:00:00Z",
			TraceID:       "trace-1",
			Summary:       artifactsv2.ReportSummary{OverallScore: 0.9, RiskLevel: "low"},
		},
		Evidence: artifactsv2.EvidenceArtifact{
			SchemaVersion: artifactsv2.EvidenceSchemaVersion,
			EngineVersion: "verabase@dev",
			Repo:          "/repo",
			Commit:        "abc123",
			Timestamp:     "2026-03-28T00:00:00Z",
			Evidence: []artifactsv2.EvidenceRecord{{
				ID:              "ev-1",
				Kind:            "rule_assertion",
				Source:          "rule",
				ProducerID:      "rule:SEC-001",
				ProducerVersion: "1.0.0",
				Repo:            "/repo",
				Commit:          "abc123",
				BoundaryHash:    "sha256:test",
				FactQuality:     "proof",
				Locations:       []artifactsv2.LocationRef{{RepoRelPath: "a.go", StartLine: 1, EndLine: 1}},
				Claims:          []string{"claim-1"},
				Payload:         map[string]any{"status": "pass"},
				CreatedAt:       "2026-03-28T00:00:00Z",
			}},
		},
		Skills: artifactsv2.SkillsArtifact{
			SchemaVersion: artifactsv2.SkillsSchemaVersion,
			EngineVersion: "verabase@dev",
			Repo:          "/repo",
			Commit:        "abc123",
			Timestamp:     "2026-03-28T00:00:00Z",
		},
		Claims: &artifactsv2.ClaimsArtifact{
			SchemaVersion: artifactsv2.ClaimsSchemaVersion,
			Repository:    artifactsv2.ClaimRepositoryRef{Path: "/repo", Commit: "abc123"},
			Claims: []artifactsv2.ClaimRecord{{
				ClaimID:                  "claim-1",
				Title:                    "Claim 1",
				Category:                 "security",
				ClaimType:                "implementation",
				Status:                   "accepted",
				SupportLevel:             "verified",
				Confidence:               0.9,
				VerificationClass:        artifactsv2.VerificationProofGrade,
				SourceOrigins:            []string{"code_inferred"},
				SupportingEvidenceIDs:    []string{"ev-1"},
				ContradictoryEvidenceIDs: []string{"ev-1"},
				Reason:                   "ok",
				ProjectionEligible:       true,
			}},
			Summary: artifactsv2.ClaimSummary{Verified: 1},
		},
		Profile: &artifactsv2.ProfileArtifact{
			SchemaVersion: "1.0.0",
			Repository:    artifactsv2.ClaimRepositoryRef{Path: "/repo", Commit: "abc123"},
			Highlights: []artifactsv2.CapabilityHighlight{{
				HighlightID:           "hl-1",
				Title:                 "Claim 1",
				SupportLevel:          "verified",
				ClaimIDs:              []string{"claim-1"},
				SupportingEvidenceIDs: []string{"ev-1"},
			}},
			ClaimIDs: []string{"claim-1"},
		},
		ResumeInput: &artifactsv2.ResumeInputArtifact{
			SchemaVersion: artifactsv2.ResumeInputSchemaVersion,
			Profile: artifactsv2.ProfileArtifact{
				SchemaVersion: "1.0.0",
				Repository:    artifactsv2.ClaimRepositoryRef{Path: "/repo", Commit: "abc123"},
				ClaimIDs:      []string{"claim-1"},
			},
			VerifiedClaims: []artifactsv2.ResumeClaimStub{{
				ClaimID:               "claim-1",
				Title:                 "Claim 1",
				SupportLevel:          "verified",
				Confidence:            0.9,
				SupportingEvidenceIDs: []string{"ev-1"},
			}},
			EvidenceReferences: []artifactsv2.EvidenceReference{{EvidenceID: "ev-1", ClaimIDs: []string{"claim-1"}, ContradictoryClaimIDs: []string{"claim-1"}}},
			SynthesisConstraints: artifactsv2.SynthesisConstraints{
				AllowUnsupportedClaims:        false,
				AllowClaimInvention:           false,
				AllowContradictionSuppression: false,
			},
		},
		OutsourceAcceptance: &artifactsv2.OutsourceAcceptanceArtifact{
			SchemaVersion:     artifactsv2.OutsourceAcceptanceSchemaVersion,
			Repository:        artifactsv2.AcceptanceRepositoryRef{Path: "/repo", Commit: "abc123"},
			TraceID:           "trace-1",
			AcceptanceProfile: "outsource-default",
			Summary:           artifactsv2.OutsourceAcceptanceSummary{Passed: 1, ProofGradeRows: 1},
			Requirements: []artifactsv2.OutsourceRequirementRow{{
				RequirementID:            "oa-1",
				Title:                    "Requirement",
				Category:                 "security",
				Status:                   "passed",
				VerificationClass:        artifactsv2.VerificationProofGrade,
				TrustClass:               artifactsv2.TrustClassMachineTrusted,
				Blocking:                 true,
				AcceptanceIntent:         artifactsv2.AcceptanceIntentBinding,
				ClaimIDs:                 []string{"claim-1"},
				SupportingEvidenceIDs:    []string{"ev-1"},
				ContradictoryEvidenceIDs: []string{"ev-1"},
				Reason:                   "ok",
			}},
		},
		PMAcceptance: &artifactsv2.PMAcceptanceArtifact{
			SchemaVersion:     artifactsv2.PMAcceptanceSchemaVersion,
			Repository:        artifactsv2.AcceptanceRepositoryRef{Path: "/repo", Commit: "abc123"},
			TraceID:           "trace-1",
			AcceptanceProfile: "pm-default",
			Summary:           artifactsv2.PMAcceptanceSummary{Implemented: 1, ProofGradeRows: 1},
			EngineeringRequirements: []artifactsv2.PMEngineeringRequirement{{
				RequirementID:            "pm-1",
				Title:                    "Requirement",
				Category:                 "security",
				Status:                   "implemented",
				VerificationClass:        artifactsv2.VerificationProofGrade,
				TrustClass:               artifactsv2.TrustClassMachineTrusted,
				DeliveryScope:            "implemented",
				ClaimIDs:                 []string{"claim-1"},
				SupportingEvidenceIDs:    []string{"ev-1"},
				ContradictoryEvidenceIDs: []string{"ev-1"},
				Reason:                   "ok",
				FollowUpAction:           "none",
			}},
		},
		Trace: artifactsv2.TraceArtifact{
			SchemaVersion: artifactsv2.TraceSchemaVersion,
			EngineVersion: "verabase@dev",
			TraceID:       "trace-1",
			Repo:          "/repo",
			Commit:        "abc123",
			Timestamp:     "2026-03-28T00:00:00Z",
			ScanBoundary:  artifactsv2.TraceScanBoundary{Mode: "repo", IncludedFiles: 1},
			ConfidenceCalibration: &artifactsv2.ConfidenceCalibration{
				Version:                 "1.0.0",
				MachineTrustedThreshold: 0.85,
				UnknownCap:              0.5,
				AgentOnlyCap:            0.4,
				RuleFamilyBaselines: map[string]float64{
					"arch_layer": 0.9, "arch_pattern": 0.9, "fe_dep": 0.9, "sec_secret": 0.9, "sec_strict": 0.9, "test_auth": 0.9, "test_payment": 0.9,
				},
				OrderingRules: []string{"machine_trusted > advisory"},
			},
			MigrationSummary: &artifactsv2.RuleMigrationSummary{
				RuleClaimFamilies: map[string][]string{"SEC-001": {"claim-1"}},
			},
		},
		SummaryMD: "# Summary\n",
	}

	if err := assertScenarioFixtureGolden(bundle, ScenarioFixtureGolden{
		MinVerifiedClaims:            1,
		MinHighlights:                1,
		RequiredVerifiedClaimIDs:     []string{"claim-1"},
		RequireOutsourceArtifact:     true,
		RequirePMArtifact:            true,
		RequireContradictionEvidence: true,
		RequiredOutsourceRows: []ScenarioRequirementExpectation{{
			RequirementID:            "oa-1",
			Status:                   "passed",
			VerificationClass:        string(artifactsv2.VerificationProofGrade),
			TrustClass:               string(artifactsv2.TrustClassMachineTrusted),
			RequireClaimIDs:          []string{"claim-1"},
			MinSupportingEvidence:    1,
			MinContradictoryEvidence: 1,
		}},
		RequiredPMRows: []ScenarioRequirementExpectation{{
			RequirementID:            "pm-1",
			Status:                   "implemented",
			VerificationClass:        string(artifactsv2.VerificationProofGrade),
			TrustClass:               string(artifactsv2.TrustClassMachineTrusted),
			RequireClaimIDs:          []string{"claim-1"},
			MinSupportingEvidence:    1,
			MinContradictoryEvidence: 1,
		}},
		ExpectedRuleClaimFamilies: map[string][]string{"SEC-001": {"claim-1"}},
	}); err != nil {
		t.Fatalf("assertScenarioFixtureGolden(full valid): %v", err)
	}

	if err := assertScenarioFixtureGolden(bundle, ScenarioFixtureGolden{RequiredVerifiedClaimIDs: []string{"claim-x"}}); err == nil {
		t.Fatal("expected missing verified claim error")
	}
	if err := assertScenarioFixtureGolden(bundle, ScenarioFixtureGolden{ForbiddenVerifiedClaimIDs: []string{"claim-1"}}); err == nil {
		t.Fatal("expected forbidden verified claim error")
	}
	if err := assertScenarioFixtureGolden(bundle, ScenarioFixtureGolden{MinHighlights: 2}); err == nil {
		t.Fatal("expected highlight count error")
	}
	if err := assertScenarioFixtureGolden(bundle, ScenarioFixtureGolden{
		RequireOutsourceArtifact: true,
		RequiredOutsourceRows:    []ScenarioRequirementExpectation{{RequirementID: "oa-1", Status: "failed"}},
	}); err == nil {
		t.Fatal("expected required outsource row mismatch")
	}
	if err := assertScenarioFixtureGolden(bundle, ScenarioFixtureGolden{
		RequirePMArtifact: true,
		RequiredPMRows:    []ScenarioRequirementExpectation{{RequirementID: "pm-1", Status: "partial"}},
	}); err == nil {
		t.Fatal("expected required PM row mismatch")
	}
}
