package artifactsv2

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestBuildClaimsProfileResumeArtifactsFixtureFamilies(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		input    ClaimsProjectionInput
		assertFn func(t *testing.T, artifacts ClaimsProjectionArtifacts)
	}{
		{
			name: "readme_overclaim",
			input: ClaimsProjectionInput{
				Repository: ClaimRepositoryRef{Path: "/repo", Commit: "abc123"},
				Claims: []ClaimRecord{
					{
						ClaimID:                  "architecture.readme_overclaim",
						Title:                    "README over-claims a capability",
						Category:                 "architecture",
						ClaimType:                "architecture",
						Status:                   "rejected",
						SupportLevel:             "unsupported",
						Confidence:               0.12,
						SourceOrigins:            []string{"readme_extracted"},
						SupportingEvidenceIDs:    []string{"ev-readme-1"},
						ContradictoryEvidenceIDs: []string{"ev-code-missing"},
						Reason:                   "README claims are not backed by code or tests.",
						ProjectionEligible:       false,
					},
				},
			},
			assertFn: func(t *testing.T, artifacts ClaimsProjectionArtifacts) {
				t.Helper()
				if artifacts.Claims.Summary.Unsupported != 1 {
					t.Fatalf("expected unsupported claim count 1, got %#v", artifacts.Claims.Summary)
				}
				if len(artifacts.Profile.Highlights) != 0 {
					t.Fatalf("unsupported claim must not create highlights: %#v", artifacts.Profile.Highlights)
				}
				if len(artifacts.ResumeInput.VerifiedClaims) != 0 || len(artifacts.ResumeInput.StronglySupportedClaims) != 0 {
					t.Fatalf("unsupported claim must not enter resume pools: %#v", artifacts.ResumeInput)
				}
			},
		},
		{
			name: "no_readme",
			input: ClaimsProjectionInput{
				Repository:   ClaimRepositoryRef{Path: "/repo", Commit: "abc123"},
				Technologies: []string{"go", "grpc", "go"},
				Claims: []ClaimRecord{
					{
						ClaimID:               "architecture.multi_agent_pipeline",
						Title:                 "Multi-agent verification pipeline exists",
						Category:              "architecture",
						ClaimType:             "architecture",
						Status:                "accepted",
						SupportLevel:          "verified",
						Confidence:            0.96,
						SourceOrigins:         []string{"code_inferred"},
						SupportingEvidenceIDs: []string{"ev-code-1"},
						Reason:                "Code-backed architecture claim.",
						ProjectionEligible:    true,
					},
					{
						ClaimID:               "security.maturity.test_strengthened",
						Title:                 "Security-sensitive flow is strengthened by tests",
						Category:              "security_maturity",
						ClaimType:             "security_maturity",
						Status:                "accepted",
						SupportLevel:          "strongly_supported",
						Confidence:            0.90,
						SourceOrigins:         []string{"code_inferred", "test_inferred"},
						SupportingEvidenceIDs: []string{"ev-sec-code", "ev-sec-test"},
						Reason:                "Security tests reinforce the implementation claim.",
						ProjectionEligible:    true,
					},
					{
						ClaimID:               "testing.maturity.baseline",
						Title:                 "Tests provide a baseline maturity signal",
						Category:              "testing_maturity",
						ClaimType:             "testing_maturity",
						Status:                "accepted",
						SupportLevel:          "supported",
						Confidence:            0.72,
						SourceOrigins:         []string{"code_inferred", "test_inferred"},
						SupportingEvidenceIDs: []string{"ev-test-1"},
						Reason:                "Baseline test evidence exists.",
						ProjectionEligible:    false,
					},
				},
			},
			assertFn: func(t *testing.T, artifacts ClaimsProjectionArtifacts) {
				t.Helper()
				if len(artifacts.Profile.Highlights) != 2 {
					t.Fatalf("expected 2 highlights, got %#v", artifacts.Profile.Highlights)
				}
				if !slices.Equal(artifacts.ResumeInput.TechnologySummary, []string{"go", "grpc"}) {
					t.Fatalf("unexpected technology summary: %#v", artifacts.ResumeInput.TechnologySummary)
				}
				if len(artifacts.ResumeInput.VerifiedClaims) != 1 || artifacts.ResumeInput.VerifiedClaims[0].ClaimID != "architecture.multi_agent_pipeline" {
					t.Fatalf("unexpected verified claim projection: %#v", artifacts.ResumeInput.VerifiedClaims)
				}
				if len(artifacts.ResumeInput.StronglySupportedClaims) != 1 || artifacts.ResumeInput.StronglySupportedClaims[0].ClaimID != "security.maturity.test_strengthened" {
					t.Fatalf("unexpected strongly supported claim projection: %#v", artifacts.ResumeInput.StronglySupportedClaims)
				}
				if !hasCapabilityArea(artifacts.Profile.CapabilityAreas, "architecture", "architecture.multi_agent_pipeline") {
					t.Fatalf("expected architecture capability area to include architecture claim: %#v", artifacts.Profile.CapabilityAreas)
				}
				if !hasCapabilityArea(artifacts.Profile.CapabilityAreas, "security_maturity", "security.maturity.test_strengthened") {
					t.Fatalf("expected security capability area to include strengthened claim: %#v", artifacts.Profile.CapabilityAreas)
				}
			},
		},
		{
			name: "code_backed_architecture",
			input: ClaimsProjectionInput{
				Repository: ClaimRepositoryRef{Path: "/repo", Commit: "abc123"},
				Claims: []ClaimRecord{
					{
						ClaimID:               "architecture.multi_agent_pipeline",
						Title:                 "Multi-agent verification pipeline exists",
						Category:              "architecture",
						ClaimType:             "architecture",
						Status:                "accepted",
						SupportLevel:          "verified",
						Confidence:            0.95,
						VerificationClass:     VerificationStructuralInference,
						SourceOrigins:         []string{"code_inferred"},
						SupportingEvidenceIDs: []string{"ev-code-1"},
						Reason:                "Code-backed architecture claim.",
						ProjectionEligible:    true,
					},
				},
			},
			assertFn: func(t *testing.T, artifacts ClaimsProjectionArtifacts) {
				t.Helper()
				if len(artifacts.Profile.Highlights) != 1 {
					t.Fatalf("expected one highlight, got %#v", artifacts.Profile.Highlights)
				}
				if artifacts.Profile.Highlights[0].SupportLevel != "verified" {
					t.Fatalf("expected verified highlight, got %#v", artifacts.Profile.Highlights[0])
				}
			},
		},
		{
			name: "heuristic_claim_excluded_from_resume_safe_projection",
			input: ClaimsProjectionInput{
				Repository: ClaimRepositoryRef{Path: "/repo", Commit: "abc123"},
				Claims: []ClaimRecord{
					{
						ClaimID:               "testing.auth_module_tests_present",
						Title:                 "Auth module has tests",
						Category:              "testing",
						ClaimType:             "testing_maturity",
						Status:                "accepted",
						SupportLevel:          "verified",
						Confidence:            0.80,
						VerificationClass:     VerificationHeuristicAdvisory,
						SourceOrigins:         []string{"rule_inferred"},
						SupportingEvidenceIDs: []string{"ev-1"},
						Reason:                "weakly matched evidence",
						ProjectionEligible:    true,
					},
				},
			},
			assertFn: func(t *testing.T, artifacts ClaimsProjectionArtifacts) {
				t.Helper()
				if len(artifacts.Profile.Highlights) != 0 {
					t.Fatalf("heuristic advisory claim must not appear in highlights: %#v", artifacts.Profile.Highlights)
				}
				if len(artifacts.ResumeInput.VerifiedClaims) != 0 {
					t.Fatalf("heuristic advisory claim must not appear in verified claims: %#v", artifacts.ResumeInput.VerifiedClaims)
				}
			},
		},
		{
			name: "test_strengthened_security",
			input: ClaimsProjectionInput{
				Repository: ClaimRepositoryRef{Path: "/repo", Commit: "abc123"},
				Claims: []ClaimRecord{
					{
						ClaimID:               "security.maturity.code_only",
						Title:                 "Security-sensitive flow exists",
						Category:              "security_maturity",
						ClaimType:             "security_maturity",
						Status:                "accepted",
						SupportLevel:          "supported",
						Confidence:            0.71,
						SourceOrigins:         []string{"code_inferred"},
						SupportingEvidenceIDs: []string{"ev-sec-code"},
						Reason:                "Code only support.",
						ProjectionEligible:    false,
					},
					{
						ClaimID:               "security.maturity.test_strengthened",
						Title:                 "Security-sensitive flow is strengthened by tests",
						Category:              "security_maturity",
						ClaimType:             "security_maturity",
						Status:                "accepted",
						SupportLevel:          "strongly_supported",
						Confidence:            0.92,
						SourceOrigins:         []string{"code_inferred", "test_inferred"},
						SupportingEvidenceIDs: []string{"ev-sec-code", "ev-sec-test"},
						Reason:                "Regression tests strengthen the maturity claim.",
						ProjectionEligible:    true,
					},
				},
			},
			assertFn: func(t *testing.T, artifacts ClaimsProjectionArtifacts) {
				t.Helper()
				if len(artifacts.Profile.Highlights) != 1 || artifacts.Profile.Highlights[0].ClaimIDs[0] != "security.maturity.test_strengthened" {
					t.Fatalf("expected only strengthened security claim to be highlighted: %#v", artifacts.Profile.Highlights)
				}
				if len(artifacts.ResumeInput.StronglySupportedClaims) != 1 || artifacts.ResumeInput.StronglySupportedClaims[0].ClaimID != "security.maturity.test_strengthened" {
					t.Fatalf("expected only strengthened claim in strongly supported pool: %#v", artifacts.ResumeInput.StronglySupportedClaims)
				}
			},
		},
		{
			name: "eval_backed_quality",
			input: ClaimsProjectionInput{
				Repository: ClaimRepositoryRef{Path: "/repo", Commit: "abc123"},
				Claims: []ClaimRecord{
					{
						ClaimID:               "evaluation.ai_quality",
						Title:                 "Eval-backed AI quality gating exists",
						Category:              "evaluation_maturity",
						ClaimType:             "evaluation_maturity",
						Status:                "accepted",
						SupportLevel:          "strongly_supported",
						Confidence:            0.88,
						SourceOrigins:         []string{"eval_inferred", "code_inferred"},
						SupportingEvidenceIDs: []string{"ev-eval-1", "ev-code-3"},
						Reason:                "Eval assets and code paths jointly support quality gating.",
						ProjectionEligible:    true,
					},
				},
			},
			assertFn: func(t *testing.T, artifacts ClaimsProjectionArtifacts) {
				t.Helper()
				if len(artifacts.Profile.Highlights) != 1 || artifacts.Profile.Highlights[0].SupportLevel != "strongly_supported" {
					t.Fatalf("expected one strongly supported eval-backed highlight: %#v", artifacts.Profile.Highlights)
				}
			},
		},
		{
			name: "contradiction_case",
			input: ClaimsProjectionInput{
				Repository: ClaimRepositoryRef{Path: "/repo", Commit: "abc123"},
				Claims: []ClaimRecord{
					{
						ClaimID:                  "docs.code_contradiction",
						Title:                    "Docs claim a feature that code contradicts",
						Category:                 "operational_maturity",
						ClaimType:                "operational_maturity",
						Status:                   "downgraded",
						SupportLevel:             "contradicted",
						Confidence:               0.10,
						SourceOrigins:            []string{"doc_extracted", "code_inferred"},
						SupportingEvidenceIDs:    []string{"ev-doc-1"},
						ContradictoryEvidenceIDs: []string{"ev-code-1"},
						Reason:                   "Stronger code evidence contradicts the docs claim.",
						ProjectionEligible:       false,
					},
				},
			},
			assertFn: func(t *testing.T, artifacts ClaimsProjectionArtifacts) {
				t.Helper()
				if len(artifacts.Profile.Highlights) != 0 {
					t.Fatalf("contradicted claim must not create highlights: %#v", artifacts.Profile.Highlights)
				}
				if len(artifacts.ResumeInput.VerifiedClaims) != 0 || len(artifacts.ResumeInput.StronglySupportedClaims) != 0 {
					t.Fatalf("contradicted claim must not be projected into resume pools: %#v", artifacts.ResumeInput)
				}
				if len(artifacts.ResumeInput.EvidenceReferences) == 0 {
					t.Fatal("expected contradiction evidence references to be retained")
				}
			},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			artifacts, err := BuildClaimsProfileResumeArtifacts(tc.input)
			if err != nil {
				t.Fatalf("BuildClaimsProfileResumeArtifacts(): %v", err)
			}
			if err := ValidateClaimsProfileResumeArtifacts(artifacts); err != nil {
				t.Fatalf("ValidateClaimsProfileResumeArtifacts(): %v", err)
			}
			tc.assertFn(t, artifacts)
		})
	}
}

func TestWriteClaimsProfileResumeArtifactsWritesAllOutputs(t *testing.T) {
	t.Parallel()

	input := ClaimsProjectionInput{
		Repository: ClaimRepositoryRef{Path: "/repo", Commit: "abc123"},
		Claims: []ClaimRecord{
			{
				ClaimID:               "architecture.multi_agent_pipeline",
				Title:                 "Multi-agent verification pipeline exists",
				Category:              "architecture",
				ClaimType:             "architecture",
				Status:                "accepted",
				SupportLevel:          "verified",
				Confidence:            0.95,
				SourceOrigins:         []string{"code_inferred"},
				SupportingEvidenceIDs: []string{"ev-1"},
				Reason:                "Code-backed architecture claim.",
				ProjectionEligible:    true,
			},
		},
	}
	artifacts, err := BuildClaimsProfileResumeArtifacts(input)
	if err != nil {
		t.Fatalf("BuildClaimsProfileResumeArtifacts(): %v", err)
	}
	dir := t.TempDir()
	if err := WriteClaimsProfileResumeArtifacts(dir, artifacts); err != nil {
		t.Fatalf("WriteClaimsProfileResumeArtifacts(): %v", err)
	}
	for _, name := range []string{"claims.json", "profile.json", "resume_input.json"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatalf("expected %s to exist: %v", name, err)
		}
	}

	var profile ProfileArtifact
	data, err := os.ReadFile(filepath.Join(dir, "profile.json"))
	if err != nil {
		t.Fatalf("ReadFile(profile.json): %v", err)
	}
	if err := json.Unmarshal(data, &profile); err != nil {
		t.Fatalf("Unmarshal(profile.json): %v", err)
	}
	if len(profile.Highlights) != 1 {
		t.Fatalf("expected one highlight, got %d", len(profile.Highlights))
	}
}

func hasCapabilityArea(areas []CapabilityArea, areaID, claimID string) bool {
	for _, area := range areas {
		if area.AreaID == areaID && slices.Contains(area.ClaimIDs, claimID) {
			return true
		}
	}
	return false
}
