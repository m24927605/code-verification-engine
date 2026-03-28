package acceptance

import (
	"testing"

	"github.com/verabase/code-verification-engine/internal/artifactsv2"
)

func TestScenarioAcceptanceProjectionFixtures(t *testing.T) {
	t.Parallel()

	claims := &artifactsv2.ClaimsArtifact{
		SchemaVersion: artifactsv2.ClaimsSchemaVersion,
		Repository:    artifactsv2.ClaimRepositoryRef{Path: "/repo", Commit: "abc123"},
		Claims: []artifactsv2.ClaimRecord{
			{
				ClaimID:               "security.hardcoded_secret_present",
				Title:                 "Hardcoded secret literals are present",
				Category:              "security",
				ClaimType:             "implementation",
				Status:                "accepted",
				SupportLevel:          "verified",
				Confidence:            0.99,
				VerificationClass:     artifactsv2.VerificationProofGrade,
				SupportingEvidenceIDs: []string{"ev-secret-1"},
				Reason:                "hardcoded secret evidence detected",
			},
			{
				ClaimID:               "testing.auth_module_tests_present",
				Title:                 "Authentication module has tests",
				Category:              "testing",
				ClaimType:             "testing_maturity",
				Status:                "accepted",
				SupportLevel:          "strongly_supported",
				Confidence:            0.90,
				VerificationClass:     artifactsv2.VerificationStructuralInference,
				SupportingEvidenceIDs: []string{"ev-test-1"},
				Reason:                "test evidence detected",
			},
		},
	}

	outsource, pm, err := artifactsv2.BuildScenarioAcceptanceArtifacts(artifactsv2.ScenarioAcceptanceBuildInput{
		RepoIdentity: "/repo",
		Commit:       "abc123",
		TraceID:      "trace-1",
		Claims:       claims,
		Options: artifactsv2.ScenarioBuildOptions{
			OutsourceAcceptanceProfile: "outsource-backend-api",
			PMAcceptanceProfile:        "pm-engineering-default",
		},
	})
	if err != nil {
		t.Fatalf("BuildScenarioAcceptanceArtifacts(): %v", err)
	}
	if outsource == nil || pm == nil {
		t.Fatal("expected scenario artifacts")
	}
	if outsource.Summary.Failed != 1 || outsource.Summary.Unknown != 1 {
		t.Fatalf("unexpected outsource summary: %#v", outsource.Summary)
	}
	if pm.Summary.Blocked != 1 || pm.Summary.Partial != 1 {
		t.Fatalf("unexpected pm summary: %#v", pm.Summary)
	}
}
