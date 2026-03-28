package engine

import (
	"testing"

	"github.com/verabase/code-verification-engine/internal/rules"
)

func TestBuildRuleBackedScenarioClaims_FirstWaveFamilies(t *testing.T) {
	t.Parallel()

	rf := &rules.RuleFile{
		Version: "0.1",
		Profile: "test",
		Rules: []rules.Rule{
			{ID: "SEC-SECRET-001", MatcherClass: rules.MatcherProof},
			{ID: "TEST-AUTH-001", MatcherClass: rules.MatcherStructural},
		},
	}
	execResult := rules.ExecutionResult{
		Findings: []rules.Finding{
			{
				RuleID:            "SEC-SECRET-001",
				Status:            rules.StatusFail,
				Confidence:        rules.ConfidenceHigh,
				VerificationLevel: rules.VerificationVerified,
				TrustClass:        rules.TrustMachineTrusted,
				FactQualityFloor:  "proof",
				Evidence:          []rules.Evidence{{ID: "ev-secret-1", File: "config.go", LineStart: 10, LineEnd: 10}},
				Message:           "hardcoded secret detected",
			},
			{
				RuleID:            "TEST-AUTH-001",
				Status:            rules.StatusPass,
				Confidence:        rules.ConfidenceHigh,
				VerificationLevel: rules.VerificationVerified,
				TrustClass:        rules.TrustAdvisory,
				FactQualityFloor:  "structural",
				Evidence:          []rules.Evidence{{ID: "ev-test-1", File: "auth_test.go", LineStart: 1, LineEnd: 3}},
				Message:           "auth tests detected",
			},
		},
	}

	claims := buildRuleBackedScenarioClaims(execResult, rf)
	if len(claims) != 3 {
		t.Fatalf("claim count = %d, want 3", len(claims))
	}

	byID := map[string]bool{}
	for _, claim := range claims {
		byID[claim.ClaimID] = true
		switch claim.ClaimID {
		case "security.hardcoded_secret_present":
			if claim.VerificationClass != "proof_grade" {
				t.Fatalf("secret present verification_class = %q", claim.VerificationClass)
			}
		case "testing.auth_module_tests_present":
			if claim.VerificationClass != "structural_inference" {
				t.Fatalf("test present verification_class = %q", claim.VerificationClass)
			}
			if !claim.ProjectionEligible {
				t.Fatal("expected auth test claim to be projection eligible")
			}
		}
	}
	if !byID["security.hardcoded_secret_absent"] {
		t.Fatal("expected absent companion claim")
	}
}
