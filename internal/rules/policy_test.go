package rules

import "testing"

func TestParseBytes_ValidatesPolicyMetadata(t *testing.T) {
	t.Parallel()

	_, err := ParseBytes([]byte(`
version: "0.1"
profile: "test"
rules:
  - id: "SEC-001"
    title: "Hardcoded credentials must not exist"
    category: "security"
    severity: "critical"
    languages: ["go"]
    type: "not_exists"
    target: "secret.hardcoded_credential"
    message: "no secrets"
    minimum_proof_fact_quality: "invalid"
`))
	if err == nil {
		t.Fatal("expected validation error")
	}
}

func TestEnforceRulePolicyMetadata_DowngradesVerifiedWhenProofFloorUnmet(t *testing.T) {
	t.Parallel()

	finding := Finding{
		RuleID:            "SEC-001",
		Status:            StatusFail,
		VerificationLevel: VerificationVerified,
		FactQualityFloor:  "structural",
	}
	EnforceRulePolicyMetadata(Rule{
		ID:                      "SEC-001",
		MinimumProofFactQuality: FactQualityProof,
	}, &finding)
	if finding.VerificationLevel != VerificationStrongInference {
		t.Fatalf("verification_level = %q, want %q", finding.VerificationLevel, VerificationStrongInference)
	}
	if len(finding.UnknownReasons) != 1 || finding.UnknownReasons[0] != unknownRuleMetadataProofFloorUnmet {
		t.Fatalf("unknown_reasons = %v", finding.UnknownReasons)
	}
}

func TestEnforceRulePolicyMetadata_DowngradesStructuralWhenFloorUnmet(t *testing.T) {
	t.Parallel()

	finding := Finding{
		RuleID:            "TEST-001",
		Status:            StatusPass,
		VerificationLevel: VerificationStrongInference,
		FactQualityFloor:  "heuristic",
	}
	EnforceRulePolicyMetadata(Rule{
		ID:                           "TEST-001",
		MinimumStructuralFactQuality: FactQualityStructural,
	}, &finding)
	if finding.VerificationLevel != VerificationWeakInference {
		t.Fatalf("verification_level = %q, want %q", finding.VerificationLevel, VerificationWeakInference)
	}
	if len(finding.UnknownReasons) != 1 || finding.UnknownReasons[0] != unknownRuleMetadataStructuralFloorUnmet {
		t.Fatalf("unknown_reasons = %v", finding.UnknownReasons)
	}
}

func TestFinalizeExecutionResult_EnforcesRulePolicyMetadataBeforeTrust(t *testing.T) {
	t.Parallel()

	rf := &RuleFile{
		Version: "0.1",
		Profile: "test",
		Rules: []Rule{{
			ID:                      "SEC-SECRET-001",
			Title:                   "No secrets",
			Category:                "security",
			Severity:                "critical",
			Languages:               []string{"go"},
			Type:                    "not_exists",
			Target:                  "secret.hardcoded_credential",
			Message:                 "no secrets",
			MatcherClass:            MatcherProof,
			MinimumProofFactQuality: FactQualityProof,
		}},
	}
	result := &ExecutionResult{
		Findings: []Finding{{
			RuleID:            "SEC-SECRET-001",
			Status:            StatusFail,
			VerificationLevel: VerificationVerified,
			FactQualityFloor:  "structural",
		}},
	}

	FinalizeExecutionResult(rf, result)

	if got := result.Findings[0].VerificationLevel; got != VerificationStrongInference {
		t.Fatalf("verification_level = %q, want %q", got, VerificationStrongInference)
	}
}
