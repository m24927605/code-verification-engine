package rules

import "testing"

func TestParseRuleMetadataFields(t *testing.T) {
	data := []byte(`
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
    message: "No hardcoded credentials."
    minimum_proof_fact_quality: "proof"
    minimum_structural_fact_quality: "structural"
    exhaustive_negative: true
    scenario_applicability:
      hiring: true
      outsource_acceptance: true
      pm_acceptance: false
    acceptance_intent: "negative_exhaustive_check"
`)
	rf, err := ParseBytes(data)
	if err != nil {
		t.Fatalf("ParseBytes(): %v", err)
	}
	if len(rf.Rules) != 1 {
		t.Fatalf("len(rf.Rules) = %d, want 1", len(rf.Rules))
	}
	r := rf.Rules[0]
	if r.MinimumProofFactQuality != FactQualityProof {
		t.Fatalf("minimum_proof_fact_quality = %q, want %q", r.MinimumProofFactQuality, FactQualityProof)
	}
	if r.MinimumStructuralFactQuality != FactQualityStructural {
		t.Fatalf("minimum_structural_fact_quality = %q, want %q", r.MinimumStructuralFactQuality, FactQualityStructural)
	}
	if !r.ExhaustiveNegative {
		t.Fatal("expected exhaustive_negative to be true")
	}
	if r.ScenarioApplicability == nil {
		t.Fatal("expected scenario_applicability to be non-nil")
	}
	if !r.ScenarioApplicability.Hiring || !r.ScenarioApplicability.OutsourceAcceptance || r.ScenarioApplicability.PMAcceptance {
		t.Fatalf("unexpected scenario_applicability value: %+v", r.ScenarioApplicability)
	}
	if r.AcceptanceIntent != AcceptanceIntentNegativeExhaustive {
		t.Fatalf("acceptance_intent = %q, want %q", r.AcceptanceIntent, AcceptanceIntentNegativeExhaustive)
	}
}

func TestValidateRuleMetadataFields(t *testing.T) {
	rf := &RuleFile{
		Version: "0.1",
		Profile: "test",
		Rules: []Rule{{
			ID: "SEC-001", Title: "Hardcoded credentials must not exist",
			Category: "security", Severity: "critical",
			Languages: []string{"go"}, Type: "not_exists",
			Target: "secret.hardcoded_credential", Message: "No hardcoded credentials.",
			MinimumProofFactQuality:      FactQualityProof,
			MinimumStructuralFactQuality: FactQualityStructural,
			ExhaustiveNegative:           true,
			ScenarioApplicability: &ScenarioApplicability{
				Hiring: true, OutsourceAcceptance: true, PMAcceptance: true,
			},
			AcceptanceIntent: AcceptanceIntentNegativeExhaustive,
		}},
	}
	if err := Validate(rf); err != nil {
		t.Fatalf("Validate(): %v", err)
	}
}

func TestValidateBackwardCompatibleWithoutNewMetadata(t *testing.T) {
	rf := &RuleFile{
		Version: "0.1",
		Profile: "test",
		Rules: []Rule{{
			ID: "SEC-001", Title: "Hardcoded credentials must not exist",
			Category: "security", Severity: "critical",
			Languages: []string{"go"}, Type: "not_exists",
			Target: "secret.hardcoded_credential", Message: "No hardcoded credentials.",
		}},
	}
	if err := Validate(rf); err != nil {
		t.Fatalf("Validate() should remain backward-compatible without new metadata: %v", err)
	}
}

func TestValidateRejectsInvalidFactQualityMetadata(t *testing.T) {
	rf := &RuleFile{
		Version: "0.1",
		Profile: "test",
		Rules: []Rule{{
			ID: "SEC-001", Title: "Hardcoded credentials must not exist",
			Category: "security", Severity: "critical",
			Languages: []string{"go"}, Type: "not_exists",
			Target: "secret.hardcoded_credential", Message: "No hardcoded credentials.",
			MinimumProofFactQuality:      FactQuality("invalid"),
			MinimumStructuralFactQuality: FactQualityStructural,
		}},
	}
	if err := Validate(rf); err == nil {
		t.Fatal("expected validation error for invalid minimum_proof_fact_quality")
	}
}

func TestValidateRejectsInvalidScenarioApplicability(t *testing.T) {
	rf := &RuleFile{
		Version: "0.1",
		Profile: "test",
		Rules: []Rule{{
			ID: "SEC-001", Title: "Hardcoded credentials must not exist",
			Category: "security", Severity: "critical",
			Languages: []string{"go"}, Type: "not_exists",
			Target: "secret.hardcoded_credential", Message: "No hardcoded credentials.",
			ScenarioApplicability: &ScenarioApplicability{},
		}},
	}
	if err := Validate(rf); err == nil {
		t.Fatal("expected validation error for empty scenario_applicability")
	}
}

func TestValidateRejectsInvalidAcceptanceIntent(t *testing.T) {
	rf := &RuleFile{
		Version: "0.1",
		Profile: "test",
		Rules: []Rule{{
			ID: "SEC-001", Title: "Hardcoded credentials must not exist",
			Category: "security", Severity: "critical",
			Languages: []string{"go"}, Type: "not_exists",
			Target: "secret.hardcoded_credential", Message: "No hardcoded credentials.",
			AcceptanceIntent: AcceptanceIntent("bogus"),
		}},
	}
	if err := Validate(rf); err == nil {
		t.Fatal("expected validation error for invalid acceptance_intent")
	}
}

func TestValidateRejectsWeakerProofFloorThanStructuralFloor(t *testing.T) {
	rf := &RuleFile{
		Version: "0.1",
		Profile: "test",
		Rules: []Rule{{
			ID: "SEC-001", Title: "Hardcoded credentials must not exist",
			Category: "security", Severity: "critical",
			Languages: []string{"go"}, Type: "not_exists",
			Target: "secret.hardcoded_credential", Message: "No hardcoded credentials.",
			MinimumProofFactQuality:      FactQualityStructural,
			MinimumStructuralFactQuality: FactQualityProof,
		}},
	}
	if err := Validate(rf); err == nil {
		t.Fatal("expected validation error for inverted fact quality floors")
	}
}

func TestValidateRejectsExhaustiveNegativeOnNonNegativeRule(t *testing.T) {
	rf := &RuleFile{
		Version: "0.1",
		Profile: "test",
		Rules: []Rule{{
			ID: "SEC-001", Title: "JWT authentication must exist",
			Category: "security", Severity: "high",
			Languages: []string{"go"}, Type: "exists",
			Target: "auth.jwt_middleware", Message: "JWT auth must exist.",
			ExhaustiveNegative: true,
		}},
	}
	if err := Validate(rf); err == nil {
		t.Fatal("expected validation error for exhaustive_negative on non-not_exists rule")
	}
}

func TestRulePolicyHelpers(t *testing.T) {
	if !FactQualityProof.AtLeast(FactQualityStructural) {
		t.Fatal("expected proof to be stronger than structural")
	}
	if FactQualityHeuristic.AtLeast(FactQualityProof) {
		t.Fatal("expected heuristic to be weaker than proof")
	}

	sa := &ScenarioApplicability{Hiring: true, OutsourceAcceptance: false, PMAcceptance: true}
	if !sa.Any() {
		t.Fatal("expected scenario applicability to report true when any scenario is enabled")
	}
	if !sa.Allows("hiring") || sa.Allows("outsource_acceptance") || !sa.Allows("pm_acceptance") {
		t.Fatalf("unexpected scenario applicability behavior: %+v", sa)
	}

	r := Rule{ScenarioApplicability: sa}
	if !r.AppliesToScenario("hiring") || r.AppliesToScenario("outsource_acceptance") {
		t.Fatal("unexpected rule scenario applicability helper behavior")
	}
}
