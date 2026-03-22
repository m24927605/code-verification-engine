package rules

import (
	"testing"
)

// ─── applyMatcherClassCeiling tests ───

func TestMatcherClassCeiling_ProofNoChange(t *testing.T) {
	f := Finding{
		RuleID:            "TEST-001",
		Status:            StatusPass,
		Confidence:        ConfidenceHigh,
		VerificationLevel: VerificationVerified,
		MatcherClass:      MatcherProof,
	}
	applyMatcherClassCeiling(&f)

	if f.VerificationLevel != VerificationVerified {
		t.Errorf("proof matcher should not cap verified, got %s", f.VerificationLevel)
	}
	if f.Status != StatusPass {
		t.Errorf("proof matcher should not change status, got %s", f.Status)
	}
}

func TestMatcherClassCeiling_StructuralCapsVerified(t *testing.T) {
	f := Finding{
		RuleID:            "TEST-002",
		Status:            StatusPass,
		Confidence:        ConfidenceHigh,
		VerificationLevel: VerificationVerified,
		MatcherClass:      MatcherStructural,
	}
	applyMatcherClassCeiling(&f)

	if f.VerificationLevel != VerificationStrongInference {
		t.Errorf("structural matcher should cap verified to strong_inference, got %s", f.VerificationLevel)
	}
	if f.Status != StatusPass {
		t.Errorf("structural matcher should not change status, got %s", f.Status)
	}
}

func TestMatcherClassCeiling_StructuralStrongInferenceUnchanged(t *testing.T) {
	f := Finding{
		RuleID:            "TEST-002",
		Status:            StatusPass,
		Confidence:        ConfidenceMedium,
		VerificationLevel: VerificationStrongInference,
		MatcherClass:      MatcherStructural,
	}
	applyMatcherClassCeiling(&f)

	if f.VerificationLevel != VerificationStrongInference {
		t.Errorf("structural matcher should not change strong_inference, got %s", f.VerificationLevel)
	}
}

func TestMatcherClassCeiling_HeuristicCapsVerified(t *testing.T) {
	f := Finding{
		RuleID:            "TEST-003",
		Status:            StatusFail,
		Confidence:        ConfidenceHigh,
		VerificationLevel: VerificationVerified,
		MatcherClass:      MatcherHeuristic,
	}
	applyMatcherClassCeiling(&f)

	if f.VerificationLevel != VerificationStrongInference {
		t.Errorf("heuristic matcher should cap verified to strong_inference, got %s", f.VerificationLevel)
	}
	if f.Status != StatusFail {
		t.Errorf("heuristic matcher should not change status, got %s", f.Status)
	}
}

func TestMatcherClassCeiling_HeuristicWeakInferenceUnchanged(t *testing.T) {
	f := Finding{
		RuleID:            "TEST-003",
		Status:            StatusFail,
		Confidence:        ConfidenceLow,
		VerificationLevel: VerificationWeakInference,
		MatcherClass:      MatcherHeuristic,
	}
	applyMatcherClassCeiling(&f)

	if f.VerificationLevel != VerificationWeakInference {
		t.Errorf("heuristic matcher should not change weak_inference, got %s", f.VerificationLevel)
	}
}

func TestMatcherClassCeiling_AttestationForcesUnknown(t *testing.T) {
	f := Finding{
		RuleID:            "TEST-004",
		Status:            StatusPass,
		Confidence:        ConfidenceHigh,
		VerificationLevel: VerificationVerified,
		MatcherClass:      MatcherAttestation,
	}
	applyMatcherClassCeiling(&f)

	if f.Status != StatusUnknown {
		t.Errorf("attestation matcher should force status to unknown, got %s", f.Status)
	}
	if f.Confidence != ConfidenceLow {
		t.Errorf("attestation matcher should force confidence to low, got %s", f.Confidence)
	}
	if f.VerificationLevel != VerificationWeakInference {
		t.Errorf("attestation matcher should force verification_level to weak_inference, got %s", f.VerificationLevel)
	}
	if len(f.UnknownReasons) != 1 || f.UnknownReasons[0] != UnknownNeedsHumanAttestation {
		t.Errorf("attestation matcher should set unknown_reasons to [needs_human_attestation], got %v", f.UnknownReasons)
	}
}

func TestMatcherClassCeiling_AttestationAlreadyUnknownNoChange(t *testing.T) {
	f := Finding{
		RuleID:            "TEST-004",
		Status:            StatusUnknown,
		Confidence:        ConfidenceLow,
		VerificationLevel: VerificationWeakInference,
		MatcherClass:      MatcherAttestation,
		UnknownReasons:    []string{"some_reason"},
	}
	applyMatcherClassCeiling(&f)

	if f.Status != StatusUnknown {
		t.Errorf("attestation matcher should not change already-unknown status, got %s", f.Status)
	}
	// Should keep the original reasons since status was already unknown
	if len(f.UnknownReasons) != 1 || f.UnknownReasons[0] != "some_reason" {
		t.Errorf("attestation matcher should preserve existing unknown_reasons when status already unknown, got %v", f.UnknownReasons)
	}
}

func TestMatcherClassCeiling_AttestationFailForcesUnknown(t *testing.T) {
	f := Finding{
		RuleID:            "TEST-004",
		Status:            StatusFail,
		Confidence:        ConfidenceMedium,
		VerificationLevel: VerificationStrongInference,
		MatcherClass:      MatcherAttestation,
	}
	applyMatcherClassCeiling(&f)

	if f.Status != StatusUnknown {
		t.Errorf("attestation matcher should force fail to unknown, got %s", f.Status)
	}
	if f.Confidence != ConfidenceLow {
		t.Errorf("attestation matcher should force confidence to low, got %s", f.Confidence)
	}
	if f.VerificationLevel != VerificationWeakInference {
		t.Errorf("attestation matcher should force verification_level to weak_inference, got %s", f.VerificationLevel)
	}
}

func TestMatcherClassCeiling_AttestationPreservesExistingReasons(t *testing.T) {
	f := Finding{
		RuleID:            "TEST-004",
		Status:            StatusPass,
		Confidence:        ConfidenceHigh,
		VerificationLevel: VerificationVerified,
		MatcherClass:      MatcherAttestation,
		UnknownReasons:    []string{"existing_reason"},
	}
	applyMatcherClassCeiling(&f)

	if f.Status != StatusUnknown {
		t.Errorf("expected status unknown, got %s", f.Status)
	}
	// When there are already reasons, don't overwrite
	if len(f.UnknownReasons) != 1 || f.UnknownReasons[0] != "existing_reason" {
		t.Errorf("should preserve existing unknown_reasons, got %v", f.UnknownReasons)
	}
}

// ─── NormalizeTrust + applyMatcherClassCeiling interaction ───

func TestNormalizeTrustAndMatcherClassCeiling_Interaction(t *testing.T) {
	// A heuristic matcher with machine_trusted rule ID should:
	// 1. applyMatcherClassCeiling caps verified -> strong_inference
	// 2. NormalizeTrust sees machine_trusted but level is already strong_inference
	f := Finding{
		RuleID:            "SEC-SECRET-001", // machine_trusted
		Status:            StatusPass,
		Confidence:        ConfidenceHigh,
		VerificationLevel: VerificationVerified,
		MatcherClass:      MatcherProof, // proof matcher
	}

	// Apply ceiling first (as engine does)
	applyMatcherClassCeiling(&f)
	// Then NormalizeTrust (as engine.go does after)
	NormalizeTrust(&f)

	if f.TrustClass != TrustMachineTrusted {
		t.Errorf("expected machine_trusted, got %s", f.TrustClass)
	}
	if f.VerificationLevel != VerificationVerified {
		t.Errorf("proof matcher + machine_trusted should keep verified, got %s", f.VerificationLevel)
	}
}

func TestNormalizeTrustAndMatcherClassCeiling_HeuristicAdvisory(t *testing.T) {
	// A heuristic matcher with advisory rule should be capped at strong_inference
	f := Finding{
		RuleID:            "SEC-AUTH-001", // advisory (not in machineTrusted or humanRequired)
		Status:            StatusPass,
		Confidence:        ConfidenceHigh,
		VerificationLevel: VerificationVerified,
		MatcherClass:      MatcherHeuristic,
	}

	applyMatcherClassCeiling(&f)
	NormalizeTrust(&f)

	if f.TrustClass != TrustAdvisory {
		t.Errorf("expected advisory, got %s", f.TrustClass)
	}
	if f.VerificationLevel != VerificationStrongInference {
		t.Errorf("heuristic + advisory should be strong_inference, got %s", f.VerificationLevel)
	}
}

func TestNormalizeTrustAndMatcherClassCeiling_AttestationHumanRequired(t *testing.T) {
	// An attestation matcher with human_required rule should stay unknown
	f := Finding{
		RuleID:            "SEC-AUTH-002", // human_or_runtime_required
		Status:            StatusPass,
		Confidence:        ConfidenceHigh,
		VerificationLevel: VerificationVerified,
		MatcherClass:      MatcherAttestation,
	}

	applyMatcherClassCeiling(&f)
	NormalizeTrust(&f)

	if f.TrustClass != TrustHumanOrRuntimeRequired {
		t.Errorf("expected human_or_runtime_required, got %s", f.TrustClass)
	}
	if f.Status != StatusUnknown {
		t.Errorf("attestation should force unknown, got %s", f.Status)
	}
	if f.VerificationLevel != VerificationWeakInference {
		t.Errorf("attestation should force weak_inference, got %s", f.VerificationLevel)
	}
}

// ─── All profiles have MatcherClass set ───

func TestAllProfilesHaveMatcherClass(t *testing.T) {
	profiles := AllProfiles()
	for profileName, profile := range profiles {
		for _, rule := range profile.Rules {
			if rule.MatcherClass == "" {
				t.Errorf("profile %q, rule %q has empty MatcherClass", profileName, rule.ID)
			}
			// Validate it's one of the known values
			switch rule.MatcherClass {
			case MatcherProof, MatcherStructural, MatcherHeuristic, MatcherAttestation:
				// ok
			default:
				t.Errorf("profile %q, rule %q has unknown MatcherClass %q", profileName, rule.ID, rule.MatcherClass)
			}
		}
	}
}

// ─── Specific rule classification tests ───

func TestProofMatcherRules(t *testing.T) {
	proofRuleIDs := map[string]bool{
		"SEC-SECRET-001": true,
		"SEC-SECRET-003": true,
		"FE-DEP-001":     true,
	}

	profiles := AllProfiles()
	for _, profile := range profiles {
		for _, rule := range profile.Rules {
			if proofRuleIDs[rule.ID] && rule.MatcherClass != MatcherProof {
				t.Errorf("rule %q should be proof_matcher, got %s", rule.ID, rule.MatcherClass)
			}
		}
	}
}

func TestAttestationMatcherRules(t *testing.T) {
	attestationRuleIDs := map[string]bool{
		"SEC-AUTH-002":  true,
		"SEC-ROUTE-001": true,
	}

	profiles := AllProfiles()
	for _, profile := range profiles {
		for _, rule := range profile.Rules {
			if attestationRuleIDs[rule.ID] && rule.MatcherClass != MatcherAttestation {
				t.Errorf("rule %q should be attestation_matcher, got %s", rule.ID, rule.MatcherClass)
			}
		}
	}
}

func TestStructuralMatcherRules(t *testing.T) {
	structuralRuleIDs := map[string]bool{
		"ARCH-LAYER-001":   true,
		"ARCH-PATTERN-001": true,
		"ARCH-PATTERN-002": true,
		"ARCH-PATTERN-003": true,
		"TEST-AUTH-001":     true,
		"TEST-PAYMENT-001": true,
		"SEC-STRICT-001":   true,
		"SEC-STRICT-002":   true,
	}

	profiles := AllProfiles()
	for _, profile := range profiles {
		for _, rule := range profile.Rules {
			if structuralRuleIDs[rule.ID] && rule.MatcherClass != MatcherStructural {
				t.Errorf("rule %q should be structural_matcher, got %s", rule.ID, rule.MatcherClass)
			}
		}
	}
}
