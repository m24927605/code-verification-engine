package rules

import (
	"sort"
	"testing"
)

// ---------------------------------------------------------------------------
// ClassifyTrustClass
// ---------------------------------------------------------------------------

func TestClassifyTrustClass_MachineTrusted(t *testing.T) {
	machineTrusted := []string{
		"SEC-SECRET-001", "SEC-SECRET-003",
		"FE-DEP-001",
	}
	for _, id := range machineTrusted {
		tc := ClassifyTrustClass(id)
		if tc != TrustMachineTrusted {
			t.Errorf("ClassifyTrustClass(%q) = %q, want machine_trusted", id, tc)
		}
	}
}

func TestClassifyTrustClass_HumanOrRuntimeRequired(t *testing.T) {
	humanRequired := []string{"SEC-AUTH-002", "SEC-ROUTE-001"}
	for _, id := range humanRequired {
		tc := ClassifyTrustClass(id)
		if tc != TrustHumanOrRuntimeRequired {
			t.Errorf("ClassifyTrustClass(%q) = %q, want human_or_runtime_required", id, tc)
		}
	}
}

func TestClassifyTrustClass_AdvisoryDefault(t *testing.T) {
	advisory := []string{
		"SEC-AUTH-001", "SEC-AUTH-003", "SEC-SECRET-002",
		"SEC-INPUT-001", "SEC-CORS-001", "SEC-HELMET-001", "SEC-RATE-001",
		"ARCH-LAYER-001", "ARCH-PATTERN-001", // downgraded: name/path heuristic matchers
		"ARCH-LAYER-002", "ARCH-LAYER-003", "ARCH-ERR-001", "ARCH-ERR-002",
		"QUAL-LOG-001", "QUAL-LOG-002", "QUAL-HEALTH-001", "QUAL-SHUTDOWN-001",
		"TEST-AUTH-001", "TEST-PAYMENT-001",
		"GOF-C-001", "GOF-S-001", "GOF-B-001",
		"FE-AUTH-001", "FE-CSP-001", "FE-ERR-001", "FE-FORM-001",
		// Frontend rules demoted from machine_trusted — heuristic matchers
		"FE-XSS-001", "FE-XSS-002", "FE-TOKEN-001", "FE-ENV-001", "FE-LOG-001",
		"UNKNOWN-RULE-ID",
	}
	for _, id := range advisory {
		tc := ClassifyTrustClass(id)
		if tc != TrustAdvisory {
			t.Errorf("ClassifyTrustClass(%q) = %q, want advisory", id, tc)
		}
	}
}

// ---------------------------------------------------------------------------
// NormalizeTrust
// ---------------------------------------------------------------------------

func TestNormalizeTrust_AdvisoryDowngradesVerified(t *testing.T) {
	// An advisory rule that a matcher returned as verified must be downgraded
	f := Finding{
		RuleID:            "SEC-AUTH-001", // advisory
		Status:            StatusPass,
		Confidence:        ConfidenceHigh,
		VerificationLevel: VerificationVerified,
	}
	NormalizeTrust(&f)
	if f.TrustClass != TrustAdvisory {
		t.Errorf("trust_class = %q, want advisory", f.TrustClass)
	}
	if f.VerificationLevel != VerificationStrongInference {
		t.Errorf("verification_level = %q, want strong_inference (downgraded from verified)", f.VerificationLevel)
	}
	// Confidence should be preserved
	if f.Confidence != ConfidenceHigh {
		t.Errorf("confidence = %q, should be preserved as high", f.Confidence)
	}
}

func TestNormalizeTrust_MachineTrustedPreservesVerified(t *testing.T) {
	f := Finding{
		RuleID:            "SEC-SECRET-001", // machine_trusted
		Status:            StatusPass,
		Confidence:        ConfidenceHigh,
		VerificationLevel: VerificationVerified,
	}
	NormalizeTrust(&f)
	if f.TrustClass != TrustMachineTrusted {
		t.Errorf("trust_class = %q, want machine_trusted", f.TrustClass)
	}
	if f.VerificationLevel != VerificationVerified {
		t.Errorf("verification_level = %q, want verified (should NOT be downgraded)", f.VerificationLevel)
	}
}

func TestNormalizeTrust_HumanRequiredDowngradesVerified(t *testing.T) {
	f := Finding{
		RuleID:            "SEC-AUTH-002", // human_or_runtime_required
		Status:            StatusPass,
		Confidence:        ConfidenceHigh,
		VerificationLevel: VerificationVerified,
	}
	NormalizeTrust(&f)
	if f.TrustClass != TrustHumanOrRuntimeRequired {
		t.Errorf("trust_class = %q, want human_or_runtime_required", f.TrustClass)
	}
	if f.VerificationLevel != VerificationStrongInference {
		t.Errorf("verification_level = %q, want strong_inference (downgraded)", f.VerificationLevel)
	}
}

func TestNormalizeTrust_AdvisoryStrongInferenceUnchanged(t *testing.T) {
	f := Finding{
		RuleID:            "SEC-AUTH-001",
		Status:            StatusPass,
		Confidence:        ConfidenceMedium,
		VerificationLevel: VerificationStrongInference,
	}
	NormalizeTrust(&f)
	if f.VerificationLevel != VerificationStrongInference {
		t.Errorf("verification_level = %q, want strong_inference (should not change)", f.VerificationLevel)
	}
}

func TestNormalizeTrust_AdvisoryWeakInferenceUnchanged(t *testing.T) {
	f := Finding{
		RuleID:            "GOF-C-001",
		Status:            StatusPass,
		Confidence:        ConfidenceLow,
		VerificationLevel: VerificationWeakInference,
	}
	NormalizeTrust(&f)
	if f.VerificationLevel != VerificationWeakInference {
		t.Errorf("verification_level = %q, should not be changed", f.VerificationLevel)
	}
}

// ---------------------------------------------------------------------------
// ValidTrustClass
// ---------------------------------------------------------------------------

func TestValidTrustClass(t *testing.T) {
	valid := []TrustClass{TrustMachineTrusted, TrustAdvisory, TrustHumanOrRuntimeRequired}
	for _, tc := range valid {
		if !ValidTrustClass(tc) {
			t.Errorf("ValidTrustClass(%q) = false, want true", tc)
		}
	}
	invalid := []TrustClass{"", "auto_trusted", "unknown"}
	for _, tc := range invalid {
		if ValidTrustClass(tc) {
			t.Errorf("ValidTrustClass(%q) = true, want false", tc)
		}
	}
}

// ---------------------------------------------------------------------------
// MachineTrustedRuleIDs
// ---------------------------------------------------------------------------

func TestMachineTrustedRuleIDs(t *testing.T) {
	ids := MachineTrustedRuleIDs()
	if len(ids) != 3 {
		t.Fatalf("MachineTrustedRuleIDs() returned %d IDs, want 3", len(ids))
	}
	sort.Strings(ids)
	expected := []string{
		"FE-DEP-001",
		"SEC-SECRET-001", "SEC-SECRET-003",
	}
	for i, id := range expected {
		if ids[i] != id {
			t.Errorf("ids[%d] = %q, want %q", i, ids[i], id)
		}
	}
}

// ---------------------------------------------------------------------------
// trusted-core profile
// ---------------------------------------------------------------------------

func TestTrustedCoreProfile_Exists(t *testing.T) {
	p, ok := GetProfile("trusted-core")
	if !ok {
		t.Fatal("GetProfile(\"trusted-core\") returned false")
	}
	if p == nil {
		t.Fatal("GetProfile(\"trusted-core\") returned nil")
	}
}

func TestTrustedCoreProfile_OnlyMachineTrustedRules(t *testing.T) {
	p, _ := GetProfile("trusted-core")
	expected := map[string]bool{
		"SEC-SECRET-001": true,
		"SEC-SECRET-003": true,
		"FE-DEP-001":     true,
	}
	if len(p.Rules) != len(expected) {
		t.Fatalf("trusted-core has %d rules, want %d", len(p.Rules), len(expected))
	}
	for _, r := range p.Rules {
		if !expected[r.ID] {
			t.Errorf("unexpected rule %q in trusted-core profile", r.ID)
		}
	}
}

func TestTrustedCoreProfile_NoAdvisoryRules(t *testing.T) {
	p, _ := GetProfile("trusted-core")
	for _, r := range p.Rules {
		tc := ClassifyTrustClass(r.ID)
		if tc != TrustMachineTrusted {
			t.Errorf("trusted-core contains rule %q with trust class %q, expected only machine_trusted", r.ID, tc)
		}
	}
}

func TestTrustedCoreProfile_InAllProfiles(t *testing.T) {
	profiles := AllProfiles()
	if _, ok := profiles["trusted-core"]; !ok {
		t.Error("trusted-core not in AllProfiles()")
	}
}
