package rules

import (
	"sort"
	"testing"

	"github.com/verabase/code-verification-engine/internal/facts"
)

// ---------------------------------------------------------------------------
// Gate 1: No increase in machine-trusted findings without fixtures
// ---------------------------------------------------------------------------

func TestMachineTrustedRules_ExactSet(t *testing.T) {
	// This test is a gate: if you add a new machine-trusted rule,
	// this test forces you to also add a fixture to testdata/autobench/.
	expected := map[string]bool{
		"SEC-SECRET-001": true,
		"SEC-SECRET-003": true,
		"FE-DEP-001":     true,
	}

	ids := MachineTrustedRuleIDs()
	if len(ids) != len(expected) {
		t.Fatalf("machineTrustedRules has %d entries, want exactly %d — "+
			"if you added a new rule, add a benchmark fixture too", len(ids), len(expected))
	}
	for _, id := range ids {
		if !expected[id] {
			t.Errorf("unexpected machine-trusted rule %q — add a benchmark fixture before admitting", id)
		}
	}

	// Also verify the sorted list is stable
	sort.Strings(ids)
	expectedSorted := []string{"FE-DEP-001", "SEC-SECRET-001", "SEC-SECRET-003"}
	for i, id := range expectedSorted {
		if ids[i] != id {
			t.Errorf("sorted ids[%d] = %q, want %q", i, ids[i], id)
		}
	}
}

// ---------------------------------------------------------------------------
// Gate 2: No verified findings backed only by heuristic facts
// ---------------------------------------------------------------------------

func TestNoVerifiedFromHeuristicMatcher(t *testing.T) {
	// For every profile, check that heuristic_matcher rules never produce
	// VerificationVerified after applyMatcherClassCeiling.
	profiles := AllProfiles()
	for profileName, profile := range profiles {
		for _, rule := range profile.Rules {
			if rule.MatcherClass != MatcherHeuristic {
				continue
			}
			// Simulate a finding that a matcher incorrectly returns as verified
			f := Finding{
				RuleID:            rule.ID,
				Status:            StatusPass,
				Confidence:        ConfidenceHigh,
				VerificationLevel: VerificationVerified,
				MatcherClass:      rule.MatcherClass,
			}
			applyMatcherClassCeiling(&f)
			if f.VerificationLevel == VerificationVerified {
				t.Errorf("profile %q, rule %q (heuristic_matcher): "+
					"VerificationVerified survived applyMatcherClassCeiling — this is a trust inflation bug",
					profileName, rule.ID)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Gate 3: TrustedPassAllowed only on proof_matcher rules
// ---------------------------------------------------------------------------

func TestTrustedPassAllowed_OnlyOnProofMatcher(t *testing.T) {
	profiles := AllProfiles()
	for profileName, profile := range profiles {
		for _, rule := range profile.Rules {
			if !rule.TrustedPassAllowed {
				continue
			}
			if rule.MatcherClass != MatcherProof {
				t.Errorf("profile %q, rule %q: TrustedPassAllowed=true but MatcherClass=%q "+
					"(must be proof_matcher to allow trusted pass)",
					profileName, rule.ID, rule.MatcherClass)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Gate 4: Attestation rules always produce unknown with empty FactSet
// ---------------------------------------------------------------------------

func TestAttestationRules_ProduceUnknownWithEmptyFacts(t *testing.T) {
	profiles := AllProfiles()
	engine := NewEngine()
	repoLanguages := []string{"go", "typescript", "javascript", "python"}

	for profileName, profile := range profiles {
		for _, rule := range profile.Rules {
			if rule.MatcherClass != MatcherAttestation {
				continue
			}
			// Execute with empty FactSet
			rf := &RuleFile{
				Version: "0.1",
				Profile: profileName,
				Rules:   []Rule{rule},
			}
			result := engine.Execute(rf, &FactSet{}, repoLanguages)

			// The rule should produce a finding (not be skipped due to language)
			found := false
			for _, f := range result.Findings {
				if f.RuleID == rule.ID {
					found = true
					if f.Status != StatusUnknown {
						t.Errorf("profile %q, rule %q (attestation_matcher): "+
							"expected StatusUnknown with empty FactSet, got %q",
							profileName, rule.ID, f.Status)
					}
					break
				}
			}
			if !found {
				// It may have been skipped — check that
				skipped := false
				for _, s := range result.SkippedRules {
					if s.RuleID == rule.ID {
						skipped = true
						break
					}
				}
				if !skipped {
					t.Errorf("profile %q, rule %q: neither in findings nor skipped", profileName, rule.ID)
				}
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Gate 5: Matcher class ceiling invariant for all matcher classes
// ---------------------------------------------------------------------------

func TestMatcherClassCeiling_Invariant_AllClasses(t *testing.T) {
	tests := []struct {
		name              string
		matcherClass      MatcherClass
		inputLevel        VerificationLevel
		expectedLevel     VerificationLevel
		expectStatusForce bool // attestation forces status to unknown
	}{
		{
			name:          "proof_verified_stays",
			matcherClass:  MatcherProof,
			inputLevel:    VerificationVerified,
			expectedLevel: VerificationVerified,
		},
		{
			name:          "proof_strong_stays",
			matcherClass:  MatcherProof,
			inputLevel:    VerificationStrongInference,
			expectedLevel: VerificationStrongInference,
		},
		{
			name:          "structural_verified_caps",
			matcherClass:  MatcherStructural,
			inputLevel:    VerificationVerified,
			expectedLevel: VerificationStrongInference,
		},
		{
			name:          "structural_strong_stays",
			matcherClass:  MatcherStructural,
			inputLevel:    VerificationStrongInference,
			expectedLevel: VerificationStrongInference,
		},
		{
			name:          "heuristic_verified_caps",
			matcherClass:  MatcherHeuristic,
			inputLevel:    VerificationVerified,
			expectedLevel: VerificationStrongInference,
		},
		{
			name:          "heuristic_weak_stays",
			matcherClass:  MatcherHeuristic,
			inputLevel:    VerificationWeakInference,
			expectedLevel: VerificationWeakInference,
		},
		{
			name:              "attestation_verified_forces_unknown",
			matcherClass:      MatcherAttestation,
			inputLevel:        VerificationVerified,
			expectedLevel:     VerificationWeakInference,
			expectStatusForce: true,
		},
		{
			name:              "attestation_strong_forces_unknown",
			matcherClass:      MatcherAttestation,
			inputLevel:        VerificationStrongInference,
			expectedLevel:     VerificationWeakInference,
			expectStatusForce: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := Finding{
				RuleID:            "TEST-GATE",
				Status:            StatusPass,
				Confidence:        ConfidenceHigh,
				VerificationLevel: tc.inputLevel,
				MatcherClass:      tc.matcherClass,
			}
			applyMatcherClassCeiling(&f)

			if f.VerificationLevel != tc.expectedLevel {
				t.Errorf("VerificationLevel = %q, want %q", f.VerificationLevel, tc.expectedLevel)
			}
			if tc.expectStatusForce && f.Status != StatusUnknown {
				t.Errorf("Status = %q, want unknown (forced by attestation ceiling)", f.Status)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Gate: All machine-trusted rules exist in at least one profile
// ---------------------------------------------------------------------------

func TestMachineTrustedRules_ExistInProfiles(t *testing.T) {
	ids := MachineTrustedRuleIDs()
	profiles := AllProfiles()

	for _, id := range ids {
		found := false
		for _, profile := range profiles {
			for _, rule := range profile.Rules {
				if rule.ID == id {
					found = true
					break
				}
			}
			if found {
				break
			}
		}
		if !found {
			t.Errorf("machine-trusted rule %q not found in any profile", id)
		}
	}
}

// ---------------------------------------------------------------------------
// Gate: Machine-trusted rules must have proof_matcher class
// ---------------------------------------------------------------------------

func TestMachineTrustedRules_MustBeProofMatcher(t *testing.T) {
	ids := MachineTrustedRuleIDs()
	profiles := AllProfiles()

	idSet := make(map[string]bool)
	for _, id := range ids {
		idSet[id] = true
	}

	for profileName, profile := range profiles {
		for _, rule := range profile.Rules {
			if !idSet[rule.ID] {
				continue
			}
			if rule.MatcherClass != MatcherProof {
				t.Errorf("profile %q, machine-trusted rule %q: MatcherClass=%q, want proof_matcher",
					profileName, rule.ID, rule.MatcherClass)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Gate: Heuristic matcher with verified finding should be capped via engine
// ---------------------------------------------------------------------------

func TestEngine_HeuristicMatcherNeverProducesVerified(t *testing.T) {
	// Use a heuristic exists rule with matching symbols — the exists matcher
	// returns verified by default, but applyMatcherClassCeiling should cap it.
	rule := Rule{
		ID:           "SEC-AUTH-001",
		Title:        "JWT authentication must exist",
		Category:     "security",
		Severity:     "high",
		Languages:    []string{"go"},
		Type:         "exists",
		Target:       "auth.jwt_middleware",
		Message:      "Test",
		MatcherClass: MatcherHeuristic,
	}
	rf := &RuleFile{Version: "0.1", Profile: "test", Rules: []Rule{rule}}
	fs := &FactSet{
		Middlewares: []facts.MiddlewareFact{
			{Name: "authMiddleware", Kind: "auth", File: "middleware.go", Language: facts.LangGo, Span: facts.Span{Start: 1, End: 10}},
		},
		Imports: []facts.ImportFact{
			{ImportPath: "github.com/golang-jwt/jwt/v5", File: "middleware.go", Language: facts.LangGo, Span: facts.Span{Start: 1, End: 1}},
		},
		Symbols: []facts.SymbolFact{
			{Name: "authMiddleware", Kind: "function", File: "middleware.go", Language: facts.LangGo, Span: facts.Span{Start: 1, End: 10}},
		},
	}

	engine := NewEngine()
	result := engine.Execute(rf, fs, []string{"go"})

	for _, f := range result.Findings {
		if f.RuleID == "SEC-AUTH-001" && f.VerificationLevel == VerificationVerified {
			t.Errorf("heuristic rule SEC-AUTH-001 produced VerificationVerified through engine — trust inflation")
		}
	}
}
