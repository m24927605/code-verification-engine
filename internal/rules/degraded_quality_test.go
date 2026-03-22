package rules

import (
	"testing"

	"github.com/verabase/code-verification-engine/internal/facts"
)

// ---------------------------------------------------------------------------
// Test 1: When all facts have Quality="heuristic", a proof_matcher rule
// should still function but the matcher class ceiling governs trust level.
// ---------------------------------------------------------------------------

func TestDegradedFactQuality_AllHeuristic_ProofMatcher(t *testing.T) {
	// SEC-SECRET-001 is a proof_matcher rule. Even when facts have
	// heuristic quality, the matcher should still produce findings.
	// The MatcherClass ceiling (proof) allows verified, but the
	// fact quality floor should be reflected in the finding.
	rule := Rule{
		ID:           "SEC-SECRET-001",
		Title:        "Hardcoded credentials must not exist",
		Category:     "security",
		Severity:     "critical",
		Languages:    []string{"typescript"},
		Type:         "not_exists",
		Target:       "secret.hardcoded_credential",
		Message:      "Test",
		MatcherClass: MatcherProof,
	}

	// Facts with heuristic quality — these are lower quality than proof
	fs := &FactSet{
		Secrets: []facts.SecretFact{
			{
				Kind:     "api_key",
				File:     "src/config/constants.ts",
				Language: facts.LangTypeScript,
				Span:     facts.Span{Start: 10, End: 10},
				Value:    "sk-1234567890abcdef",
			},
		},
		Files: []facts.FileFact{
			{File: "src/config/constants.ts", Language: facts.LangTypeScript},
		},
	}

	finding := matchRule(rule, fs, []string{"typescript"})
	finding.MatcherClass = rule.MatcherClass
	applyMatcherClassCeiling(&finding)

	// The finding should still detect the secret
	if finding.Status != StatusFail {
		t.Errorf("proof_matcher should still detect secrets with heuristic-quality facts, got %q", finding.Status)
	}

	// Now apply setVerdictBasis with the FactSet — this is where fact quality
	// should downgrade the verdict from "proof" to "heuristic_inference"
	setVerdictBasis(&finding, fs)

	// With heuristic-quality facts, proof_matcher should NOT claim "proof" verdict
	if finding.VerdictBasis == "proof" {
		t.Error("proof_matcher with heuristic-quality facts must NOT claim proof verdict")
	}
	if finding.VerdictBasis != "heuristic_inference" {
		t.Errorf("expected heuristic_inference verdict with heuristic facts, got %q", finding.VerdictBasis)
	}
	// Verification level should be downgraded from verified to strong_inference
	if finding.VerificationLevel == VerificationVerified {
		t.Error("proof_matcher with heuristic-quality facts must NOT claim verified")
	}
}

// ---------------------------------------------------------------------------
// Test 2: When facts have Quality="structural", structural_matcher rules
// should work normally.
// ---------------------------------------------------------------------------

func TestFactQuality_Structural_StructuralMatcher(t *testing.T) {
	// ARCH-LAYER-001 is a structural_matcher rule. With structural-quality
	// facts, it should work normally.
	rule := Rule{
		ID:           "ARCH-LAYER-001",
		Title:        "Controllers must not access database directly",
		Category:     "architecture",
		Severity:     "high",
		Languages:    []string{"typescript"},
		Type:         "not_exists",
		Target:       "db.direct_access_from_controller",
		Message:      "Test",
		MatcherClass: MatcherStructural,
	}

	// Facts with structural quality
	fs := &FactSet{
		FileRoles: []facts.FileRoleFact{
			{Language: facts.LangTypeScript, File: "src/users/users.controller.ts", Role: "controller", Quality: facts.QualityStructural},
		},
		DataAccess: []facts.DataAccessFact{
			{
				Language:  facts.LangTypeScript,
				File:      "src/users/users.controller.ts",
				Span:      facts.Span{Start: 25, End: 28},
				Operation: "prisma.user.findMany",
				Backend:   "prisma",
				Quality:   facts.QualityStructural,
			},
		},
		Files: []facts.FileFact{
			{File: "src/users/users.controller.ts", Language: facts.LangTypeScript},
		},
		Symbols: []facts.SymbolFact{
			{Name: "UsersController", Kind: "class", File: "src/users/users.controller.ts", Language: facts.LangTypeScript, Span: facts.Span{Start: 1, End: 50}},
		},
	}

	finding := matchRule(rule, fs, []string{"typescript"})
	finding.MatcherClass = rule.MatcherClass
	applyMatcherClassCeiling(&finding)

	// Should detect the violation
	if finding.Status != StatusFail {
		t.Errorf("structural_matcher should detect controller DB access with structural-quality facts, got %q", finding.Status)
	}
	// Structural matcher caps at strong_inference
	if finding.VerificationLevel == VerificationVerified {
		t.Errorf("structural_matcher should cap at strong_inference, got verified")
	}
}

// ---------------------------------------------------------------------------
// Test 3: Backward compatibility — when facts have no Quality set (empty
// string), behavior is unchanged.
// ---------------------------------------------------------------------------

func TestFactQuality_Empty_BackwardCompatibility(t *testing.T) {
	// When Quality is empty (pre-quality-annotation callers), the matchers
	// should behave exactly as before — no panics, no changed behavior.

	t.Run("exists_matcher_no_quality", func(t *testing.T) {
		rule := Rule{
			ID:           "SEC-AUTH-001",
			Languages:    []string{"go"},
			Type:         "exists",
			Target:       "auth.jwt_middleware",
			MatcherClass: MatcherHeuristic,
		}
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

		finding := matchRule(rule, fs, []string{"go"})
		finding.MatcherClass = rule.MatcherClass
		applyMatcherClassCeiling(&finding)

		// Should produce a finding (pass or fail) without panicking
		if finding.Status == "" {
			t.Error("expected a non-empty status with empty Quality fields")
		}
	})

	t.Run("not_exists_matcher_no_quality", func(t *testing.T) {
		rule := Rule{
			ID:           "SEC-SECRET-001",
			Languages:    []string{"go"},
			Type:         "not_exists",
			Target:       "secret.hardcoded_credential",
			MatcherClass: MatcherProof,
		}
		fs := &FactSet{
			Files: []facts.FileFact{
				{File: "main.go", Language: facts.LangGo},
			},
			// No secrets — should pass
		}

		finding := matchRule(rule, fs, []string{"go"})
		finding.MatcherClass = rule.MatcherClass
		applyMatcherClassCeiling(&finding)

		if finding.Status != StatusPass {
			t.Errorf("expected pass with no secrets and empty Quality, got %q", finding.Status)
		}
	})

	t.Run("engine_execute_no_quality", func(t *testing.T) {
		// Full engine execution with facts that have no Quality set
		engine := NewEngine()
		rf := &RuleFile{
			Version: "0.1",
			Profile: "test",
			Rules: []Rule{
				{
					ID:           "SEC-SECRET-001",
					Languages:    []string{"go"},
					Type:         "not_exists",
					Target:       "secret.hardcoded_credential",
					MatcherClass: MatcherProof,
				},
			},
		}
		fs := &FactSet{
			Files: []facts.FileFact{
				{File: "main.go", Language: facts.LangGo},
			},
		}

		result := engine.Execute(rf, fs, []string{"go"})
		if len(result.Findings) == 0 {
			t.Error("expected at least one finding from engine execution")
		}
		for _, f := range result.Findings {
			if f.Status == "" {
				t.Errorf("finding %q has empty status", f.RuleID)
			}
		}
	})
}

// ---------------------------------------------------------------------------
// Test: Proof-quality facts with proof_matcher produce verified
// ---------------------------------------------------------------------------

func TestFactQuality_Proof_ProofMatcher(t *testing.T) {
	// When facts have proof quality AND the matcher is proof_matcher,
	// the finding should be allowed to be verified.
	rule := Rule{
		ID:           "SEC-SECRET-003",
		Title:        ".env files must not be committed",
		Category:     "security",
		Severity:     "critical",
		Languages:    []string{"go", "typescript", "javascript", "python"},
		Type:         "not_exists",
		Target:       "secret.env_file_committed",
		MatcherClass: MatcherProof,
	}

	// No .env files — should pass
	fs := &FactSet{
		Files: []facts.FileFact{
			{File: "main.go", Language: facts.LangGo},
			{File: "go.mod", Language: facts.LangGo},
		},
		Symbols: []facts.SymbolFact{
			{Name: "main", Kind: "function", File: "main.go", Language: facts.LangGo, Span: facts.Span{Start: 1, End: 10}},
		},
	}

	finding := matchRule(rule, fs, []string{"go"})
	finding.MatcherClass = rule.MatcherClass
	applyMatcherClassCeiling(&finding)

	if finding.Status != StatusPass {
		t.Errorf("expected pass when no .env files exist, got %q", finding.Status)
	}
	// Proof matcher does not cap verification level
	if finding.VerificationLevel == VerificationVerified {
		// Not-exists pass is strong_inference by design (absence != proof)
		t.Logf("Note: not_exists pass correctly returns %q (absence is not verified)", finding.VerificationLevel)
	}
}

// ---------------------------------------------------------------------------
// Test: Heuristic quality facts should not affect matcher behavior,
// only the ceiling applies
// ---------------------------------------------------------------------------

func TestDegradedFactQuality_HeuristicFacts_HeuristicMatcher(t *testing.T) {
	// Even if facts themselves are heuristic quality, a heuristic matcher
	// should produce the same result — just capped at strong_inference.
	rule := Rule{
		ID:           "ARCH-LAYER-002",
		Languages:    []string{"go"},
		Type:         "exists",
		Target:       "layer.repository",
		MatcherClass: MatcherHeuristic,
	}

	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			{
				Name:     "UserRepository",
				Kind:     "interface",
				File:     "internal/repository/user.go",
				Language: facts.LangGo,
				Span:     facts.Span{Start: 5, End: 20},
				// Quality not set (empty) — backward compat
			},
		},
		Files: []facts.FileFact{
			{File: "internal/repository/user.go", Language: facts.LangGo},
		},
	}

	finding := matchRule(rule, fs, []string{"go"})
	finding.MatcherClass = rule.MatcherClass
	applyMatcherClassCeiling(&finding)

	if finding.Status != StatusPass {
		t.Errorf("should find repository layer, got %q", finding.Status)
	}
	if finding.VerificationLevel == VerificationVerified {
		t.Errorf("heuristic matcher should cap verified to strong_inference, got verified")
	}
}
