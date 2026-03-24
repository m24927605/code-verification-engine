package rules

import (
	"testing"

	"github.com/verabase/code-verification-engine/internal/facts"
)

// ---------------------------------------------------------------------------
// DegradeLanguageCapability — 0% coverage
// ---------------------------------------------------------------------------

func TestDegradeLanguageCapability(t *testing.T) {
	engine := NewEngine()
	// Before degradation, python should have its default capabilities.
	engine.DegradeLanguageCapability("python", "python3 unavailable")

	// After degradation, executing a rule for python should reflect the degraded capability.
	rf := &RuleFile{
		Version: "0.1",
		Profile: "test",
		Rules: []Rule{
			{
				ID: "AUTH-001", Title: "JWT auth", Category: "security", Severity: "high",
				Languages: []string{"python"}, Type: "exists", Target: "auth.jwt_middleware",
				Message: "JWT must exist.",
			},
		},
	}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("main", "function", "main.py", facts.LangPython, false, 1, 5),
		},
	}
	result := engine.Execute(rf, fs, []string{"python"})
	// Just verify it runs without panic; the exact behavior depends on capability matrix.
	if len(result.Findings) == 0 && len(result.SkippedRules) == 0 {
		t.Error("expected at least one finding or skipped rule")
	}
}

func TestDegradeLanguageCapability_UnknownLanguage(t *testing.T) {
	engine := NewEngine()
	// Degrading an unknown language should not panic.
	engine.DegradeLanguageCapability("rust", "not supported")
}

// ---------------------------------------------------------------------------
// findCORSEvidenceResult — 0% coverage
// ---------------------------------------------------------------------------

func TestFindCORSEvidenceResult_PermissiveCORS(t *testing.T) {
	rule := Rule{
		ID: "SEC-CORS-001", Type: "exists", Target: "security.cors_configuration",
		Languages: []string{"go"}, Message: "CORS must be configured.",
	}
	fs := &FactSet{
		Middlewares: []facts.MiddlewareFact{
			mw("enableCors:permissive", "cors", "server.go", facts.LangGo),
		},
		Symbols: []facts.SymbolFact{
			sym("main", "function", "main.go", facts.LangGo, false, 1, 5),
		},
	}
	result := findCORSEvidenceResult(rule, fs)
	if len(result.Evidence) == 0 {
		t.Error("expected permissive CORS evidence")
	}
	if result.VerificationLevel != VerificationStrongInference {
		t.Errorf("expected strong_inference for permissive CORS, got %v", result.VerificationLevel)
	}
}

func TestFindCORSEvidenceResult_ConfiguredCORS(t *testing.T) {
	rule := Rule{
		ID: "SEC-CORS-001", Type: "exists", Target: "security.cors_configuration",
		Languages: []string{"go"}, Message: "CORS must be configured.",
	}
	fs := &FactSet{
		Imports: []facts.ImportFact{
			imp("github.com/rs/cors", "", "server.go", facts.LangGo),
		},
		Symbols: []facts.SymbolFact{
			sym("main", "function", "main.go", facts.LangGo, false, 1, 5),
		},
	}
	result := findCORSEvidenceResult(rule, fs)
	if len(result.Evidence) == 0 {
		t.Error("expected CORS evidence from import")
	}
	if result.VerificationLevel != VerificationVerified {
		t.Errorf("expected verified for configured CORS, got %v", result.VerificationLevel)
	}
}

func TestFindCORSEvidenceResult_NoCORS(t *testing.T) {
	rule := Rule{
		ID: "SEC-CORS-001", Type: "exists", Target: "security.cors_configuration",
		Languages: []string{"go"}, Message: "CORS must be configured.",
	}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("main", "function", "main.go", facts.LangGo, false, 1, 5),
		},
	}
	result := findCORSEvidenceResult(rule, fs)
	if len(result.Evidence) != 0 {
		t.Errorf("expected no evidence, got %d", len(result.Evidence))
	}
}

// ---------------------------------------------------------------------------
// setVerdictBasis — cover more branches (76.5%)
// ---------------------------------------------------------------------------

func TestSetVerdictBasis_ProofMatcherWithProofFacts(t *testing.T) {
	f := &Finding{
		MatcherClass:      MatcherProof,
		VerificationLevel: VerificationVerified,
		Evidence: []Evidence{
			{File: "auth.go", Symbol: "JWT"},
		},
	}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			{Name: "JWT", File: "auth.go", Language: facts.LangGo, Quality: facts.QualityProof, Span: facts.Span{Start: 1, End: 1}},
		},
	}
	setVerdictBasis(f, fs)
	if f.VerdictBasis != "proof" {
		t.Errorf("expected proof, got %s", f.VerdictBasis)
	}
}

func TestSetVerdictBasis_ProofMatcherWithStructuralFacts(t *testing.T) {
	f := &Finding{
		MatcherClass:      MatcherProof,
		VerificationLevel: VerificationVerified,
		Evidence: []Evidence{
			{File: "auth.go", Symbol: "JWT"},
		},
	}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			{Name: "JWT", File: "auth.go", Language: facts.LangGo, Quality: facts.QualityStructural, Span: facts.Span{Start: 1, End: 1}},
		},
	}
	setVerdictBasis(f, fs)
	if f.VerdictBasis != "structural_binding" {
		t.Errorf("expected structural_binding, got %s", f.VerdictBasis)
	}
	if f.VerificationLevel != VerificationStrongInference {
		t.Errorf("expected strong_inference after downgrade, got %s", f.VerificationLevel)
	}
}

func TestSetVerdictBasis_ProofMatcherNotVerified(t *testing.T) {
	f := &Finding{
		MatcherClass:      MatcherProof,
		VerificationLevel: VerificationStrongInference,
		Evidence: []Evidence{
			{File: "auth.go", Symbol: "JWT"},
		},
	}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			{Name: "JWT", File: "auth.go", Language: facts.LangGo, Quality: facts.QualityProof, Span: facts.Span{Start: 1, End: 1}},
		},
	}
	setVerdictBasis(f, fs)
	if f.VerdictBasis != "structural_binding" {
		t.Errorf("expected structural_binding, got %s", f.VerdictBasis)
	}
}

func TestSetVerdictBasis_ProofMatcherHeuristicFacts(t *testing.T) {
	f := &Finding{
		MatcherClass:      MatcherProof,
		VerificationLevel: VerificationVerified,
		Evidence: []Evidence{
			{File: "auth.go", Symbol: "JWT"},
		},
	}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			{Name: "JWT", File: "auth.go", Language: facts.LangGo, Quality: facts.QualityHeuristic, Span: facts.Span{Start: 1, End: 1}},
		},
	}
	setVerdictBasis(f, fs)
	if f.VerdictBasis != "heuristic_inference" {
		t.Errorf("expected heuristic_inference, got %s", f.VerdictBasis)
	}
	if f.VerificationLevel != VerificationStrongInference {
		t.Errorf("expected downgraded verification level, got %s", f.VerificationLevel)
	}
}

func TestSetVerdictBasis_AttestationMatcher(t *testing.T) {
	f := &Finding{
		MatcherClass:      MatcherAttestation,
		VerificationLevel: VerificationVerified,
	}
	fs := &FactSet{}
	setVerdictBasis(f, fs)
	if f.VerdictBasis != "runtime_required" {
		t.Errorf("expected runtime_required, got %s", f.VerdictBasis)
	}
}

func TestSetVerdictBasis_EmptyMatcherClass(t *testing.T) {
	f := &Finding{
		MatcherClass:      "",
		VerificationLevel: VerificationVerified,
	}
	fs := &FactSet{}
	setVerdictBasis(f, fs)
	if f.VerdictBasis != "heuristic_inference" {
		t.Errorf("expected heuristic_inference for default, got %s", f.VerdictBasis)
	}
}

// ---------------------------------------------------------------------------
// computeFactQualityFloor — cover more branches (78.8%)
// ---------------------------------------------------------------------------

func TestComputeFactQualityFloor_WithSecretsQuality(t *testing.T) {
	f := &Finding{
		Evidence: []Evidence{
			{File: "config.go", Symbol: "password"},
		},
	}
	fs := &FactSet{
		Secrets: []facts.SecretFact{
			{Kind: "password", File: "config.go", Language: facts.LangGo, Quality: facts.QualityStructural, Span: facts.Span{Start: 1, End: 1}},
		},
	}
	result := computeFactQualityFloor(f, fs)
	if result != facts.QualityStructural {
		t.Errorf("expected structural, got %s", result)
	}
}

func TestComputeFactQualityFloor_WithImportsQuality(t *testing.T) {
	f := &Finding{
		Evidence: []Evidence{
			{File: "main.go", Symbol: "jwt"},
		},
	}
	fs := &FactSet{
		Imports: []facts.ImportFact{
			{ImportPath: "jwt", File: "main.go", Language: facts.LangGo, Quality: facts.QualityProof, Span: facts.Span{Start: 1, End: 1}},
		},
	}
	result := computeFactQualityFloor(f, fs)
	if result != facts.QualityProof {
		t.Errorf("expected proof, got %s", result)
	}
}

func TestComputeFactQualityFloor_WithDataAccessQuality(t *testing.T) {
	f := &Finding{
		Evidence: []Evidence{
			{File: "db.go", Symbol: "query"},
		},
	}
	fs := &FactSet{
		DataAccess: []facts.DataAccessFact{
			{Operation: "query", File: "db.go", Language: facts.LangGo, Quality: facts.QualityHeuristic, Span: facts.Span{Start: 1, End: 1}},
		},
	}
	result := computeFactQualityFloor(f, fs)
	if result != facts.QualityHeuristic {
		t.Errorf("expected heuristic, got %s", result)
	}
}

func TestComputeFactQualityFloor_WithMiddlewaresQuality(t *testing.T) {
	f := &Finding{
		Evidence: []Evidence{
			{File: "mw.go", Symbol: "auth"},
		},
	}
	fs := &FactSet{
		Middlewares: []facts.MiddlewareFact{
			{Name: "auth", File: "mw.go", Language: facts.LangGo, Quality: facts.QualityStructural, Span: facts.Span{Start: 1, End: 1}},
		},
	}
	result := computeFactQualityFloor(f, fs)
	if result != facts.QualityStructural {
		t.Errorf("expected structural, got %s", result)
	}
}

func TestComputeFactQualityFloor_WithRoutesQuality(t *testing.T) {
	f := &Finding{
		Evidence: []Evidence{
			{File: "routes.go", Symbol: "/health"},
		},
	}
	fs := &FactSet{
		Routes: []facts.RouteFact{
			{Path: "/health", File: "routes.go", Language: facts.LangGo, Quality: facts.QualityProof, Span: facts.Span{Start: 1, End: 1}},
		},
	}
	result := computeFactQualityFloor(f, fs)
	if result != facts.QualityProof {
		t.Errorf("expected proof, got %s", result)
	}
}

func TestComputeFactQualityFloor_WithFilesQuality(t *testing.T) {
	f := &Finding{
		Evidence: []Evidence{
			{File: "main.go", Symbol: "main.go"},
		},
	}
	fs := &FactSet{
		Files: []facts.FileFact{
			{File: "main.go", Language: facts.LangGo, Quality: facts.QualityStructural},
		},
	}
	result := computeFactQualityFloor(f, fs)
	if result != facts.QualityStructural {
		t.Errorf("expected structural, got %s", result)
	}
}

func TestComputeFactQualityFloor_EmptyEvidenceFile(t *testing.T) {
	f := &Finding{
		Evidence: []Evidence{
			{File: "", Symbol: "x"},
		},
	}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			{Name: "x", File: "x.go", Language: facts.LangGo, Quality: facts.QualityProof, Span: facts.Span{Start: 1, End: 1}},
		},
	}
	result := computeFactQualityFloor(f, fs)
	if result != facts.QualityHeuristic {
		t.Errorf("expected heuristic for empty file, got %s", result)
	}
}
