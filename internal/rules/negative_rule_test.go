package rules

import (
	"testing"

	"github.com/verabase/code-verification-engine/internal/facts"
)

// ---------------------------------------------------------------------------
// Coverage-aware pass trust gate tests
// ---------------------------------------------------------------------------

func TestNegativeRule_PassWithFullAnalyzerCoverage(t *testing.T) {
	rule := Rule{
		ID: "SEC-SECRET-001", Type: "not_exists", Target: "secret.hardcoded_credential",
		Languages: []string{"typescript"}, Message: "No hardcoded creds.",
		MatcherClass: MatcherProof, TrustedPassAllowed: true,
	}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("main", "function", "main.ts", facts.LangTypeScript, false, 1, 5),
		},
		Files: []facts.FileFact{
			fileFact("main.ts", facts.LangTypeScript),
		},
		AnalyzerStatus: map[string]string{
			"typescript": "ok",
		},
	}
	finding := matchNotExists(rule, fs, []string{"typescript"})
	if finding.Status != StatusPass {
		t.Fatalf("status = %v, want pass", finding.Status)
	}
	if finding.Confidence != ConfidenceMedium {
		t.Errorf("confidence = %v, want medium", finding.Confidence)
	}
	if finding.VerificationLevel != VerificationStrongInference {
		t.Errorf("level = %v, want strong_inference", finding.VerificationLevel)
	}
	if len(finding.UnknownReasons) != 0 {
		t.Errorf("unexpected unknown reasons: %v", finding.UnknownReasons)
	}
}

func TestNegativeRule_PassWithPartialAnalyzer(t *testing.T) {
	rule := Rule{
		ID: "ARCH-LAYER-001", Type: "not_exists", Target: "db.direct_access_from_controller",
		Languages: []string{"typescript"}, Message: "No direct DB access.",
		MatcherClass: MatcherStructural,
	}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("UserController", "function", "controller.ts", facts.LangTypeScript, true, 5, 20),
		},
		Files: []facts.FileFact{
			fileFact("controller.ts", facts.LangTypeScript),
		},
		AnalyzerStatus: map[string]string{
			"typescript": "partial",
		},
	}
	finding := matchNotExists(rule, fs, []string{"typescript"})
	if finding.Status != StatusPass {
		t.Fatalf("status = %v, want pass", finding.Status)
	}
	if finding.Confidence != ConfidenceLow {
		t.Errorf("confidence = %v, want low (partial analyzer)", finding.Confidence)
	}
	if finding.VerificationLevel != VerificationWeakInference {
		t.Errorf("level = %v, want weak_inference (partial analyzer)", finding.VerificationLevel)
	}
}

func TestNegativeRule_PassWithMissingAnalyzer(t *testing.T) {
	rule := Rule{
		ID: "FE-XSS-001", Type: "not_exists", Target: "frontend.xss_dangerous_html",
		Languages: []string{"javascript", "typescript"}, Message: "No dangerous HTML.",
		MatcherClass: MatcherHeuristic,
	}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("App", "function", "App.tsx", facts.LangTypeScript, true, 1, 30),
		},
		Imports: []facts.ImportFact{
			imp("react", "", "App.tsx", facts.LangTypeScript),
		},
		AnalyzerStatus: map[string]string{
			"typescript": "ok",
			// "javascript" is missing — not all languages covered
		},
	}
	finding := matchNotExists(rule, fs, []string{"typescript", "javascript"})
	if finding.Status != StatusPass {
		t.Fatalf("status = %v, want pass", finding.Status)
	}
	if finding.Confidence != ConfidenceLow {
		t.Errorf("confidence = %v, want low (missing analyzer)", finding.Confidence)
	}
	if finding.VerificationLevel != VerificationWeakInference {
		t.Errorf("level = %v, want weak_inference (missing analyzer)", finding.VerificationLevel)
	}
	// Should have analyzer_incomplete reason
	hasIncomplete := false
	for _, r := range finding.UnknownReasons {
		if r == UnknownAnalyzerIncomplete {
			hasIncomplete = true
		}
	}
	if !hasIncomplete {
		t.Errorf("expected UnknownAnalyzerIncomplete in reasons, got %v", finding.UnknownReasons)
	}
}

func TestNegativeRule_PassWithErrorAnalyzer(t *testing.T) {
	rule := Rule{
		ID: "FE-TOKEN-001", Type: "not_exists", Target: "frontend.token_in_localstorage",
		Languages: []string{"typescript"}, Message: "No localStorage tokens.",
		MatcherClass: MatcherHeuristic,
	}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("login", "function", "auth.ts", facts.LangTypeScript, false, 1, 20),
		},
		AnalyzerStatus: map[string]string{
			"typescript": "error",
		},
	}
	finding := matchNotExists(rule, fs, []string{"typescript"})
	if finding.Status != StatusPass {
		t.Fatalf("status = %v, want pass", finding.Status)
	}
	if finding.Confidence != ConfidenceLow {
		t.Errorf("confidence = %v, want low (error analyzer)", finding.Confidence)
	}
	if finding.VerificationLevel != VerificationWeakInference {
		t.Errorf("level = %v, want weak_inference (error analyzer)", finding.VerificationLevel)
	}
	hasIncomplete := false
	for _, r := range finding.UnknownReasons {
		if r == UnknownAnalyzerIncomplete {
			hasIncomplete = true
		}
	}
	if !hasIncomplete {
		t.Errorf("expected UnknownAnalyzerIncomplete in reasons, got %v", finding.UnknownReasons)
	}
}

func TestNegativeRule_FailAlwaysVerifiedRegardlessOfCoverage(t *testing.T) {
	rule := Rule{
		ID: "SEC-SECRET-001", Type: "not_exists", Target: "secret.hardcoded_credential",
		Languages: []string{"typescript"}, Message: "No hardcoded creds.",
		MatcherClass: MatcherProof, TrustedPassAllowed: true,
	}
	fs := &FactSet{
		Files: []facts.FileFact{
			fileFact("config.ts", facts.LangTypeScript),
		},
		Secrets: []facts.SecretFact{
			secret("api_key", "config.ts", facts.LangTypeScript, 10),
		},
		// Even with missing/partial analyzer, fail should stay verified
		AnalyzerStatus: map[string]string{
			"typescript": "partial",
		},
	}
	finding := matchNotExists(rule, fs, []string{"typescript"})
	if finding.Status != StatusFail {
		t.Fatalf("status = %v, want fail", finding.Status)
	}
	if finding.Confidence != ConfidenceHigh {
		t.Errorf("confidence = %v, want high (fail with evidence)", finding.Confidence)
	}
	if finding.VerificationLevel != VerificationVerified {
		t.Errorf("level = %v, want verified (fail with evidence)", finding.VerificationLevel)
	}
}

func TestNegativeRule_NilAnalyzerStatusPreservesBackwardCompat(t *testing.T) {
	// When AnalyzerStatus is nil (pre-Phase-5), pass should still be strong_inference
	rule := Rule{
		ID: "ARCH-LAYER-001", Type: "not_exists", Target: "db.direct_access_from_controller",
		Languages: []string{"go"}, Message: "No direct DB access.",
	}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("UserController", "function", "controller/user.go", facts.LangGo, true, 5, 20),
		},
		Files: []facts.FileFact{
			fileFact("controller/user.go", facts.LangGo),
		},
		// AnalyzerStatus is nil — backward compat
	}
	finding := matchNotExists(rule, fs, []string{"go"})
	if finding.Status != StatusPass {
		t.Fatalf("status = %v, want pass", finding.Status)
	}
	if finding.Confidence != ConfidenceMedium {
		t.Errorf("confidence = %v, want medium (nil AnalyzerStatus = backward compat)", finding.Confidence)
	}
	if finding.VerificationLevel != VerificationStrongInference {
		t.Errorf("level = %v, want strong_inference (nil AnalyzerStatus = backward compat)", finding.VerificationLevel)
	}
}

// ---------------------------------------------------------------------------
// Pass/fail asymmetry tests per negative-rule family
// ---------------------------------------------------------------------------

func TestNegativeRule_SEC_SECRET_001_Asymmetry(t *testing.T) {
	rule := Rule{
		ID: "SEC-SECRET-001", Type: "not_exists", Target: "secret.hardcoded_credential",
		Languages: []string{"go"}, Message: "No hardcoded creds.",
		MatcherClass: MatcherProof, TrustedPassAllowed: true,
	}

	// Fail: concrete evidence -> verified + high
	fsFail := &FactSet{
		Secrets: []facts.SecretFact{
			secret("password", "config.go", facts.LangGo, 15),
		},
		AnalyzerStatus: map[string]string{"go": "ok"},
	}
	fail := matchNotExists(rule, fsFail, []string{"go"})
	if fail.Status != StatusFail {
		t.Fatalf("fail status = %v, want fail", fail.Status)
	}
	if fail.VerificationLevel != VerificationVerified {
		t.Errorf("fail level = %v, want verified", fail.VerificationLevel)
	}
	if fail.Confidence != ConfidenceHigh {
		t.Errorf("fail confidence = %v, want high", fail.Confidence)
	}

	// Pass: no evidence -> at most strong_inference + medium
	fsPass := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("main", "function", "main.go", facts.LangGo, false, 1, 5),
		},
		Files: []facts.FileFact{
			fileFact("main.go", facts.LangGo),
		},
		AnalyzerStatus: map[string]string{"go": "ok"},
	}
	pass := matchNotExists(rule, fsPass, []string{"go"})
	if pass.Status != StatusPass {
		t.Fatalf("pass status = %v, want pass", pass.Status)
	}
	if pass.VerificationLevel == VerificationVerified {
		t.Errorf("pass should NOT be verified — at most strong_inference")
	}
	if pass.Confidence == ConfidenceHigh {
		t.Errorf("pass confidence should NOT be high — at most medium")
	}
}

func TestNegativeRule_ARCH_LAYER_001_Asymmetry(t *testing.T) {
	rule := Rule{
		ID: "ARCH-LAYER-001", Type: "not_exists", Target: "db.direct_access_from_controller",
		Languages: []string{"go"}, Message: "No direct DB from controller.",
		MatcherClass: MatcherStructural,
	}

	// Fail: direct DB access from controller
	fsFail := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("getUserController", "function", "internal/controller/user.go", facts.LangGo, true, 10, 25),
		},
		DataAccess: []facts.DataAccessFact{
			dataAccess("direct_query", "internal/controller/user.go", facts.LangGo),
		},
		Files: []facts.FileFact{
			fileFact("internal/controller/user.go", facts.LangGo),
		},
		AnalyzerStatus: map[string]string{"go": "ok"},
	}
	fail := matchNotExists(rule, fsFail, []string{"go"})
	if fail.Status != StatusFail {
		t.Fatalf("fail status = %v, want fail", fail.Status)
	}
	if fail.VerificationLevel != VerificationVerified {
		t.Errorf("fail level = %v, want verified", fail.VerificationLevel)
	}
	if fail.Confidence != ConfidenceHigh {
		t.Errorf("fail confidence = %v, want high", fail.Confidence)
	}

	// Pass
	fsPass := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("UserController", "function", "internal/controller/user.go", facts.LangGo, true, 5, 20),
		},
		Files: []facts.FileFact{
			fileFact("internal/controller/user.go", facts.LangGo),
		},
		AnalyzerStatus: map[string]string{"go": "ok"},
	}
	pass := matchNotExists(rule, fsPass, []string{"go"})
	if pass.Status != StatusPass {
		t.Fatalf("pass status = %v, want pass", pass.Status)
	}
	if pass.VerificationLevel == VerificationVerified {
		t.Errorf("pass should NOT be verified")
	}
	if pass.Confidence == ConfidenceHigh {
		t.Errorf("pass confidence should NOT be high")
	}
}

func TestNegativeRule_FE_XSS_001_Asymmetry(t *testing.T) {
	rule := Rule{
		ID: "FE-XSS-001", Type: "not_exists", Target: "frontend.xss_dangerous_html",
		Languages: []string{"javascript", "typescript"}, Message: "No dangerouslySetInnerHTML.",
		MatcherClass: MatcherHeuristic,
	}

	// Fail: dangerous HTML found
	fsFail := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("dangerouslySetInnerHTML", "property", "App.jsx", facts.LangJavaScript, false, 10, 10),
		},
		AnalyzerStatus: map[string]string{"javascript": "ok", "typescript": "ok"},
	}
	fail := matchNotExists(rule, fsFail, []string{"javascript", "typescript"})
	if fail.Status != StatusFail {
		t.Fatalf("fail status = %v, want fail", fail.Status)
	}
	if fail.VerificationLevel != VerificationVerified {
		t.Errorf("fail level = %v, want verified", fail.VerificationLevel)
	}
	if fail.Confidence != ConfidenceHigh {
		t.Errorf("fail confidence = %v, want high", fail.Confidence)
	}

	// Pass with full coverage
	fsPass := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("App", "function", "App.tsx", facts.LangTypeScript, true, 1, 30),
		},
		Imports: []facts.ImportFact{
			imp("react", "", "App.tsx", facts.LangTypeScript),
		},
		AnalyzerStatus: map[string]string{"javascript": "ok", "typescript": "ok"},
	}
	pass := matchNotExists(rule, fsPass, []string{"javascript", "typescript"})
	if pass.Status != StatusPass {
		t.Fatalf("pass status = %v, want pass", pass.Status)
	}
	if pass.VerificationLevel == VerificationVerified {
		t.Errorf("pass should NOT be verified")
	}
	if pass.Confidence == ConfidenceHigh {
		t.Errorf("pass confidence should NOT be high")
	}
}

func TestNegativeRule_FE_TOKEN_001_Asymmetry(t *testing.T) {
	rule := Rule{
		ID: "FE-TOKEN-001", Type: "not_exists", Target: "frontend.token_in_localstorage",
		Languages: []string{"javascript", "typescript"}, Message: "No localStorage tokens.",
		MatcherClass: MatcherHeuristic,
	}

	// Fail: localStorage token found
	fsFail := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("localStorageSetToken", "function", "auth.js", facts.LangJavaScript, false, 10, 15),
		},
		AnalyzerStatus: map[string]string{"javascript": "ok", "typescript": "ok"},
	}
	fail := matchNotExists(rule, fsFail, []string{"javascript", "typescript"})
	if fail.Status != StatusFail {
		t.Fatalf("fail status = %v, want fail", fail.Status)
	}
	if fail.VerificationLevel != VerificationVerified {
		t.Errorf("fail level = %v, want verified", fail.VerificationLevel)
	}
	if fail.Confidence != ConfidenceHigh {
		t.Errorf("fail confidence = %v, want high", fail.Confidence)
	}

	// Pass with full coverage
	fsPass := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("login", "function", "auth.ts", facts.LangTypeScript, false, 1, 20),
		},
		AnalyzerStatus: map[string]string{"javascript": "ok", "typescript": "ok"},
	}
	pass := matchNotExists(rule, fsPass, []string{"javascript", "typescript"})
	if pass.Status != StatusPass {
		t.Fatalf("pass status = %v, want pass", pass.Status)
	}
	if pass.VerificationLevel == VerificationVerified {
		t.Errorf("pass should NOT be verified")
	}
	if pass.Confidence == ConfidenceHigh {
		t.Errorf("pass confidence should NOT be high")
	}
}

// ---------------------------------------------------------------------------
// analyzerCoverageForRule unit tests
// ---------------------------------------------------------------------------

func TestAnalyzerCoverageForRule_NilFactSet(t *testing.T) {
	got := analyzerCoverageForRule(nil, []string{"go"}, []string{"go"})
	if got != analyzerCoverageOK {
		t.Errorf("nil FactSet: got %v, want OK", got)
	}
}

func TestAnalyzerCoverageForRule_NilAnalyzerStatus(t *testing.T) {
	fs := &FactSet{}
	got := analyzerCoverageForRule(fs, []string{"go"}, []string{"go"})
	if got != analyzerCoverageOK {
		t.Errorf("nil AnalyzerStatus: got %v, want OK", got)
	}
}

func TestAnalyzerCoverageForRule_AllOK(t *testing.T) {
	fs := &FactSet{
		AnalyzerStatus: map[string]string{
			"go":         "ok",
			"typescript": "ok",
		},
	}
	got := analyzerCoverageForRule(fs, []string{"go", "typescript"}, []string{"go", "typescript"})
	if got != analyzerCoverageOK {
		t.Errorf("all OK: got %v, want OK", got)
	}
}

func TestAnalyzerCoverageForRule_OnePartial(t *testing.T) {
	fs := &FactSet{
		AnalyzerStatus: map[string]string{
			"go":         "ok",
			"typescript": "partial",
		},
	}
	got := analyzerCoverageForRule(fs, []string{"go", "typescript"}, []string{"go", "typescript"})
	if got != analyzerCoveragePartial {
		t.Errorf("one partial: got %v, want Partial", got)
	}
}

func TestAnalyzerCoverageForRule_OneError(t *testing.T) {
	fs := &FactSet{
		AnalyzerStatus: map[string]string{
			"go":         "ok",
			"typescript": "error",
		},
	}
	got := analyzerCoverageForRule(fs, []string{"go", "typescript"}, []string{"go", "typescript"})
	if got != analyzerCoverageMissing {
		t.Errorf("one error: got %v, want Missing", got)
	}
}

func TestAnalyzerCoverageForRule_OneMissing(t *testing.T) {
	fs := &FactSet{
		AnalyzerStatus: map[string]string{
			"go": "ok",
			// typescript not present
		},
	}
	got := analyzerCoverageForRule(fs, []string{"go", "typescript"}, []string{"go", "typescript"})
	if got != analyzerCoverageMissing {
		t.Errorf("one missing: got %v, want Missing", got)
	}
}

func TestAnalyzerCoverageForRule_ErrorTrumpPartial(t *testing.T) {
	fs := &FactSet{
		AnalyzerStatus: map[string]string{
			"go":         "error",
			"typescript": "partial",
		},
	}
	got := analyzerCoverageForRule(fs, []string{"go", "typescript"}, []string{"go", "typescript"})
	if got != analyzerCoverageMissing {
		t.Errorf("error trumps partial: got %v, want Missing", got)
	}
}

func TestAnalyzerCoverageForRule_RepoLanguageIntersection(t *testing.T) {
	// A Go-only repo should NOT require JS/TS/Python analyzers to achieve
	// full coverage, even if the rule is declared against allLanguages.
	fs := &FactSet{
		AnalyzerStatus: map[string]string{
			"go": "ok",
			// No typescript, javascript, python entries
		},
	}
	// Rule declared with allLanguages, but repo only has Go
	ruleLanguages := []string{"go", "javascript", "typescript", "python"}
	repoLanguages := []string{"go"}
	got := analyzerCoverageForRule(fs, ruleLanguages, repoLanguages)
	if got != analyzerCoverageOK {
		t.Errorf("Go-only repo with Go=ok should be full coverage, got %v", got)
	}
}

func TestAnalyzerCoverageForRule_RepoLanguageIntersection_MissingRelevant(t *testing.T) {
	// If the repo has Go AND TypeScript, but only Go analyzer ran,
	// that's still incomplete coverage.
	fs := &FactSet{
		AnalyzerStatus: map[string]string{
			"go": "ok",
		},
	}
	ruleLanguages := []string{"go", "javascript", "typescript", "python"}
	repoLanguages := []string{"go", "typescript"}
	got := analyzerCoverageForRule(fs, ruleLanguages, repoLanguages)
	if got != analyzerCoverageMissing {
		t.Errorf("Go+TS repo with only Go=ok should be missing, got %v", got)
	}
}

// ---------------------------------------------------------------------------
// TrustedPassAllowed field tests
// ---------------------------------------------------------------------------

func TestTrustedPassAllowed_SetOnProofMatcherRules(t *testing.T) {
	profiles := AllProfiles()
	for _, profile := range profiles {
		for _, rule := range profile.Rules {
			if rule.Type != "not_exists" {
				continue
			}
			switch rule.ID {
			case "SEC-SECRET-001", "SEC-SECRET-003":
				if !rule.TrustedPassAllowed {
					t.Errorf("rule %s should have TrustedPassAllowed=true", rule.ID)
				}
			default:
				if rule.TrustedPassAllowed {
					t.Errorf("rule %s should have TrustedPassAllowed=false (default)", rule.ID)
				}
			}
		}
	}
}
