package rules

import (
	"testing"

	"github.com/verabase/code-verification-engine/internal/facts"
)

func TestEngineExecuteFullRuleFile(t *testing.T) {
	rf := &RuleFile{
		Version: "0.1",
		Profile: "test",
		Rules: []Rule{
			{
				ID: "AUTH-001", Title: "JWT auth", Category: "security", Severity: "high",
				Languages: []string{"go"}, Type: "exists", Target: "auth.jwt_middleware",
				Message: "JWT must exist.",
			},
			{
				ID: "SEC-001", Title: "No secrets", Category: "security", Severity: "critical",
				Languages: []string{"go"}, Type: "not_exists", Target: "secret.hardcoded_credential",
				Message: "No hardcoded creds.",
			},
		},
	}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("VerifyToken", "function", "auth/jwt.go", facts.LangGo, true, 10, 30),
		},
		Middlewares: []facts.MiddlewareFact{
			mw("JWTMiddleware", "auth", "auth/jwt.go", facts.LangGo),
		},
		Imports: []facts.ImportFact{
			imp("github.com/golang-jwt/jwt/v5", "", "auth/jwt.go", facts.LangGo),
		},
		Files: []facts.FileFact{
			fileFact("auth/jwt.go", facts.LangGo),
		},
	}
	engine := NewEngine()
	result := engine.Execute(rf, fs, []string{"go"})

	if len(result.Findings) != 2 {
		t.Fatalf("findings count = %d, want 2", len(result.Findings))
	}
	if result.Findings[0].Status != StatusPass {
		t.Errorf("AUTH-001 status = %v, want pass", result.Findings[0].Status)
	}
	if result.Findings[1].Status != StatusPass {
		t.Errorf("SEC-001 status = %v, want pass", result.Findings[1].Status)
	}
}

func TestEngineSkipsRulesForUnsupportedLanguages(t *testing.T) {
	rf := &RuleFile{
		Version: "0.1",
		Profile: "test",
		Rules: []Rule{
			{
				ID: "TS-001", Title: "TS only rule", Category: "security", Severity: "high",
				Languages: []string{"typescript"}, Type: "exists", Target: "auth.jwt_middleware",
				Message: "TS only.",
			},
		},
	}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("main", "function", "main.go", facts.LangGo, false, 1, 5),
		},
	}
	engine := NewEngine()
	result := engine.Execute(rf, fs, []string{"go"})

	if len(result.Findings) != 0 {
		t.Errorf("findings count = %d, want 0 (rule should be skipped)", len(result.Findings))
	}
	if len(result.SkippedRules) != 1 {
		t.Fatalf("skipped_rules count = %d, want 1", len(result.SkippedRules))
	}
	if result.SkippedRules[0].RuleID != "TS-001" {
		t.Errorf("skipped rule = %v, want TS-001", result.SkippedRules[0].RuleID)
	}
}

func TestEngineProducesOrderedFindings(t *testing.T) {
	rf := &RuleFile{
		Version: "0.1",
		Profile: "test",
		Rules: []Rule{
			{ID: "B-001", Title: "B", Category: "x", Severity: "low",
				Languages: []string{"go"}, Type: "exists", Target: "auth.jwt_middleware", Message: "B."},
			{ID: "A-001", Title: "A", Category: "x", Severity: "low",
				Languages: []string{"go"}, Type: "exists", Target: "auth.jwt_middleware", Message: "A."},
		},
	}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("main", "function", "main.go", facts.LangGo, false, 1, 5),
		},
	}
	engine := NewEngine()
	result := engine.Execute(rf, fs, []string{"go"})

	if len(result.Findings) != 2 {
		t.Fatalf("findings count = %d, want 2", len(result.Findings))
	}
	if result.Findings[0].RuleID != "B-001" {
		t.Errorf("first finding = %v, want B-001", result.Findings[0].RuleID)
	}
	if result.Findings[1].RuleID != "A-001" {
		t.Errorf("second finding = %v, want A-001", result.Findings[1].RuleID)
	}
}

func TestEngineMultipleLanguageOverlap(t *testing.T) {
	rf := &RuleFile{
		Version: "0.1",
		Profile: "test",
		Rules: []Rule{
			{
				ID: "AUTH-001", Title: "JWT auth", Category: "security", Severity: "high",
				Languages: []string{"go", "typescript"}, Type: "exists", Target: "auth.jwt_middleware",
				Message: "JWT must exist.",
			},
		},
	}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("VerifyToken", "function", "auth/jwt.go", facts.LangGo, true, 10, 30),
		},
		Middlewares: []facts.MiddlewareFact{
			mw("JWTMiddleware", "auth", "auth/jwt.go", facts.LangGo),
		},
		Imports: []facts.ImportFact{
			imp("github.com/golang-jwt/jwt/v5", "", "auth/jwt.go", facts.LangGo),
		},
	}
	engine := NewEngine()
	result := engine.Execute(rf, fs, []string{"go"})

	if len(result.Findings) != 1 {
		t.Fatalf("findings count = %d, want 1", len(result.Findings))
	}
	if result.Findings[0].Status != StatusPass {
		t.Errorf("status = %v, want pass", result.Findings[0].Status)
	}
}

func TestEngineEmptyRuleFile(t *testing.T) {
	rf := &RuleFile{Version: "0.1", Profile: "test"}
	fs := &FactSet{}
	engine := NewEngine()
	result := engine.Execute(rf, fs, []string{"go"})
	if len(result.Findings) != 0 {
		t.Errorf("findings count = %d, want 0", len(result.Findings))
	}
}
