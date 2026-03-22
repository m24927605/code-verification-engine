package rules

import (
	"testing"

	"github.com/verabase/code-verification-engine/internal/facts"
)

func TestExistsMatcherPass(t *testing.T) {
	rule := Rule{
		ID: "AUTH-001", Type: "exists", Target: "auth.jwt_middleware",
		Languages: []string{"go"}, Message: "JWT auth must exist.",
	}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("VerifyToken", "function", "internal/auth/jwt.go", facts.LangGo, true, 10, 30),
		},
		Middlewares: []facts.MiddlewareFact{
			mw("JWTMiddleware", "auth", "internal/auth/jwt.go", facts.LangGo),
		},
		Imports: []facts.ImportFact{
			imp("github.com/golang-jwt/jwt/v5", "", "internal/auth/jwt.go", facts.LangGo),
		},
	}
	finding := matchExists(rule, fs, []string{"go"})
	if finding.Status != StatusPass {
		t.Errorf("status = %v, want pass", finding.Status)
	}
	if finding.Confidence != ConfidenceHigh {
		t.Errorf("confidence = %v, want high", finding.Confidence)
	}
	if len(finding.Evidence) == 0 {
		t.Error("expected evidence")
	}
}

func TestExistsMatcherFail(t *testing.T) {
	rule := Rule{
		ID: "AUTH-001", Type: "exists", Target: "auth.jwt_middleware",
		Languages: []string{"go"}, Message: "JWT auth must exist.",
	}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("UserService", "function", "internal/user/service.go", facts.LangGo, true, 5, 15),
		},
	}
	finding := matchExists(rule, fs, []string{"go"})
	if finding.Status != StatusFail {
		t.Errorf("status = %v, want fail", finding.Status)
	}
}

func TestExistsMatcherUnknown(t *testing.T) {
	rule := Rule{
		ID: "AUTH-001", Type: "exists", Target: "auth.jwt_middleware",
		Languages: []string{"go"}, Message: "JWT auth must exist.",
	}
	fs := &FactSet{}
	finding := matchExists(rule, fs, []string{"go"})
	if finding.Status != StatusUnknown {
		t.Errorf("status = %v, want unknown", finding.Status)
	}
	if len(finding.UnknownReasons) == 0 {
		t.Error("expected unknown_reasons")
	}
}

func TestExistsAPIKeyValidation(t *testing.T) {
	rule := Rule{
		ID: "AUTH-003", Type: "exists", Target: "auth.api_key_validation",
		Languages: []string{"go"}, Message: "API key validation must exist.",
	}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("ValidateAPIKey", "function", "auth/apikey.go", facts.LangGo, true, 5, 20),
		},
		Imports: []facts.ImportFact{
			imp("crypto/subtle", "", "auth/apikey.go", facts.LangGo),
		},
	}
	finding := matchExists(rule, fs, []string{"go"})
	if finding.Status != StatusPass {
		t.Errorf("status = %v, want pass", finding.Status)
	}
}

func TestExistsRateLimitMiddleware(t *testing.T) {
	rule := Rule{
		ID: "RL-001", Type: "exists", Target: "rate_limit.middleware",
		Languages: []string{"go"}, Message: "Rate limiting must exist.",
	}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("main", "function", "main.go", facts.LangGo, false, 1, 5),
		},
		Middlewares: []facts.MiddlewareFact{
			mw("RateLimiter", "middleware", "middleware/rate.go", facts.LangGo),
		},
	}
	finding := matchExists(rule, fs, []string{"go"})
	if finding.Status != StatusPass {
		t.Errorf("status = %v, want pass", finding.Status)
	}
}

func TestExistsRepositoryLayer(t *testing.T) {
	rule := Rule{
		ID: "LAYER-001", Type: "exists", Target: "layer.repository",
		Languages: []string{"go"}, Message: "Repository layer must exist.",
	}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("UserRepository", "struct", "internal/repo/user.go", facts.LangGo, true, 10, 30),
		},
		Files: []facts.FileFact{
			fileFact("internal/repo/user.go", facts.LangGo),
		},
	}
	finding := matchExists(rule, fs, []string{"go"})
	if finding.Status != StatusPass {
		t.Errorf("status = %v, want pass", finding.Status)
	}
}

func TestExistsJWTByImportAndSymbol(t *testing.T) {
	rule := Rule{
		ID: "AUTH-001", Type: "exists", Target: "auth.jwt_middleware",
		Languages: []string{"go"}, Message: "JWT auth must exist.",
	}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("AuthMiddleware", "function", "auth/middleware.go", facts.LangGo, true, 5, 20),
		},
		Imports: []facts.ImportFact{
			imp("github.com/golang-jwt/jwt/v5", "", "auth/middleware.go", facts.LangGo),
		},
	}
	finding := matchExists(rule, fs, []string{"go"})
	if finding.Status != StatusPass {
		t.Errorf("status = %v, want pass (JWT import + auth symbol)", finding.Status)
	}
}

func TestExistsAPIKeyValidationDifferentLang(t *testing.T) {
	rule := Rule{
		ID: "AUTH-003", Type: "exists", Target: "auth.api_key_validation",
		Languages: []string{"go"}, Message: "API key validation.",
	}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("ValidateAPIKey", "function", "auth.py", facts.LangPython, true, 5, 20),
		},
		Imports: []facts.ImportFact{
			imp("os", "", "auth.py", facts.LangPython),
		},
	}
	finding := matchExists(rule, fs, []string{"go"})
	if finding.Status != StatusFail {
		t.Errorf("status = %v, want fail (python symbol for go rule)", finding.Status)
	}
}

func TestExistsRateLimitDifferentLang(t *testing.T) {
	rule := Rule{
		ID: "RL-001", Type: "exists", Target: "rate_limit.middleware",
		Languages: []string{"go"}, Message: "Rate limiting.",
	}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("main", "function", "main.go", facts.LangGo, false, 1, 5),
		},
		Middlewares: []facts.MiddlewareFact{
			mw("RateLimiter", "middleware", "rate.ts", facts.LangTypeScript),
		},
	}
	finding := matchExists(rule, fs, []string{"go"})
	if finding.Status != StatusFail {
		t.Errorf("status = %v, want fail (TS middleware for go rule)", finding.Status)
	}
}

func TestExistsRepositoryLayerDifferentLang(t *testing.T) {
	rule := Rule{
		ID: "LAYER-001", Type: "exists", Target: "layer.repository",
		Languages: []string{"go"}, Message: "Repository layer.",
	}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("UserRepository", "struct", "repo.py", facts.LangPython, true, 10, 30),
		},
		Files: []facts.FileFact{
			fileFact("repo.py", facts.LangPython),
		},
	}
	finding := matchExists(rule, fs, []string{"go"})
	// Python symbol filtered by language → fail (no go repository found)
	if finding.Status != StatusFail {
		t.Errorf("status = %v, want fail (python facts for go rule)", finding.Status)
	}
}

func TestExistsNilFactSet(t *testing.T) {
	rule := Rule{
		ID: "AUTH-001", Type: "exists", Target: "auth.jwt_middleware",
		Languages: []string{"go"}, Message: "x",
	}
	finding := matchExists(rule, nil, []string{"go"})
	if finding.Status != StatusUnknown {
		t.Errorf("status = %v, want unknown for nil FactSet", finding.Status)
	}
}
