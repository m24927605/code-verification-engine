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

func TestExistsRateLimitMiddleware_WhereClauseRejects(t *testing.T) {
	rule := Rule{
		ID: "RL-001", Type: "exists", Target: "rate_limit.middleware",
		Languages: []string{"go"}, Message: "Rate limiting.",
		Where: &Where{NameExact: []string{"SpecificLimiter"}},
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
	if finding.Status != StatusFail {
		t.Errorf("status = %v, want fail (where rejects RateLimiter)", finding.Status)
	}
}

func TestExistsRepositoryLayer_WhereClauseRejects(t *testing.T) {
	rule := Rule{
		ID: "LAYER-001", Type: "exists", Target: "layer.repository",
		Languages: []string{"go"}, Message: "Repository layer.",
		Where: &Where{NameExact: []string{"SpecificRepo"}},
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
	if finding.Status != StatusFail {
		t.Errorf("status = %v, want fail (where rejects UserRepository)", finding.Status)
	}
}

func TestExistsRateLimitMiddleware_ThrottleName(t *testing.T) {
	rule := Rule{
		ID: "RL-001", Type: "exists", Target: "rate_limit.middleware",
		Languages: []string{"go"}, Message: "Rate limiting must exist.",
	}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("main", "function", "main.go", facts.LangGo, false, 1, 5),
		},
		Middlewares: []facts.MiddlewareFact{
			mw("ThrottleMiddleware", "middleware", "middleware/throttle.go", facts.LangGo),
		},
	}
	finding := matchExists(rule, fs, []string{"go"})
	if finding.Status != StatusPass {
		t.Errorf("status = %v, want pass (throttle matches rate limit)", finding.Status)
	}
}

func TestExistsRepositoryLayer_RepoName(t *testing.T) {
	rule := Rule{
		ID: "LAYER-001", Type: "exists", Target: "layer.repository",
		Languages: []string{"go"}, Message: "Repository layer must exist.",
	}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("UserRepo", "struct", "internal/repo/user.go", facts.LangGo, true, 10, 30),
		},
		Files: []facts.FileFact{
			fileFact("internal/repo/user.go", facts.LangGo),
		},
	}
	finding := matchExists(rule, fs, []string{"go"})
	if finding.Status != StatusPass {
		t.Errorf("status = %v, want pass (repo matches repository)", finding.Status)
	}
}

// ---------------------------------------------------------------------------
// Task 6: findJWTMiddlewareResult — auth evidence scoring tests
// ---------------------------------------------------------------------------

// TestFindJWTMiddleware_StrongEvidence_AuthNamePlusImport verifies that a middleware
// with an auth name token AND a known JWT import produces strong_inference evidence.
// Score: HasMiddlewareBinding=false(0) + HasAuthImport=true(2) + HasAuthName=true(1) = 3 → AuthWeak
// Note: Without binding, score is capped at 3. With binding it would be 6 → AuthStrong.
// This test verifies the weak path for an exists (non-route-bound) check.
func TestFindJWTMiddleware_AuthNamePlusImport_Weak(t *testing.T) {
	rule := Rule{
		ID: "AUTH-001", Type: "exists", Target: "auth.jwt_middleware",
		Languages: []string{"go"}, Message: "JWT auth must exist.",
	}
	fs := &FactSet{
		Middlewares: []facts.MiddlewareFact{
			mw("AuthMiddleware", "auth", "internal/auth/middleware.go", facts.LangGo),
		},
		Imports: []facts.ImportFact{
			imp("github.com/golang-jwt/jwt", "", "internal/auth/middleware.go", facts.LangGo),
		},
	}
	result := findJWTMiddlewareResult(rule, fs)
	if len(result.Evidence) == 0 {
		t.Fatal("expected evidence for auth name + JWT import")
	}
	if result.VerificationLevel != VerificationWeakInference {
		t.Errorf("verification_level = %v, want weak_inference (no route binding)", result.VerificationLevel)
	}
	if result.Evidence[0].Symbol != "AuthMiddleware" {
		t.Errorf("symbol = %q, want AuthMiddleware", result.Evidence[0].Symbol)
	}
}

// TestFindJWTMiddleware_StrongEvidence: auth name + JWT import → weak_inference via matchExists.
// The exists match produces VerificationWeakInference when evidence is AuthWeak (no route binding).
// The finding should be StatusPass with weak_inference.
func TestFindJWTMiddleware_MatchExists_WeakInference(t *testing.T) {
	rule := Rule{
		ID: "AUTH-001", Type: "exists", Target: "auth.jwt_middleware",
		Languages: []string{"go"}, Message: "JWT auth must exist.",
	}
	fs := &FactSet{
		// SymbolFact required by hasMinimalFacts for auth.jwt_middleware
		Symbols: []facts.SymbolFact{
			sym("JWTMiddleware", "function", "internal/auth/jwt.go", facts.LangGo, true, 1, 10),
		},
		Middlewares: []facts.MiddlewareFact{
			mw("JWTMiddleware", "auth", "internal/auth/jwt.go", facts.LangGo),
		},
		Imports: []facts.ImportFact{
			imp("github.com/golang-jwt/jwt", "", "internal/auth/jwt.go", facts.LangGo),
		},
	}
	finding := matchExists(rule, fs, []string{"go"})
	if finding.Status != StatusPass {
		t.Errorf("status = %v, want pass", finding.Status)
	}
	// Auth name + JWT import (no binding) = score 3 → AuthWeak → weak_inference
	if finding.VerificationLevel != VerificationWeakInference {
		t.Errorf("verification_level = %v, want weak_inference", finding.VerificationLevel)
	}
}

// TestFindJWTMiddleware_ContradictoryName_NoEvidence verifies that a middleware
// with a contradictory name (e.g. CORS handler) is NOT classified as auth evidence.
func TestFindJWTMiddleware_ContradictoryName_NoEvidence(t *testing.T) {
	rule := Rule{
		ID: "AUTH-001", Type: "exists", Target: "auth.jwt_middleware",
		Languages: []string{"go"}, Message: "JWT auth must exist.",
	}
	fs := &FactSet{
		Middlewares: []facts.MiddlewareFact{
			mw("CORSMiddleware", "cors", "middleware/cors.go", facts.LangGo),
		},
		Imports: []facts.ImportFact{
			imp("github.com/golang-jwt/jwt", "", "middleware/cors.go", facts.LangGo),
		},
	}
	result := findJWTMiddlewareResult(rule, fs)
	// "cors" is contradictory → ClassifyAuth returns AuthNotDetected regardless of import
	// Falls back to findJWTByImportsAndSymbols (which needs symbols with auth tokens → none here)
	if len(result.Evidence) != 0 {
		t.Errorf("expected 0 evidence for contradictory middleware name, got %d", len(result.Evidence))
	}
}

// TestFindJWTMiddleware_NoEvidence_NoMiddleware verifies that absence of JWT-related
// facts produces no evidence (StatusFail in matchExists).
func TestFindJWTMiddleware_NoEvidence_NoMiddleware(t *testing.T) {
	rule := Rule{
		ID: "AUTH-001", Type: "exists", Target: "auth.jwt_middleware",
		Languages: []string{"go"}, Message: "JWT auth must exist.",
	}
	fs := &FactSet{
		// SymbolFact required by hasMinimalFacts for auth.jwt_middleware
		Symbols: []facts.SymbolFact{
			sym("LoggingMiddleware", "function", "middleware/log.go", facts.LangGo, true, 1, 5),
		},
		Middlewares: []facts.MiddlewareFact{
			mw("LoggingMiddleware", "logging", "middleware/log.go", facts.LangGo),
		},
	}
	finding := matchExists(rule, fs, []string{"go"})
	if finding.Status != StatusFail {
		t.Errorf("status = %v, want fail (no JWT evidence)", finding.Status)
	}
}
