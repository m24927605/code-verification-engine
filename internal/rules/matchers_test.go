package rules

import (
	"testing"

	"github.com/verabase/code-verification-engine/internal/facts"
)

func TestMatchRuleUnsupportedType(t *testing.T) {
	rule := Rule{
		ID: "X-001", Type: "custom_unsupported",
		Languages: []string{"go"}, Message: "x",
	}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("main", "function", "main.go", facts.LangGo, false, 1, 5),
		},
	}
	finding := matchRule(rule, fs, []string{"go"})
	if finding.Status != StatusUnknown {
		t.Errorf("status = %v, want unknown", finding.Status)
	}
	if len(finding.UnknownReasons) == 0 {
		t.Error("expected unknown reasons")
	}
}

func TestLanguageMatchEmpty(t *testing.T) {
	if languageMatch("go", nil) {
		t.Error("expected false for nil allowed list")
	}
	if languageMatch("go", []string{}) {
		t.Error("expected false for empty allowed list")
	}
}

func TestHasMinimalFactsNil(t *testing.T) {
	if hasMinimalFacts(nil, []string{"SymbolFact"}) {
		t.Error("expected false for nil FactSet")
	}
}

func TestExistsMatcherWithWhereClause(t *testing.T) {
	rule := Rule{
		ID: "AUTH-001", Type: "exists", Target: "auth.jwt_middleware",
		Languages: []string{"go"}, Message: "JWT auth must exist.",
		Where: &Where{NameMatches: []string{"jwt"}},
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
	finding := matchExists(rule, fs, []string{"go"})
	if finding.Status != StatusPass {
		t.Errorf("status = %v, want pass with where clause", finding.Status)
	}
}

func TestNotExistsWithDifferentLanguage(t *testing.T) {
	rule := Rule{
		ID: "SEC-001", Type: "not_exists", Target: "secret.hardcoded_credential",
		Languages: []string{"go"}, Message: "No hardcoded creds.",
	}
	fs := &FactSet{
		Secrets: []facts.SecretFact{
			secret("password", "config.py", facts.LangPython, 10),
		},
		Files: []facts.FileFact{
			fileFact("main.go", facts.LangGo),
		},
	}
	finding := matchNotExists(rule, fs, []string{"go"})
	// Python secret should not trigger for go-only rule
	if finding.Status != StatusPass {
		t.Errorf("status = %v, want pass (secret in different language)", finding.Status)
	}
}

func TestRelationshipMatcherWithLanguageFilter(t *testing.T) {
	rule := Rule{
		ID: "AUTH-002", Type: "relationship", Target: "route.protected_uses_auth_middleware",
		Languages: []string{"go"}, Message: "Protected routes use auth middleware.",
	}
	// TS route is filtered (Go-only rule); Go route has auth binding + JWT import → AuthStrong → pass
	fs := &FactSet{
		Routes: []facts.RouteFact{
			route("GET", "/api/users", "GetUsers", "routes.ts", facts.LangTypeScript, nil),
			route("GET", "/api/items", "GetItems", "routes.go", facts.LangGo, []string{"AuthMiddleware"}),
		},
		Middlewares: []facts.MiddlewareFact{
			mw("AuthMiddleware", "auth", "middleware.go", facts.LangGo),
		},
		Imports: []facts.ImportFact{
			imp("github.com/golang-jwt/jwt", "", "routes.go", facts.LangGo),
		},
	}
	finding := matchRelationship(rule, fs, []string{"go"})
	// TS route without auth should be ignored because rule is Go-only
	if finding.Status != StatusPass {
		t.Errorf("status = %v, want pass (TS route filtered out)", finding.Status)
	}
}

func TestNotExistsDefaultTarget(t *testing.T) {
	// A target that exists in registry but has no specific not_exists handler
	rule := Rule{
		ID: "X-001", Type: "not_exists", Target: "layer.repository",
		Languages: []string{"go"}, Message: "x",
	}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("main", "function", "main.go", facts.LangGo, false, 1, 5),
		},
		Files: []facts.FileFact{
			fileFact("main.go", facts.LangGo),
		},
	}
	finding := matchNotExists(rule, fs, []string{"go"})
	// No specific handler, so no evidence found → pass
	if finding.Status != StatusPass {
		t.Errorf("status = %v, want pass for unhandled not_exists target", finding.Status)
	}
}

func TestExistsMatcherWhereFilterRejectsMiddleware(t *testing.T) {
	rule := Rule{
		ID: "AUTH-001", Type: "exists", Target: "auth.jwt_middleware",
		Languages: []string{"go"}, Message: "JWT auth must exist.",
		Where: &Where{NameExact: []string{"SpecificMiddleware"}},
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
	finding := matchExists(rule, fs, []string{"go"})
	// Where clause rejects "JWTMiddleware" since name_exact wants "SpecificMiddleware"
	if finding.Status != StatusFail {
		t.Errorf("status = %v, want fail (where rejects middleware)", finding.Status)
	}
}

func TestExistsMatcherDifferentLanguageMiddleware(t *testing.T) {
	rule := Rule{
		ID: "AUTH-001", Type: "exists", Target: "auth.jwt_middleware",
		Languages: []string{"go"}, Message: "JWT auth must exist.",
	}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("main", "function", "main.go", facts.LangGo, false, 1, 5),
		},
		Middlewares: []facts.MiddlewareFact{
			mw("JWTMiddleware", "auth", "auth.ts", facts.LangTypeScript),
		},
		Imports: []facts.ImportFact{
			imp("jsonwebtoken", "", "auth.ts", facts.LangTypeScript),
		},
	}
	finding := matchExists(rule, fs, []string{"go"})
	if finding.Status != StatusFail {
		t.Errorf("status = %v, want fail (middleware in wrong language)", finding.Status)
	}
}

func TestRelationshipPublicRoutesNoPublicRoutes(t *testing.T) {
	rule := Rule{
		ID: "AUTH-003", Type: "relationship", Target: "route.public_without_auth",
		Languages: []string{"go"}, Message: "Public routes identified.",
	}
	fs := &FactSet{
		Routes: []facts.RouteFact{
			route("GET", "/api/users", "GetUsers", "routes.go", facts.LangGo, []string{"AuthMiddleware"}),
		},
		Middlewares: []facts.MiddlewareFact{
			mw("AuthMiddleware", "auth", "middleware.go", facts.LangGo),
		},
	}
	finding := matchRelationship(rule, fs, []string{"go"})
	// No public routes detected → unknown (not enough info to say fail)
	if finding.Status != StatusUnknown {
		t.Errorf("status = %v, want unknown (no public routes without auth)", finding.Status)
	}
}

func TestRelationshipPublicRoutesFilterLanguage(t *testing.T) {
	rule := Rule{
		ID: "AUTH-003", Type: "relationship", Target: "route.public_without_auth",
		Languages: []string{"go"}, Message: "Public routes identified.",
	}
	fs := &FactSet{
		Routes: []facts.RouteFact{
			route("GET", "/health", "HealthCheck", "routes.ts", facts.LangTypeScript, nil),
		},
		Middlewares: []facts.MiddlewareFact{
			mw("AuthMiddleware", "auth", "middleware.go", facts.LangGo),
		},
	}
	finding := matchRelationship(rule, fs, []string{"go"})
	// TS route filtered out for Go-only rule → no public routes → unknown
	if finding.Status != StatusUnknown {
		t.Errorf("status = %v, want unknown (TS route filtered)", finding.Status)
	}
}

func TestDirectDBAccessControllerBySymbolName(t *testing.T) {
	rule := Rule{
		ID: "ARCH-001", Type: "not_exists", Target: "db.direct_access_from_controller",
		Languages: []string{"go"}, Message: "No direct DB access from controllers.",
	}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("UserHandler", "function", "handlers/user.go", facts.LangGo, true, 5, 20),
		},
		DataAccess: []facts.DataAccessFact{
			dataAccess("query", "handlers/user.go", facts.LangGo),
		},
		Files: []facts.FileFact{
			fileFact("handlers/user.go", facts.LangGo),
		},
	}
	finding := matchNotExists(rule, fs, []string{"go"})
	if finding.Status != StatusFail {
		t.Errorf("status = %v, want fail (handler symbol + data access)", finding.Status)
	}
}

func TestDirectDBAccessDifferentLangFiltered(t *testing.T) {
	rule := Rule{
		ID: "ARCH-001", Type: "not_exists", Target: "db.direct_access_from_controller",
		Languages: []string{"go"}, Message: "No direct DB access from controllers.",
	}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("UserHandler", "function", "handlers/user.py", facts.LangPython, true, 5, 20),
		},
		DataAccess: []facts.DataAccessFact{
			dataAccess("query", "handlers/user.py", facts.LangPython),
		},
		Files: []facts.FileFact{
			fileFact("handlers/user.go", facts.LangGo),
		},
	}
	finding := matchNotExists(rule, fs, []string{"go"})
	// Python data access shouldn't trigger for Go-only rule
	if finding.Status != StatusPass {
		t.Errorf("status = %v, want pass (different language filtered)", finding.Status)
	}
}

func TestTestRequiredMatchByTestName(t *testing.T) {
	rule := Rule{
		ID: "TEST-002", Type: "test_required", Target: "module.auth_service",
		Languages: []string{"go"}, Message: "Auth service needs tests.",
	}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("AuthService", "struct", "pkg/auth/service.go", facts.LangGo, true, 5, 30),
		},
		Tests: []facts.TestFact{
			testFact("TestAuth_Integration", "tests/auth_test.go", facts.LangGo, ""),
		},
		Files: []facts.FileFact{
			fileFact("pkg/auth/service.go", facts.LangGo),
			fileFact("tests/auth_test.go", facts.LangGo),
		},
	}
	finding := matchTestRequired(rule, fs, []string{"go"})
	// Test name contains "auth" token → should match
	if finding.Status != StatusPass {
		t.Errorf("status = %v, want pass (test name matches module keyword)", finding.Status)
	}
}

func TestTestRequiredFilterLanguage(t *testing.T) {
	rule := Rule{
		ID: "TEST-001", Type: "test_required", Target: "module.payment_service",
		Languages: []string{"go"}, Message: "Payment service needs tests.",
	}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("PaymentService", "struct", "payment/service.py", facts.LangPython, true, 10, 50),
		},
		Tests: []facts.TestFact{
			testFact("test_payment", "payment/test_service.py", facts.LangPython, "payment"),
		},
		Files: []facts.FileFact{
			fileFact("payment/service.py", facts.LangPython),
		},
	}
	finding := matchTestRequired(rule, fs, []string{"go"})
	// Python facts for Go-only rule → module not found → unknown
	if finding.Status != StatusUnknown {
		t.Errorf("status = %v, want unknown (wrong language)", finding.Status)
	}
}

func TestExistsMatcherNoJWTImports(t *testing.T) {
	rule := Rule{
		ID: "AUTH-001", Type: "exists", Target: "auth.jwt_middleware",
		Languages: []string{"go"}, Message: "JWT auth must exist.",
	}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("VerifyToken", "function", "auth/jwt.go", facts.LangGo, true, 10, 30),
		},
		Imports: []facts.ImportFact{
			imp("fmt", "", "auth/jwt.go", facts.LangGo),
		},
	}
	// No JWT import, no middleware → fail
	finding := matchExists(rule, fs, []string{"go"})
	if finding.Status != StatusFail {
		t.Errorf("status = %v, want fail (no JWT imports)", finding.Status)
	}
}

func TestMatchRuleAllTypes(t *testing.T) {
	// Ensures matchRule dispatches correctly for all 4 types
	types := []string{"exists", "not_exists", "relationship", "test_required"}
	for _, ruleType := range types {
		t.Run(ruleType, func(t *testing.T) {
			rule := Rule{
				ID: "T-001", Type: ruleType, Target: "auth.jwt_middleware",
				Languages: []string{"go"}, Message: "x",
			}
			fs := &FactSet{
				Symbols: []facts.SymbolFact{
					sym("main", "function", "main.go", facts.LangGo, false, 1, 5),
				},
				Files: []facts.FileFact{
					fileFact("main.go", facts.LangGo),
				},
			}
			finding := matchRule(rule, fs, []string{"go"})
			if finding.RuleID != "T-001" {
				t.Errorf("rule ID = %v, want T-001", finding.RuleID)
			}
		})
	}
}

func TestTestRequiredModuleByTargetModule(t *testing.T) {
	rule := Rule{
		ID: "TEST-001", Type: "test_required", Target: "module.payment_service",
		Languages: []string{"go"}, Message: "Payment service needs tests.",
	}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("PaymentService", "struct", "svc/pay/service.go", facts.LangGo, true, 10, 50),
		},
		Tests: []facts.TestFact{
			testFact("TestPayment", "tests/pay_test.go", facts.LangGo, "payment"),
		},
		Files: []facts.FileFact{
			fileFact("svc/pay/service.go", facts.LangGo),
			fileFact("tests/pay_test.go", facts.LangGo),
		},
	}
	finding := matchTestRequired(rule, fs, []string{"go"})
	// TestName contains "payment" token → should match
	if finding.Status != StatusPass {
		t.Errorf("status = %v, want pass (test name has payment token)", finding.Status)
	}
}

func TestTestRequiredLanguageFilterTests(t *testing.T) {
	rule := Rule{
		ID: "TEST-001", Type: "test_required", Target: "module.payment_service",
		Languages: []string{"go"}, Message: "Payment service needs tests.",
	}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("PaymentService", "struct", "payment/service.go", facts.LangGo, true, 10, 50),
		},
		Tests: []facts.TestFact{
			testFact("test_payment", "payment/test_service.py", facts.LangPython, "payment"),
		},
		Files: []facts.FileFact{
			fileFact("payment/service.go", facts.LangGo),
		},
	}
	finding := matchTestRequired(rule, fs, []string{"go"})
	// Python test should be filtered out → no Go tests → fail
	if finding.Status != StatusFail {
		t.Errorf("status = %v, want fail (python test for go rule)", finding.Status)
	}
}

func TestRelationshipProtectedRoutesNoBindingData(t *testing.T) {
	rule := Rule{
		ID: "AUTH-002", Type: "relationship", Target: "route.protected_uses_auth_middleware",
		Languages: []string{"go"}, Message: "Protected routes use auth middleware.",
	}
	// Routes without middleware binding data → unknown (not guessable)
	fs := &FactSet{
		Routes: []facts.RouteFact{
			route("GET", "/api/users", "GetUsers", "routes.go", facts.LangGo, nil),
		},
		Middlewares: []facts.MiddlewareFact{
			mw("JWTAuth", "auth", "routes.go", facts.LangGo),
		},
	}
	finding := matchRelationship(rule, fs, []string{"go"})
	if finding.Status != StatusUnknown {
		t.Errorf("status = %v, want unknown (no per-route middleware binding data)", finding.Status)
	}
}

func TestRelationshipMiddlewareFilterLanguage(t *testing.T) {
	rule := Rule{
		ID: "AUTH-002", Type: "relationship", Target: "route.protected_uses_auth_middleware",
		Languages: []string{"go"}, Message: "Protected routes use auth middleware.",
	}
	fs := &FactSet{
		Routes: []facts.RouteFact{
			route("GET", "/api/users", "GetUsers", "routes.go", facts.LangGo, nil),
		},
		Middlewares: []facts.MiddlewareFact{
			mw("AuthMiddleware", "auth", "middleware.ts", facts.LangTypeScript),
		},
	}
	finding := matchRelationship(rule, fs, []string{"go"})
	// No binding data → unknown
	if finding.Status != StatusUnknown {
		t.Errorf("status = %v, want unknown (no binding data)", finding.Status)
	}
}

func TestIsPublicRoute(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"/health", true},
		{"/Health", true},
		{"/ping", true},
		{"/public/page", true},
		{"/login", true},
		{"/register", true},
		{"/signup", true},
		{"/auth/callback", true},
		{"/api/users", false},
		{"/admin/panel", false},
		{"/dashboard", false},
	}
	for _, tc := range tests {
		got := isPublicRoute(tc.path)
		if got != tc.want {
			t.Errorf("isPublicRoute(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}

func TestHasMinimalFacts_FileFactRequired(t *testing.T) {
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("main", "function", "main.go", facts.LangGo, false, 1, 5),
		},
	}
	if hasMinimalFacts(fs, []string{"SymbolFact", "FileFact"}) {
		t.Error("expected false when FileFact required but missing")
	}
}

func TestHasMinimalFacts_RouteFactRequired(t *testing.T) {
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("main", "function", "main.go", facts.LangGo, false, 1, 5),
		},
	}
	if hasMinimalFacts(fs, []string{"RouteFact"}) {
		t.Error("expected false when RouteFact required but missing")
	}
}

func TestHasMinimalFacts_UnknownFactType(t *testing.T) {
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("main", "function", "main.go", facts.LangGo, false, 1, 5),
		},
	}
	// Unknown fact types are ignored (no case for them), so result should be true
	if !hasMinimalFacts(fs, []string{"SomethingElse"}) {
		t.Error("expected true for unknown fact type (no check)")
	}
}

func TestPublicRoutesWithMiddleware(t *testing.T) {
	rule := Rule{
		ID: "AUTH-003", Type: "relationship", Target: "route.public_without_auth",
		Languages: []string{"go"}, Message: "Public routes without auth.",
	}
	fs := &FactSet{
		Routes: []facts.RouteFact{
			route("GET", "/health", "HealthCheck", "routes.go", facts.LangGo, nil),
		},
		Middlewares: []facts.MiddlewareFact{
			mw("LoggingMiddleware", "logging", "middleware.go", facts.LangGo),
		},
	}
	finding := matchRelationship(rule, fs, []string{"go"})
	// /health is a public route → pass
	if finding.Status != StatusPass {
		t.Errorf("status = %v, want pass (public route detected)", finding.Status)
	}
}
