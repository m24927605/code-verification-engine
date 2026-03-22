package rules

import (
	"testing"

	"github.com/verabase/code-verification-engine/internal/facts"
)

func TestRelationshipMatcherPass(t *testing.T) {
	rule := Rule{
		ID: "AUTH-002", Type: "relationship", Target: "route.protected_uses_auth_middleware",
		Languages: []string{"go"}, Message: "Protected routes use auth middleware.",
	}
	// Routes WITH explicit middleware bindings + auth import → AuthStrong → matcher can verify
	fs := &FactSet{
		Routes: []facts.RouteFact{
			route("GET", "/api/users", "GetUsers", "routes.go", facts.LangGo, []string{"AuthMiddleware"}),
			route("POST", "/api/users", "CreateUser", "routes.go", facts.LangGo, []string{"AuthMiddleware"}),
		},
		Middlewares: []facts.MiddlewareFact{
			mw("AuthMiddleware", "auth", "middleware.go", facts.LangGo),
		},
		Imports: []facts.ImportFact{
			imp("github.com/golang-jwt/jwt", "", "routes.go", facts.LangGo),
		},
	}
	finding := matchRelationship(rule, fs, []string{"go"})
	if finding.Status != StatusPass {
		t.Errorf("status = %v, want pass (routes have explicit middleware binding)", finding.Status)
	}
}

func TestRelationshipMatcherFailUnprotectedRoute(t *testing.T) {
	rule := Rule{
		ID: "AUTH-002", Type: "relationship", Target: "route.protected_uses_auth_middleware",
		Languages: []string{"go"}, Message: "Protected routes use auth middleware.",
	}
	// One route has auth binding, one has explicit empty binding (no auth) → fail
	// Note: []string{} (empty slice) means "binding data present, no middleware"
	//       nil means "no binding data available" (unknown per route)
	fs := &FactSet{
		Routes: []facts.RouteFact{
			route("GET", "/api/users", "GetUsers", "routes.go", facts.LangGo, []string{"AuthMiddleware"}),
			route("POST", "/api/admin", "AdminAction", "routes.go", facts.LangGo, []string{}),
		},
		Middlewares: []facts.MiddlewareFact{
			mw("AuthMiddleware", "auth", "middleware.go", facts.LangGo),
		},
	}
	finding := matchRelationship(rule, fs, []string{"go"})
	if finding.Status != StatusFail {
		t.Errorf("status = %v, want fail (admin route explicitly has no auth)", finding.Status)
	}
	if len(finding.Evidence) == 0 {
		t.Error("expected evidence for unprotected route")
	}
}

func TestRelationshipMatcherMixedBindingWithNil(t *testing.T) {
	rule := Rule{
		ID: "AUTH-002", Type: "relationship", Target: "route.protected_uses_auth_middleware",
		Languages: []string{"go"}, Message: "Protected routes use auth middleware.",
	}
	// One route has auth binding + JWT import, one has nil (no binding data)
	// → pass with reduced confidence (nil routes are unknown, not fail)
	fs := &FactSet{
		Routes: []facts.RouteFact{
			route("GET", "/api/users", "GetUsers", "routes.go", facts.LangGo, []string{"AuthMiddleware"}),
			route("POST", "/api/admin", "AdminAction", "routes.go", facts.LangGo, nil),
		},
		Middlewares: []facts.MiddlewareFact{
			mw("AuthMiddleware", "auth", "middleware.go", facts.LangGo),
		},
		Imports: []facts.ImportFact{
			imp("github.com/golang-jwt/jwt", "", "routes.go", facts.LangGo),
		},
	}
	finding := matchRelationship(rule, fs, []string{"go"})
	// The protected route passes (AuthStrong), the nil route is unknown → overall pass with strong_inference
	if finding.Status != StatusPass {
		t.Errorf("status = %v, want pass (protected route OK, nil route is unknown not fail)", finding.Status)
	}
	if finding.VerificationLevel != VerificationStrongInference {
		t.Errorf("verification = %v, want strong_inference (some routes lack binding data)", finding.VerificationLevel)
	}
}

func TestRelationshipMatcherUnknownNoBindingData(t *testing.T) {
	rule := Rule{
		ID: "AUTH-002", Type: "relationship", Target: "route.protected_uses_auth_middleware",
		Languages: []string{"go"}, Message: "Protected routes use auth middleware.",
	}
	// Routes WITHOUT middleware bindings → matcher cannot verify, returns unknown
	fs := &FactSet{
		Routes: []facts.RouteFact{
			route("GET", "/api/users", "GetUsers", "routes.go", facts.LangGo, nil),
		},
		Middlewares: []facts.MiddlewareFact{
			mw("AuthMiddleware", "auth", "middleware.go", facts.LangGo),
		},
	}
	finding := matchRelationship(rule, fs, []string{"go"})
	if finding.Status != StatusUnknown {
		t.Errorf("status = %v, want unknown (no per-route middleware binding data)", finding.Status)
	}
}

func TestRelationshipMatcherUnknownNoFacts(t *testing.T) {
	rule := Rule{
		ID: "AUTH-002", Type: "relationship", Target: "route.protected_uses_auth_middleware",
		Languages: []string{"go"}, Message: "Protected routes use auth middleware.",
	}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("main", "function", "main.go", facts.LangGo, false, 1, 5),
		},
	}
	finding := matchRelationship(rule, fs, []string{"go"})
	if finding.Status != StatusUnknown {
		t.Errorf("status = %v, want unknown", finding.Status)
	}
}

func TestRelationshipPublicRoutesWithoutAuth(t *testing.T) {
	rule := Rule{
		ID: "AUTH-003", Type: "relationship", Target: "route.public_without_auth",
		Languages: []string{"go"}, Message: "Public routes identified.",
	}
	fs := &FactSet{
		Routes: []facts.RouteFact{
			route("GET", "/health", "HealthCheck", "routes.go", facts.LangGo, nil),
		},
		Middlewares: []facts.MiddlewareFact{
			mw("AuthMiddleware", "auth", "middleware.go", facts.LangGo),
		},
	}
	finding := matchRelationship(rule, fs, []string{"go"})
	if finding.Status != StatusPass {
		t.Errorf("status = %v, want pass (public route without auth)", finding.Status)
	}
}

func TestRelationshipPublicRoutesSkipMixed(t *testing.T) {
	rule := Rule{
		ID: "AUTH-002", Type: "relationship", Target: "route.protected_uses_auth_middleware",
		Languages: []string{"go"}, Message: "Protected routes use auth middleware.",
	}
	fs := &FactSet{
		Routes: []facts.RouteFact{
			route("GET", "/health", "HealthCheck", "routes.go", facts.LangGo, nil),
			route("GET", "/api/users", "GetUsers", "routes.go", facts.LangGo, []string{"AuthMiddleware"}),
		},
		Middlewares: []facts.MiddlewareFact{
			mw("AuthMiddleware", "auth", "middleware.go", facts.LangGo),
		},
		Imports: []facts.ImportFact{
			imp("github.com/golang-jwt/jwt", "", "routes.go", facts.LangGo),
		},
	}
	finding := matchRelationship(rule, fs, []string{"go"})
	if finding.Status != StatusPass {
		t.Errorf("status = %v, want pass (public route skipped, protected has auth)", finding.Status)
	}
}

func TestRelationship_AllRoutesProtected(t *testing.T) {
	rule := Rule{
		ID: "AUTH-002", Type: "relationship", Target: "route.protected_uses_auth_middleware",
		Languages: []string{"typescript"}, Message: "All routes use auth middleware.",
	}
	// Routes with auth bindings + JWT import → AuthStrong → pass
	fs := &FactSet{
		Routes: []facts.RouteFact{
			route("GET", "/api/users", "getUsers", "routes.ts", facts.LangTypeScript, []string{"AuthGuard"}),
			route("POST", "/api/users", "createUser", "routes.ts", facts.LangTypeScript, []string{"JwtGuard"}),
			route("DELETE", "/api/users/:id", "deleteUser", "routes.ts", facts.LangTypeScript, []string{"AuthMiddleware"}),
		},
		Middlewares: []facts.MiddlewareFact{
			mw("AuthGuard", "nestjs-guard", "auth.guard.ts", facts.LangTypeScript),
			mw("JwtGuard", "nestjs-guard", "jwt.guard.ts", facts.LangTypeScript),
			mw("AuthMiddleware", "express", "auth.ts", facts.LangTypeScript),
		},
		Imports: []facts.ImportFact{
			imp("@nestjs/jwt", "", "routes.ts", facts.LangTypeScript),
		},
	}
	finding := matchRelationship(rule, fs, []string{"typescript"})
	if finding.Status != StatusPass {
		t.Errorf("status = %v, want pass (all non-public routes have auth middleware)", finding.Status)
	}
	// Per spec: route protection never produces VerificationVerified — strong_inference at most
	if finding.VerificationLevel != VerificationStrongInference {
		t.Errorf("verification_level = %v, want strong_inference", finding.VerificationLevel)
	}
}

func TestRelationship_UnprotectedRoute(t *testing.T) {
	rule := Rule{
		ID: "AUTH-002", Type: "relationship", Target: "route.protected_uses_auth_middleware",
		Languages: []string{"javascript"}, Message: "Protected routes use auth middleware.",
	}
	fs := &FactSet{
		Routes: []facts.RouteFact{
			route("GET", "/api/users", "getUsers", "routes.js", facts.LangJavaScript, []string{"authMiddleware"}),
			route("POST", "/api/admin", "adminAction", "routes.js", facts.LangJavaScript, []string{}),
			route("GET", "/api/secrets", "getSecrets", "routes.js", facts.LangJavaScript, []string{"rateLimiter"}),
		},
		Middlewares: []facts.MiddlewareFact{
			mw("authMiddleware", "express", "auth.js", facts.LangJavaScript),
		},
	}
	finding := matchRelationship(rule, fs, []string{"javascript"})
	if finding.Status != StatusFail {
		t.Errorf("status = %v, want fail (admin and secrets routes lack auth)", finding.Status)
	}
	if len(finding.Evidence) != 2 {
		t.Errorf("expected 2 unprotected route evidence entries, got %d", len(finding.Evidence))
	}
}

func TestRelationship_MixedBindingExplicitNoAuth(t *testing.T) {
	rule := Rule{
		ID: "AUTH-002", Type: "relationship", Target: "route.protected_uses_auth_middleware",
		Languages: []string{"go"}, Message: "Protected routes use auth middleware.",
	}
	// /api/users has auth, /api/data has explicit empty binding (no auth), /health is public
	fs := &FactSet{
		Routes: []facts.RouteFact{
			route("GET", "/api/users", "GetUsers", "routes.go", facts.LangGo, []string{"AuthMiddleware"}),
			route("POST", "/api/data", "PostData", "routes.go", facts.LangGo, []string{}),
			route("GET", "/health", "Health", "routes.go", facts.LangGo, nil),
		},
		Middlewares: []facts.MiddlewareFact{
			mw("AuthMiddleware", "http", "middleware.go", facts.LangGo),
		},
	}
	finding := matchRelationship(rule, fs, []string{"go"})
	// /api/data has explicit empty binding → unprotected (fail)
	// /health is public → skipped
	// nil route is not counted as fail
	if finding.Status != StatusFail {
		t.Errorf("status = %v, want fail (/api/data explicitly has no auth)", finding.Status)
	}
	if len(finding.Evidence) != 1 {
		t.Errorf("expected 1 unprotected route evidence entry, got %d: %+v", len(finding.Evidence), finding.Evidence)
	}
}

func TestRelationshipUnsupportedTarget(t *testing.T) {
	rule := Rule{
		ID: "X-001", Type: "relationship", Target: "auth.jwt_middleware",
		Languages: []string{"go"}, Message: "x",
	}
	fs := &FactSet{
		Routes: []facts.RouteFact{
			route("GET", "/api/users", "GetUsers", "routes.go", facts.LangGo, nil),
		},
		Middlewares: []facts.MiddlewareFact{
			mw("AuthMiddleware", "auth", "middleware.go", facts.LangGo),
		},
	}
	finding := matchRelationship(rule, fs, []string{"go"})
	if finding.Status != StatusUnknown {
		t.Errorf("status = %v, want unknown for unsupported relationship target", finding.Status)
	}
}

// ---------------------------------------------------------------------------
// Task 7: matchProtectedRoutesUseAuth — auth evidence scoring tests
// ---------------------------------------------------------------------------

// TestProtectedRoutes_StrongAuth_BindingPlusImport verifies that a route with a middleware
// that has auth name + JWT import (AuthStrong via binding+import) → pass + strong_inference.
func TestProtectedRoutes_StrongAuth_BindingPlusImport(t *testing.T) {
	rule := Rule{
		ID: "AUTH-002", Type: "relationship", Target: "route.protected_uses_auth_middleware",
		Languages: []string{"go"}, Message: "Protected routes use auth middleware.",
	}
	// AuthMiddleware: HasMiddlewareBinding(3) + HasAuthImport(2) + HasAuthName(1) = 6 → AuthStrong
	fs := &FactSet{
		Routes: []facts.RouteFact{
			route("GET", "/api/users", "GetUsers", "routes.go", facts.LangGo, []string{"AuthMiddleware"}),
		},
		Imports: []facts.ImportFact{
			imp("github.com/golang-jwt/jwt", "", "routes.go", facts.LangGo),
		},
	}
	finding := matchProtectedRoutesUseAuth(rule, fs)
	if finding.Status != StatusPass {
		t.Errorf("status = %v, want pass (AuthStrong evidence via binding + import)", finding.Status)
	}
	// Per spec: route protection never produces VerificationVerified
	if finding.VerificationLevel != VerificationStrongInference {
		t.Errorf("verification_level = %v, want strong_inference", finding.VerificationLevel)
	}
}

// TestProtectedRoutes_WeakAuthOnly verifies that when all bound middlewares only
// produce AuthWeak evidence (auth name but no import), the result is unknown.
func TestProtectedRoutes_WeakAuthOnly(t *testing.T) {
	rule := Rule{
		ID: "AUTH-002", Type: "relationship", Target: "route.protected_uses_auth_middleware",
		Languages: []string{"go"}, Message: "Protected routes use auth middleware.",
	}
	// AuthMiddleware: HasMiddlewareBinding(3) + HasAuthName(1) = 4 → AuthWeak (no import → score < 5)
	fs := &FactSet{
		Routes: []facts.RouteFact{
			route("GET", "/api/users", "GetUsers", "routes.go", facts.LangGo, []string{"AuthMiddleware"}),
		},
		// No imports → HasAuthImport=false → score=4 → AuthWeak
	}
	finding := matchProtectedRoutesUseAuth(rule, fs)
	if finding.Status != StatusUnknown {
		t.Errorf("status = %v, want unknown (only AuthWeak evidence, no import confirmation)", finding.Status)
	}
	if finding.VerificationLevel != VerificationWeakInference {
		t.Errorf("verification_level = %v, want weak_inference", finding.VerificationLevel)
	}
}

// TestProtectedRoutes_NilMiddlewares verifies that routes with nil Middlewares
// (binding data unavailable) produce StatusUnknown.
func TestProtectedRoutes_NilMiddlewares(t *testing.T) {
	rule := Rule{
		ID: "AUTH-002", Type: "relationship", Target: "route.protected_uses_auth_middleware",
		Languages: []string{"go"}, Message: "Protected routes use auth middleware.",
	}
	fs := &FactSet{
		Routes: []facts.RouteFact{
			route("GET", "/api/users", "GetUsers", "routes.go", facts.LangGo, nil),
			route("POST", "/api/orders", "CreateOrder", "routes.go", facts.LangGo, nil),
		},
		Imports: []facts.ImportFact{
			imp("github.com/golang-jwt/jwt", "", "routes.go", facts.LangGo),
		},
	}
	finding := matchProtectedRoutesUseAuth(rule, fs)
	if finding.Status != StatusUnknown {
		t.Errorf("status = %v, want unknown (nil middleware binding data)", finding.Status)
	}
}

// TestProtectedRoutes_FailNeverVerified verifies that a fail finding from route
// protection uses strong_inference (not verified) per spec.
func TestProtectedRoutes_FailNeverVerified(t *testing.T) {
	rule := Rule{
		ID: "AUTH-002", Type: "relationship", Target: "route.protected_uses_auth_middleware",
		Languages: []string{"go"}, Message: "Protected routes use auth middleware.",
	}
	fs := &FactSet{
		Routes: []facts.RouteFact{
			route("GET", "/api/users", "GetUsers", "routes.go", facts.LangGo, []string{"AuthMiddleware"}),
			route("POST", "/api/admin", "AdminAction", "routes.go", facts.LangGo, []string{}),
		},
		Imports: []facts.ImportFact{
			imp("github.com/golang-jwt/jwt", "", "routes.go", facts.LangGo),
		},
	}
	finding := matchProtectedRoutesUseAuth(rule, fs)
	if finding.Status != StatusFail {
		t.Errorf("status = %v, want fail (admin route has no auth middleware)", finding.Status)
	}
	// Per spec: route protection never produces VerificationVerified
	if finding.VerificationLevel != VerificationStrongInference {
		t.Errorf("verification_level = %v, want strong_inference (never verified for route protection)", finding.VerificationLevel)
	}
}

// TestProtectedRoutes_ContradictoryMiddlewareUnprotected verifies that a route
// bound only to a contradictory middleware (e.g. CORS) is treated as unprotected.
func TestProtectedRoutes_ContradictoryMiddlewareUnprotected(t *testing.T) {
	rule := Rule{
		ID: "AUTH-002", Type: "relationship", Target: "route.protected_uses_auth_middleware",
		Languages: []string{"go"}, Message: "Protected routes use auth middleware.",
	}
	fs := &FactSet{
		Routes: []facts.RouteFact{
			route("GET", "/api/users", "GetUsers", "routes.go", facts.LangGo, []string{"CORSMiddleware"}),
		},
		Imports: []facts.ImportFact{
			imp("github.com/golang-jwt/jwt", "", "routes.go", facts.LangGo),
		},
	}
	finding := matchProtectedRoutesUseAuth(rule, fs)
	if finding.Status != StatusFail {
		t.Errorf("status = %v, want fail (CORSMiddleware is contradictory, not auth)", finding.Status)
	}
	if len(finding.Evidence) == 0 {
		t.Error("expected evidence for unprotected route")
	}
}
