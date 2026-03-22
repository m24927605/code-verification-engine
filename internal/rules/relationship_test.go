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
	// Routes WITH explicit middleware bindings → matcher can verify
	fs := &FactSet{
		Routes: []facts.RouteFact{
			route("GET", "/api/users", "GetUsers", "routes.go", facts.LangGo, []string{"AuthMiddleware"}),
			route("POST", "/api/users", "CreateUser", "routes.go", facts.LangGo, []string{"AuthMiddleware"}),
		},
		Middlewares: []facts.MiddlewareFact{
			mw("AuthMiddleware", "auth", "middleware.go", facts.LangGo),
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
	// One route has binding, one doesn't → fail with evidence
	fs := &FactSet{
		Routes: []facts.RouteFact{
			route("GET", "/api/users", "GetUsers", "routes.go", facts.LangGo, []string{"AuthMiddleware"}),
			route("POST", "/api/admin", "AdminAction", "routes.go", facts.LangGo, nil),
		},
		Middlewares: []facts.MiddlewareFact{
			mw("AuthMiddleware", "auth", "middleware.go", facts.LangGo),
		},
	}
	finding := matchRelationship(rule, fs, []string{"go"})
	// The route without binding data → overall falls to unknown because not all have bindings
	// Actually, hasBindingData is true because one route has Middlewares.
	// So the matcher checks: /api/admin has no auth → fail
	if finding.Status != StatusFail {
		t.Errorf("status = %v, want fail (admin route has no auth binding)", finding.Status)
	}
	if len(finding.Evidence) == 0 {
		t.Error("expected evidence for unprotected route")
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
	}
	finding := matchRelationship(rule, fs, []string{"go"})
	if finding.Status != StatusPass {
		t.Errorf("status = %v, want pass (public route skipped, protected has auth)", finding.Status)
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
