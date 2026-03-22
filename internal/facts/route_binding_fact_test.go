package facts_test

import (
	"testing"

	"github.com/verabase/code-verification-engine/internal/facts"
)

func TestNewRouteBindingFactValid(t *testing.T) {
	rb, err := facts.NewRouteBindingFact(facts.LangTypeScript, "app.module.ts", facts.Span{Start: 10, End: 20},
		"UsersController.getAll", "GET", "/api/users",
		[]string{"AuthMiddleware"}, []string{"RolesGuard"}, "route")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rb.Handler != "UsersController.getAll" {
		t.Errorf("expected handler UsersController.getAll, got %s", rb.Handler)
	}
	if rb.Method != "GET" {
		t.Errorf("expected method GET, got %s", rb.Method)
	}
	if rb.Path != "/api/users" {
		t.Errorf("expected path /api/users, got %s", rb.Path)
	}
	if len(rb.Middlewares) != 1 || rb.Middlewares[0] != "AuthMiddleware" {
		t.Errorf("expected middlewares [AuthMiddleware], got %v", rb.Middlewares)
	}
	if len(rb.Guards) != 1 || rb.Guards[0] != "RolesGuard" {
		t.Errorf("expected guards [RolesGuard], got %v", rb.Guards)
	}
	if rb.Scope != "route" {
		t.Errorf("expected scope route, got %s", rb.Scope)
	}
}

func TestNewRouteBindingFactMinimal(t *testing.T) {
	rb, err := facts.NewRouteBindingFact(facts.LangGo, "routes.go", facts.Span{Start: 1, End: 5},
		"GetUsers", "", "", nil, nil, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rb.Method != "" {
		t.Errorf("expected empty method, got %s", rb.Method)
	}
	if len(rb.Middlewares) != 0 {
		t.Errorf("expected no middlewares, got %v", rb.Middlewares)
	}
}

func TestNewRouteBindingFactInvalidLanguage(t *testing.T) {
	_, err := facts.NewRouteBindingFact("rust", "routes.go", facts.Span{Start: 1, End: 5}, "handler", "", "", nil, nil, "")
	if err == nil {
		t.Fatal("expected error for invalid language")
	}
}

func TestNewRouteBindingFactMissingFile(t *testing.T) {
	_, err := facts.NewRouteBindingFact(facts.LangGo, "", facts.Span{Start: 1, End: 5}, "handler", "", "", nil, nil, "")
	if err == nil {
		t.Fatal("expected error for empty file")
	}
}

func TestNewRouteBindingFactInvalidSpan(t *testing.T) {
	_, err := facts.NewRouteBindingFact(facts.LangGo, "routes.go", facts.Span{Start: 0, End: 5}, "handler", "", "", nil, nil, "")
	if err == nil {
		t.Fatal("expected error for invalid span")
	}
}

func TestNewRouteBindingFactMissingHandler(t *testing.T) {
	_, err := facts.NewRouteBindingFact(facts.LangGo, "routes.go", facts.Span{Start: 1, End: 5}, "", "", "", nil, nil, "")
	if err == nil {
		t.Fatal("expected error for empty handler")
	}
}

func TestRouteBindingFactQuality(t *testing.T) {
	rb, err := facts.NewRouteBindingFact(facts.LangGo, "routes.go", facts.Span{Start: 1, End: 5}, "handler", "", "", nil, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if rb.Quality != "" {
		t.Errorf("expected zero quality on new RouteBindingFact, got %q", rb.Quality)
	}
	rb.Quality = facts.QualityStructural
	if rb.Quality != facts.QualityStructural {
		t.Errorf("expected quality structural, got %q", rb.Quality)
	}
}
