package facts_test

import (
	"testing"

	"github.com/verabase/code-verification-engine/internal/facts"
)

func TestNewAppBindingFactValid(t *testing.T) {
	ab, err := facts.NewAppBindingFact(facts.LangTypeScript, "app.module.ts", facts.Span{Start: 5, End: 10},
		"guard", "RolesGuard", "controller")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ab.Kind != "guard" {
		t.Errorf("expected kind guard, got %s", ab.Kind)
	}
	if ab.Name != "RolesGuard" {
		t.Errorf("expected name RolesGuard, got %s", ab.Name)
	}
	if ab.Scope != "controller" {
		t.Errorf("expected scope controller, got %s", ab.Scope)
	}
}

func TestNewAppBindingFactNoScope(t *testing.T) {
	ab, err := facts.NewAppBindingFact(facts.LangGo, "main.go", facts.Span{Start: 1, End: 5},
		"middleware", "Logger", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ab.Scope != "" {
		t.Errorf("expected empty scope, got %s", ab.Scope)
	}
}

func TestNewAppBindingFactInvalidLanguage(t *testing.T) {
	_, err := facts.NewAppBindingFact("rust", "main.rs", facts.Span{Start: 1, End: 5}, "middleware", "Auth", "global")
	if err == nil {
		t.Fatal("expected error for invalid language")
	}
}

func TestNewAppBindingFactMissingFile(t *testing.T) {
	_, err := facts.NewAppBindingFact(facts.LangGo, "", facts.Span{Start: 1, End: 5}, "middleware", "Auth", "global")
	if err == nil {
		t.Fatal("expected error for empty file")
	}
}

func TestNewAppBindingFactInvalidSpan(t *testing.T) {
	_, err := facts.NewAppBindingFact(facts.LangGo, "main.go", facts.Span{Start: 0, End: 5}, "middleware", "Auth", "global")
	if err == nil {
		t.Fatal("expected error for invalid span")
	}
}

func TestNewAppBindingFactMissingKind(t *testing.T) {
	_, err := facts.NewAppBindingFact(facts.LangGo, "main.go", facts.Span{Start: 1, End: 5}, "", "Auth", "global")
	if err == nil {
		t.Fatal("expected error for empty kind")
	}
}

func TestNewAppBindingFactMissingName(t *testing.T) {
	_, err := facts.NewAppBindingFact(facts.LangGo, "main.go", facts.Span{Start: 1, End: 5}, "middleware", "", "global")
	if err == nil {
		t.Fatal("expected error for empty name")
	}
}

func TestAppBindingFactQuality(t *testing.T) {
	ab, err := facts.NewAppBindingFact(facts.LangGo, "main.go", facts.Span{Start: 1, End: 5}, "middleware", "Auth", "global")
	if err != nil {
		t.Fatal(err)
	}
	if ab.Quality != "" {
		t.Errorf("expected zero quality on new AppBindingFact, got %q", ab.Quality)
	}
	ab.Quality = facts.QualityHeuristic
	if ab.Quality != facts.QualityHeuristic {
		t.Errorf("expected quality heuristic, got %q", ab.Quality)
	}
}
