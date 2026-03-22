package facts_test

import (
	"testing"

	"github.com/verabase/code-verification-engine/internal/facts"
)

func TestNewFileRoleFactValid(t *testing.T) {
	fr, err := facts.NewFileRoleFact(facts.LangGo, "internal/auth/handler.go", "controller")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fr.File != "internal/auth/handler.go" {
		t.Errorf("expected file internal/auth/handler.go, got %s", fr.File)
	}
	if fr.Role != "controller" {
		t.Errorf("expected role controller, got %s", fr.Role)
	}
}

func TestNewFileRoleFactAllRoles(t *testing.T) {
	roles := []string{"controller", "service", "repository", "middleware", "test", "config", "model", "migration"}
	for _, role := range roles {
		fr, err := facts.NewFileRoleFact(facts.LangGo, "main.go", role)
		if err != nil {
			t.Errorf("unexpected error for role %s: %v", role, err)
		}
		if fr.Role != role {
			t.Errorf("expected role %s, got %s", role, fr.Role)
		}
	}
}

func TestNewFileRoleFactInvalidLanguage(t *testing.T) {
	_, err := facts.NewFileRoleFact("rust", "main.rs", "controller")
	if err == nil {
		t.Fatal("expected error for invalid language")
	}
}

func TestNewFileRoleFactMissingFile(t *testing.T) {
	_, err := facts.NewFileRoleFact(facts.LangGo, "", "controller")
	if err == nil {
		t.Fatal("expected error for empty file")
	}
}

func TestNewFileRoleFactMissingRole(t *testing.T) {
	_, err := facts.NewFileRoleFact(facts.LangGo, "main.go", "")
	if err == nil {
		t.Fatal("expected error for empty role")
	}
}

func TestFileRoleFactQuality(t *testing.T) {
	fr, err := facts.NewFileRoleFact(facts.LangGo, "main.go", "service")
	if err != nil {
		t.Fatal(err)
	}
	if fr.Quality != "" {
		t.Errorf("expected zero quality on new FileRoleFact, got %q", fr.Quality)
	}
	fr.Quality = facts.QualityHeuristic
	if fr.Quality != facts.QualityHeuristic {
		t.Errorf("expected quality heuristic, got %q", fr.Quality)
	}
}
