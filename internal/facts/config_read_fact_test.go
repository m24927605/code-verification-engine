package facts_test

import (
	"testing"

	"github.com/verabase/code-verification-engine/internal/facts"
)

func TestNewConfigReadFactValid(t *testing.T) {
	cr, err := facts.NewConfigReadFact(facts.LangGo, "config.go", facts.Span{Start: 3, End: 8}, "DATABASE_URL", "env")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cr.Key != "DATABASE_URL" {
		t.Errorf("expected key DATABASE_URL, got %s", cr.Key)
	}
	if cr.SourceKind != "env" {
		t.Errorf("expected source_kind env, got %s", cr.SourceKind)
	}
}

func TestNewConfigReadFactNoSourceKind(t *testing.T) {
	cr, err := facts.NewConfigReadFact(facts.LangTypeScript, "config.ts", facts.Span{Start: 1, End: 3}, "API_KEY", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cr.SourceKind != "" {
		t.Errorf("expected empty source_kind, got %s", cr.SourceKind)
	}
}

func TestNewConfigReadFactInvalidLanguage(t *testing.T) {
	_, err := facts.NewConfigReadFact("rust", "config.go", facts.Span{Start: 1, End: 3}, "KEY", "env")
	if err == nil {
		t.Fatal("expected error for invalid language")
	}
}

func TestNewConfigReadFactMissingFile(t *testing.T) {
	_, err := facts.NewConfigReadFact(facts.LangGo, "", facts.Span{Start: 1, End: 3}, "KEY", "env")
	if err == nil {
		t.Fatal("expected error for empty file")
	}
}

func TestNewConfigReadFactInvalidSpan(t *testing.T) {
	_, err := facts.NewConfigReadFact(facts.LangGo, "config.go", facts.Span{Start: 0, End: 3}, "KEY", "env")
	if err == nil {
		t.Fatal("expected error for invalid span")
	}
}

func TestNewConfigReadFactMissingKey(t *testing.T) {
	_, err := facts.NewConfigReadFact(facts.LangGo, "config.go", facts.Span{Start: 1, End: 3}, "", "env")
	if err == nil {
		t.Fatal("expected error for empty key")
	}
}

func TestConfigReadFactQuality(t *testing.T) {
	cr, err := facts.NewConfigReadFact(facts.LangGo, "config.go", facts.Span{Start: 1, End: 3}, "KEY", "env")
	if err != nil {
		t.Fatal(err)
	}
	if cr.Quality != "" {
		t.Errorf("expected zero quality on new ConfigReadFact, got %q", cr.Quality)
	}
	cr.Quality = facts.QualityProof
	if cr.Quality != facts.QualityProof {
		t.Errorf("expected quality proof, got %q", cr.Quality)
	}
}
