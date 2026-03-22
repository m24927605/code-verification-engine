package facts_test

import (
	"testing"

	"github.com/verabase/code-verification-engine/internal/facts"
)

func TestNewCallFactValid(t *testing.T) {
	c, err := facts.NewCallFact(facts.LangGo, "service.go", facts.Span{Start: 10, End: 15}, "HandleRequest", "handler.go", "QueryDB", "repo.go")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.CallerName != "HandleRequest" {
		t.Errorf("expected caller name HandleRequest, got %s", c.CallerName)
	}
	if c.CalleeName != "QueryDB" {
		t.Errorf("expected callee name QueryDB, got %s", c.CalleeName)
	}
	if c.CallerFile != "handler.go" {
		t.Errorf("expected caller file handler.go, got %s", c.CallerFile)
	}
	if c.CalleeFile != "repo.go" {
		t.Errorf("expected callee file repo.go, got %s", c.CalleeFile)
	}
}

func TestNewCallFactNoOptionalFiles(t *testing.T) {
	c, err := facts.NewCallFact(facts.LangTypeScript, "app.ts", facts.Span{Start: 5, End: 8}, "main", "", "helper", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.CallerFile != "" {
		t.Errorf("expected empty caller file, got %s", c.CallerFile)
	}
	if c.CalleeFile != "" {
		t.Errorf("expected empty callee file, got %s", c.CalleeFile)
	}
}

func TestNewCallFactInvalidLanguage(t *testing.T) {
	_, err := facts.NewCallFact("rust", "main.rs", facts.Span{Start: 1, End: 5}, "caller", "", "callee", "")
	if err == nil {
		t.Fatal("expected error for invalid language")
	}
}

func TestNewCallFactMissingFile(t *testing.T) {
	_, err := facts.NewCallFact(facts.LangGo, "", facts.Span{Start: 1, End: 5}, "caller", "", "callee", "")
	if err == nil {
		t.Fatal("expected error for empty file")
	}
}

func TestNewCallFactInvalidSpan(t *testing.T) {
	_, err := facts.NewCallFact(facts.LangGo, "main.go", facts.Span{Start: 0, End: 5}, "caller", "", "callee", "")
	if err == nil {
		t.Fatal("expected error for invalid span")
	}
}

func TestNewCallFactMissingCallerName(t *testing.T) {
	_, err := facts.NewCallFact(facts.LangGo, "main.go", facts.Span{Start: 1, End: 5}, "", "", "callee", "")
	if err == nil {
		t.Fatal("expected error for empty caller name")
	}
}

func TestNewCallFactMissingCalleeName(t *testing.T) {
	_, err := facts.NewCallFact(facts.LangGo, "main.go", facts.Span{Start: 1, End: 5}, "caller", "", "", "")
	if err == nil {
		t.Fatal("expected error for empty callee name")
	}
}

func TestCallFactQuality(t *testing.T) {
	c, err := facts.NewCallFact(facts.LangGo, "main.go", facts.Span{Start: 1, End: 5}, "caller", "", "callee", "")
	if err != nil {
		t.Fatal(err)
	}
	if c.Quality != "" {
		t.Errorf("expected zero quality on new CallFact, got %q", c.Quality)
	}
	c.Quality = facts.QualityProof
	if c.Quality != facts.QualityProof {
		t.Errorf("expected quality proof, got %q", c.Quality)
	}
}
