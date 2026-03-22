package facts_test

import (
	"testing"

	"github.com/verabase/code-verification-engine/internal/facts"
)

func TestFactQualityConstants(t *testing.T) {
	if facts.QualityProof != "proof" {
		t.Errorf("expected QualityProof = %q, got %q", "proof", facts.QualityProof)
	}
	if facts.QualityStructural != "structural" {
		t.Errorf("expected QualityStructural = %q, got %q", "structural", facts.QualityStructural)
	}
	if facts.QualityHeuristic != "heuristic" {
		t.Errorf("expected QualityHeuristic = %q, got %q", "heuristic", facts.QualityHeuristic)
	}
}

func TestMinQualityEmpty(t *testing.T) {
	result := facts.MinQuality()
	if result != facts.QualityHeuristic {
		t.Errorf("MinQuality() with no args: expected %q, got %q", facts.QualityHeuristic, result)
	}
}

func TestMinQualitySingle(t *testing.T) {
	tests := []struct {
		input    facts.FactQuality
		expected facts.FactQuality
	}{
		{facts.QualityProof, facts.QualityProof},
		{facts.QualityStructural, facts.QualityStructural},
		{facts.QualityHeuristic, facts.QualityHeuristic},
	}
	for _, tc := range tests {
		result := facts.MinQuality(tc.input)
		if result != tc.expected {
			t.Errorf("MinQuality(%q) = %q, want %q", tc.input, result, tc.expected)
		}
	}
}

func TestMinQualityOrdering(t *testing.T) {
	// heuristic < structural < proof
	tests := []struct {
		name     string
		inputs   []facts.FactQuality
		expected facts.FactQuality
	}{
		{
			name:     "proof and structural returns structural",
			inputs:   []facts.FactQuality{facts.QualityProof, facts.QualityStructural},
			expected: facts.QualityStructural,
		},
		{
			name:     "proof and heuristic returns heuristic",
			inputs:   []facts.FactQuality{facts.QualityProof, facts.QualityHeuristic},
			expected: facts.QualityHeuristic,
		},
		{
			name:     "structural and heuristic returns heuristic",
			inputs:   []facts.FactQuality{facts.QualityStructural, facts.QualityHeuristic},
			expected: facts.QualityHeuristic,
		},
		{
			name:     "all three returns heuristic",
			inputs:   []facts.FactQuality{facts.QualityProof, facts.QualityStructural, facts.QualityHeuristic},
			expected: facts.QualityHeuristic,
		},
		{
			name:     "all proof returns proof",
			inputs:   []facts.FactQuality{facts.QualityProof, facts.QualityProof, facts.QualityProof},
			expected: facts.QualityProof,
		},
		{
			name:     "reversed order still works",
			inputs:   []facts.FactQuality{facts.QualityHeuristic, facts.QualityStructural, facts.QualityProof},
			expected: facts.QualityHeuristic,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := facts.MinQuality(tc.inputs...)
			if result != tc.expected {
				t.Errorf("MinQuality(%v) = %q, want %q", tc.inputs, result, tc.expected)
			}
		})
	}
}

func TestQualityOnFactStructs(t *testing.T) {
	// Verify that Quality field exists and works on all fact types
	// by creating facts and checking the zero value is empty string (omitempty works)

	sf, err := facts.NewSymbolFact(facts.LangGo, "main.go", facts.Span{Start: 1, End: 5}, "Foo", "function", true)
	if err != nil {
		t.Fatal(err)
	}
	if sf.Quality != "" {
		t.Errorf("expected zero quality on new SymbolFact, got %q", sf.Quality)
	}
	sf.Quality = facts.QualityProof
	if sf.Quality != facts.QualityProof {
		t.Errorf("expected quality proof, got %q", sf.Quality)
	}

	imf, err := facts.NewImportFact(facts.LangGo, "main.go", facts.Span{Start: 1, End: 1}, "fmt", "")
	if err != nil {
		t.Fatal(err)
	}
	imf.Quality = facts.QualityStructural
	if imf.Quality != facts.QualityStructural {
		t.Errorf("expected quality structural, got %q", imf.Quality)
	}

	mf, err := facts.NewMiddlewareFact(facts.LangGo, "mw.go", facts.Span{Start: 1, End: 5}, "Auth", "http")
	if err != nil {
		t.Fatal(err)
	}
	mf.Quality = facts.QualityHeuristic
	if mf.Quality != facts.QualityHeuristic {
		t.Errorf("expected quality heuristic, got %q", mf.Quality)
	}

	rf, err := facts.NewRouteFact(facts.LangGo, "routes.go", facts.Span{Start: 1, End: 5}, "GET", "/api", "h", nil)
	if err != nil {
		t.Fatal(err)
	}
	rf.Quality = facts.QualityProof
	if rf.Quality != facts.QualityProof {
		t.Errorf("expected quality proof, got %q", rf.Quality)
	}

	tf, err := facts.NewTestFact(facts.LangGo, "test.go", facts.Span{Start: 1, End: 5}, "TestFoo", "", "")
	if err != nil {
		t.Fatal(err)
	}
	tf.Quality = facts.QualityProof
	if tf.Quality != facts.QualityProof {
		t.Errorf("expected quality proof, got %q", tf.Quality)
	}

	da, err := facts.NewDataAccessFact(facts.LangGo, "repo.go", facts.Span{Start: 1, End: 5}, "Query", "sql")
	if err != nil {
		t.Fatal(err)
	}
	da.Quality = facts.QualityProof
	if da.Quality != facts.QualityProof {
		t.Errorf("expected quality proof, got %q", da.Quality)
	}

	sec, err := facts.NewSecretFact(facts.LangGo, "config.go", facts.Span{Start: 1, End: 1}, "password", "pw")
	if err != nil {
		t.Fatal(err)
	}
	sec.Quality = facts.QualityHeuristic
	if sec.Quality != facts.QualityHeuristic {
		t.Errorf("expected quality heuristic, got %q", sec.Quality)
	}

	ff, err := facts.NewFileFact(facts.LangGo, "main.go", 100)
	if err != nil {
		t.Fatal(err)
	}
	ff.Quality = facts.QualityProof
	if ff.Quality != facts.QualityProof {
		t.Errorf("expected quality proof, got %q", ff.Quality)
	}

	cf, err := facts.NewConfigFact(facts.LangGo, "config.go", facts.Span{Start: 1, End: 3}, "KEY", "env")
	if err != nil {
		t.Fatal(err)
	}
	cf.Quality = facts.QualityStructural
	if cf.Quality != facts.QualityStructural {
		t.Errorf("expected quality structural, got %q", cf.Quality)
	}

	df, err := facts.NewDependencyFact(facts.LangGo, "go.mod", facts.Span{Start: 1, End: 1}, "gin", "v1.0")
	if err != nil {
		t.Fatal(err)
	}
	df.Quality = facts.QualityProof
	if df.Quality != facts.QualityProof {
		t.Errorf("expected quality proof, got %q", df.Quality)
	}
}
