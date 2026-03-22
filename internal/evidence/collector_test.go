package evidence

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/verabase/code-verification-engine/internal/facts"
)

func TestCollectorValidate(t *testing.T) {
	c := NewCollector()

	tests := []struct {
		name     string
		evidence []facts.Evidence
		wantErrs int
	}{
		{
			name: "valid evidence",
			evidence: []facts.Evidence{
				{Type: "symbol", File: "main.go", LineStart: 1, LineEnd: 10, Symbol: "main"},
			},
			wantErrs: 0,
		},
		{
			name: "missing file",
			evidence: []facts.Evidence{
				{Type: "symbol", File: "", LineStart: 1, LineEnd: 10},
			},
			wantErrs: 1,
		},
		{
			name: "invalid line_start",
			evidence: []facts.Evidence{
				{Type: "symbol", File: "main.go", LineStart: 0, LineEnd: 10},
			},
			wantErrs: 1,
		},
		{
			name: "line_end before line_start",
			evidence: []facts.Evidence{
				{Type: "symbol", File: "main.go", LineStart: 10, LineEnd: 5},
			},
			wantErrs: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errs := c.Validate(tt.evidence)
			if len(errs) != tt.wantErrs {
				t.Errorf("got %d errors, want %d: %v", len(errs), tt.wantErrs, errs)
			}
		})
	}
}

func TestGenerateEvidenceID(t *testing.T) {
	ev1 := facts.Evidence{Type: "symbol", File: "main.go", LineStart: 1, LineEnd: 10, Symbol: "main"}
	ev2 := facts.Evidence{Type: "symbol", File: "main.go", LineStart: 1, LineEnd: 10, Symbol: "main"}
	ev3 := facts.Evidence{Type: "symbol", File: "other.go", LineStart: 1, LineEnd: 10, Symbol: "main"}

	id1 := generateEvidenceID(ev1)
	id2 := generateEvidenceID(ev2)
	id3 := generateEvidenceID(ev3)

	if id1 != id2 {
		t.Error("identical evidence should produce identical IDs")
	}
	if id1 == id3 {
		t.Error("different evidence should produce different IDs")
	}
	if !strings.HasPrefix(id1, "ev-") {
		t.Errorf("evidence ID should start with 'ev-', got %s", id1)
	}
}

func TestReadExcerptFileNotFound(t *testing.T) {
	result := readExcerpt("/nonexistent/dir", "missing.go", 1, 5)
	if result != "" {
		t.Errorf("expected empty string for missing file, got %q", result)
	}
}

func TestReadExcerptInvalidLineStart(t *testing.T) {
	tmpDir := t.TempDir()
	err := os.WriteFile(filepath.Join(tmpDir, "test.go"), []byte("line1\nline2\n"), 0o644)
	if err != nil {
		t.Fatal(err)
	}

	// lineStart < 1
	result := readExcerpt(tmpDir, "test.go", 0, 2)
	if result != "" {
		t.Errorf("expected empty for lineStart=0, got %q", result)
	}

	// lineStart > number of lines
	result = readExcerpt(tmpDir, "test.go", 100, 200)
	if result != "" {
		t.Errorf("expected empty for lineStart=100, got %q", result)
	}
}

func TestReadExcerptLineEndBeyondFile(t *testing.T) {
	tmpDir := t.TempDir()
	err := os.WriteFile(filepath.Join(tmpDir, "test.go"), []byte("line1\nline2\nline3\n"), 0o644)
	if err != nil {
		t.Fatal(err)
	}

	// lineEnd beyond file length should be clamped
	result := readExcerpt(tmpDir, "test.go", 2, 100)
	if !strings.Contains(result, "line2") {
		t.Errorf("expected line2 in result, got %q", result)
	}
}

func TestReadExcerptAbsolutePath(t *testing.T) {
	tmpDir := t.TempDir()
	absPath := filepath.Join(tmpDir, "test.go")
	err := os.WriteFile(absPath, []byte("line1\nline2\n"), 0o644)
	if err != nil {
		t.Fatal(err)
	}

	// When file is absolute path, scanDir should not be prepended
	result := readExcerpt("", absPath, 1, 1)
	if result != "line1" {
		t.Errorf("expected 'line1', got %q", result)
	}
}

func TestEnrichPreservesExistingExcerpt(t *testing.T) {
	c := NewCollector()
	evidence := []facts.Evidence{
		{Type: "symbol", File: "test.go", LineStart: 1, LineEnd: 2, Symbol: "foo", Excerpt: "existing"},
	}

	enriched := c.Enrich(evidence, "/some/dir")
	if enriched[0].Excerpt != "existing" {
		t.Errorf("expected existing excerpt to be preserved, got %q", enriched[0].Excerpt)
	}
}

func TestCollectorEnrich(t *testing.T) {
	c := NewCollector()
	tmpDir := t.TempDir()
	err := os.WriteFile(filepath.Join(tmpDir, "test.go"), []byte("line1\nline2\nline3\nline4\nline5\n"), 0o644)
	if err != nil {
		t.Fatal(err)
	}

	evidence := []facts.Evidence{
		{Type: "symbol", File: "test.go", LineStart: 2, LineEnd: 4, Symbol: "foo"},
	}

	enriched := c.Enrich(evidence, tmpDir)
	if len(enriched) != 1 {
		t.Fatalf("expected 1 enriched evidence, got %d", len(enriched))
	}
	if enriched[0].ID == "" {
		t.Error("enriched evidence should have an ID")
	}
	if enriched[0].Excerpt != "line2\nline3\nline4" {
		t.Errorf("unexpected excerpt: %q", enriched[0].Excerpt)
	}
}
