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
