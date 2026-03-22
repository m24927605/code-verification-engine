package evidence

import (
	"crypto/sha256"
	"fmt"
	"os"
	"strings"

	"github.com/verabase/code-verification-engine/internal/facts"
)

// Collector normalizes, enriches, and validates evidence.
type Collector struct{}

// NewCollector creates a new evidence collector.
func NewCollector() *Collector {
	return &Collector{}
}

// Enrich attaches stable metadata and bounded excerpts to evidence items.
// It normalizes file paths and generates deterministic evidence IDs.
func (c *Collector) Enrich(evidence []facts.Evidence, scanDir string) []EnrichedEvidence {
	result := make([]EnrichedEvidence, 0, len(evidence))
	for _, ev := range evidence {
		enriched := EnrichedEvidence{
			Evidence: ev,
			ID:       generateEvidenceID(ev),
		}
		if ev.Excerpt == "" && scanDir != "" {
			enriched.Evidence.Excerpt = readExcerpt(scanDir, ev.File, ev.LineStart, ev.LineEnd)
		}
		result = append(result, enriched)
	}
	return result
}

// Validate checks evidence structure and basic content consistency.
func (c *Collector) Validate(evidence []facts.Evidence) []string {
	var errors []string
	for i, ev := range evidence {
		if ev.File == "" {
			errors = append(errors, fmt.Sprintf("evidence[%d]: file path is required", i))
		}
		if ev.LineStart < 1 {
			errors = append(errors, fmt.Sprintf("evidence[%d]: line_start must be >= 1", i))
		}
		if ev.LineEnd < ev.LineStart {
			errors = append(errors, fmt.Sprintf("evidence[%d]: line_end must be >= line_start", i))
		}
	}
	return errors
}

// EnrichedEvidence wraps evidence with additional metadata.
type EnrichedEvidence struct {
	facts.Evidence
	ID string `json:"evidence_id"`
}

// generateEvidenceID creates a deterministic content-derived identifier.
func generateEvidenceID(ev facts.Evidence) string {
	content := fmt.Sprintf("%s:%s:%d:%d:%s", ev.Type, ev.File, ev.LineStart, ev.LineEnd, ev.Symbol)
	hash := sha256.Sum256([]byte(content))
	return fmt.Sprintf("ev-%x", hash[:8])
}

// readExcerpt reads bounded lines from a source file for evidence excerpts.
func readExcerpt(scanDir, file string, lineStart, lineEnd int) string {
	path := file
	if scanDir != "" && !strings.HasPrefix(file, "/") {
		path = scanDir + "/" + file
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	lines := strings.Split(string(data), "\n")
	if lineStart < 1 || lineStart > len(lines) {
		return ""
	}
	end := lineEnd
	if end > len(lines) {
		end = len(lines)
	}
	selected := lines[lineStart-1 : end]
	return strings.Join(selected, "\n")
}
