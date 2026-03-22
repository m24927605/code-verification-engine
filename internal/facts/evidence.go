package facts

import "fmt"

// Evidence represents a piece of evidence backing a finding.
type Evidence struct {
	Type      string `json:"type"`
	File      string `json:"file"`
	LineStart int    `json:"line_start"`
	LineEnd   int    `json:"line_end"`
	Symbol    string `json:"symbol,omitempty"`
	Excerpt   string `json:"excerpt,omitempty"`
}

// NewEvidence creates a validated Evidence.
func NewEvidence(evidenceType, file string, lineStart, lineEnd int, symbol, excerpt string) (Evidence, error) {
	if evidenceType == "" {
		return Evidence{}, fmt.Errorf("evidence type is required")
	}
	if file == "" {
		return Evidence{}, fmt.Errorf("file path is required")
	}
	if lineStart < 1 {
		return Evidence{}, fmt.Errorf("line_start must be >= 1, got %d", lineStart)
	}
	if lineEnd < lineStart {
		return Evidence{}, fmt.Errorf("line_end (%d) must be >= line_start (%d)", lineEnd, lineStart)
	}
	return Evidence{
		Type:      evidenceType,
		File:      file,
		LineStart: lineStart,
		LineEnd:   lineEnd,
		Symbol:    symbol,
		Excerpt:   excerpt,
	}, nil
}
