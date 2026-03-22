package facts

import "fmt"

// Span represents a line range in a source file.
type Span struct {
	Start int `json:"start"`
	End   int `json:"end"`
}

// Validate checks that the span has valid start/end lines.
func (s Span) Validate() error {
	if s.Start < 1 {
		return fmt.Errorf("span start must be >= 1, got %d", s.Start)
	}
	if s.End < s.Start {
		return fmt.Errorf("span end (%d) must be >= start (%d)", s.End, s.Start)
	}
	return nil
}
