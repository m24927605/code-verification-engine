package facts

import "fmt"

// DataAccessFact represents a database or data store access pattern.
type DataAccessFact struct {
	Language  Language `json:"language"`
	File      string   `json:"file"`
	Span      Span     `json:"span"`
	Operation string   `json:"operation"`
	Backend   string   `json:"backend,omitempty"`
}

// NewDataAccessFact creates a validated DataAccessFact.
func NewDataAccessFact(lang Language, file string, span Span, operation, backend string) (DataAccessFact, error) {
	if !lang.IsValid() {
		return DataAccessFact{}, fmt.Errorf("unsupported language: %q", lang)
	}
	if file == "" {
		return DataAccessFact{}, fmt.Errorf("file path is required")
	}
	if err := span.Validate(); err != nil {
		return DataAccessFact{}, fmt.Errorf("invalid span: %w", err)
	}
	if operation == "" {
		return DataAccessFact{}, fmt.Errorf("operation is required")
	}
	return DataAccessFact{Language: lang, File: file, Span: span, Operation: operation, Backend: backend}, nil
}
