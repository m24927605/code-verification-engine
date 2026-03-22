package facts

import "fmt"

// SymbolFact represents an extracted symbol (function, method, class, etc.).
type SymbolFact struct {
	Language Language `json:"language"`
	File     string   `json:"file"`
	Span     Span     `json:"span"`
	Name     string   `json:"symbol"`
	Kind     string   `json:"kind"`
	Exported bool     `json:"exported"`
}

// NewSymbolFact creates a validated SymbolFact.
func NewSymbolFact(lang Language, file string, span Span, name, kind string, exported bool) (SymbolFact, error) {
	if !lang.IsValid() {
		return SymbolFact{}, fmt.Errorf("unsupported language: %q", lang)
	}
	if file == "" {
		return SymbolFact{}, fmt.Errorf("file path is required")
	}
	if err := span.Validate(); err != nil {
		return SymbolFact{}, fmt.Errorf("invalid span: %w", err)
	}
	if name == "" {
		return SymbolFact{}, fmt.Errorf("symbol name is required")
	}
	return SymbolFact{
		Language: lang,
		File:     file,
		Span:     span,
		Name:     name,
		Kind:     kind,
		Exported: exported,
	}, nil
}
