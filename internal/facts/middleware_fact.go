package facts

import "fmt"

// MiddlewareFact represents a middleware definition.
type MiddlewareFact struct {
	Language Language `json:"language"`
	File     string   `json:"file"`
	Span     Span     `json:"span"`
	Name     string   `json:"name"`
	Kind     string   `json:"kind"`
}

// NewMiddlewareFact creates a validated MiddlewareFact.
func NewMiddlewareFact(lang Language, file string, span Span, name, kind string) (MiddlewareFact, error) {
	if !lang.IsValid() {
		return MiddlewareFact{}, fmt.Errorf("unsupported language: %q", lang)
	}
	if file == "" {
		return MiddlewareFact{}, fmt.Errorf("file path is required")
	}
	if err := span.Validate(); err != nil {
		return MiddlewareFact{}, fmt.Errorf("invalid span: %w", err)
	}
	if name == "" {
		return MiddlewareFact{}, fmt.Errorf("middleware name is required")
	}
	return MiddlewareFact{Language: lang, File: file, Span: span, Name: name, Kind: kind}, nil
}
