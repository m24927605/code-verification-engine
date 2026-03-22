package facts

import "fmt"

// RouteFact represents an HTTP route definition.
type RouteFact struct {
	Language    Language    `json:"language"`
	File        string      `json:"file"`
	Span        Span        `json:"span"`
	Method      string      `json:"method"`
	Path        string      `json:"path"`
	Handler     string      `json:"handler"`
	Middlewares []string    `json:"middlewares,omitempty"`
	Quality     FactQuality    `json:"quality,omitempty"`
	Provenance  FactProvenance `json:"provenance,omitempty"`
}

// NewRouteFact creates a validated RouteFact.
func NewRouteFact(lang Language, file string, span Span, method, path, handler string, middlewares []string) (RouteFact, error) {
	if !lang.IsValid() {
		return RouteFact{}, fmt.Errorf("unsupported language: %q", lang)
	}
	if file == "" {
		return RouteFact{}, fmt.Errorf("file path is required")
	}
	if err := span.Validate(); err != nil {
		return RouteFact{}, fmt.Errorf("invalid span: %w", err)
	}
	if method == "" {
		return RouteFact{}, fmt.Errorf("HTTP method is required")
	}
	if path == "" {
		return RouteFact{}, fmt.Errorf("route path is required")
	}
	return RouteFact{Language: lang, File: file, Span: span, Method: method, Path: path, Handler: handler, Middlewares: middlewares}, nil
}
