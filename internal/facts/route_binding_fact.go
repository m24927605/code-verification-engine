package facts

import "fmt"

// RouteBindingFact represents a route-to-handler binding with associated middleware/guards.
type RouteBindingFact struct {
	Language    Language    `json:"language"`
	File        string      `json:"file"`
	Span        Span        `json:"span"`
	Handler     string      `json:"handler"`
	Method      string      `json:"method,omitempty"`
	Path        string      `json:"path,omitempty"`
	Middlewares []string    `json:"middlewares,omitempty"`
	Guards      []string    `json:"guards,omitempty"`
	Scope       string      `json:"scope,omitempty"` // "route", "controller", "global"
	Quality     FactQuality `json:"quality,omitempty"`
}

// NewRouteBindingFact creates a validated RouteBindingFact.
func NewRouteBindingFact(lang Language, file string, span Span, handler string, method, path string, middlewares, guards []string, scope string) (RouteBindingFact, error) {
	if !lang.IsValid() {
		return RouteBindingFact{}, fmt.Errorf("unsupported language: %q", lang)
	}
	if file == "" {
		return RouteBindingFact{}, fmt.Errorf("file path is required")
	}
	if err := span.Validate(); err != nil {
		return RouteBindingFact{}, fmt.Errorf("invalid span: %w", err)
	}
	if handler == "" {
		return RouteBindingFact{}, fmt.Errorf("handler is required")
	}
	return RouteBindingFact{
		Language:    lang,
		File:        file,
		Span:        span,
		Handler:     handler,
		Method:      method,
		Path:        path,
		Middlewares: middlewares,
		Guards:      guards,
		Scope:       scope,
	}, nil
}
