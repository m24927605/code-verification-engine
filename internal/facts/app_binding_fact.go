package facts

import "fmt"

// AppBindingFact represents an application-level binding (middleware, guard, interceptor, etc.).
type AppBindingFact struct {
	Language Language    `json:"language"`
	File     string      `json:"file"`
	Span     Span        `json:"span"`
	Kind     string      `json:"kind"`  // "middleware", "guard", "interceptor", "filter", "pipe"
	Name     string      `json:"name"`
	Scope    string      `json:"scope"` // "global", "module", "controller"
	Quality  FactQuality `json:"quality,omitempty"`
}

// NewAppBindingFact creates a validated AppBindingFact.
func NewAppBindingFact(lang Language, file string, span Span, kind, name, scope string) (AppBindingFact, error) {
	if !lang.IsValid() {
		return AppBindingFact{}, fmt.Errorf("unsupported language: %q", lang)
	}
	if file == "" {
		return AppBindingFact{}, fmt.Errorf("file path is required")
	}
	if err := span.Validate(); err != nil {
		return AppBindingFact{}, fmt.Errorf("invalid span: %w", err)
	}
	if kind == "" {
		return AppBindingFact{}, fmt.Errorf("binding kind is required")
	}
	if name == "" {
		return AppBindingFact{}, fmt.Errorf("binding name is required")
	}
	return AppBindingFact{
		Language: lang,
		File:     file,
		Span:     span,
		Kind:     kind,
		Name:     name,
		Scope:    scope,
	}, nil
}
