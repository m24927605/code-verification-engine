package facts

import "fmt"

// DependencyFact represents a project dependency.
type DependencyFact struct {
	Language Language    `json:"language"`
	File     string      `json:"file"`
	Span     Span        `json:"span"`
	Name     string      `json:"name"`
	Version  string      `json:"version,omitempty"`
	Quality  FactQuality `json:"quality,omitempty"`
}

// NewDependencyFact creates a validated DependencyFact.
func NewDependencyFact(lang Language, file string, span Span, name, version string) (DependencyFact, error) {
	if !lang.IsValid() {
		return DependencyFact{}, fmt.Errorf("unsupported language: %q", lang)
	}
	if file == "" {
		return DependencyFact{}, fmt.Errorf("file path is required")
	}
	if err := span.Validate(); err != nil {
		return DependencyFact{}, fmt.Errorf("invalid span: %w", err)
	}
	if name == "" {
		return DependencyFact{}, fmt.Errorf("dependency name is required")
	}
	return DependencyFact{Language: lang, File: file, Span: span, Name: name, Version: version}, nil
}
