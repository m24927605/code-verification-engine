package facts

import "fmt"

// ConfigReadFact represents a configuration value read operation.
type ConfigReadFact struct {
	Language   Language    `json:"language"`
	File       string      `json:"file"`
	Span       Span        `json:"span"`
	Key        string      `json:"key"`
	SourceKind string      `json:"source_kind"` // "env", "file", "default", "literal", "unknown"
	Quality    FactQuality `json:"quality,omitempty"`
}

// NewConfigReadFact creates a validated ConfigReadFact.
func NewConfigReadFact(lang Language, file string, span Span, key, sourceKind string) (ConfigReadFact, error) {
	if !lang.IsValid() {
		return ConfigReadFact{}, fmt.Errorf("unsupported language: %q", lang)
	}
	if file == "" {
		return ConfigReadFact{}, fmt.Errorf("file path is required")
	}
	if err := span.Validate(); err != nil {
		return ConfigReadFact{}, fmt.Errorf("invalid span: %w", err)
	}
	if key == "" {
		return ConfigReadFact{}, fmt.Errorf("config key is required")
	}
	return ConfigReadFact{
		Language:   lang,
		File:       file,
		Span:       span,
		Key:        key,
		SourceKind: sourceKind,
	}, nil
}
