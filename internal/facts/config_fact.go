package facts

import "fmt"

// ConfigFact represents a configuration value reference.
type ConfigFact struct {
	Language Language `json:"language"`
	File     string   `json:"file"`
	Span     Span     `json:"span"`
	Key      string   `json:"key"`
	Source   string   `json:"source,omitempty"`
}

// NewConfigFact creates a validated ConfigFact.
func NewConfigFact(lang Language, file string, span Span, key, source string) (ConfigFact, error) {
	if !lang.IsValid() {
		return ConfigFact{}, fmt.Errorf("unsupported language: %q", lang)
	}
	if file == "" {
		return ConfigFact{}, fmt.Errorf("file path is required")
	}
	if err := span.Validate(); err != nil {
		return ConfigFact{}, fmt.Errorf("invalid span: %w", err)
	}
	if key == "" {
		return ConfigFact{}, fmt.Errorf("config key is required")
	}
	return ConfigFact{Language: lang, File: file, Span: span, Key: key, Source: source}, nil
}
