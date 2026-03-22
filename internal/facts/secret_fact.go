package facts

import "fmt"

// SecretFact represents a detected secret or credential.
type SecretFact struct {
	Language Language `json:"language"`
	File     string   `json:"file"`
	Span     Span     `json:"span"`
	Kind     string   `json:"kind"`
	Value    string   `json:"value,omitempty"`
}

// NewSecretFact creates a validated SecretFact.
func NewSecretFact(lang Language, file string, span Span, kind, value string) (SecretFact, error) {
	if !lang.IsValid() {
		return SecretFact{}, fmt.Errorf("unsupported language: %q", lang)
	}
	if file == "" {
		return SecretFact{}, fmt.Errorf("file path is required")
	}
	if err := span.Validate(); err != nil {
		return SecretFact{}, fmt.Errorf("invalid span: %w", err)
	}
	if kind == "" {
		return SecretFact{}, fmt.Errorf("secret kind is required")
	}
	return SecretFact{Language: lang, File: file, Span: span, Kind: kind, Value: value}, nil
}
