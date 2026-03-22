package facts

import "fmt"

// FileRoleFact represents the architectural role of a source file.
type FileRoleFact struct {
	Language Language    `json:"language"`
	File     string      `json:"file"`
	Role     string      `json:"role"` // "controller", "service", "repository", "middleware", "test", "config", "model", "migration"
	Quality  FactQuality `json:"quality,omitempty"`
}

// NewFileRoleFact creates a validated FileRoleFact.
func NewFileRoleFact(lang Language, file, role string) (FileRoleFact, error) {
	if !lang.IsValid() {
		return FileRoleFact{}, fmt.Errorf("unsupported language: %q", lang)
	}
	if file == "" {
		return FileRoleFact{}, fmt.Errorf("file path is required")
	}
	if role == "" {
		return FileRoleFact{}, fmt.Errorf("file role is required")
	}
	return FileRoleFact{
		Language: lang,
		File:     file,
		Role:     role,
	}, nil
}
