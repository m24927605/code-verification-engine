package facts

import "fmt"

// FileFact represents a source file in the scanned repository.
type FileFact struct {
	Language  Language    `json:"language"`
	File      string      `json:"file"`
	LineCount int         `json:"line_count"`
	Quality   FactQuality `json:"quality,omitempty"`
}

// NewFileFact creates a validated FileFact.
func NewFileFact(lang Language, file string, lineCount int) (FileFact, error) {
	if !lang.IsValid() {
		return FileFact{}, fmt.Errorf("unsupported language: %q", lang)
	}
	if file == "" {
		return FileFact{}, fmt.Errorf("file path is required")
	}
	return FileFact{
		Language:  lang,
		File:      file,
		LineCount: lineCount,
	}, nil
}
