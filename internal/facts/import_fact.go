package facts

import "fmt"

// ImportFact represents an import/require/include statement.
type ImportFact struct {
	Language   Language `json:"language"`
	File       string   `json:"file"`
	Span       Span     `json:"span"`
	ImportPath string   `json:"import_path"`
	Alias      string   `json:"alias,omitempty"`
}

// NewImportFact creates a validated ImportFact.
func NewImportFact(lang Language, file string, span Span, importPath, alias string) (ImportFact, error) {
	if !lang.IsValid() {
		return ImportFact{}, fmt.Errorf("unsupported language: %q", lang)
	}
	if file == "" {
		return ImportFact{}, fmt.Errorf("file path is required")
	}
	if err := span.Validate(); err != nil {
		return ImportFact{}, fmt.Errorf("invalid span: %w", err)
	}
	if importPath == "" {
		return ImportFact{}, fmt.Errorf("import path is required")
	}
	return ImportFact{
		Language:   lang,
		File:       file,
		Span:       span,
		ImportPath: importPath,
		Alias:      alias,
	}, nil
}
