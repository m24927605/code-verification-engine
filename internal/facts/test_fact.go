package facts

import "fmt"

// TestFact represents a detected test case.
type TestFact struct {
	Language     Language `json:"language"`
	File         string   `json:"file"`
	Span         Span     `json:"span"`
	TestName     string   `json:"test_name"`
	TargetModule string   `json:"target_module,omitempty"`
	TargetPath   string   `json:"target_path,omitempty"`
}

// NewTestFact creates a validated TestFact.
func NewTestFact(lang Language, file string, span Span, testName, targetModule, targetPath string) (TestFact, error) {
	if !lang.IsValid() {
		return TestFact{}, fmt.Errorf("unsupported language: %q", lang)
	}
	if file == "" {
		return TestFact{}, fmt.Errorf("file path is required")
	}
	if err := span.Validate(); err != nil {
		return TestFact{}, fmt.Errorf("invalid span: %w", err)
	}
	if testName == "" {
		return TestFact{}, fmt.Errorf("test name is required")
	}
	return TestFact{Language: lang, File: file, Span: span, TestName: testName, TargetModule: targetModule, TargetPath: targetPath}, nil
}
