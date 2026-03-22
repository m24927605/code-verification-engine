package schema

import (
	"fmt"

	"github.com/verabase/code-verification-engine/internal/facts"
	"github.com/verabase/code-verification-engine/internal/rules"
)

// ValidateFileFact checks required fields on a FileFact.
func ValidateFileFact(f facts.FileFact) error {
	if !f.Language.IsValid() {
		return fmt.Errorf("invalid language: %q", f.Language)
	}
	if f.File == "" {
		return fmt.Errorf("file path is required")
	}
	return nil
}

// ValidateSymbolFact checks required fields on a SymbolFact.
func ValidateSymbolFact(s facts.SymbolFact) error {
	if !s.Language.IsValid() {
		return fmt.Errorf("invalid language: %q", s.Language)
	}
	if s.File == "" {
		return fmt.Errorf("file path is required")
	}
	if err := s.Span.Validate(); err != nil {
		return fmt.Errorf("invalid span: %w", err)
	}
	if s.Name == "" {
		return fmt.Errorf("symbol name is required")
	}
	if s.Kind == "" {
		return fmt.Errorf("symbol kind is required")
	}
	return nil
}

// ValidateImportFact checks required fields on an ImportFact.
func ValidateImportFact(i facts.ImportFact) error {
	if !i.Language.IsValid() {
		return fmt.Errorf("invalid language: %q", i.Language)
	}
	if i.File == "" {
		return fmt.Errorf("file path is required")
	}
	if err := i.Span.Validate(); err != nil {
		return fmt.Errorf("invalid span: %w", err)
	}
	if i.ImportPath == "" {
		return fmt.Errorf("import path is required")
	}
	return nil
}

// ValidateRouteFact checks required fields on a RouteFact.
func ValidateRouteFact(r facts.RouteFact) error {
	if !r.Language.IsValid() {
		return fmt.Errorf("invalid language: %q", r.Language)
	}
	if r.File == "" {
		return fmt.Errorf("file path is required")
	}
	if err := r.Span.Validate(); err != nil {
		return fmt.Errorf("invalid span: %w", err)
	}
	if r.Method == "" {
		return fmt.Errorf("HTTP method is required")
	}
	if r.Path == "" {
		return fmt.Errorf("route path is required")
	}
	return nil
}

// ValidateMiddlewareFact checks required fields on a MiddlewareFact.
func ValidateMiddlewareFact(m facts.MiddlewareFact) error {
	if !m.Language.IsValid() {
		return fmt.Errorf("invalid language: %q", m.Language)
	}
	if m.File == "" {
		return fmt.Errorf("file path is required")
	}
	if err := m.Span.Validate(); err != nil {
		return fmt.Errorf("invalid span: %w", err)
	}
	if m.Name == "" {
		return fmt.Errorf("middleware name is required")
	}
	return nil
}

// ValidateTestFact checks required fields on a TestFact.
func ValidateTestFact(tf facts.TestFact) error {
	if !tf.Language.IsValid() {
		return fmt.Errorf("invalid language: %q", tf.Language)
	}
	if tf.File == "" {
		return fmt.Errorf("file path is required")
	}
	if err := tf.Span.Validate(); err != nil {
		return fmt.Errorf("invalid span: %w", err)
	}
	if tf.TestName == "" {
		return fmt.Errorf("test name is required")
	}
	return nil
}

// ValidateDataAccessFact checks required fields on a DataAccessFact.
func ValidateDataAccessFact(d facts.DataAccessFact) error {
	if !d.Language.IsValid() {
		return fmt.Errorf("invalid language: %q", d.Language)
	}
	if d.File == "" {
		return fmt.Errorf("file path is required")
	}
	if err := d.Span.Validate(); err != nil {
		return fmt.Errorf("invalid span: %w", err)
	}
	if d.Operation == "" {
		return fmt.Errorf("operation is required")
	}
	return nil
}

// ValidateConfigFact checks required fields on a ConfigFact.
func ValidateConfigFact(c facts.ConfigFact) error {
	if !c.Language.IsValid() {
		return fmt.Errorf("invalid language: %q", c.Language)
	}
	if c.File == "" {
		return fmt.Errorf("file path is required")
	}
	if err := c.Span.Validate(); err != nil {
		return fmt.Errorf("invalid span: %w", err)
	}
	if c.Key == "" {
		return fmt.Errorf("config key is required")
	}
	return nil
}

// ValidateSecretFact checks required fields on a SecretFact.
func ValidateSecretFact(s facts.SecretFact) error {
	if !s.Language.IsValid() {
		return fmt.Errorf("invalid language: %q", s.Language)
	}
	if s.File == "" {
		return fmt.Errorf("file path is required")
	}
	if err := s.Span.Validate(); err != nil {
		return fmt.Errorf("invalid span: %w", err)
	}
	if s.Kind == "" {
		return fmt.Errorf("secret kind is required")
	}
	return nil
}

// ValidateDependencyFact checks required fields on a DependencyFact.
func ValidateDependencyFact(d facts.DependencyFact) error {
	if !d.Language.IsValid() {
		return fmt.Errorf("invalid language: %q", d.Language)
	}
	if d.File == "" {
		return fmt.Errorf("file path is required")
	}
	if err := d.Span.Validate(); err != nil {
		return fmt.Errorf("invalid span: %w", err)
	}
	if d.Name == "" {
		return fmt.Errorf("dependency name is required")
	}
	return nil
}

// ValidateReportFinding checks required fields on a rules.Finding (the type
// actually used in report.json output). This is separate from ValidateFinding
// which validates facts.Finding (the internal fact model).
func ValidateReportFinding(f rules.Finding) error {
	if f.RuleID == "" {
		return fmt.Errorf("rule ID is required")
	}
	if f.Status == "" {
		return fmt.Errorf("status is required")
	}
	if f.Confidence == "" {
		return fmt.Errorf("confidence is required")
	}
	if f.VerificationLevel == "" {
		return fmt.Errorf("verification level is required")
	}
	for i, e := range f.Evidence {
		if err := ValidateReportEvidence(e); err != nil {
			return fmt.Errorf("evidence[%d]: %w", i, err)
		}
	}
	return nil
}

// ValidateReportEvidence checks required fields on a rules.Evidence
// (the type used in report.json). Unlike facts.Evidence, this type
// does not have a Type field.
func ValidateReportEvidence(e rules.Evidence) error {
	if e.File == "" {
		return fmt.Errorf("file path is required")
	}
	if e.LineStart < 1 {
		return fmt.Errorf("line_start must be >= 1, got %d", e.LineStart)
	}
	if e.LineEnd < e.LineStart {
		return fmt.Errorf("line_end (%d) must be >= line_start (%d)", e.LineEnd, e.LineStart)
	}
	return nil
}

// ValidateFinding checks required fields on a Finding.
func ValidateFinding(f facts.Finding) error {
	if f.RuleID == "" {
		return fmt.Errorf("rule ID is required")
	}
	if f.Status == "" {
		return fmt.Errorf("status is required")
	}
	if f.Confidence == "" {
		return fmt.Errorf("confidence is required")
	}
	if f.VerificationLevel == "" {
		return fmt.Errorf("verification level is required")
	}
	if f.Message == "" {
		return fmt.Errorf("message is required")
	}
	for i, e := range f.Evidence {
		if err := ValidateEvidence(e); err != nil {
			return fmt.Errorf("evidence[%d]: %w", i, err)
		}
	}
	return nil
}

// ValidateEvidence checks required fields on an Evidence.
func ValidateEvidence(e facts.Evidence) error {
	if e.Type == "" {
		return fmt.Errorf("evidence type is required")
	}
	if e.File == "" {
		return fmt.Errorf("file path is required")
	}
	if e.LineStart < 1 {
		return fmt.Errorf("line_start must be >= 1, got %d", e.LineStart)
	}
	if e.LineEnd < e.LineStart {
		return fmt.Errorf("line_end (%d) must be >= line_start (%d)", e.LineEnd, e.LineStart)
	}
	return nil
}
