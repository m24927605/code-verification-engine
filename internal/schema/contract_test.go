package schema

import (
	"strings"
	"testing"

	"github.com/verabase/code-verification-engine/internal/rules"
)

func validFinding() rules.Finding {
	return rules.Finding{
		RuleID:            "TEST-001",
		Status:            rules.StatusPass,
		Confidence:        rules.ConfidenceHigh,
		VerificationLevel: rules.VerificationVerified,
		Message:           "test finding",
		Evidence: []rules.Evidence{{
			File:      "main.go",
			LineStart: 1,
			LineEnd:   5,
			Symbol:    "main",
		}},
	}
}

// --- ValidateReportContract tests ---

func TestValidateReportContract_Valid(t *testing.T) {
	input := ReportContractInput{
		ReportSchemaVersion: "1.0.0",
		Findings:            []rules.Finding{validFinding()},
		SummaryPass:         1,
		SummaryFail:         0,
		SummaryUnknown:      0,
	}
	if errs := ValidateReportContract(input); len(errs) != 0 {
		t.Errorf("expected no errors, got %v", errs)
	}
}

func TestValidateReportContract_MissingSchemaVersion(t *testing.T) {
	input := ReportContractInput{
		Findings:    []rules.Finding{validFinding()},
		SummaryPass: 1,
	}
	errs := ValidateReportContract(input)
	if len(errs) == 0 {
		t.Fatal("expected error for missing schema version")
	}
	found := false
	for _, e := range errs {
		if e.Error() == "report_schema_version is required" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected report_schema_version error, got %v", errs)
	}
}

func TestValidateReportContract_SummaryMismatch(t *testing.T) {
	input := ReportContractInput{
		ReportSchemaVersion: "1.0.0",
		Findings:            []rules.Finding{validFinding()},
		SummaryPass:         5,
	}
	errs := ValidateReportContract(input)
	found := false
	for _, e := range errs {
		if strings.Contains(e.Error(), "summary counts don't match") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected summary mismatch error, got %v", errs)
	}
}

func TestValidateReportContract_InvalidFinding(t *testing.T) {
	input := ReportContractInput{
		ReportSchemaVersion: "1.0.0",
		Findings:            []rules.Finding{{}}, // Missing required fields
	}
	errs := ValidateReportContract(input)
	if len(errs) == 0 {
		t.Fatal("expected errors for invalid finding")
	}
}

// --- ValidateScanContract tests ---

func TestValidateScanContract_Valid(t *testing.T) {
	input := ScanContractInput{
		ScanSchemaVersion: "1.0.0",
		RepoPath:          "/tmp/repo",
		ScannedAt:         "2026-01-01T00:00:00Z",
		Analyzers:         map[string]string{"go": "ok"},
	}
	if errs := ValidateScanContract(input); len(errs) != 0 {
		t.Errorf("expected no errors, got %v", errs)
	}
}

func TestValidateScanContract_MissingFields(t *testing.T) {
	errs := ValidateScanContract(ScanContractInput{})
	if len(errs) < 3 {
		t.Errorf("expected at least 3 errors for missing fields, got %d: %v", len(errs), errs)
	}
}

func TestValidateScanContract_InvalidAnalyzerStatus(t *testing.T) {
	input := ScanContractInput{
		ScanSchemaVersion: "1.0.0",
		RepoPath:          "/tmp/repo",
		ScannedAt:         "2026-01-01T00:00:00Z",
		Analyzers:         map[string]string{"go": "invalid_status"},
	}
	errs := ValidateScanContract(input)
	if len(errs) != 1 {
		t.Errorf("expected 1 error, got %d: %v", len(errs), errs)
	}
}

// --- ValidateVerificationLevel tests ---

func TestVerificationLevel_VerifiedHighPass(t *testing.T) {
	f := rules.Finding{
		RuleID:            "R-001",
		Status:            rules.StatusPass,
		Confidence:        rules.ConfidenceHigh,
		VerificationLevel: rules.VerificationVerified,
	}
	if err := ValidateVerificationLevel(f); err != nil {
		t.Errorf("expected no error, got %v", err)
	}
}

func TestVerificationLevel_VerifiedHighFailWithEvidence(t *testing.T) {
	f := rules.Finding{
		RuleID:            "R-001",
		Status:            rules.StatusFail,
		Confidence:        rules.ConfidenceHigh,
		VerificationLevel: rules.VerificationVerified,
		Evidence: []rules.Evidence{{
			File: "main.go", LineStart: 1, LineEnd: 5, Symbol: "fn",
		}},
	}
	if err := ValidateVerificationLevel(f); err != nil {
		t.Errorf("expected no error, got %v", err)
	}
}

func TestVerificationLevel_VerifiedLowConfidence(t *testing.T) {
	f := rules.Finding{
		RuleID:            "R-001",
		Status:            rules.StatusPass,
		Confidence:        rules.ConfidenceLow,
		VerificationLevel: rules.VerificationVerified,
	}
	if err := ValidateVerificationLevel(f); err == nil {
		t.Error("expected error for verified with low confidence")
	}
}

func TestVerificationLevel_VerifiedUnknownStatus(t *testing.T) {
	f := rules.Finding{
		RuleID:            "R-001",
		Status:            rules.StatusUnknown,
		Confidence:        rules.ConfidenceHigh,
		VerificationLevel: rules.VerificationVerified,
		UnknownReasons:    []string{"test"},
	}
	if err := ValidateVerificationLevel(f); err == nil {
		t.Error("expected error for verified with unknown status")
	}
}

func TestVerificationLevel_StrongInferenceLow(t *testing.T) {
	f := rules.Finding{
		RuleID:            "R-001",
		Status:            rules.StatusPass,
		Confidence:        rules.ConfidenceLow,
		VerificationLevel: rules.VerificationStrongInference,
	}
	if err := ValidateVerificationLevel(f); err == nil {
		t.Error("expected error for strong_inference with low confidence")
	}
}

func TestVerificationLevel_UnknownNoReasons(t *testing.T) {
	f := rules.Finding{
		RuleID:            "R-001",
		Status:            rules.StatusUnknown,
		Confidence:        rules.ConfidenceLow,
		VerificationLevel: rules.VerificationWeakInference,
	}
	if err := ValidateVerificationLevel(f); err == nil {
		t.Error("expected error for unknown status without reasons")
	}
}

func TestVerificationLevel_UnknownVerifiedLevel(t *testing.T) {
	f := rules.Finding{
		RuleID:            "R-001",
		Status:            rules.StatusUnknown,
		Confidence:        rules.ConfidenceHigh,
		VerificationLevel: rules.VerificationVerified,
		UnknownReasons:    []string{"insufficient data"},
	}
	if err := ValidateVerificationLevel(f); err == nil {
		t.Error("expected error for unknown status with verified level")
	}
}

func TestVerificationLevel_VerifiedMediumConfidence(t *testing.T) {
	f := rules.Finding{
		RuleID:            "R-001",
		Status:            rules.StatusPass,
		Confidence:        rules.ConfidenceMedium,
		VerificationLevel: rules.VerificationVerified,
	}
	if err := ValidateVerificationLevel(f); err == nil {
		t.Error("expected error for verified with medium confidence")
	}
}

func TestVerificationLevel_VerifiedFailNoEvidence(t *testing.T) {
	f := rules.Finding{
		RuleID:            "R-001",
		Status:            rules.StatusFail,
		Confidence:        rules.ConfidenceHigh,
		VerificationLevel: rules.VerificationVerified,
		Evidence:          nil,
	}
	if err := ValidateVerificationLevel(f); err == nil {
		t.Error("expected error for verified fail without evidence")
	}
}

func TestVerificationLevel_VerifiedUnknownStatusNotAllowed(t *testing.T) {
	f := rules.Finding{
		RuleID:            "R-001",
		Status:            rules.StatusUnknown,
		Confidence:        rules.ConfidenceHigh,
		VerificationLevel: rules.VerificationVerified,
	}
	// Missing unknown_reasons, so two errors are expected.
	// We just need it to fail at the unknown+verified check.
	if err := ValidateVerificationLevel(f); err == nil {
		t.Error("expected error for unknown status with verified level")
	}
}

func TestVerificationLevel_StrongInferenceMediumOK(t *testing.T) {
	f := rules.Finding{
		RuleID:            "R-001",
		Status:            rules.StatusPass,
		Confidence:        rules.ConfidenceMedium,
		VerificationLevel: rules.VerificationStrongInference,
	}
	if err := ValidateVerificationLevel(f); err != nil {
		t.Errorf("expected no error for strong_inference with medium confidence, got %v", err)
	}
}

func TestVerificationLevel_StrongInferenceHighOK(t *testing.T) {
	f := rules.Finding{
		RuleID:            "R-001",
		Status:            rules.StatusPass,
		Confidence:        rules.ConfidenceHigh,
		VerificationLevel: rules.VerificationStrongInference,
	}
	if err := ValidateVerificationLevel(f); err != nil {
		t.Errorf("expected no error for strong_inference with high confidence, got %v", err)
	}
}

func TestVerificationLevel_WeakInferenceAnyConfidence(t *testing.T) {
	for _, conf := range []rules.Confidence{rules.ConfidenceHigh, rules.ConfidenceMedium, rules.ConfidenceLow} {
		f := rules.Finding{
			RuleID:            "R-001",
			Status:            rules.StatusPass,
			Confidence:        conf,
			VerificationLevel: rules.VerificationWeakInference,
		}
		if err := ValidateVerificationLevel(f); err != nil {
			t.Errorf("expected no error for weak_inference with %s confidence, got %v", conf, err)
		}
	}
}

func TestVerificationLevel_UnknownLevelNonUnknownStatus(t *testing.T) {
	f := rules.Finding{
		RuleID:            "R-001",
		Status:            rules.StatusPass,
		Confidence:        rules.ConfidenceHigh,
		VerificationLevel: "some_random_level",
	}
	if err := ValidateVerificationLevel(f); err == nil {
		t.Error("expected error for unknown verification level with non-unknown status")
	}
}

func TestVerificationLevel_UnknownStatusWithReasons(t *testing.T) {
	f := rules.Finding{
		RuleID:            "R-001",
		Status:            rules.StatusUnknown,
		Confidence:        rules.ConfidenceLow,
		VerificationLevel: rules.VerificationWeakInference,
		UnknownReasons:    []string{"no analyzer support"},
	}
	if err := ValidateVerificationLevel(f); err != nil {
		t.Errorf("expected no error for valid unknown finding, got %v", err)
	}
}

// --- ValidateReportContract additional tests ---

func TestValidateReportContract_FindingWithVerificationLevelError(t *testing.T) {
	input := ReportContractInput{
		ReportSchemaVersion: "1.0.0",
		Findings: []rules.Finding{
			{
				RuleID:            "R-001",
				Status:            rules.StatusPass,
				Confidence:        rules.ConfidenceLow,
				VerificationLevel: rules.VerificationVerified,
			},
		},
		SummaryPass: 1,
	}
	errs := ValidateReportContract(input)
	if len(errs) == 0 {
		t.Fatal("expected errors for verification level violation")
	}
}

func TestValidateReportContract_EmptyFindings(t *testing.T) {
	input := ReportContractInput{
		ReportSchemaVersion: "1.0.0",
		Findings:            []rules.Finding{},
		SummaryPass:         0,
		SummaryFail:         0,
		SummaryUnknown:      0,
	}
	if errs := ValidateReportContract(input); len(errs) != 0 {
		t.Errorf("expected no errors for empty findings, got %v", errs)
	}
}

func TestValidateReportContract_MultipleFindingStatuses(t *testing.T) {
	input := ReportContractInput{
		ReportSchemaVersion: "1.0.0",
		Findings: []rules.Finding{
			{RuleID: "R-001", Status: rules.StatusPass, Confidence: rules.ConfidenceHigh, VerificationLevel: rules.VerificationVerified},
			{RuleID: "R-002", Status: rules.StatusFail, Confidence: rules.ConfidenceHigh, VerificationLevel: rules.VerificationVerified, Evidence: []rules.Evidence{{File: "f.go", LineStart: 1, LineEnd: 1}}},
			{RuleID: "R-003", Status: rules.StatusUnknown, Confidence: rules.ConfidenceLow, VerificationLevel: rules.VerificationWeakInference, UnknownReasons: []string{"no data"}},
		},
		SummaryPass:    1,
		SummaryFail:    1,
		SummaryUnknown: 1,
	}
	if errs := ValidateReportContract(input); len(errs) != 0 {
		t.Errorf("expected no errors, got %v", errs)
	}
}

// --- ValidateScanContract additional tests ---

func TestValidateScanContract_ValidMultipleAnalyzers(t *testing.T) {
	input := ScanContractInput{
		ScanSchemaVersion: "1.0.0",
		RepoPath:          "/tmp/repo",
		ScannedAt:         "2026-01-01T00:00:00Z",
		Analyzers:         map[string]string{"go": "ok", "python": "error", "typescript": "partial"},
	}
	if errs := ValidateScanContract(input); len(errs) != 0 {
		t.Errorf("expected no errors, got %v", errs)
	}
}

func TestValidateScanContract_EmptyAnalyzers(t *testing.T) {
	input := ScanContractInput{
		ScanSchemaVersion: "1.0.0",
		RepoPath:          "/tmp/repo",
		ScannedAt:         "2026-01-01T00:00:00Z",
		Analyzers:         map[string]string{},
	}
	if errs := ValidateScanContract(input); len(errs) != 0 {
		t.Errorf("expected no errors for empty (non-nil) analyzers, got %v", errs)
	}
}
