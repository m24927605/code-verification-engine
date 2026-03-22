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
		TrustClass:        rules.TrustMachineTrusted,
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
				TrustClass:        rules.TrustMachineTrusted,
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
			{RuleID: "R-001", Status: rules.StatusPass, Confidence: rules.ConfidenceHigh, VerificationLevel: rules.VerificationVerified, TrustClass: rules.TrustMachineTrusted},
			{RuleID: "R-002", Status: rules.StatusFail, Confidence: rules.ConfidenceHigh, VerificationLevel: rules.VerificationVerified, TrustClass: rules.TrustMachineTrusted, Evidence: []rules.Evidence{{File: "f.go", LineStart: 1, LineEnd: 1}}},
			{RuleID: "R-003", Status: rules.StatusUnknown, Confidence: rules.ConfidenceLow, VerificationLevel: rules.VerificationWeakInference, TrustClass: rules.TrustAdvisory, UnknownReasons: []string{"no data"}},
		},
		SummaryPass:          1,
		SummaryFail:          1,
		SummaryUnknown:       1,
		SignalAdvisoryFail:   1, // R-002 maps to advisory (unknown prefix)
		SignalUnknown:        1, // R-003 is unknown
	}
	if errs := ValidateReportContract(input); len(errs) != 0 {
		t.Errorf("expected no errors, got %v", errs)
	}
}

func TestValidateReportContract_SignalSummaryMismatch(t *testing.T) {
	input := ReportContractInput{
		ReportSchemaVersion: "1.0.0",
		Findings: []rules.Finding{
			{RuleID: "SEC-AUTH-001", Status: rules.StatusFail, Confidence: rules.ConfidenceHigh, VerificationLevel: rules.VerificationStrongInference, TrustClass: rules.TrustAdvisory, Evidence: []rules.Evidence{{File: "a.go", LineStart: 1, LineEnd: 1}}},
		},
		SummaryFail:          1,
		SignalActionableFail: 0, // Wrong: should be 1
		SignalAdvisoryFail:   0,
	}
	errs := ValidateReportContract(input)
	found := false
	for _, e := range errs {
		if strings.Contains(e.Error(), "signal_summary fail partition mismatch") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected signal_summary partition mismatch error, got %v", errs)
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

// --- Trust class contract tests ---

func TestValidateReportFinding_MissingTrustClass(t *testing.T) {
	f := rules.Finding{
		RuleID:            "R-001",
		Status:            rules.StatusPass,
		Confidence:        rules.ConfidenceHigh,
		VerificationLevel: rules.VerificationVerified,
		// TrustClass intentionally omitted
	}
	if err := ValidateReportFinding(f); err == nil {
		t.Fatal("expected error for missing trust_class")
	}
}

func TestValidateReportFinding_InvalidTrustClass(t *testing.T) {
	f := rules.Finding{
		RuleID:            "R-001",
		Status:            rules.StatusPass,
		Confidence:        rules.ConfidenceHigh,
		VerificationLevel: rules.VerificationVerified,
		TrustClass:        "auto_trusted", // invalid
	}
	if err := ValidateReportFinding(f); err == nil {
		t.Fatal("expected error for invalid trust_class")
	}
}

func TestVerificationLevel_AdvisoryCannotBeVerified(t *testing.T) {
	f := rules.Finding{
		RuleID:            "R-001",
		Status:            rules.StatusPass,
		Confidence:        rules.ConfidenceHigh,
		VerificationLevel: rules.VerificationVerified,
		TrustClass:        rules.TrustAdvisory,
	}
	if err := ValidateVerificationLevel(f); err == nil {
		t.Fatal("expected error: advisory trust class cannot have verified level")
	}
}

func TestVerificationLevel_HumanRequiredCannotBeVerified(t *testing.T) {
	f := rules.Finding{
		RuleID:            "R-001",
		Status:            rules.StatusPass,
		Confidence:        rules.ConfidenceHigh,
		VerificationLevel: rules.VerificationVerified,
		TrustClass:        rules.TrustHumanOrRuntimeRequired,
	}
	if err := ValidateVerificationLevel(f); err == nil {
		t.Fatal("expected error: human_or_runtime_required cannot have verified level")
	}
}

func TestVerificationLevel_MachineTrustedCanBeVerified(t *testing.T) {
	f := rules.Finding{
		RuleID:            "R-001",
		Status:            rules.StatusPass,
		Confidence:        rules.ConfidenceHigh,
		VerificationLevel: rules.VerificationVerified,
		TrustClass:        rules.TrustMachineTrusted,
	}
	if err := ValidateVerificationLevel(f); err != nil {
		t.Errorf("machine_trusted should allow verified, got error: %v", err)
	}
}

func TestVerificationLevel_AdvisoryStrongInferenceOK(t *testing.T) {
	f := rules.Finding{
		RuleID:            "R-001",
		Status:            rules.StatusPass,
		Confidence:        rules.ConfidenceMedium,
		VerificationLevel: rules.VerificationStrongInference,
		TrustClass:        rules.TrustAdvisory,
	}
	if err := ValidateVerificationLevel(f); err != nil {
		t.Errorf("advisory with strong_inference should be valid, got: %v", err)
	}
}

// --- Trust boundary violation contract tests ---

func TestTrustBoundary_AdvisoryPassNeverVerified(t *testing.T) {
	// This is the critical trust boundary invariant: advisory findings
	// must NEVER pass contract validation with verified level.
	f := rules.Finding{
		RuleID:            "R-001",
		Status:            rules.StatusPass,
		Confidence:        rules.ConfidenceHigh,
		VerificationLevel: rules.VerificationVerified,
		TrustClass:        rules.TrustAdvisory,
	}
	if err := ValidateVerificationLevel(f); err == nil {
		t.Fatal("TRUST BOUNDARY VIOLATION: advisory finding with verified level must be rejected")
	}
}

func TestTrustBoundary_HumanRequiredNeverVerified(t *testing.T) {
	f := rules.Finding{
		RuleID:            "R-001",
		Status:            rules.StatusPass,
		Confidence:        rules.ConfidenceHigh,
		VerificationLevel: rules.VerificationVerified,
		TrustClass:        rules.TrustHumanOrRuntimeRequired,
	}
	if err := ValidateVerificationLevel(f); err == nil {
		t.Fatal("TRUST BOUNDARY VIOLATION: human_or_runtime_required finding with verified level must be rejected")
	}
}

func TestTrustBoundary_MachineTrustedPassVerified(t *testing.T) {
	// machine_trusted + high confidence + verified = valid
	f := rules.Finding{
		RuleID:            "R-001",
		Status:            rules.StatusPass,
		Confidence:        rules.ConfidenceHigh,
		VerificationLevel: rules.VerificationVerified,
		TrustClass:        rules.TrustMachineTrusted,
	}
	if err := ValidateVerificationLevel(f); err != nil {
		t.Errorf("machine_trusted with verified should be valid, got: %v", err)
	}
}

func TestTrustBoundary_MissingTrustClassFailsContract(t *testing.T) {
	input := ReportContractInput{
		ReportSchemaVersion: "1.0.0",
		Findings: []rules.Finding{
			{
				RuleID:            "R-001",
				Status:            rules.StatusPass,
				Confidence:        rules.ConfidenceHigh,
				VerificationLevel: rules.VerificationVerified,
				// TrustClass deliberately omitted
			},
		},
		SummaryPass: 1,
	}
	errs := ValidateReportContract(input)
	if len(errs) == 0 {
		t.Fatal("TRUST BOUNDARY VIOLATION: missing trust_class must fail contract validation")
	}
	found := false
	for _, e := range errs {
		if strings.Contains(e.Error(), "trust_class") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected trust_class error, got: %v", errs)
	}
}

func TestTrustBoundary_InvalidTrustClassFailsContract(t *testing.T) {
	input := ReportContractInput{
		ReportSchemaVersion: "1.0.0",
		Findings: []rules.Finding{
			{
				RuleID:            "R-001",
				Status:            rules.StatusPass,
				Confidence:        rules.ConfidenceHigh,
				VerificationLevel: rules.VerificationStrongInference,
				TrustClass:        "auto_trusted", // invalid value
			},
		},
		SummaryPass: 1,
	}
	errs := ValidateReportContract(input)
	if len(errs) == 0 {
		t.Fatal("invalid trust_class value must fail contract validation")
	}
}

func TestTrustBoundary_AllThreeTrustClassesValid(t *testing.T) {
	input := ReportContractInput{
		ReportSchemaVersion: "1.0.0",
		Findings: []rules.Finding{
			{
				RuleID:            "R-001",
				Status:            rules.StatusPass,
				Confidence:        rules.ConfidenceHigh,
				VerificationLevel: rules.VerificationVerified,
				TrustClass:        rules.TrustMachineTrusted,
			},
			{
				RuleID:            "R-002",
				Status:            rules.StatusPass,
				Confidence:        rules.ConfidenceMedium,
				VerificationLevel: rules.VerificationStrongInference,
				TrustClass:        rules.TrustAdvisory,
			},
			{
				RuleID:            "R-003",
				Status:            rules.StatusPass,
				Confidence:        rules.ConfidenceLow,
				VerificationLevel: rules.VerificationWeakInference,
				TrustClass:        rules.TrustHumanOrRuntimeRequired,
			},
		},
		SummaryPass: 3,
	}
	errs := ValidateReportContract(input)
	if len(errs) != 0 {
		t.Errorf("all three valid trust classes should pass contract, got: %v", errs)
	}
}

func TestTrustBoundary_AdvisoryVerifiedFailsReportContract(t *testing.T) {
	// End-to-end: a report containing advisory+verified should fail ValidateReportContract
	input := ReportContractInput{
		ReportSchemaVersion: "1.0.0",
		Findings: []rules.Finding{
			{
				RuleID:            "R-001",
				Status:            rules.StatusPass,
				Confidence:        rules.ConfidenceHigh,
				VerificationLevel: rules.VerificationVerified,
				TrustClass:        rules.TrustAdvisory,
			},
		},
		SummaryPass: 1,
	}
	errs := ValidateReportContract(input)
	if len(errs) == 0 {
		t.Fatal("advisory + verified must fail report contract validation")
	}
}

// --- Trust summary contract tests ---

func TestValidateTrustSummaryContract_Valid(t *testing.T) {
	findings := []rules.Finding{
		{RuleID: "R-001", TrustClass: rules.TrustMachineTrusted},
		{RuleID: "R-002", TrustClass: rules.TrustAdvisory},
		{RuleID: "R-003", TrustClass: rules.TrustHumanOrRuntimeRequired},
	}
	errs := ValidateTrustSummaryContract(findings, 1, 1, 1)
	if len(errs) != 0 {
		t.Errorf("expected no errors, got %v", errs)
	}
}

func TestValidateTrustSummaryContract_Mismatch(t *testing.T) {
	findings := []rules.Finding{
		{RuleID: "R-001", TrustClass: rules.TrustMachineTrusted},
		{RuleID: "R-002", TrustClass: rules.TrustAdvisory},
	}
	errs := ValidateTrustSummaryContract(findings, 2, 0, 0)
	if len(errs) != 2 {
		t.Errorf("expected 2 mismatch errors, got %d: %v", len(errs), errs)
	}
}

func TestValidateTrustSummaryContract_Empty(t *testing.T) {
	errs := ValidateTrustSummaryContract(nil, 0, 0, 0)
	if len(errs) != 0 {
		t.Errorf("empty findings with zero counts should pass, got %v", errs)
	}
}

// --- Cross-profile trust invariant tests ---

func TestAllProfiles_RespectTrustInvariants(t *testing.T) {
	for name, profile := range rules.AllProfiles() {
		for _, rule := range profile.Rules {
			tc := rules.ClassifyTrustClass(rule.ID)
			// If trusted-core profile, all rules must be machine_trusted
			if name == "trusted-core" && tc != rules.TrustMachineTrusted {
				t.Errorf("profile %q rule %q has trust class %s, expected machine_trusted for trusted-core profile",
					name, rule.ID, tc)
			}
			// Every rule must have a valid trust class
			if !rules.ValidTrustClass(tc) {
				t.Errorf("profile %q rule %q has invalid trust class %s", name, rule.ID, tc)
			}
		}
	}
}

// --- Skipped rule not in findings contract test ---

func TestSkippedRuleIDs_NeverOverlapWithFindings(t *testing.T) {
	// Simulate a report with findings and skipped rules sharing no IDs
	findings := []rules.Finding{
		{RuleID: "SEC-AUTH-001", Status: rules.StatusPass, TrustClass: rules.TrustAdvisory,
			Confidence: rules.ConfidenceMedium, VerificationLevel: rules.VerificationStrongInference},
		{RuleID: "SEC-SECRET-001", Status: rules.StatusPass, TrustClass: rules.TrustMachineTrusted,
			Confidence: rules.ConfidenceHigh, VerificationLevel: rules.VerificationVerified},
	}
	skipped := []rules.SkippedRule{
		{RuleID: "FE-XSS-001", Reason: "no matching language"},
		{RuleID: "FE-TOKEN-001", Reason: "no matching language"},
	}

	// Build sets
	findingIDs := make(map[string]bool)
	for _, f := range findings {
		findingIDs[f.RuleID] = true
	}
	for _, sr := range skipped {
		if findingIDs[sr.RuleID] {
			t.Errorf("skipped rule %s also appears in findings, violating mutual exclusion", sr.RuleID)
		}
	}

	// Also test the reverse: construct a bad case and verify detection
	badFindings := append(findings, rules.Finding{
		RuleID: "FE-XSS-001", Status: rules.StatusPass, TrustClass: rules.TrustAdvisory,
		Confidence: rules.ConfidenceMedium, VerificationLevel: rules.VerificationStrongInference,
	})
	badFindingIDs := make(map[string]bool)
	for _, f := range badFindings {
		badFindingIDs[f.RuleID] = true
	}
	overlapCount := 0
	for _, sr := range skipped {
		if badFindingIDs[sr.RuleID] {
			overlapCount++
		}
	}
	if overlapCount != 1 {
		t.Errorf("expected exactly 1 overlap in bad case, got %d", overlapCount)
	}
}

// --- Capability summary contract validation ---

func TestValidateCapabilitySummaryConsistency(t *testing.T) {
	// CapabilitySummary should be derived from capability signals (unknown_reasons),
	// not from trust_class. Trust summary and capability summary are independent.
	findings := []rules.Finding{
		{RuleID: "R-1", TrustClass: rules.TrustMachineTrusted},
		{RuleID: "R-2", TrustClass: rules.TrustAdvisory},
		{RuleID: "R-3", TrustClass: rules.TrustHumanOrRuntimeRequired},
	}
	// Trust class counts must sum to total findings
	mt, adv, hr := 0, 0, 0
	for _, f := range findings {
		switch f.TrustClass {
		case rules.TrustMachineTrusted:
			mt++
		case rules.TrustAdvisory:
			adv++
		case rules.TrustHumanOrRuntimeRequired:
			hr++
		}
	}
	total := mt + adv + hr
	if total != len(findings) {
		t.Errorf("trust class counts should sum to total findings: %d != %d", total, len(findings))
	}

	// Capability classification is independent of trust class:
	// all 3 findings above have no capability annotations → all fully_supported
	capFull := 0
	for _, f := range findings {
		isPartial := false
		isUnsupported := false
		for _, r := range f.UnknownReasons {
			if r == rules.UnknownCapabilityUnsupported {
				isUnsupported = true
			}
			if r == rules.UnknownCapabilityPartial || r == rules.UnknownMatcherLimitation {
				isPartial = true
			}
		}
		if !isUnsupported && !isPartial {
			capFull++
		}
	}
	if capFull != 3 {
		t.Errorf("expected all 3 findings to be fully_supported capability (no capability annotations), got %d", capFull)
	}
}
