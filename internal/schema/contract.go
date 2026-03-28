package schema

import (
	"fmt"

	"github.com/verabase/code-verification-engine/internal/rules"
)

// Model Boundary Documentation
//
// INTERNAL models (not part of public output contract):
//   - facts.* types — extracted by analyzers, consumed by rule engine
//   - typegraph.* types — type graph for pattern detection
//   - analyzers.AnalysisResult — intermediate analyzer output
//
// PUBLIC OUTPUT models (stable contract for downstream consumers):
//   - rules.Finding — finding in report.json
//   - rules.Evidence — evidence in report.json
//   - rules.SkippedRule — skipped rule in report.json
//   - report.ScanReport — scan.json structure
//   - report.VerificationReport — report.json structure
//
// The public output models are versioned via ScanSchemaVersion and
// ReportSchemaVersion. Any breaking change requires a major version bump.

// ReportContractInput holds the fields needed to validate a verification report contract.
// This avoids importing the report package (which already imports schema).
type ReportContractInput struct {
	ReportSchemaVersion string
	Issues              []ReportIssueContract
	Findings            []rules.Finding
	SummaryPass         int
	SummaryFail         int
	SummaryUnknown      int
	// Signal summary counts — must partition the fail+unknown space.
	SignalActionableFail         int
	SignalAdvisoryFail           int
	SignalInformationalDetection int
	SignalUnknown                int
}

// ReportIssueContract is the issue-centric subset needed for report.json
// contract validation without depending on the report package.
type ReportIssueContract struct {
	Title    string
	Category string
	Status   string
}

// ScanContractInput holds the fields needed to validate a scan report contract.
type ScanContractInput struct {
	ScanSchemaVersion string
	RepoPath          string
	ScannedAt         string
	Analyzers         map[string]string
}

// ValidateReportContract validates the complete report.json structure
// against the versioned contract.
func ValidateReportContract(input ReportContractInput) []error {
	var errs []error
	if input.ReportSchemaVersion == "" {
		errs = append(errs, fmt.Errorf("report_schema_version is required"))
	}
	// Validate every finding
	for i, f := range input.Findings {
		if err := ValidateReportFinding(f); err != nil {
			errs = append(errs, fmt.Errorf("findings[%d]: %w", i, err))
		}
		// Enforce verification level rules
		if err := ValidateVerificationLevel(f); err != nil {
			errs = append(errs, fmt.Errorf("findings[%d]: %w", i, err))
		}
	}
	if len(input.Issues) > 0 {
		return append(errs, validateIssueReportContract(input)...)
	}
	// Summary must match findings
	pass, fail, unknown := 0, 0, 0
	for _, f := range input.Findings {
		switch f.Status {
		case rules.StatusPass:
			pass++
		case rules.StatusFail:
			fail++
		case rules.StatusUnknown:
			unknown++
		}
	}
	if input.SummaryPass != pass || input.SummaryFail != fail || input.SummaryUnknown != unknown {
		errs = append(errs, fmt.Errorf("summary counts don't match findings: pass=%d/%d fail=%d/%d unknown=%d/%d",
			input.SummaryPass, pass, input.SummaryFail, fail, input.SummaryUnknown, unknown))
	}

	// Signal summary must partition the non-pass findings: actionable + advisory + informational = fail,
	// and signal unknown = summary unknown.
	signalTotal := input.SignalActionableFail + input.SignalAdvisoryFail + input.SignalInformationalDetection
	if signalTotal != fail {
		errs = append(errs, fmt.Errorf("signal_summary fail partition mismatch: actionable(%d)+advisory(%d)+informational(%d)=%d, want fail=%d",
			input.SignalActionableFail, input.SignalAdvisoryFail, input.SignalInformationalDetection, signalTotal, fail))
	}
	if input.SignalUnknown != unknown {
		errs = append(errs, fmt.Errorf("signal_summary.unknown mismatch: got %d, want %d",
			input.SignalUnknown, unknown))
	}

	return errs
}

func validateIssueReportContract(input ReportContractInput) []error {
	var errs []error
	pass, fail, unknown := 0, 0, 0
	for i, issue := range input.Issues {
		if issue.Title == "" {
			errs = append(errs, fmt.Errorf("issues[%d]: title is required", i))
		}
		if issue.Status == "" {
			errs = append(errs, fmt.Errorf("issues[%d]: status is required", i))
		}
		if issue.Category == "" {
			errs = append(errs, fmt.Errorf("issues[%d]: category is required", i))
		}
		switch issue.Status {
		case "resolved", "pass":
			pass++
		case "unknown":
			unknown++
		case "open", "fail":
			fail++
		default:
			errs = append(errs, fmt.Errorf("issues[%d]: invalid status %q", i, issue.Status))
		}
	}
	if input.SummaryPass != pass || input.SummaryFail != fail || input.SummaryUnknown != unknown {
		errs = append(errs, fmt.Errorf("summary counts don't match issues: pass=%d/%d fail=%d/%d unknown=%d/%d",
			input.SummaryPass, pass, input.SummaryFail, fail, input.SummaryUnknown, unknown))
	}
	signalTotal := input.SignalActionableFail + input.SignalAdvisoryFail + input.SignalInformationalDetection
	if signalTotal != fail {
		errs = append(errs, fmt.Errorf("signal_summary fail partition mismatch: actionable(%d)+advisory(%d)+informational(%d)=%d, want fail=%d",
			input.SignalActionableFail, input.SignalAdvisoryFail, input.SignalInformationalDetection, signalTotal, fail))
	}
	if input.SignalUnknown != unknown {
		errs = append(errs, fmt.Errorf("signal_summary.unknown mismatch: got %d, want %d", input.SignalUnknown, unknown))
	}
	return errs
}


// ValidateTrustSummaryContract validates that the trust summary counts match findings.
func ValidateTrustSummaryContract(findings []rules.Finding, machineTrusted, advisory, humanOrRuntimeRequired int) []error {
	var errs []error
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
	if machineTrusted != mt {
		errs = append(errs, fmt.Errorf("trust_summary.machine_trusted count mismatch: got %d, want %d", machineTrusted, mt))
	}
	if advisory != adv {
		errs = append(errs, fmt.Errorf("trust_summary.advisory count mismatch: got %d, want %d", advisory, adv))
	}
	if humanOrRuntimeRequired != hr {
		errs = append(errs, fmt.Errorf("trust_summary.human_or_runtime_required count mismatch: got %d, want %d", humanOrRuntimeRequired, hr))
	}
	return errs
}

// ValidateScanContract validates the complete scan.json structure.
func ValidateScanContract(input ScanContractInput) []error {
	var errs []error
	if input.ScanSchemaVersion == "" {
		errs = append(errs, fmt.Errorf("scan_schema_version is required"))
	}
	if input.RepoPath == "" {
		errs = append(errs, fmt.Errorf("repo_path is required"))
	}
	if input.ScannedAt == "" {
		errs = append(errs, fmt.Errorf("scanned_at is required"))
	}
	// Analyzers must not be nil
	if input.Analyzers == nil {
		errs = append(errs, fmt.Errorf("analyzers map is required"))
	}
	// Valid analyzer statuses
	for lang, status := range input.Analyzers {
		switch status {
		case "ok", "error", "partial":
			// valid
		default:
			errs = append(errs, fmt.Errorf("analyzer %s has invalid status %q (must be ok/error/partial)", lang, status))
		}
	}
	return errs
}
