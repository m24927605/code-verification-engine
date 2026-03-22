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
	Findings            []rules.Finding
	SummaryPass         int
	SummaryFail         int
	SummaryUnknown      int
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
