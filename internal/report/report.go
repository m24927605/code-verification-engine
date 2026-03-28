package report

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"


	"github.com/verabase/code-verification-engine/internal/rules"
	"github.com/verabase/code-verification-engine/internal/schema"
)

// ScanReport represents scan.json content.
type ScanReport struct {
	ScanSchemaVersion string            `json:"scan_schema_version"`
	RepoPath          string            `json:"repo_path"`
	RepoName          string            `json:"repo_name"`
	Ref               string            `json:"ref"`
	CommitSHA         string            `json:"commit_sha"`
	ScannedAt         string            `json:"scanned_at"`
	Languages         []string          `json:"languages"`
	FileCount         int               `json:"file_count"`
	Partial           bool              `json:"partial"`
	Analyzers         map[string]string `json:"analyzers"`
	Errors            []string          `json:"errors"`
	Profile           string            `json:"profile"`
	// Scan boundary metadata
	SourceRepoRoot string `json:"source_repo_root,omitempty"`
	RequestedPath  string `json:"requested_path,omitempty"`
	ScanSubdir     string `json:"scan_subdir,omitempty"`
	BoundaryMode   string `json:"boundary_mode,omitempty"`
}

// CapabilitySummary counts findings by capability support level and
// flags runtime degradation. Consumers can use this to understand
// how many findings are fully backed by analyzer capability.
type CapabilitySummary struct {
	FullySupported int  `json:"fully_supported"`
	Partial        int  `json:"partial"`
	Unsupported    int  `json:"unsupported"`
	Degraded       bool `json:"degraded"` // true if any runtime degradation occurred
}

// FactQualitySummary counts findings by their verdict basis,
// indicating how many findings are backed by each evidence tier.
type FactQualitySummary struct {
	ProofBacked      int `json:"proof_backed"`
	StructuralBacked int `json:"structural_backed"`
	HeuristicBacked  int `json:"heuristic_backed"`
	RuntimeRequired  int `json:"runtime_required"`
}

// VerificationReport represents report.json content.
type VerificationReport struct {
	ReportSchemaVersion string              `json:"report_schema_version"`
	Partial             bool                `json:"partial"`
	Summary             Summary             `json:"summary"`
	TrustSummary        TrustSummary        `json:"trust_summary"`
	CapabilitySummary   CapabilitySummary   `json:"capability_summary"`
	SignalSummary       SignalSummary        `json:"signal_summary"`
	FactQualitySummary  FactQualitySummary  `json:"fact_quality_summary"`
	Findings            []rules.Finding     `json:"findings"`
	SkippedRules        []rules.SkippedRule `json:"skipped_rules,omitempty"`
	Errors              []string            `json:"errors,omitempty"`
}

// Summary holds pass/fail/unknown counts.
type Summary struct {
	Pass    int `json:"pass"`
	Fail    int `json:"fail"`
	Unknown int `json:"unknown"`
}

// TrustSummary counts findings by trust class.
type TrustSummary struct {
	MachineTrusted         int `json:"machine_trusted"`
	Advisory               int `json:"advisory"`
	HumanOrRuntimeRequired int `json:"human_or_runtime_required"`
}

// ScanInput holds the data needed to generate a scan report.
type ScanInput struct {
	RepoPath  string
	RepoName  string
	Ref       string
	CommitSHA string
	Languages []string
	FileCount int
	Partial   bool
	Analyzers map[string]string
	Errors    []string
	Profile   string
	// Scan boundary
	SourceRepoRoot string
	RequestedPath  string
	ScanSubdir     string
	BoundaryMode   string
}

// ReportInput holds the data needed to generate verification reports.
type ReportInput struct {
	Partial      bool
	Findings     []rules.Finding
	RuleMetadata map[string]rules.Rule
	SkippedRules []rules.SkippedRule
	Errors       []string
	Degraded     bool // true if any analyzer runtime was degraded
}

// GenerateScanReport creates a ScanReport from input data.
func GenerateScanReport(input ScanInput) ScanReport {
	return ScanReport{
		ScanSchemaVersion: schema.ScanSchemaVersion,
		RepoPath:          input.RepoPath,
		RepoName:          input.RepoName,
		Ref:               input.Ref,
		CommitSHA:         input.CommitSHA,
		ScannedAt:         time.Now().Format(time.RFC3339),
		Languages:         input.Languages,
		FileCount:         input.FileCount,
		Partial:           input.Partial,
		Analyzers:         input.Analyzers,
		Errors:            input.Errors,
		Profile:           input.Profile,
		SourceRepoRoot:    input.SourceRepoRoot,
		RequestedPath:     input.RequestedPath,
		ScanSubdir:        input.ScanSubdir,
		BoundaryMode:      input.BoundaryMode,
	}
}

// GenerateVerificationReport creates a VerificationReport from input data.
func GenerateVerificationReport(input ReportInput) VerificationReport {
	summary := Summary{}
	trustSummary := TrustSummary{}
	capSummary := CapabilitySummary{
		Degraded: input.Degraded,
	}
	for _, f := range input.Findings {
		switch f.Status {
		case rules.StatusPass:
			summary.Pass++
		case rules.StatusFail:
			summary.Fail++
		case rules.StatusUnknown:
			summary.Unknown++
		}
		switch f.TrustClass {
		case rules.TrustMachineTrusted:
			trustSummary.MachineTrusted++
		case rules.TrustAdvisory:
			trustSummary.Advisory++
		case rules.TrustHumanOrRuntimeRequired:
			trustSummary.HumanOrRuntimeRequired++
		}

		// CapabilitySummary: classify based on actual capability signals,
		// not trust class. A finding's unknown_reasons tell us whether it
		// was capability-limited, and the status tells us if the rule ran.
		capLevel := classifyFindingCapability(f)
		switch capLevel {
		case "fully_supported":
			capSummary.FullySupported++
		case "partial":
			capSummary.Partial++
		case "unsupported":
			capSummary.Unsupported++
		}
	}
	// Skipped rules: only count those that were skipped for capability reasons
	// (not "no matching languages"). Capability-unsupported rules already
	// produce an unknown finding WITH UnknownCapabilityUnsupported, which is
	// counted above. So we must NOT double-count them here.
	// Only count skipped rules that have NO corresponding finding.
	findingRuleIDs := make(map[string]bool, len(input.Findings))
	for _, f := range input.Findings {
		findingRuleIDs[f.RuleID] = true
	}
	for _, sr := range input.SkippedRules {
		if !findingRuleIDs[sr.RuleID] && strings.Contains(sr.Reason, "capability_unsupported") {
			capSummary.Unsupported++
		}
	}
	signalSummary := ComputeSignalSummary(input.Findings, input.RuleMetadata)

	var fqSummary FactQualitySummary
	for _, f := range input.Findings {
		switch f.VerdictBasis {
		case "proof":
			fqSummary.ProofBacked++
		case "structural_binding":
			fqSummary.StructuralBacked++
		case "heuristic_inference":
			fqSummary.HeuristicBacked++
		case "runtime_required":
			fqSummary.RuntimeRequired++
		}
	}

	return VerificationReport{
		ReportSchemaVersion: schema.ReportSchemaVersion,
		Partial:             input.Partial,
		Summary:             summary,
		TrustSummary:        trustSummary,
		CapabilitySummary:   capSummary,
		SignalSummary:       signalSummary,
		FactQualitySummary:  fqSummary,
		Findings:            input.Findings,
		SkippedRules:        input.SkippedRules,
		Errors:              input.Errors,
	}
}

// classifyFindingCapability determines the capability level of a finding based
// on its unknown_reasons, not its trust_class. This correctly distinguishes:
//   - "fully_supported": rule ran with full capability (no capability annotations)
//   - "partial": rule ran but with partial capability (has capability_partial reason)
//   - "unsupported": rule could not run due to capability gap (has capability_unsupported reason)
func classifyFindingCapability(f rules.Finding) string {
	for _, reason := range f.UnknownReasons {
		if reason == rules.UnknownCapabilityUnsupported {
			return "unsupported"
		}
	}
	for _, reason := range f.UnknownReasons {
		if reason == rules.UnknownCapabilityPartial ||
			reason == rules.UnknownCapabilityDegraded ||
			reason == rules.UnknownFactExtractionGap ||
			reason == rules.UnknownMatcherLimitation {
			return "partial"
		}
	}
	return "fully_supported"
}

// GenerateMarkdown creates a human-readable markdown report.
func GenerateMarkdown(scan ScanReport, vr VerificationReport) string {
	var b strings.Builder
	b.WriteString("# Code Verification Report\n\n")
	b.WriteString("## Scan Summary\n")
	b.WriteString(fmt.Sprintf("- Repo: %s\n", scan.RepoName))
	b.WriteString(fmt.Sprintf("- Ref: %s\n", scan.Ref))
	b.WriteString(fmt.Sprintf("- Languages: %s\n", strings.Join(scan.Languages, ", ")))
	b.WriteString(fmt.Sprintf("- Profile: %s\n", scan.Profile))
	if vr.Partial {
		b.WriteString("- **Partial scan**: some analyzers failed\n")
	}
	b.WriteString("\n## Results\n")
	b.WriteString(fmt.Sprintf("- **Actionable Failures: %d**\n", vr.SignalSummary.ActionableFail))
	b.WriteString(fmt.Sprintf("- Advisory Failures: %d\n", vr.SignalSummary.AdvisoryFail))
	b.WriteString(fmt.Sprintf("- Informational Detections: %d\n", vr.SignalSummary.InformationalDetection))
	b.WriteString(fmt.Sprintf("- Pass: %d\n", vr.Summary.Pass))
	b.WriteString(fmt.Sprintf("- Unknown: %d\n", vr.SignalSummary.Unknown))
	b.WriteString(fmt.Sprintf("\n> Total findings: %d (pass=%d fail=%d unknown=%d)\n",
		vr.Summary.Pass+vr.Summary.Fail+vr.Summary.Unknown,
		vr.Summary.Pass, vr.Summary.Fail, vr.Summary.Unknown))
	b.WriteString("\n## Trust Summary\n")
	b.WriteString(fmt.Sprintf("- Machine Trusted: %d\n", vr.TrustSummary.MachineTrusted))
	b.WriteString(fmt.Sprintf("- Advisory: %d\n", vr.TrustSummary.Advisory))
	b.WriteString(fmt.Sprintf("- Human/Runtime Required: %d\n", vr.TrustSummary.HumanOrRuntimeRequired))
	b.WriteString("\n## Capability Summary\n")
	b.WriteString(fmt.Sprintf("- Fully Supported: %d\n", vr.CapabilitySummary.FullySupported))
	b.WriteString(fmt.Sprintf("- Partial: %d\n", vr.CapabilitySummary.Partial))
	b.WriteString(fmt.Sprintf("- Unsupported: %d\n", vr.CapabilitySummary.Unsupported))
	if vr.CapabilitySummary.Degraded {
		b.WriteString("- **Degraded**: Runtime degradation detected; some findings may have reduced accuracy\n")
	}
	b.WriteString("\n## Verdict Basis\n")
	b.WriteString(fmt.Sprintf("- Proof-backed: %d\n", vr.FactQualitySummary.ProofBacked))
	b.WriteString(fmt.Sprintf("- Structural/Binding: %d\n", vr.FactQualitySummary.StructuralBacked))
	b.WriteString(fmt.Sprintf("- Heuristic: %d\n", vr.FactQualitySummary.HeuristicBacked))
	b.WriteString(fmt.Sprintf("- Runtime Required: %d\n", vr.FactQualitySummary.RuntimeRequired))

	// Trust warnings
	if vr.TrustSummary.Advisory > 0 || vr.TrustSummary.HumanOrRuntimeRequired > 0 {
		b.WriteString("\n## Trust Warnings\n")
		if vr.TrustSummary.Advisory > 0 {
			b.WriteString(fmt.Sprintf("- **Advisory findings present (%d)**: These findings use heuristic analysis and should NOT be treated as authoritative. Manual review is recommended before acting on them.\n", vr.TrustSummary.Advisory))
		}
		if vr.TrustSummary.HumanOrRuntimeRequired > 0 {
			b.WriteString(fmt.Sprintf("- **Human/runtime review required (%d)**: These findings cannot be resolved by static analysis alone. They require human judgment or runtime testing to validate.\n", vr.TrustSummary.HumanOrRuntimeRequired))
		}
	}
	if vr.CapabilitySummary.Degraded {
		b.WriteString("\n> **Note**: Analysis was performed in a degraded mode. Some analyzers may not have had full runtime support. Findings from affected languages may have lower accuracy than normal.\n")
	}
	// Separate GOF (pattern detection) findings from primary findings
	var primaryFindings, gofFindings []rules.Finding
	for _, f := range vr.Findings {
		if IsGOFRule(f.RuleID) {
			gofFindings = append(gofFindings, f)
		} else {
			primaryFindings = append(primaryFindings, f)
		}
	}

	b.WriteString("\n## Findings\n")
	for _, f := range primaryFindings {
		writeFindingMarkdown(&b, f)
	}

	if len(gofFindings) > 0 {
		b.WriteString("\n## Pattern Detections\n")
		b.WriteString("\n> GoF pattern detections are informational and do not count toward actionable failure totals.\n")
		for _, f := range gofFindings {
			writeFindingMarkdown(&b, f)
		}
	}
	if len(vr.SkippedRules) > 0 {
		b.WriteString("\n## Skipped Rules\n")
		for _, sr := range vr.SkippedRules {
			b.WriteString(fmt.Sprintf("- %s: %s\n", sr.RuleID, sr.Reason))
		}
	}
	return b.String()
}

// writeFindingMarkdown writes a single finding in markdown format.
func writeFindingMarkdown(b *strings.Builder, f rules.Finding) {
	b.WriteString(fmt.Sprintf("\n### %s %s\n", f.RuleID, f.Message))
	b.WriteString(fmt.Sprintf("- Status: %s\n", f.Status))
	b.WriteString(fmt.Sprintf("- Trust Class: %s\n", f.TrustClass))
	b.WriteString(fmt.Sprintf("- Confidence: %s\n", f.Confidence))
	b.WriteString(fmt.Sprintf("- Verification Level: %s\n", f.VerificationLevel))
	b.WriteString(fmt.Sprintf("\n%s\n", f.Message))
	if len(f.Evidence) > 0 {
		b.WriteString("\nEvidence:\n")
		for _, ev := range f.Evidence {
			if ev.LineStart > 0 && ev.LineEnd > 0 {
				b.WriteString(fmt.Sprintf("- `%s:%d-%d`", ev.File, ev.LineStart, ev.LineEnd))
			} else {
				b.WriteString(fmt.Sprintf("- `%s`", ev.File))
			}
			if ev.Symbol != "" {
				b.WriteString(fmt.Sprintf(" `%s`", ev.Symbol))
			}
			b.WriteString("\n")
		}
	}
	if len(f.UnknownReasons) > 0 {
		b.WriteString("\nUnknown reasons:\n")
		for _, r := range f.UnknownReasons {
			b.WriteString(fmt.Sprintf("- %s\n", r))
		}
	}
}

// WriteOutputs writes scan.json, report.json, and optionally report.md to the output directory.
//
// Write strategy: all files are staged in a temporary directory first. Only after
// all staging writes succeed are files renamed into the output directory. os.Rename
// on Unix atomically replaces the destination per-file. Stale files from previous
// runs (e.g., report.md when switching to json-only format) are removed only AFTER
// all new files are committed, so a failure never leaves the output directory empty.
//
// This is per-file atomic, not directory-level atomic. A concurrent reader may
// briefly see a mix of old and new files during the rename batch.
func WriteOutputs(outputDir string, scan ScanReport, vr VerificationReport, format string) error {
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return fmt.Errorf("create output dir: %w", err)
	}

	stageDir, err := os.MkdirTemp(outputDir, ".cve-stage-*")
	if err != nil {
		return fmt.Errorf("create staging dir: %w", err)
	}
	defer os.RemoveAll(stageDir)

	// Determine which files to write
	newFiles := map[string]bool{"scan.json": true}

	// Always write scan.json
	if err := writeJSON(filepath.Join(stageDir, "scan.json"), scan); err != nil {
		return fmt.Errorf("write scan.json: %w", err)
	}

	if format == "json" || format == "both" {
		if err := writeJSON(filepath.Join(stageDir, "report.json"), vr); err != nil {
			return fmt.Errorf("write report.json: %w", err)
		}
		newFiles["report.json"] = true
	}

	if format == "md" || format == "both" {
		md := GenerateMarkdown(scan, vr)
		if err := os.WriteFile(filepath.Join(stageDir, "report.md"), []byte(md), 0o644); err != nil {
			return fmt.Errorf("write report.md: %w", err)
		}
		newFiles["report.md"] = true
	}

	// Commit: rename staged files into output directory.
	// os.Rename atomically replaces the destination on Unix,
	// so existing files are overwritten without a delete-then-write gap.
	entries, err := os.ReadDir(stageDir)
	if err != nil {
		return fmt.Errorf("read staging dir: %w", err)
	}
	for _, entry := range entries {
		src := filepath.Join(stageDir, entry.Name())
		dst := filepath.Join(outputDir, entry.Name())
		if err := os.Rename(src, dst); err != nil {
			return fmt.Errorf("rename %s: %w", entry.Name(), err)
		}
	}

	// Clean up stale files AFTER all renames succeed.
	// This prevents leaving the output directory empty on failure.
	knownOutputs := []string{"scan.json", "report.json", "report.md"}
	for _, name := range knownOutputs {
		if !newFiles[name] {
			os.Remove(filepath.Join(outputDir, name))
		}
	}

	return nil
}

func writeJSON(path string, v interface{}) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}
