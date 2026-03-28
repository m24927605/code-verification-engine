package report

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
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
	SourceRepoRoot    string            `json:"source_repo_root,omitempty"`
	RequestedPath     string            `json:"requested_path,omitempty"`
	ScanSubdir        string            `json:"scan_subdir,omitempty"`
	BoundaryMode      string            `json:"boundary_mode,omitempty"`
}

type CapabilitySummary struct {
	FullySupported int  `json:"fully_supported"`
	Partial        int  `json:"partial"`
	Unsupported    int  `json:"unsupported"`
	Degraded       bool `json:"degraded"`
}

type FactQualitySummary struct {
	ProofBacked      int `json:"proof_backed"`
	StructuralBacked int `json:"structural_backed"`
	HeuristicBacked  int `json:"heuristic_backed"`
	RuntimeRequired  int `json:"runtime_required"`
}

// IssueEvidence is the report-level issue evidence projection.
type IssueEvidence struct {
	ID        string `json:"evidence_id,omitempty"`
	File      string `json:"file"`
	LineStart int    `json:"line_start"`
	LineEnd   int    `json:"line_end"`
	Symbol    string `json:"symbol,omitempty"`
}

// Issue is the canonical report.json issue representation.
type Issue struct {
	ID             string          `json:"id,omitempty"`
	RuleID         string          `json:"rule_id,omitempty"`
	RuleIDs        []string        `json:"rule_ids,omitempty"`
	Title          string          `json:"title"`
	Category       string          `json:"category"`
	Severity       string          `json:"severity"`
	Status         string          `json:"status"`
	Confidence     string          `json:"confidence,omitempty"`
	TrustClass     string          `json:"trust_class,omitempty"`
	Capability     string          `json:"capability,omitempty"`
	SignalClass    string          `json:"signal_class,omitempty"`
	FactQuality    string          `json:"fact_quality,omitempty"`
	EvidenceIDs    []string        `json:"evidence_ids,omitempty"`
	Evidence       []IssueEvidence `json:"evidence,omitempty"`
	UnknownReasons []string        `json:"unknown_reasons,omitempty"`
}

// VerificationReport represents report.json content.
type VerificationReport struct {
	ReportSchemaVersion string              `json:"report_schema_version"`
	Partial             bool                `json:"partial"`
	Summary             Summary             `json:"summary"`
	TrustSummary        TrustSummary        `json:"trust_summary"`
	CapabilitySummary   CapabilitySummary   `json:"capability_summary"`
	SignalSummary       SignalSummary       `json:"signal_summary"`
	FactQualitySummary  FactQualitySummary  `json:"fact_quality_summary"`
	Issues              []Issue             `json:"issues"`
	SkippedRules        []rules.SkippedRule `json:"skipped_rules,omitempty"`
	Errors              []string            `json:"errors,omitempty"`
}

type Summary struct {
	Pass    int `json:"pass"`
	Fail    int `json:"fail"`
	Unknown int `json:"unknown"`
}

type TrustSummary struct {
	MachineTrusted         int `json:"machine_trusted"`
	Advisory               int `json:"advisory"`
	HumanOrRuntimeRequired int `json:"human_or_runtime_required"`
}

type ScanInput struct {
	RepoPath       string
	RepoName       string
	Ref            string
	CommitSHA      string
	Languages      []string
	FileCount      int
	Partial        bool
	Analyzers      map[string]string
	Errors         []string
	Profile        string
	SourceRepoRoot string
	RequestedPath  string
	ScanSubdir     string
	BoundaryMode   string
}

type ReportInput struct {
	Partial      bool
	Issues       []Issue
	Findings     []rules.Finding
	RuleMetadata map[string]rules.Rule
	SkippedRules []rules.SkippedRule
	Errors       []string
	Degraded     bool
}

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

func GenerateVerificationReport(input ReportInput) VerificationReport {
	issues := append([]Issue(nil), input.Issues...)
	if len(issues) == 0 {
		issues = deriveIssuesFromFindings(input.Findings, input.RuleMetadata)
	}

	summary := Summary{}
	trustSummary := TrustSummary{}
	capSummary := CapabilitySummary{Degraded: input.Degraded}
	signalSummary := ComputeIssueSignalSummary(issues, input.RuleMetadata)
	var fqSummary FactQualitySummary

	for _, issue := range issues {
		switch issue.Status {
		case "resolved", "pass":
			summary.Pass++
		case "unknown":
			summary.Unknown++
		default:
			summary.Fail++
		}

		switch issue.TrustClass {
		case string(rules.TrustMachineTrusted):
			trustSummary.MachineTrusted++
		case string(rules.TrustAdvisory):
			trustSummary.Advisory++
		case string(rules.TrustHumanOrRuntimeRequired):
			trustSummary.HumanOrRuntimeRequired++
		}

		switch issue.Capability {
		case "unsupported":
			capSummary.Unsupported++
		case "partial":
			capSummary.Partial++
		default:
			capSummary.FullySupported++
		}

		switch issue.FactQuality {
		case "proof":
			fqSummary.ProofBacked++
		case "structural":
			fqSummary.StructuralBacked++
		case "runtime_required":
			fqSummary.RuntimeRequired++
		default:
			if issue.FactQuality != "" {
				fqSummary.HeuristicBacked++
			}
		}
	}

	for _, sr := range input.SkippedRules {
		if strings.Contains(sr.Reason, "capability_unsupported") && !issuesContainRuleID(issues, sr.RuleID) {
			capSummary.Unsupported++
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
		Issues:              issues,
		SkippedRules:        input.SkippedRules,
		Errors:              input.Errors,
	}
}

func deriveIssuesFromFindings(findings []rules.Finding, metadata map[string]rules.Rule) []Issue {
	out := make([]Issue, 0, len(findings))
	for _, finding := range findings {
		rule := metadata[finding.RuleID]
		evIDs := make([]string, 0, len(finding.Evidence))
		evidence := make([]IssueEvidence, 0, len(finding.Evidence))
		for _, ev := range finding.Evidence {
			id := ev.ID
			if id == "" {
				id = rules.EvidenceID(ev)
			}
			evIDs = append(evIDs, id)
			evidence = append(evidence, IssueEvidence{
				ID:        id,
				File:      ev.File,
				LineStart: ev.LineStart,
				LineEnd:   ev.LineEnd,
				Symbol:    ev.Symbol,
			})
		}
		category := rules.CanonicalIssueCategory(rule, finding.RuleID)
		out = append(out, Issue{
			ID:             finding.RuleID,
			RuleID:         finding.RuleID,
			RuleIDs:        []string{finding.RuleID},
			Title:          rules.CanonicalIssueTitle(rule, finding.Message),
			Category:       category,
			Severity:       rules.CanonicalIssueSeverity(rule, finding.TrustClass, finding.Status),
			Status:         issueStatusFromFinding(finding.Status),
			Confidence:     string(finding.Confidence),
			TrustClass:     string(finding.TrustClass),
			Capability:     classifyFindingCapability(finding),
			SignalClass:    string(ClassifySignal(finding, metadata)),
			FactQuality:    normalizeFactQuality(finding.VerdictBasis, finding.FactQualityFloor),
			EvidenceIDs:    dedupeStrings(evIDs),
			Evidence:       evidence,
			UnknownReasons: append([]string(nil), finding.UnknownReasons...),
		})
	}
	return out
}

func dedupeStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	slices.Sort(out)
	return out
}

func issuesContainRuleID(issues []Issue, ruleID string) bool {
	for _, issue := range issues {
		if issue.RuleID == ruleID || slices.Contains(issue.RuleIDs, ruleID) {
			return true
		}
	}
	return false
}

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

func normalizeFactQuality(verdictBasis, factQualityFloor string) string {
	switch verdictBasis {
	case "proof", "structural_binding", "heuristic_inference", "runtime_required":
		if verdictBasis == "structural_binding" {
			return "structural"
		}
		if verdictBasis == "heuristic_inference" {
			return "heuristic"
		}
		return verdictBasis
	}
	switch factQualityFloor {
	case "proof", "structural", "heuristic", "runtime_required":
		return factQualityFloor
	default:
		return "heuristic"
	}
}

func issueStatusFromFinding(status rules.Status) string {
	switch status {
	case rules.StatusPass:
		return "resolved"
	case rules.StatusUnknown:
		return "unknown"
	default:
		return "open"
	}
}

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
	b.WriteString(fmt.Sprintf("\n> Total issues: %d (pass=%d fail=%d unknown=%d)\n",
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
		b.WriteString("- **Degraded**: Runtime degradation detected; some issues may have reduced accuracy\n")
	}
	b.WriteString("\n## Verdict Basis\n")
	b.WriteString(fmt.Sprintf("- Proof-backed: %d\n", vr.FactQualitySummary.ProofBacked))
	b.WriteString(fmt.Sprintf("- Structural/Binding: %d\n", vr.FactQualitySummary.StructuralBacked))
	b.WriteString(fmt.Sprintf("- Heuristic: %d\n", vr.FactQualitySummary.HeuristicBacked))
	b.WriteString(fmt.Sprintf("- Runtime Required: %d\n", vr.FactQualitySummary.RuntimeRequired))

	if vr.TrustSummary.Advisory > 0 || vr.TrustSummary.HumanOrRuntimeRequired > 0 {
		b.WriteString("\n## Trust Warnings\n")
		if vr.TrustSummary.Advisory > 0 {
			b.WriteString(fmt.Sprintf("- **Advisory issues present (%d)**: These issues use heuristic analysis and should NOT be treated as authoritative. Manual review is recommended before acting on them.\n", vr.TrustSummary.Advisory))
		}
		if vr.TrustSummary.HumanOrRuntimeRequired > 0 {
			b.WriteString(fmt.Sprintf("- **Human/runtime review required (%d)**: These issues cannot be resolved by static analysis alone. They require human judgment or runtime testing to validate.\n", vr.TrustSummary.HumanOrRuntimeRequired))
		}
	}
	if vr.CapabilitySummary.Degraded {
		b.WriteString("\n> **Note**: Analysis was performed in a degraded mode. Some analyzers may not have had full runtime support. Issues from affected languages may have lower accuracy than normal.\n")
	}

	var primaryIssues, gofIssues []Issue
	for _, issue := range vr.Issues {
		if IsGOFRule(issue.RuleID) {
			gofIssues = append(gofIssues, issue)
			continue
		}
		primaryIssues = append(primaryIssues, issue)
	}

	b.WriteString("\n## Issues\n")
	for _, issue := range primaryIssues {
		writeIssueMarkdown(&b, issue)
	}
	if len(gofIssues) > 0 {
		b.WriteString("\n## Pattern Detections\n")
		b.WriteString("\n> GoF pattern detections are informational and do not count toward actionable failure totals.\n")
		for _, issue := range gofIssues {
			writeIssueMarkdown(&b, issue)
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

func writeIssueMarkdown(b *strings.Builder, issue Issue) {
	title := issue.Title
	if title == "" {
		title = issue.RuleID
	}
	b.WriteString(fmt.Sprintf("\n### %s\n", title))
	if issue.RuleID != "" {
		b.WriteString(fmt.Sprintf("- Rule ID: %s\n", issue.RuleID))
	}
	if len(issue.RuleIDs) > 0 {
		b.WriteString(fmt.Sprintf("- Rule IDs: %s\n", strings.Join(issue.RuleIDs, ", ")))
	}
	b.WriteString(fmt.Sprintf("- Status: %s\n", issue.Status))
	if issue.TrustClass != "" {
		b.WriteString(fmt.Sprintf("- Trust Class: %s\n", issue.TrustClass))
	}
	if issue.Confidence != "" {
		b.WriteString(fmt.Sprintf("- Confidence: %s\n", issue.Confidence))
	}
	if issue.Severity != "" {
		b.WriteString(fmt.Sprintf("- Severity: %s\n", issue.Severity))
	}
	if len(issue.Evidence) > 0 {
		b.WriteString("\nEvidence:\n")
		for _, ev := range issue.Evidence {
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
	if len(issue.UnknownReasons) > 0 {
		b.WriteString("\nUnknown reasons:\n")
		for _, reason := range issue.UnknownReasons {
			b.WriteString(fmt.Sprintf("- %s\n", reason))
		}
	}
}

func WriteOutputs(outputDir string, scan ScanReport, vr VerificationReport, format string) error {
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return fmt.Errorf("create output dir: %w", err)
	}
	stageDir, err := os.MkdirTemp(outputDir, ".cve-stage-*")
	if err != nil {
		return fmt.Errorf("create staging dir: %w", err)
	}
	defer os.RemoveAll(stageDir)

	newFiles := map[string]bool{"scan.json": true}
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
	for _, name := range []string{"scan.json", "report.json", "report.md"} {
		if !newFiles[name] {
			os.Remove(filepath.Join(outputDir, name))
		}
	}
	return nil
}

func writeJSON(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(path, data, 0o644)
}
