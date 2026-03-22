package autobench

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"

	"github.com/verabase/code-verification-engine/internal/engine"
	"github.com/verabase/code-verification-engine/internal/rules"
)

// RunConfig controls dataset execution for autonomous calibration.
type RunConfig struct {
	ModuleRoot   string
	ManifestPath string
	OutputRoot   string
	Ref          string
	Progress     io.Writer
	SuiteIDs     []string
	CaseIDs      []string
}

// DatasetRunResult summarizes the execution of an autonomous benchmark dataset.
type DatasetRunResult struct {
	SchemaVersion string           `json:"schema_version"`
	DatasetID     string           `json:"dataset_id"`
	ManifestPath  string           `json:"manifest_path"`
	OutputRoot    string           `json:"output_root"`
	Suites        []SuiteRunResult `json:"suites"`
	Summary       RunSummary       `json:"summary"`
	Gate          GateResult       `json:"gate"`
}

// SuiteRunResult is the result of executing one suite from the dataset.
type SuiteRunResult struct {
	ID       string          `json:"id"`
	Profile  string          `json:"profile"`
	ClaimSet string          `json:"claim_set,omitempty"`
	Cases    []CaseRunResult `json:"cases"`
	Summary  RunSummary      `json:"summary"`
}

// CaseRunResult is the execution result for one case fixture.
type CaseRunResult struct {
	ID                  string                `json:"id"`
	RepoPath            string                `json:"repo_path"`
	Framework           string                `json:"framework"`
	CaseType            string                `json:"case_type"`
	ExitCode            int                   `json:"exit_code"`
	OutputDir           string                `json:"output_dir"`
	ActualFindings      int                   `json:"actual_findings"`
	BlockingDiscrepancies int                 `json:"blocking_discrepancies"`
	AdvisoryDiscrepancies int                 `json:"advisory_discrepancies"`
	Adjudication        AdjudicationReport    `json:"adjudication"`
	Errors              []string              `json:"errors,omitempty"`
}

// RunSummary aggregates suite or dataset execution counts.
type RunSummary struct {
	Suites                int `json:"suites"`
	Cases                 int `json:"cases"`
	PassedCases           int `json:"passed_cases"`
	FailedCases           int `json:"failed_cases"`
	BlockingDiscrepancies int `json:"blocking_discrepancies"`
	AdvisoryDiscrepancies int `json:"advisory_discrepancies"`
}

// GateResult records whether dataset promotion is allowed.
type GateResult struct {
	Passed bool     `json:"passed"`
	Reasons []string `json:"reasons,omitempty"`
}

// RunDataset executes all selected cases in a dataset and writes actual outputs.
func RunDataset(ctx context.Context, cfg RunConfig) (*DatasetRunResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if cfg.ModuleRoot == "" || cfg.ManifestPath == "" || cfg.OutputRoot == "" {
		return nil, fmt.Errorf("module_root, manifest_path, and output_root are required")
	}
	progress := cfg.Progress
	if progress == nil {
		progress = io.Discard
	}

	manifest, expectedByCase, err := LoadDataset(cfg.ModuleRoot, cfg.ManifestPath)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(cfg.OutputRoot, 0o755); err != nil {
		return nil, err
	}

	result := &DatasetRunResult{
		SchemaVersion: SchemaVersion,
		DatasetID:     manifest.DatasetID,
		ManifestPath:  cfg.ManifestPath,
		OutputRoot:    cfg.OutputRoot,
	}

	for _, suite := range manifest.Suites {
		if !matchesFilter(suite.ID, cfg.SuiteIDs) {
			continue
		}
		suiteResult := SuiteRunResult{
			ID:       suite.ID,
			Profile:  suite.Profile,
			ClaimSet: suite.ClaimSet,
		}

		for _, c := range suite.Cases {
			if !matchesFilter(c.ID, cfg.CaseIDs) {
				continue
			}
			caseResult, err := runCase(ctx, cfg, manifest, suite, c, expectedByCase[c.ID], progress)
			if err != nil {
				return nil, err
			}
			suiteResult.Cases = append(suiteResult.Cases, caseResult)
			accumulateSummary(&suiteResult.Summary, caseResult)
		}

		if len(suiteResult.Cases) == 0 {
			continue
		}
		suiteResult.Summary.Suites = 1
		result.Suites = append(result.Suites, suiteResult)
		accumulateSuiteSummary(&result.Summary, suiteResult.Summary)
	}

	result.Gate = evaluateGate(manifest, result.Summary)
	if err := writeJSON(filepath.Join(cfg.OutputRoot, "dataset-run.json"), result); err != nil {
		return nil, err
	}
	return result, nil
}

func runCase(ctx context.Context, cfg RunConfig, manifest *DatasetManifest, suite SuiteManifest, c CaseManifest, expected ExpectedCase, progress io.Writer) (CaseRunResult, error) {
	caseOutputDir := filepath.Join(cfg.OutputRoot, suite.ID, c.ID)
	actualDir := filepath.Join(caseOutputDir, "actual")
	if err := os.MkdirAll(actualDir, 0o755); err != nil {
		return CaseRunResult{}, err
	}

	repoDir, err := initTempGitRepo(filepath.Join(cfg.ModuleRoot, c.RepoPath))
	if err != nil {
		return CaseRunResult{}, err
	}
	defer os.RemoveAll(repoDir)

	ref := cfg.Ref
	if ref == "" {
		ref = "HEAD"
	}
	fmt.Fprintf(progress, "[AUTO] suite=%s case=%s profile=%s\n", suite.ID, c.ID, suite.Profile)

	engineResult := engine.Run(engine.Config{
		Ctx:       ctx,
		RepoPath:  repoDir,
		Ref:       ref,
		Profile:   suite.Profile,
		ClaimSet:  suite.ClaimSet,
		OutputDir: actualDir,
		Format:    "both",
		Progress:  progress,
	})

	adjudication := buildAdjudication(manifest, suite, c, expected, engineResult.Report.Findings)
	caseResult := CaseRunResult{
		ID:                   c.ID,
		RepoPath:             c.RepoPath,
		Framework:            c.Framework,
		CaseType:             c.CaseType,
		ExitCode:             engineResult.ExitCode,
		OutputDir:            caseOutputDir,
		ActualFindings:       len(engineResult.Report.Findings),
		BlockingDiscrepancies: adjudication.Summary.Blocking,
		AdvisoryDiscrepancies: adjudication.Summary.Advisory,
		Adjudication:         adjudication,
		Errors:               slices.Clone(engineResult.Errors),
	}

	if err := writeJSON(filepath.Join(caseOutputDir, "adjudication.json"), adjudication); err != nil {
		return CaseRunResult{}, err
	}
	if err := os.WriteFile(filepath.Join(caseOutputDir, "discrepancy.md"), []byte(renderDiscrepancyMarkdown(caseResult)), 0o644); err != nil {
		return CaseRunResult{}, err
	}
	return caseResult, nil
}

func buildAdjudication(manifest *DatasetManifest, suite SuiteManifest, c CaseManifest, expected ExpectedCase, findings []rules.Finding) AdjudicationReport {
	adjudication := AdjudicationReport{
		SchemaVersion: SchemaVersion,
		DatasetID:     manifest.DatasetID,
		SuiteID:       suite.ID,
		CaseID:        c.ID,
		Verdict:       "matches",
	}

	findingByRule := make(map[string]rules.Finding, len(findings))
	for _, finding := range findings {
		findingByRule[finding.RuleID] = finding
	}

	for _, exp := range expected.Expectations {
		finding, ok := findingByRule[exp.RuleID]
		if !ok {
			adjudication.Discrepancies = append(adjudication.Discrepancies, RuleDiscrepancy{
				RuleID:           exp.RuleID,
				ExpectedStatus:   expectedStatusLabel(exp),
				ReviewerVerdict:  "missing_finding",
				SuspectedCauses:  []string{"rule_not_emitted", "matcher_gap"},
				RecommendedOwner: OwnerRules,
				RecommendedAction: "Inspect why the target rule was not emitted for this case and whether the matcher skipped a supported scenario.",
			})
			incrementDiscrepancySummary(&adjudication.Summary, exp.Priority)
			continue
		}

		if !matchesExpectation(exp, finding) {
			suspectedCauses := discrepancyCauses(exp, finding)
			adjudication.Discrepancies = append(adjudication.Discrepancies, RuleDiscrepancy{
				RuleID:            exp.RuleID,
				ExpectedStatus:    expectedStatusLabel(exp),
				ActualStatus:      string(finding.Status),
				ReviewerVerdict:   "mismatch",
				SuspectedCauses:   suspectedCauses,
				RecommendedOwner:  recommendedOwner(suspectedCauses),
				RecommendedAction: recommendedAction(suspectedCauses),
			})
			incrementDiscrepancySummary(&adjudication.Summary, exp.Priority)
		}
	}

	if adjudication.Summary.Blocking > 0 || adjudication.Summary.Advisory > 0 {
		adjudication.Verdict = "mismatch"
	}
	return adjudication
}

func matchesExpectation(exp RuleExpectation, finding rules.Finding) bool {
	if exp.ExpectedStatus != "" && string(finding.Status) != exp.ExpectedStatus {
		return false
	}
	if len(exp.AllowedStatuses) > 0 && !slices.Contains(exp.AllowedStatuses, string(finding.Status)) {
		return false
	}
	if exp.ExpectedTrustClass != "" && string(finding.TrustClass) != exp.ExpectedTrustClass {
		return false
	}
	if len(finding.Evidence) < exp.MinimumEvidenceCount {
		return false
	}
	return true
}

func expectedStatusLabel(exp RuleExpectation) string {
	if exp.ExpectedStatus != "" {
		return exp.ExpectedStatus
	}
	return strings.Join(exp.AllowedStatuses, "|")
}

func discrepancyCauses(exp RuleExpectation, finding rules.Finding) []string {
	var causes []string
	if exp.ExpectedStatus != "" && string(finding.Status) != exp.ExpectedStatus {
		switch {
		case finding.Status == rules.StatusUnknown:
			causes = append(causes, "fact_extraction_gap")
		case exp.ExpectedStatus == string(rules.StatusPass) && finding.Status == rules.StatusFail:
			causes = append(causes, "false_positive")
		case exp.ExpectedStatus == string(rules.StatusFail) && finding.Status == rules.StatusPass:
			causes = append(causes, "false_negative")
		default:
			causes = append(causes, "status_mismatch")
		}
	}
	if len(exp.AllowedStatuses) > 0 && !slices.Contains(exp.AllowedStatuses, string(finding.Status)) {
		causes = append(causes, "status_outside_allowed_range")
	}
	if exp.ExpectedTrustClass != "" && string(finding.TrustClass) != exp.ExpectedTrustClass {
		causes = append(causes, "trust_miscalibration")
	}
	if len(finding.Evidence) < exp.MinimumEvidenceCount {
		causes = append(causes, "insufficient_evidence")
	}
	if len(causes) == 0 {
		causes = append(causes, "review_needed")
	}
	return causes
}

func recommendedOwner(causes []string) string {
	for _, cause := range causes {
		switch cause {
		case "fact_extraction_gap", "insufficient_evidence":
			return OwnerAnalyzer
		case "false_positive", "false_negative", "status_mismatch":
			return OwnerRules
		case "trust_miscalibration":
			return OwnerReport
		}
	}
	return OwnerUnknown
}

func recommendedAction(causes []string) string {
	for _, cause := range causes {
		switch cause {
		case "fact_extraction_gap":
			return "Strengthen fact extraction or add a framework-aware analyzer path for this scenario."
		case "insufficient_evidence":
			return "Improve evidence capture so the rule can meet the benchmark evidence floor."
		case "false_positive":
			return "Refine matcher guards to avoid flagging this clean fixture."
		case "false_negative":
			return "Expand matcher coverage to catch the intended negative fixture."
		case "trust_miscalibration":
			return "Revisit trust class mapping so machine-trusted and advisory labels remain calibrated."
		}
	}
	return "Review the discrepancy and route it to the appropriate analyzer or matcher owner."
}

func renderDiscrepancyMarkdown(caseResult CaseRunResult) string {
	var b strings.Builder
	b.WriteString("# Discrepancy Report\n\n")
	b.WriteString(fmt.Sprintf("- Case: %s\n", caseResult.ID))
	b.WriteString(fmt.Sprintf("- Repo Fixture: %s\n", caseResult.RepoPath))
	b.WriteString(fmt.Sprintf("- Exit Code: %d\n", caseResult.ExitCode))
	b.WriteString(fmt.Sprintf("- Verdict: %s\n", caseResult.Adjudication.Verdict))
	b.WriteString(fmt.Sprintf("- Blocking Discrepancies: %d\n", caseResult.BlockingDiscrepancies))
	b.WriteString(fmt.Sprintf("- Advisory Discrepancies: %d\n", caseResult.AdvisoryDiscrepancies))
	if len(caseResult.Errors) > 0 {
		b.WriteString("\n## Engine Errors\n")
		for _, err := range caseResult.Errors {
			b.WriteString(fmt.Sprintf("- %s\n", err))
		}
	}
	if len(caseResult.Adjudication.Discrepancies) == 0 {
		b.WriteString("\nNo discrepancies detected.\n")
		return b.String()
	}
	b.WriteString("\n## Discrepancies\n")
	for _, d := range caseResult.Adjudication.Discrepancies {
		b.WriteString(fmt.Sprintf("\n### %s\n", d.RuleID))
		b.WriteString(fmt.Sprintf("- Expected: %s\n", d.ExpectedStatus))
		if d.ActualStatus != "" {
			b.WriteString(fmt.Sprintf("- Actual: %s\n", d.ActualStatus))
		}
		if d.ReviewerVerdict != "" {
			b.WriteString(fmt.Sprintf("- Verdict: %s\n", d.ReviewerVerdict))
		}
		b.WriteString(fmt.Sprintf("- Recommended Owner: %s\n", d.RecommendedOwner))
		if len(d.SuspectedCauses) > 0 {
			b.WriteString(fmt.Sprintf("- Suspected Causes: %s\n", strings.Join(d.SuspectedCauses, ", ")))
		}
		if d.RecommendedAction != "" {
			b.WriteString(fmt.Sprintf("- Recommended Action: %s\n", d.RecommendedAction))
		}
	}
	return b.String()
}

func accumulateSummary(summary *RunSummary, caseResult CaseRunResult) {
	summary.Cases++
	summary.BlockingDiscrepancies += caseResult.BlockingDiscrepancies
	summary.AdvisoryDiscrepancies += caseResult.AdvisoryDiscrepancies
	if caseResult.BlockingDiscrepancies == 0 && caseResult.AdvisoryDiscrepancies == 0 && caseResult.ExitCode == 0 {
		summary.PassedCases++
		return
	}
	summary.FailedCases++
}

func accumulateSuiteSummary(summary *RunSummary, suiteSummary RunSummary) {
	summary.Suites++
	summary.Cases += suiteSummary.Cases
	summary.PassedCases += suiteSummary.PassedCases
	summary.FailedCases += suiteSummary.FailedCases
	summary.BlockingDiscrepancies += suiteSummary.BlockingDiscrepancies
	summary.AdvisoryDiscrepancies += suiteSummary.AdvisoryDiscrepancies
}

func evaluateGate(manifest *DatasetManifest, summary RunSummary) GateResult {
	var reasons []string
	if manifest.GatePolicy.BlockOnFrozenRegression && summary.BlockingDiscrepancies > 0 {
		reasons = append(reasons, "blocking discrepancies detected in frozen dataset")
	}
	if manifest.GatePolicy.MaxNewUnknowns == 0 && summary.AdvisoryDiscrepancies > 0 {
		reasons = append(reasons, "advisory discrepancies require adjudication before promotion")
	}
	return GateResult{
		Passed: len(reasons) == 0,
		Reasons: reasons,
	}
}

func incrementDiscrepancySummary(summary *AdjudicationSummary, priority string) {
	if priority == "blocking" {
		summary.Blocking++
		return
	}
	summary.Advisory++
}

func matchesFilter(id string, allow []string) bool {
	if len(allow) == 0 {
		return true
	}
	return slices.Contains(allow, id)
}

func writeJSON(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

func initTempGitRepo(sourceDir string) (string, error) {
	tmpDir, err := os.MkdirTemp("", "cve-autobench-*")
	if err != nil {
		return "", err
	}
	if err := filepath.Walk(sourceDir, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, _ := filepath.Rel(sourceDir, path)
		dest := filepath.Join(tmpDir, rel)
		if info.IsDir() {
			return os.MkdirAll(dest, 0o755)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
			return err
		}
		return os.WriteFile(dest, data, 0o644)
	}); err != nil {
		os.RemoveAll(tmpDir)
		return "", err
	}

	cmds := [][]string{
		{"git", "init"},
		{"git", "config", "user.email", "autobench@test.local"},
		{"git", "config", "user.name", "autobench"},
		{"git", "add", "-A"},
		{"git", "commit", "-m", "autobench fixture"},
	}
	for _, args := range cmds {
		cmd := exec.Command(args[0], args[1:]...)
		cmd.Dir = tmpDir
		cmd.Stdout = io.Discard
		cmd.Stderr = io.Discard
		if err := cmd.Run(); err != nil {
			os.RemoveAll(tmpDir)
			return "", fmt.Errorf("git command %v failed: %w", args, err)
		}
	}
	return tmpDir, nil
}
