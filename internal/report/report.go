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
}

// VerificationReport represents report.json content.
type VerificationReport struct {
	ReportSchemaVersion string              `json:"report_schema_version"`
	Partial             bool                `json:"partial"`
	Summary             Summary             `json:"summary"`
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
	Profile string
}

// ReportInput holds the data needed to generate verification reports.
type ReportInput struct {
	Partial      bool
	Findings     []rules.Finding
	SkippedRules []rules.SkippedRule
	Errors       []string
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
	}
}

// GenerateVerificationReport creates a VerificationReport from input data.
func GenerateVerificationReport(input ReportInput) VerificationReport {
	summary := Summary{}
	for _, f := range input.Findings {
		switch f.Status {
		case rules.StatusPass:
			summary.Pass++
		case rules.StatusFail:
			summary.Fail++
		case rules.StatusUnknown:
			summary.Unknown++
		}
	}
	return VerificationReport{
		ReportSchemaVersion: schema.ReportSchemaVersion,
		Partial:             input.Partial,
		Summary:             summary,
		Findings:            input.Findings,
		SkippedRules:        input.SkippedRules,
		Errors:              input.Errors,
	}
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
	b.WriteString(fmt.Sprintf("- Pass: %d\n", vr.Summary.Pass))
	b.WriteString(fmt.Sprintf("- Fail: %d\n", vr.Summary.Fail))
	b.WriteString(fmt.Sprintf("- Unknown: %d\n", vr.Summary.Unknown))
	b.WriteString("\n## Findings\n")
	for _, f := range vr.Findings {
		b.WriteString(fmt.Sprintf("\n### %s %s\n", f.RuleID, f.Message))
		b.WriteString(fmt.Sprintf("- Status: %s\n", f.Status))
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
	if len(vr.SkippedRules) > 0 {
		b.WriteString("\n## Skipped Rules\n")
		for _, sr := range vr.SkippedRules {
			b.WriteString(fmt.Sprintf("- %s: %s\n", sr.RuleID, sr.Reason))
		}
	}
	return b.String()
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
