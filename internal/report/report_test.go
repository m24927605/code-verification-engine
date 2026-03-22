package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/verabase/code-verification-engine/internal/rules"
	"github.com/verabase/code-verification-engine/internal/schema"
)

func TestGenerateScanReport(t *testing.T) {
	input := ScanInput{
		RepoPath:  "/tmp/test-repo",
		RepoName:  "test-repo",
		Ref:       "main",
		CommitSHA: "abc123",
		Languages: []string{"go", "typescript"},
		FileCount: 42,
		Partial:   false,
		Analyzers: map[string]string{"go": "ok", "typescript": "ok"},
		Errors:    nil,
		Profile: "backend-api",
	}

	sr := GenerateScanReport(input)
	if sr.ScanSchemaVersion != schema.ScanSchemaVersion {
		t.Errorf("schema version = %s, want %s", sr.ScanSchemaVersion, schema.ScanSchemaVersion)
	}
	if sr.RepoName != "test-repo" {
		t.Errorf("repo name = %s, want test-repo", sr.RepoName)
	}
	if sr.ScannedAt == "" {
		t.Error("scanned_at should not be empty")
	}
}

func TestGenerateVerificationReport(t *testing.T) {
	input := ReportInput{
		Partial: false,
		Findings: []rules.Finding{
			{RuleID: "AUTH-001", Status: rules.StatusPass},
			{RuleID: "AUTH-002", Status: rules.StatusFail},
			{RuleID: "AUTH-003", Status: rules.StatusUnknown},
			{RuleID: "AUTH-004", Status: rules.StatusPass},
		},
		SkippedRules: []rules.SkippedRule{
			{RuleID: "TEST-001", Reason: "no matching languages"},
		},
	}

	vr := GenerateVerificationReport(input)
	if vr.ReportSchemaVersion != schema.ReportSchemaVersion {
		t.Errorf("schema version = %s, want %s", vr.ReportSchemaVersion, schema.ReportSchemaVersion)
	}
	if vr.Summary.Pass != 2 {
		t.Errorf("pass = %d, want 2", vr.Summary.Pass)
	}
	if vr.Summary.Fail != 1 {
		t.Errorf("fail = %d, want 1", vr.Summary.Fail)
	}
	if vr.Summary.Unknown != 1 {
		t.Errorf("unknown = %d, want 1", vr.Summary.Unknown)
	}
}

func TestGenerateMarkdown(t *testing.T) {
	scan := ScanReport{
		RepoName:  "test-repo",
		Ref:       "main",
		Languages: []string{"go"},
		Profile: "backend-api",
	}
	vr := VerificationReport{
		Summary: Summary{Pass: 1, Fail: 1, Unknown: 0},
		Findings: []rules.Finding{
			{
				RuleID:  "AUTH-001",
				Status:  rules.StatusPass,
				Message: "JWT auth found",
				Evidence: []rules.Evidence{
					{File: "auth.go", LineStart: 10, LineEnd: 20, Symbol: "VerifyJWT"},
				},
			},
		},
	}

	md := GenerateMarkdown(scan, vr)
	if !strings.Contains(md, "# Code Verification Report") {
		t.Error("missing report title")
	}
	if !strings.Contains(md, "test-repo") {
		t.Error("missing repo name")
	}
	if !strings.Contains(md, "AUTH-001") {
		t.Error("missing finding ID")
	}
	if !strings.Contains(md, "`auth.go:10-20`") {
		t.Error("missing evidence reference")
	}
}

func TestWriteOutputs(t *testing.T) {
	tmpDir := t.TempDir()
	outputDir := filepath.Join(tmpDir, "output")

	scan := ScanReport{
		ScanSchemaVersion: schema.ScanSchemaVersion,
		RepoName:          "test",
		Ref:               "HEAD",
	}
	vr := VerificationReport{
		ReportSchemaVersion: schema.ReportSchemaVersion,
		Summary:             Summary{Pass: 1},
		Findings: []rules.Finding{
			{RuleID: "T-1", Status: rules.StatusPass},
		},
	}

	err := WriteOutputs(outputDir, scan, vr, "both")
	if err != nil {
		t.Fatal(err)
	}

	// Check scan.json
	data, err := os.ReadFile(filepath.Join(outputDir, "scan.json"))
	if err != nil {
		t.Fatal("scan.json not written:", err)
	}
	var readScan ScanReport
	if err := json.Unmarshal(data, &readScan); err != nil {
		t.Fatal("invalid scan.json:", err)
	}
	if readScan.RepoName != "test" {
		t.Errorf("scan.json repo_name = %s, want test", readScan.RepoName)
	}

	// Check report.json
	data, err = os.ReadFile(filepath.Join(outputDir, "report.json"))
	if err != nil {
		t.Fatal("report.json not written:", err)
	}
	var readReport VerificationReport
	if err := json.Unmarshal(data, &readReport); err != nil {
		t.Fatal("invalid report.json:", err)
	}

	// Check report.md
	data, err = os.ReadFile(filepath.Join(outputDir, "report.md"))
	if err != nil {
		t.Fatal("report.md not written:", err)
	}
	if !strings.Contains(string(data), "Code Verification Report") {
		t.Error("report.md missing title")
	}
}

func TestWriteOutputsCleanupStaleFiles(t *testing.T) {
	tmpDir := t.TempDir()
	outputDir := filepath.Join(tmpDir, "output")
	os.MkdirAll(outputDir, 0o755)

	scan := ScanReport{ScanSchemaVersion: schema.ScanSchemaVersion}
	vr := VerificationReport{ReportSchemaVersion: schema.ReportSchemaVersion}

	// First write with "both" format
	err := WriteOutputs(outputDir, scan, vr, "both")
	if err != nil {
		t.Fatal(err)
	}
	// Verify all 3 files exist
	for _, name := range []string{"scan.json", "report.json", "report.md"} {
		if _, err := os.Stat(filepath.Join(outputDir, name)); err != nil {
			t.Fatalf("%s should exist after 'both' write: %v", name, err)
		}
	}

	// Now write with "json" format — report.md should be removed
	err = WriteOutputs(outputDir, scan, vr, "json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(outputDir, "scan.json")); err != nil {
		t.Fatal("scan.json should still exist")
	}
	if _, err := os.Stat(filepath.Join(outputDir, "report.json")); err != nil {
		t.Fatal("report.json should still exist")
	}
	if _, err := os.Stat(filepath.Join(outputDir, "report.md")); err == nil {
		t.Fatal("report.md should have been removed after switching to json format")
	}
}

func TestWriteOutputsCleanupStaleMdToJson(t *testing.T) {
	tmpDir := t.TempDir()
	outputDir := filepath.Join(tmpDir, "output")
	os.MkdirAll(outputDir, 0o755)

	scan := ScanReport{ScanSchemaVersion: schema.ScanSchemaVersion}
	vr := VerificationReport{ReportSchemaVersion: schema.ReportSchemaVersion}

	// First write with "md" format
	err := WriteOutputs(outputDir, scan, vr, "md")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(outputDir, "report.md")); err != nil {
		t.Fatal("report.md should exist after 'md' write")
	}

	// Switch to "json" format — report.md should be removed, report.json created
	err = WriteOutputs(outputDir, scan, vr, "json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(outputDir, "report.json")); err != nil {
		t.Fatal("report.json should exist after switching to json format")
	}
	if _, err := os.Stat(filepath.Join(outputDir, "report.md")); err == nil {
		t.Fatal("report.md should have been removed after switching to json format")
	}
}

func TestWriteOutputsOverwriteExisting(t *testing.T) {
	tmpDir := t.TempDir()
	outputDir := filepath.Join(tmpDir, "output")
	os.MkdirAll(outputDir, 0o755)

	// Write initial scan.json with repo name "old"
	scan1 := ScanReport{ScanSchemaVersion: schema.ScanSchemaVersion, RepoName: "old"}
	vr1 := VerificationReport{ReportSchemaVersion: schema.ReportSchemaVersion}
	WriteOutputs(outputDir, scan1, vr1, "json")

	// Overwrite with repo name "new"
	scan2 := ScanReport{ScanSchemaVersion: schema.ScanSchemaVersion, RepoName: "new"}
	vr2 := VerificationReport{ReportSchemaVersion: schema.ReportSchemaVersion}
	WriteOutputs(outputDir, scan2, vr2, "json")

	// Read and verify content is updated
	data, _ := os.ReadFile(filepath.Join(outputDir, "scan.json"))
	var readScan ScanReport
	json.Unmarshal(data, &readScan)
	if readScan.RepoName != "new" {
		t.Errorf("scan.json should have been overwritten, got repo_name=%s", readScan.RepoName)
	}
}

func TestWriteOutputsPreservesUnrelatedFiles(t *testing.T) {
	tmpDir := t.TempDir()
	outputDir := filepath.Join(tmpDir, "output")
	os.MkdirAll(outputDir, 0o755)

	// Create an unrelated file in the output directory
	os.WriteFile(filepath.Join(outputDir, "custom-notes.txt"), []byte("keep me"), 0o644)

	scan := ScanReport{ScanSchemaVersion: schema.ScanSchemaVersion}
	vr := VerificationReport{ReportSchemaVersion: schema.ReportSchemaVersion}
	WriteOutputs(outputDir, scan, vr, "both")

	// Verify unrelated file is preserved
	data, err := os.ReadFile(filepath.Join(outputDir, "custom-notes.txt"))
	if err != nil {
		t.Fatal("unrelated file should be preserved")
	}
	if string(data) != "keep me" {
		t.Error("unrelated file content should be unchanged")
	}
}

func TestWriteOutputsJSONOnly(t *testing.T) {
	tmpDir := t.TempDir()
	outputDir := filepath.Join(tmpDir, "output")

	scan := ScanReport{ScanSchemaVersion: schema.ScanSchemaVersion}
	vr := VerificationReport{ReportSchemaVersion: schema.ReportSchemaVersion}

	err := WriteOutputs(outputDir, scan, vr, "json")
	if err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat(filepath.Join(outputDir, "scan.json")); err != nil {
		t.Error("scan.json should always be written")
	}
	if _, err := os.Stat(filepath.Join(outputDir, "report.json")); err != nil {
		t.Error("report.json should be written for format=json")
	}
	if _, err := os.Stat(filepath.Join(outputDir, "report.md")); err == nil {
		t.Error("report.md should NOT be written for format=json")
	}
}

func TestWriteOutputsMDOnly(t *testing.T) {
	tmpDir := t.TempDir()
	outputDir := filepath.Join(tmpDir, "output")

	scan := ScanReport{ScanSchemaVersion: schema.ScanSchemaVersion}
	vr := VerificationReport{ReportSchemaVersion: schema.ReportSchemaVersion}

	err := WriteOutputs(outputDir, scan, vr, "md")
	if err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat(filepath.Join(outputDir, "scan.json")); err != nil {
		t.Error("scan.json should always be written")
	}
	if _, err := os.Stat(filepath.Join(outputDir, "report.md")); err != nil {
		t.Error("report.md should be written for format=md")
	}
	if _, err := os.Stat(filepath.Join(outputDir, "report.json")); err == nil {
		t.Error("report.json should NOT be written for format=md")
	}
}

func TestGenerateMarkdownPartialScan(t *testing.T) {
	scan := ScanReport{
		RepoName:  "test-repo",
		Ref:       "main",
		Languages: []string{"go"},
		Profile:   "backend-api",
	}
	vr := VerificationReport{
		Partial: true,
		Summary: Summary{Pass: 0, Fail: 0, Unknown: 1},
		Findings: []rules.Finding{
			{
				RuleID:         "AUTH-001",
				Status:         rules.StatusUnknown,
				Message:        "Could not verify",
				UnknownReasons: []string{"no analyzer", "missing data"},
			},
		},
	}

	md := GenerateMarkdown(scan, vr)
	if !strings.Contains(md, "Partial scan") {
		t.Error("missing partial scan indicator")
	}
	if !strings.Contains(md, "Unknown reasons:") {
		t.Error("missing unknown reasons section")
	}
	if !strings.Contains(md, "no analyzer") {
		t.Error("missing unknown reason text")
	}
}

func TestGenerateMarkdownWithSkippedRules(t *testing.T) {
	scan := ScanReport{
		RepoName:  "test-repo",
		Ref:       "main",
		Languages: []string{"go"},
		Profile:   "backend-api",
	}
	vr := VerificationReport{
		Summary:  Summary{Pass: 0, Fail: 0, Unknown: 0},
		Findings: []rules.Finding{},
		SkippedRules: []rules.SkippedRule{
			{RuleID: "TEST-001", Reason: "no matching languages"},
		},
	}

	md := GenerateMarkdown(scan, vr)
	if !strings.Contains(md, "Skipped Rules") {
		t.Error("missing skipped rules section")
	}
	if !strings.Contains(md, "TEST-001") {
		t.Error("missing skipped rule ID")
	}
}

func TestGenerateMarkdownEvidenceWithoutLineNumbers(t *testing.T) {
	scan := ScanReport{
		RepoName:  "test-repo",
		Ref:       "main",
		Languages: []string{"go"},
		Profile:   "backend-api",
	}
	vr := VerificationReport{
		Summary: Summary{Pass: 1},
		Findings: []rules.Finding{
			{
				RuleID:  "AUTH-001",
				Status:  rules.StatusPass,
				Message: "Found",
				Evidence: []rules.Evidence{
					{File: "auth.go", LineStart: 0, LineEnd: 0, Symbol: ""},
				},
			},
		},
	}

	md := GenerateMarkdown(scan, vr)
	if !strings.Contains(md, "`auth.go`") {
		t.Error("should have file-only evidence reference without line numbers")
	}
}

func TestGenerateMarkdownEvidenceWithSymbol(t *testing.T) {
	scan := ScanReport{
		RepoName:  "test-repo",
		Ref:       "main",
		Languages: []string{"go"},
		Profile:   "backend-api",
	}
	vr := VerificationReport{
		Summary: Summary{Pass: 1},
		Findings: []rules.Finding{
			{
				RuleID:  "AUTH-001",
				Status:  rules.StatusPass,
				Message: "Found",
				Evidence: []rules.Evidence{
					{File: "auth.go", LineStart: 10, LineEnd: 20, Symbol: "VerifyJWT"},
				},
			},
		},
	}

	md := GenerateMarkdown(scan, vr)
	if !strings.Contains(md, "`VerifyJWT`") {
		t.Error("should include symbol in evidence")
	}
}

func TestGenerateScanReportAllFields(t *testing.T) {
	input := ScanInput{
		RepoPath:  "/tmp/test-repo",
		RepoName:  "test-repo",
		Ref:       "v1.0.0",
		CommitSHA: "deadbeef",
		Languages: []string{"go", "python"},
		FileCount: 100,
		Partial:   true,
		Analyzers: map[string]string{"go": "ok", "python": "error"},
		Errors:    []string{"python analyzer failed"},
		Profile:   "backend-api",
	}

	sr := GenerateScanReport(input)
	if sr.RepoPath != "/tmp/test-repo" {
		t.Errorf("repo path = %s, want /tmp/test-repo", sr.RepoPath)
	}
	if sr.CommitSHA != "deadbeef" {
		t.Errorf("commit sha = %s, want deadbeef", sr.CommitSHA)
	}
	if !sr.Partial {
		t.Error("partial should be true")
	}
	if len(sr.Errors) != 1 {
		t.Errorf("errors count = %d, want 1", len(sr.Errors))
	}
	if sr.FileCount != 100 {
		t.Errorf("file count = %d, want 100", sr.FileCount)
	}
	if sr.Profile != "backend-api" {
		t.Errorf("profile = %s, want backend-api", sr.Profile)
	}
}

func TestGenerateVerificationReportWithSkippedAndErrors(t *testing.T) {
	input := ReportInput{
		Partial: true,
		Findings: []rules.Finding{
			{RuleID: "R-1", Status: rules.StatusPass},
		},
		SkippedRules: []rules.SkippedRule{
			{RuleID: "R-2", Reason: "no language"},
		},
		Errors: []string{"some error"},
	}

	vr := GenerateVerificationReport(input)
	if !vr.Partial {
		t.Error("partial should be true")
	}
	if len(vr.SkippedRules) != 1 {
		t.Errorf("skipped rules = %d, want 1", len(vr.SkippedRules))
	}
	if len(vr.Errors) != 1 {
		t.Errorf("errors = %d, want 1", len(vr.Errors))
	}
}

func TestGenerateVerificationReportEmptyFindings(t *testing.T) {
	input := ReportInput{
		Findings: []rules.Finding{},
	}
	vr := GenerateVerificationReport(input)
	if vr.Summary.Pass != 0 || vr.Summary.Fail != 0 || vr.Summary.Unknown != 0 {
		t.Errorf("summary should be all zeros for empty findings")
	}
}

func TestWriteOutputsInvalidDir(t *testing.T) {
	// Try writing to a path under a file (not a directory)
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "not-a-dir")
	os.WriteFile(filePath, []byte("x"), 0o644)

	scan := ScanReport{ScanSchemaVersion: schema.ScanSchemaVersion}
	vr := VerificationReport{ReportSchemaVersion: schema.ReportSchemaVersion}

	err := WriteOutputs(filepath.Join(filePath, "subdir"), scan, vr, "json")
	if err == nil {
		t.Fatal("expected error when output dir parent is a file")
	}
}
