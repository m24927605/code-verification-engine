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

func TestReportJSONContainsTrustClass(t *testing.T) {
	vr := VerificationReport{
		ReportSchemaVersion: schema.ReportSchemaVersion,
		Summary:             Summary{Fail: 1},
		Findings: []rules.Finding{
			{
				RuleID:            "SEC-AUTH-001",
				Status:            rules.StatusFail,
				Confidence:        rules.ConfidenceMedium,
				VerificationLevel: rules.VerificationStrongInference,
				TrustClass:        rules.TrustAdvisory,
				Message:           "test",
			},
		},
	}
	data, err := json.Marshal(vr)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"trust_class":"advisory"`) {
		t.Error("report.json should contain trust_class field")
	}
}

func TestMarkdownContainsTrustClass(t *testing.T) {
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
				RuleID:     "SEC-SECRET-001",
				Status:     rules.StatusPass,
				Message:    "No hardcoded secrets",
				TrustClass: rules.TrustMachineTrusted,
			},
		},
	}
	md := GenerateMarkdown(scan, vr)
	if !strings.Contains(md, "Trust Class: machine_trusted") {
		t.Error("report.md should contain Trust Class line")
	}
}

func TestWriteOutputsDefaultFormat(t *testing.T) {
	// Test with empty format string - should only write scan.json
	tmpDir := t.TempDir()
	outputDir := filepath.Join(tmpDir, "output")

	scan := ScanReport{ScanSchemaVersion: schema.ScanSchemaVersion}
	vr := VerificationReport{
		ReportSchemaVersion: schema.ReportSchemaVersion,
		Summary:             Summary{Pass: 1},
		Findings: []rules.Finding{
			{
				RuleID:     "T-1",
				Status:     rules.StatusPass,
				TrustClass: rules.TrustMachineTrusted,
			},
		},
	}

	err := WriteOutputs(outputDir, scan, vr, "")
	if err != nil {
		t.Fatal(err)
	}

	// scan.json should always be written
	if _, err := os.Stat(filepath.Join(outputDir, "scan.json")); err != nil {
		t.Error("scan.json should be written regardless of format")
	}
	// Neither report.json nor report.md should be written with empty format
	if _, err := os.Stat(filepath.Join(outputDir, "report.json")); err == nil {
		t.Error("report.json should NOT be written for empty format")
	}
	if _, err := os.Stat(filepath.Join(outputDir, "report.md")); err == nil {
		t.Error("report.md should NOT be written for empty format")
	}
}

func TestWriteOutputsScanJSONValid(t *testing.T) {
	tmpDir := t.TempDir()
	outputDir := filepath.Join(tmpDir, "output")

	scan := ScanReport{
		ScanSchemaVersion: schema.ScanSchemaVersion,
		RepoName:          "validate-json-test",
		Ref:               "main",
		Languages:         []string{"go"},
	}
	vr := VerificationReport{
		ReportSchemaVersion: schema.ReportSchemaVersion,
		Summary:             Summary{Pass: 2, Fail: 1},
		Findings: []rules.Finding{
			{
				RuleID:     "R-1",
				Status:     rules.StatusPass,
				TrustClass: rules.TrustMachineTrusted,
			},
			{
				RuleID:     "R-2",
				Status:     rules.StatusPass,
				TrustClass: rules.TrustAdvisory,
			},
			{
				RuleID:     "R-3",
				Status:     rules.StatusFail,
				TrustClass: rules.TrustHumanOrRuntimeRequired,
			},
		},
	}

	err := WriteOutputs(outputDir, scan, vr, "json")
	if err != nil {
		t.Fatal(err)
	}

	// Verify report.json is valid and contains all findings
	data, err := os.ReadFile(filepath.Join(outputDir, "report.json"))
	if err != nil {
		t.Fatal(err)
	}
	var readReport VerificationReport
	if err := json.Unmarshal(data, &readReport); err != nil {
		t.Fatalf("invalid report.json: %v", err)
	}
	if len(readReport.Findings) != 3 {
		t.Errorf("expected 3 findings, got %d", len(readReport.Findings))
	}
}

func TestWriteJSONMarshalError(t *testing.T) {
	// writeJSON with an unmarshalable type (channel) should return an error
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "test.json")

	err := writeJSON(path, make(chan int))
	if err == nil {
		t.Fatal("expected error for unmarshalable type")
	}
}

func TestWriteJSONFileError(t *testing.T) {
	// writeJSON to an invalid path should return an error
	err := writeJSON("/nonexistent/dir/test.json", map[string]string{"key": "value"})
	if err == nil {
		t.Fatal("expected error for invalid path")
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

func TestWriteOutputsStagingDirFailure(t *testing.T) {
	tmpDir := t.TempDir()
	outputDir := filepath.Join(tmpDir, "output")
	os.MkdirAll(outputDir, 0o755)

	// Make outputDir read-only so MkdirTemp fails
	os.Chmod(outputDir, 0o444)
	defer os.Chmod(outputDir, 0o755)

	scan := ScanReport{ScanSchemaVersion: schema.ScanSchemaVersion}
	vr := VerificationReport{ReportSchemaVersion: schema.ReportSchemaVersion}

	err := WriteOutputs(outputDir, scan, vr, "json")
	if err == nil {
		t.Fatal("expected error when staging dir cannot be created")
	}
}

func TestWriteOutputsRenameError(t *testing.T) {
	// Test that WriteOutputs handles rename errors gracefully.
	// We create a valid output directory but make it read-only after staging.
	// Since staging happens inside WriteOutputs, we intercept by creating
	// a pre-existing read-only file at the destination.
	tmpDir := t.TempDir()
	outputDir := filepath.Join(tmpDir, "output")
	os.MkdirAll(outputDir, 0o755)

	// Create a subdirectory (not a file) named scan.json to block the rename
	scanDir := filepath.Join(outputDir, "scan.json")
	os.MkdirAll(filepath.Join(scanDir, "blocker"), 0o755)

	scan := ScanReport{ScanSchemaVersion: schema.ScanSchemaVersion}
	vr := VerificationReport{ReportSchemaVersion: schema.ReportSchemaVersion}

	err := WriteOutputs(outputDir, scan, vr, "json")
	// On some systems, renaming a file over a non-empty directory fails
	if err != nil {
		// Expected error - the rename should fail
		if !strings.Contains(err.Error(), "rename") {
			t.Fatalf("expected rename error, got: %v", err)
		}
	}
	// Clean up the blocker
	os.RemoveAll(scanDir)
}

func TestWriteOutputsMdFormat(t *testing.T) {
	tmpDir := t.TempDir()
	outputDir := filepath.Join(tmpDir, "output")

	scan := ScanReport{
		ScanSchemaVersion: schema.ScanSchemaVersion,
		RepoName:          "md-test",
		Ref:               "main",
		Languages:         []string{"go"},
		Profile:           "backend-api",
	}
	vr := VerificationReport{
		ReportSchemaVersion: schema.ReportSchemaVersion,
		Summary:             Summary{Pass: 1, Fail: 1},
		Findings: []rules.Finding{
			{
				RuleID:     "R-1",
				Status:     rules.StatusPass,
				Message:    "All good",
				TrustClass: rules.TrustMachineTrusted,
			},
			{
				RuleID:     "R-2",
				Status:     rules.StatusFail,
				Message:    "Issue found",
				TrustClass: rules.TrustAdvisory,
				Evidence: []rules.Evidence{
					{File: "bad.go", LineStart: 5, LineEnd: 10, Symbol: "badFunc"},
				},
			},
		},
	}

	err := WriteOutputs(outputDir, scan, vr, "md")
	if err != nil {
		t.Fatal(err)
	}

	// Read and verify markdown
	data, err := os.ReadFile(filepath.Join(outputDir, "report.md"))
	if err != nil {
		t.Fatal("report.md should exist:", err)
	}
	md := string(data)
	if !strings.Contains(md, "md-test") {
		t.Error("markdown should contain repo name")
	}
	if !strings.Contains(md, "R-2") {
		t.Error("markdown should contain finding R-2")
	}
}

func TestGenerateVerificationReportTrustSummary(t *testing.T) {
	input := ReportInput{
		Findings: []rules.Finding{
			{RuleID: "R-1", Status: rules.StatusPass, TrustClass: rules.TrustMachineTrusted},
			{RuleID: "R-2", Status: rules.StatusPass, TrustClass: rules.TrustAdvisory},
			{RuleID: "R-3", Status: rules.StatusFail, TrustClass: rules.TrustAdvisory},
			{RuleID: "R-4", Status: rules.StatusUnknown, TrustClass: rules.TrustHumanOrRuntimeRequired},
		},
	}
	vr := GenerateVerificationReport(input)
	if vr.TrustSummary.MachineTrusted != 1 {
		t.Errorf("expected 1 machine_trusted, got %d", vr.TrustSummary.MachineTrusted)
	}
	if vr.TrustSummary.Advisory != 2 {
		t.Errorf("expected 2 advisory, got %d", vr.TrustSummary.Advisory)
	}
	if vr.TrustSummary.HumanOrRuntimeRequired != 1 {
		t.Errorf("expected 1 human_or_runtime_required, got %d", vr.TrustSummary.HumanOrRuntimeRequired)
	}
}

func TestReportJSONContainsTrustSummary(t *testing.T) {
	vr := VerificationReport{
		ReportSchemaVersion: schema.ReportSchemaVersion,
		Summary:             Summary{Pass: 1},
		TrustSummary: TrustSummary{
			MachineTrusted: 1,
			Advisory:       0,
		},
		Findings: []rules.Finding{
			{RuleID: "R-1", Status: rules.StatusPass, TrustClass: rules.TrustMachineTrusted},
		},
	}
	data, err := json.Marshal(vr)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"trust_summary"`) {
		t.Error("report.json should contain trust_summary field")
	}
	if !strings.Contains(string(data), `"machine_trusted":1`) {
		t.Error("trust_summary should contain machine_trusted count")
	}
}

func TestMarkdownContainsTrustSummary(t *testing.T) {
	scan := ScanReport{
		RepoName:  "test-repo",
		Ref:       "main",
		Languages: []string{"go"},
		Profile:   "backend-api",
	}
	vr := VerificationReport{
		Summary: Summary{Pass: 1},
		TrustSummary: TrustSummary{
			MachineTrusted: 1,
			Advisory:       2,
		},
		Findings: []rules.Finding{
			{RuleID: "R-1", Status: rules.StatusPass, TrustClass: rules.TrustMachineTrusted},
		},
	}
	md := GenerateMarkdown(scan, vr)
	if !strings.Contains(md, "Trust Summary") {
		t.Error("markdown should contain Trust Summary section")
	}
	if !strings.Contains(md, "Machine Trusted: 1") {
		t.Error("markdown should contain machine trusted count")
	}
	if !strings.Contains(md, "Advisory: 2") {
		t.Error("markdown should contain advisory count")
	}
}

func TestWriteOutputsBothFormatWithFindings(t *testing.T) {
	tmpDir := t.TempDir()
	outputDir := filepath.Join(tmpDir, "output")

	scan := ScanReport{ScanSchemaVersion: schema.ScanSchemaVersion}
	vr := VerificationReport{
		ReportSchemaVersion: schema.ReportSchemaVersion,
		Summary:             Summary{Pass: 1},
		Findings: []rules.Finding{
			{
				RuleID:     "T-1",
				Status:     rules.StatusPass,
				TrustClass: rules.TrustMachineTrusted,
			},
		},
	}

	err := WriteOutputs(outputDir, scan, vr, "both")
	if err != nil {
		t.Fatal(err)
	}

	// Verify all 3 files
	for _, name := range []string{"scan.json", "report.json", "report.md"} {
		if _, err := os.Stat(filepath.Join(outputDir, name)); err != nil {
			t.Fatalf("%s should exist: %v", name, err)
		}
	}

	// Verify scan.json is valid JSON
	data, _ := os.ReadFile(filepath.Join(outputDir, "scan.json"))
	var s ScanReport
	if err := json.Unmarshal(data, &s); err != nil {
		t.Fatalf("scan.json invalid: %v", err)
	}

	// Verify report.json is valid JSON
	data, _ = os.ReadFile(filepath.Join(outputDir, "report.json"))
	var r VerificationReport
	if err := json.Unmarshal(data, &r); err != nil {
		t.Fatalf("report.json invalid: %v", err)
	}
}

// --- CapabilitySummary tests ---

func TestCapabilitySummary_PopulatedFromCapabilitySignals(t *testing.T) {
	// CapabilitySummary must be derived from actual capability signals
	// (unknown_reasons), NOT from trust_class.
	input := ReportInput{
		Findings: []rules.Finding{
			// No capability annotations → fully_supported
			{RuleID: "R-1", Status: rules.StatusPass, TrustClass: rules.TrustMachineTrusted},
			// Has capability_partial → partial
			{RuleID: "R-2", Status: rules.StatusPass, TrustClass: rules.TrustAdvisory,
				UnknownReasons: []string{rules.UnknownCapabilityPartial}},
			// Has matcher_limitation → partial
			{RuleID: "R-3", Status: rules.StatusFail, TrustClass: rules.TrustAdvisory,
				UnknownReasons: []string{rules.UnknownMatcherLimitation}},
			// Has capability_unsupported → unsupported (also has skipped-rule entry)
			{RuleID: "R-4", Status: rules.StatusUnknown, TrustClass: rules.TrustAdvisory,
				UnknownReasons: []string{rules.UnknownCapabilityUnsupported}},
		},
		SkippedRules: []rules.SkippedRule{
			// R-4 already counted as unsupported via its finding — must NOT double-count
			{RuleID: "R-4", Reason: "capability_unsupported: target X"},
			// R-5 has no corresponding finding but is a language mismatch, not capability
			{RuleID: "R-5", Reason: "no matching languages in repository"},
		},
	}
	vr := GenerateVerificationReport(input)
	if vr.CapabilitySummary.FullySupported != 1 {
		t.Errorf("expected 1 fully_supported (R-1), got %d", vr.CapabilitySummary.FullySupported)
	}
	if vr.CapabilitySummary.Partial != 2 {
		t.Errorf("expected 2 partial (R-2 + R-3), got %d", vr.CapabilitySummary.Partial)
	}
	// R-4 counted once via finding, R-4 skipped-rule NOT double-counted,
	// R-5 is language mismatch NOT counted as capability-unsupported
	if vr.CapabilitySummary.Unsupported != 1 {
		t.Errorf("expected 1 unsupported (R-4 only, no double-count), got %d", vr.CapabilitySummary.Unsupported)
	}
	if vr.CapabilitySummary.Degraded {
		t.Error("expected degraded=false when input.Degraded is false")
	}
}

func TestCapabilitySummary_DegradedFromInput(t *testing.T) {
	input := ReportInput{
		Findings: []rules.Finding{
			{RuleID: "R-1", Status: rules.StatusPass, TrustClass: rules.TrustMachineTrusted},
		},
		Degraded: true,
	}
	vr := GenerateVerificationReport(input)
	if !vr.CapabilitySummary.Degraded {
		t.Error("expected degraded=true when input.Degraded is true")
	}
}

func TestCapabilitySummary_EmptyFindings(t *testing.T) {
	input := ReportInput{Findings: []rules.Finding{}}
	vr := GenerateVerificationReport(input)
	if vr.CapabilitySummary.FullySupported != 0 || vr.CapabilitySummary.Partial != 0 || vr.CapabilitySummary.Unsupported != 0 {
		t.Error("expected all zeros for empty findings")
	}
}

func TestCapabilitySummary_InJSON(t *testing.T) {
	vr := VerificationReport{
		ReportSchemaVersion: schema.ReportSchemaVersion,
		CapabilitySummary: CapabilitySummary{
			FullySupported: 3,
			Partial:        2,
			Unsupported:    1,
			Degraded:       true,
		},
	}
	data, err := json.Marshal(vr)
	if err != nil {
		t.Fatal(err)
	}
	s := string(data)
	if !strings.Contains(s, `"capability_summary"`) {
		t.Error("JSON should contain capability_summary field")
	}
	if !strings.Contains(s, `"fully_supported":3`) {
		t.Error("JSON should contain fully_supported count")
	}
	if !strings.Contains(s, `"degraded":true`) {
		t.Error("JSON should contain degraded flag")
	}
}

func TestCapabilitySummary_InMarkdown(t *testing.T) {
	scan := ScanReport{
		RepoName:  "test-repo",
		Ref:       "main",
		Languages: []string{"go"},
		Profile:   "backend-api",
	}
	vr := VerificationReport{
		Summary: Summary{Pass: 1},
		CapabilitySummary: CapabilitySummary{
			FullySupported: 1,
			Partial:        2,
			Unsupported:    0,
			Degraded:       false,
		},
		Findings: []rules.Finding{
			{RuleID: "R-1", Status: rules.StatusPass, TrustClass: rules.TrustMachineTrusted},
		},
	}
	md := GenerateMarkdown(scan, vr)
	if !strings.Contains(md, "Capability Summary") {
		t.Error("markdown should contain Capability Summary section")
	}
	if !strings.Contains(md, "Fully Supported: 1") {
		t.Error("markdown should contain fully supported count")
	}
}

// --- Trust warning tests in markdown ---

func TestMarkdownTrustWarnings_AdvisoryFindings(t *testing.T) {
	scan := ScanReport{
		RepoName:  "test-repo",
		Ref:       "main",
		Languages: []string{"go"},
		Profile:   "backend-api",
	}
	vr := VerificationReport{
		Summary:      Summary{Pass: 1},
		TrustSummary: TrustSummary{Advisory: 2},
		Findings: []rules.Finding{
			{RuleID: "R-1", Status: rules.StatusPass, TrustClass: rules.TrustAdvisory},
		},
	}
	md := GenerateMarkdown(scan, vr)
	if !strings.Contains(md, "Trust Warnings") {
		t.Error("markdown should contain Trust Warnings section when advisory findings exist")
	}
	if !strings.Contains(md, "Advisory findings present") {
		t.Error("markdown should warn about advisory findings")
	}
}

func TestMarkdownTrustWarnings_HumanRequired(t *testing.T) {
	scan := ScanReport{
		RepoName:  "test-repo",
		Ref:       "main",
		Languages: []string{"go"},
		Profile:   "backend-api",
	}
	vr := VerificationReport{
		Summary:      Summary{Pass: 1},
		TrustSummary: TrustSummary{HumanOrRuntimeRequired: 1},
		Findings: []rules.Finding{
			{RuleID: "R-1", Status: rules.StatusPass, TrustClass: rules.TrustHumanOrRuntimeRequired},
		},
	}
	md := GenerateMarkdown(scan, vr)
	if !strings.Contains(md, "Human/runtime review required") {
		t.Error("markdown should warn about human-required findings")
	}
}

func TestMarkdownTrustWarnings_NoWarningsForMachineTrustedOnly(t *testing.T) {
	scan := ScanReport{
		RepoName:  "test-repo",
		Ref:       "main",
		Languages: []string{"go"},
		Profile:   "backend-api",
	}
	vr := VerificationReport{
		Summary:      Summary{Pass: 1},
		TrustSummary: TrustSummary{MachineTrusted: 1},
		Findings: []rules.Finding{
			{RuleID: "R-1", Status: rules.StatusPass, TrustClass: rules.TrustMachineTrusted},
		},
	}
	md := GenerateMarkdown(scan, vr)
	if strings.Contains(md, "Trust Warnings") {
		t.Error("markdown should NOT contain Trust Warnings when only machine_trusted findings")
	}
}

func TestMarkdownDegradedNote(t *testing.T) {
	scan := ScanReport{
		RepoName:  "test-repo",
		Ref:       "main",
		Languages: []string{"go"},
		Profile:   "backend-api",
	}
	vr := VerificationReport{
		Summary:           Summary{Pass: 1},
		CapabilitySummary: CapabilitySummary{Degraded: true},
		Findings: []rules.Finding{
			{RuleID: "R-1", Status: rules.StatusPass, TrustClass: rules.TrustMachineTrusted},
		},
	}
	md := GenerateMarkdown(scan, vr)
	if !strings.Contains(md, "degraded mode") {
		t.Error("markdown should note degraded analysis")
	}
}

// --- Skipped rules not in findings contract test ---

func TestSkippedRules_NotInFindings(t *testing.T) {
	input := ReportInput{
		Findings: []rules.Finding{
			{RuleID: "R-1", Status: rules.StatusPass, TrustClass: rules.TrustMachineTrusted},
			{RuleID: "R-2", Status: rules.StatusFail, TrustClass: rules.TrustAdvisory},
		},
		SkippedRules: []rules.SkippedRule{
			{RuleID: "R-SKIP-1", Reason: "no matching language"},
			{RuleID: "R-SKIP-2", Reason: "unsupported target"},
		},
	}
	vr := GenerateVerificationReport(input)

	// Build set of skipped rule IDs
	skippedIDs := make(map[string]bool)
	for _, sr := range vr.SkippedRules {
		skippedIDs[sr.RuleID] = true
	}

	// Verify none of the skipped rule IDs appear in findings
	for _, f := range vr.Findings {
		if skippedIDs[f.RuleID] {
			t.Errorf("skipped rule %s should NOT appear in findings", f.RuleID)
		}
	}

	// Also verify the converse: finding IDs are not in skipped
	findingIDs := make(map[string]bool)
	for _, f := range vr.Findings {
		findingIDs[f.RuleID] = true
	}
	for _, sr := range vr.SkippedRules {
		if findingIDs[sr.RuleID] {
			t.Errorf("finding rule %s should NOT appear in skipped rules", sr.RuleID)
		}
	}
}
