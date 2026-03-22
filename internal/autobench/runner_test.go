package autobench

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestRunDatasetSingleCase(t *testing.T) {
	moduleRoot := filepath.Join("..", "..")
	manifestPath := filepath.Join(moduleRoot, "testdata", "autobench", "datasets", "autocal-v1", "manifest.json")
	outputRoot := t.TempDir()

	result, err := RunDataset(context.Background(), RunConfig{
		ModuleRoot:   moduleRoot,
		ManifestPath: manifestPath,
		OutputRoot:   outputRoot,
		SuiteIDs:     []string{"frontend-js"},
		CaseIDs:      []string{"js-node-no-auth-frontend"},
	})
	if err != nil {
		t.Fatal(err)
	}

	if result.DatasetID != "autocal-v1" {
		t.Fatalf("dataset_id = %q, want autocal-v1", result.DatasetID)
	}
	if len(result.Suites) != 1 {
		t.Fatalf("suite count = %d, want 1", len(result.Suites))
	}
	if result.Summary.Cases != 1 {
		t.Fatalf("case count = %d, want 1", result.Summary.Cases)
	}

	caseResult := result.Suites[0].Cases[0]
	if caseResult.ID != "js-node-no-auth-frontend" {
		t.Fatalf("case id = %q, want js-node-no-auth-frontend", caseResult.ID)
	}
	if caseResult.OutputDir == "" {
		t.Fatal("case output dir should not be empty")
	}
	if _, err := os.Stat(filepath.Join(caseResult.OutputDir, "actual", "report.json")); err != nil {
		t.Fatalf("actual report.json missing: %v", err)
	}
	if _, err := os.Stat(filepath.Join(caseResult.OutputDir, "adjudication.json")); err != nil {
		t.Fatalf("adjudication.json missing: %v", err)
	}
	if _, err := os.Stat(filepath.Join(caseResult.OutputDir, "discrepancy.md")); err != nil {
		t.Fatalf("discrepancy.md missing: %v", err)
	}
	if _, err := os.Stat(filepath.Join(outputRoot, "dataset-run.json")); err != nil {
		t.Fatalf("dataset-run.json missing: %v", err)
	}
}
