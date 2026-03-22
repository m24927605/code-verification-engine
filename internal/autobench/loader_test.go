package autobench

import (
	"path/filepath"
	"testing"
)

func TestLoadDataset(t *testing.T) {
	moduleRoot := filepath.Join("..", "..")
	manifestPath := filepath.Join(moduleRoot, "testdata", "autobench", "datasets", "autocal-v1", "manifest.json")

	manifest, expectedByCase, err := LoadDataset(moduleRoot, manifestPath)
	if err != nil {
		t.Fatal(err)
	}

	if manifest.DatasetID != "autocal-v1" {
		t.Fatalf("dataset_id = %q, want autocal-v1", manifest.DatasetID)
	}
	if manifest.Mode != ModeFrozen {
		t.Fatalf("mode = %q, want %q", manifest.Mode, ModeFrozen)
	}
	if len(manifest.Suites) != 4 {
		t.Fatalf("suite count = %d, want 4", len(manifest.Suites))
	}
	if len(expectedByCase) != 5 {
		t.Fatalf("expected case count = %d, want 5", len(expectedByCase))
	}

	tsCase, ok := expectedByCase["ts-express-auth-fullstack"]
	if !ok {
		t.Fatal("ts-express-auth-fullstack expectation missing")
	}
	if tsCase.ClaimSet != "fullstack-security" {
		t.Fatalf("claim_set = %q, want fullstack-security", tsCase.ClaimSet)
	}
	if len(tsCase.Expectations) != 4 {
		t.Fatalf("expectation count = %d, want 4", len(tsCase.Expectations))
	}
}
