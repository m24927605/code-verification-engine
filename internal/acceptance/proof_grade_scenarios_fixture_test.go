package acceptance

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestProofGradeScenarioFixtureCorpus(t *testing.T) {
	t.Parallel()

	base := filepath.Join("..", "..", "testdata", "acceptance", "proof_grade_scenarios")
	fixtures := map[string][]string{
		"hiring-proof-backed":          {"README.md", "scenario_golden.json", filepath.Join("src", "auth.ts"), filepath.Join("src", "routes.ts"), filepath.Join("test", "auth.test.ts")},
		"hiring-overclaim-downgrade":   {"README.md", "scenario_golden.json", filepath.Join("src", "server.ts")},
		"outsource-pass":               {"README.md", "scenario_golden.json", filepath.Join("src", "auth.ts"), filepath.Join("src", "routes.ts"), filepath.Join("test", "auth.test.ts")},
		"outsource-fail":               {"README.md", "scenario_golden.json", filepath.Join("src", "controller.ts"), filepath.Join("src", "db.ts")},
		"outsource-unknown-incomplete": {"README.md", "scenario_golden.json", filepath.Join("backend", "routes.ts"), filepath.Join("backend", "auth.ts"), filepath.Join("docs", "scan-boundary.md"), filepath.Join("excluded", "controller.ts")},
		"pm-engineering-implemented":   {"README.md", "scenario_golden.json", filepath.Join("src", "controller.ts"), filepath.Join("src", "service.ts"), filepath.Join("src", "repository.ts"), filepath.Join("test", "service.test.ts")},
		"pm-runtime-required":          {"README.md", "scenario_golden.json", filepath.Join("src", "feature.ts"), filepath.Join("docs", "runtime-contract.md"), "service.go"},
		"contradiction":                {"README.md", "scenario_golden.json", filepath.Join("src", "routes.ts"), filepath.Join("src", "auth.ts")},
		"analyzer-degradation":         {"README.md", "scenario_golden.json", filepath.Join("src", "partial.py"), filepath.Join("src", "generated.ts")},
		"unsupported-framework":        {"README.md", "scenario_golden.json", filepath.Join("src", "main.rs")},
	}

	for fixture, files := range fixtures {
		fixture := fixture
		files := files
		t.Run(fixture, func(t *testing.T) {
			t.Parallel()
			dir := filepath.Join(base, fixture)
			if st, err := os.Stat(dir); err != nil || !st.IsDir() {
				t.Fatalf("fixture dir %q missing: %v", dir, err)
			}
			for _, rel := range files {
				path := filepath.Join(dir, rel)
				if _, err := os.Stat(path); err != nil {
					t.Fatalf("missing fixture file %q: %v", path, err)
				}
			}
		})
	}
}

func TestProofGradeScenarioFixtureRetiredDirsAbsent(t *testing.T) {
	t.Parallel()

	base := filepath.Join("..", "..", "testdata", "acceptance", "proof_grade_scenarios")
	retired := []string{
		"outsource-pass-auth-binding",
		"outsource-fail-secret",
		"outsource-unknown-incomplete-negative",
		"pm-runtime-required-feature-behavior",
	}
	for _, name := range retired {
		if _, err := os.Stat(filepath.Join(base, name)); err == nil {
			t.Fatalf("retired fixture dir %q must not exist", name)
		}
	}
}

func TestProofGradeScenarioFixtureMarkers(t *testing.T) {
	t.Parallel()

	cases := []struct {
		path    string
		markers []string
	}{
		{
			path:    filepath.Join("..", "..", "testdata", "acceptance", "proof_grade_scenarios", "hiring-overclaim-downgrade", "README.md"),
			markers: []string{"overclaims", "not backed"},
		},
		{
			path:    filepath.Join("..", "..", "testdata", "acceptance", "proof_grade_scenarios", "outsource-fail", "src", "db.ts"),
			markers: []string{"hardcoded-secret-value"},
		},
		{
			path:    filepath.Join("..", "..", "testdata", "acceptance", "proof_grade_scenarios", "pm-runtime-required", "docs", "runtime-contract.md"),
			markers: []string{"requires live integration"},
		},
		{
			path:    filepath.Join("..", "..", "testdata", "acceptance", "proof_grade_scenarios", "unsupported-framework", "src", "main.rs"),
			markers: []string{"unsupported framework"},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(filepath.Base(filepath.Dir(tc.path)), func(t *testing.T) {
			t.Parallel()
			data, err := os.ReadFile(tc.path)
			if err != nil {
				t.Fatalf("ReadFile(%q): %v", tc.path, err)
			}
			text := strings.ToLower(string(data))
			for _, marker := range tc.markers {
				if !strings.Contains(text, strings.ToLower(marker)) {
					t.Fatalf("expected %q to contain marker %q", tc.path, marker)
				}
			}
		})
	}
}
