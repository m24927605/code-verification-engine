package acceptance

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestProofGradeFixtureLayoutExists(t *testing.T) {
	t.Parallel()

	root := filepath.Join("..", "..", "testdata", "acceptance", "proof_grade_scenarios")
	requiredDirs := []string{
		"hiring-proof-backed",
		"hiring-overclaim-downgrade",
		"outsource-pass",
		"outsource-fail",
		"outsource-unknown-incomplete",
		"pm-engineering-implemented",
		"pm-runtime-required",
		"contradiction",
		"analyzer-degradation",
		"unsupported-framework",
	}
	for _, dir := range requiredDirs {
		info, err := os.Stat(filepath.Join(root, dir))
		if err != nil {
			t.Fatalf("fixture dir %q missing: %v", dir, err)
		}
		if !info.IsDir() {
			t.Fatalf("fixture path %q is not a directory", dir)
		}
		if _, err := os.Stat(filepath.Join(root, dir, "scenario_golden.json")); err != nil {
			t.Fatalf("fixture %q missing scenario_golden.json: %v", dir, err)
		}
	}
}

func TestProofGradeBenchmarkLayoutExists(t *testing.T) {
	t.Parallel()

	root := filepath.Join("..", "..", "testdata", "benchmark", "proof-grade")
	requiredFamilies := []string{
		"SEC-001",
		"TEST-001",
		"AUTH-002",
		"ARCH-001",
		"CONFIG",
	}
	requiredScenarios := []string{
		"true-positive",
		"opposite-outcome",
		"false-positive-guard",
		"degraded-or-incomplete",
		"unsupported",
	}
	for _, family := range requiredFamilies {
		familyDir := filepath.Join(root, family)
		info, err := os.Stat(familyDir)
		if err != nil {
			t.Fatalf("benchmark dir %q missing: %v", family, err)
		}
		if !info.IsDir() {
			t.Fatalf("benchmark path %q is not a directory", family)
		}
		entries, err := os.ReadDir(familyDir)
		if err != nil {
			t.Fatalf("ReadDir(%q): %v", familyDir, err)
		}
		for _, entry := range entries {
			if !entry.IsDir() {
				t.Fatalf("benchmark family %q must not contain root-level file %q", family, entry.Name())
			}
		}
		for _, scenario := range requiredScenarios {
			scenarioDir := filepath.Join(root, family, scenario)
			if st, err := os.Stat(scenarioDir); err != nil || !st.IsDir() {
				t.Fatalf("benchmark scenario %q/%q missing: %v", family, scenario, err)
			}
			if _, err := os.Stat(filepath.Join(scenarioDir, "golden.json")); err != nil {
				t.Fatalf("benchmark scenario %q/%q missing golden.json: %v", family, scenario, err)
			}
			data, err := os.ReadFile(filepath.Join(scenarioDir, "golden.json"))
			if err != nil {
				t.Fatalf("ReadFile(%q/%q golden): %v", family, scenario, err)
			}
			var golden struct {
				Family         string `json:"family"`
				Scenario       string `json:"scenario"`
				ExpectedStatus string `json:"expected_status"`
				TrustIntent    string `json:"trust_intent"`
			}
			if err := json.Unmarshal(data, &golden); err != nil {
				t.Fatalf("invalid benchmark golden for %q/%q: %v", family, scenario, err)
			}
			if golden.Family == "" || golden.Scenario == "" || golden.ExpectedStatus == "" || golden.TrustIntent == "" {
				t.Fatalf("benchmark golden for %q/%q missing required fields: %#v", family, scenario, golden)
			}
		}
	}
}
