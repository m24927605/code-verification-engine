package acceptance

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestProofGradeScenarioGoldenHarness(t *testing.T) {
	t.Parallel()

	root := filepath.Join("..", "..", "testdata", "acceptance", "proof_grade_scenarios")
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("ReadDir(%q): %v", root, err)
	}

	ran := 0
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		fixtureDir := filepath.Join(root, entry.Name())
		if _, err := os.Stat(filepath.Join(fixtureDir, "scenario_golden.json")); err != nil {
			continue
		}
		ran++
		t.Run(entry.Name(), func(t *testing.T) {
			golden, err := loadScenarioFixtureGolden(fixtureDir)
			if err != nil {
				t.Fatalf("loadScenarioFixtureGolden(%q): %v", fixtureDir, err)
			}
			result, err := runScenarioFixture(context.Background(), fixtureDir, golden)
			if err != nil {
				t.Fatalf("runScenarioFixture(%q): %v", fixtureDir, err)
			}
			if err := assertScenarioFixtureGolden(result.Bundle, golden); err != nil {
				t.Fatalf("assertScenarioFixtureGolden(%q): %v", fixtureDir, err)
			}
		})
	}

	if ran == 0 {
		t.Fatal("no scenario_golden.json fixtures discovered")
	}
}
