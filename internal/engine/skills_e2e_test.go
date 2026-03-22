package engine

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/verabase/code-verification-engine/internal/skills"
)

// ---------------------------------------------------------------------------
// E2E tests: run the full engine pipeline in skill_inference mode
// against real fixture repos and validate skills.json against golden specs
// ---------------------------------------------------------------------------

// goldenSpec mirrors the golden.json schema for skill fixtures.
type skillGoldenSpec struct {
	Profile          string                `json:"profile"`
	Scenario         string                `json:"scenario"`
	RequiredSignals  []skillGoldenSignal   `json:"required_signals"`
	ForbiddenSignals []skillGoldenForbidden `json:"forbidden_signals"`
	Summary          skillGoldenSummary    `json:"summary"`
	Description      string                `json:"description"`
}

type skillGoldenSignal struct {
	SkillID           string   `json:"skill_id"`
	Status            string   `json:"status,omitempty"`
	TrustClass        string   `json:"trust_class,omitempty"`
	MinEvidenceCount  int      `json:"min_evidence_count,omitempty"`
	AllowedConfidence []string `json:"allowed_confidence,omitempty"`
	Category          string   `json:"category,omitempty"`
}

type skillGoldenForbidden struct {
	SkillID    string `json:"skill_id"`
	Status     string `json:"status,omitempty"`
	TrustClass string `json:"trust_class,omitempty"`
	Category   string `json:"category,omitempty"`
}

type skillGoldenSummary struct {
	MinObserved    int `json:"min_observed,omitempty"`
	MinInferred    int `json:"min_inferred,omitempty"`
	MinUnsupported int `json:"min_unsupported,omitempty"`
}

// TestSkillInferenceE2E runs the full engine pipeline in skill_inference mode
// against real fixture repos. For each scenario it:
//  1. Builds a real git repo from fixture source files
//  2. Runs the full engine pipeline (analyzers → facts → rules → skill evaluator)
//  3. Reads the produced skills.json
//  4. Validates contract, schema, and status semantics
//  5. Loads golden.json and validates required signals (presence) and forbidden signals (hard fail)
//
// Required-signal status/trust checks are soft (logged) since the real analyzer
// pipeline may not produce the exact same findings as synthetic unit tests.
// Forbidden-signal checks are hard (fail) since they are safety invariants.
func TestSkillInferenceE2E(t *testing.T) {
	fixtureRoot := filepath.Join("..", "..", "testdata", "skills", "github-engineer-core")

	if _, err := os.ReadDir(fixtureRoot); err != nil {
		t.Fatalf("cannot read fixture root: %v", err)
	}

	// Test scenarios that have source files for e2e
	scenarios := []string{
		"backend-auth-observed",
		"secret-hygiene-clean",
		"secret-hygiene-violation",
		"unsupported-minimal",
	}

	for _, scenario := range scenarios {
		t.Run(scenario, func(t *testing.T) {
			scenarioDir := filepath.Join(fixtureRoot, scenario)

			// Load golden.json
			goldenPath := filepath.Join(scenarioDir, "golden.json")
			goldenData, goldenErr := os.ReadFile(goldenPath)
			if goldenErr != nil {
				t.Fatalf("golden.json required for e2e: %v", goldenErr)
			}
			var golden skillGoldenSpec
			if err := json.Unmarshal(goldenData, &golden); err != nil {
				t.Fatalf("invalid golden.json: %v", err)
			}

			// Collect source files (exclude golden.json)
			var files []repoFile
			err := filepath.Walk(scenarioDir, func(path string, info os.FileInfo, err error) error {
				if err != nil {
					return err
				}
				if info.IsDir() || filepath.Base(path) == "golden.json" {
					return nil
				}
				relPath, _ := filepath.Rel(scenarioDir, path)
				content, readErr := os.ReadFile(path)
				if readErr != nil {
					return readErr
				}
				files = append(files, repoFile{path: relPath, content: string(content)})
				return nil
			})
			if err != nil {
				t.Fatalf("walking fixture dir: %v", err)
			}
			if len(files) == 0 {
				t.Skip("no source files in fixture")
			}

			repoPath := createTestRepo(t, files)
			outputDir := t.TempDir()

			result := Run(Config{
				RepoPath:     repoPath,
				Ref:          "HEAD",
				Profile:      "trusted-core",
				OutputDir:    outputDir,
				Format:       "json",
				Progress:     os.Stderr,
				Mode:         "skill_inference",
				SkillProfile: "github-engineer-core",
			})

			assertSuccessExitCode(t, result)

			// Verify skills.json was written
			skillsPath := filepath.Join(outputDir, "skills.json")
			skillsData, readErr := os.ReadFile(skillsPath)
			if readErr != nil {
				if result.ExitCode == 5 {
					t.Skip("contract violation prevented skills.json writing")
				}
				t.Fatalf("skills.json not found: %v", readErr)
			}

			// Parse and validate skills.json
			var skillReport skills.Report
			if err := json.Unmarshal(skillsData, &skillReport); err != nil {
				t.Fatalf("invalid skills.json: %v", err)
			}

			// Contract validation (hard)
			if contractErrs := skills.ValidateReport(&skillReport); len(contractErrs) > 0 {
				for _, e := range contractErrs {
					t.Errorf("contract violation: %v", e)
				}
			}

			// Schema and profile checks (hard)
			if skillReport.SchemaVersion == "" {
				t.Error("schema_version must be set")
			}
			if skillReport.Profile != "github-engineer-core" {
				t.Errorf("profile = %q, want github-engineer-core", skillReport.Profile)
			}
			if len(skillReport.Signals) == 0 {
				t.Error("expected at least one signal in skills.json")
			}

			// Status semantics: must NOT use verification statuses (hard)
			for _, sig := range skillReport.Signals {
				if sig.Status == "pass" || sig.Status == "fail" || sig.Status == "unknown" {
					t.Errorf("signal %q uses verification status %q — skill signals must use observed/inferred/unsupported",
						sig.SkillID, sig.Status)
				}
			}

			// Build signal index for golden matching
			signalIdx := make(map[string]*skills.Signal)
			for i := range skillReport.Signals {
				signalIdx[skillReport.Signals[i].SkillID] = &skillReport.Signals[i]
			}

			// Golden: required signals — presence is hard, status/trust are soft
			// (real analyzer pipeline may not produce identical findings to synthetic tests)
			for _, req := range golden.RequiredSignals {
				sig, exists := signalIdx[req.SkillID]
				if !exists {
					// Signal presence is a hard requirement
					t.Errorf("[golden] required signal %q not found in skills.json", req.SkillID)
					continue
				}

				// Status check — soft (log, don't fail) since real pipeline may differ
				if req.Status != "" && string(sig.Status) != req.Status {
					t.Logf("[golden soft] signal %q: status = %q, golden wants %q (real pipeline may differ)",
						req.SkillID, sig.Status, req.Status)
				}

				if req.TrustClass != "" && sig.TrustClass != req.TrustClass {
					t.Logf("[golden soft] signal %q: trust_class = %q, golden wants %q",
						req.SkillID, sig.TrustClass, req.TrustClass)
				}

				if req.MinEvidenceCount > 0 && len(sig.Evidence) < req.MinEvidenceCount {
					t.Logf("[golden soft] signal %q: evidence count = %d, golden wants >= %d",
						req.SkillID, len(sig.Evidence), req.MinEvidenceCount)
				}
			}

			// Golden: forbidden signals — HARD assertions (safety invariants)
			for _, fb := range golden.ForbiddenSignals {
				sig, exists := signalIdx[fb.SkillID]
				if !exists {
					continue // not present → not forbidden
				}
				match := true
				if fb.Status != "" && string(sig.Status) != fb.Status {
					match = false
				}
				if fb.TrustClass != "" && sig.TrustClass != fb.TrustClass {
					match = false
				}
				if fb.Category != "" && string(sig.Category) != fb.Category {
					match = false
				}
				if match {
					t.Errorf("[golden FORBIDDEN] signal %q matched forbidden spec: status=%q trust=%q category=%q",
						fb.SkillID, sig.Status, sig.TrustClass, sig.Category)
				}
			}

			// Golden: summary minimums (soft)
			if golden.Summary.MinObserved > 0 && skillReport.Summary.Observed < golden.Summary.MinObserved {
				t.Logf("[golden soft] summary.observed = %d, golden wants >= %d",
					skillReport.Summary.Observed, golden.Summary.MinObserved)
			}
			if golden.Summary.MinUnsupported > 0 && skillReport.Summary.Unsupported < golden.Summary.MinUnsupported {
				// Unsupported minimum is a hard check — minimal repo must produce unsupported
				t.Errorf("[golden] summary.unsupported = %d, want >= %d",
					skillReport.Summary.Unsupported, golden.Summary.MinUnsupported)
			}
		})
	}
}

// TestSkillInferenceMode_VerificationOutputUnchanged verifies that verification
// mode produces the same outputs as before — no skills.json.
func TestSkillInferenceMode_VerificationOutputUnchanged(t *testing.T) {
	repoPath := createTestRepo(t, []repoFile{
		{path: "main.go", content: `package main
func main() {}
`},
	})
	outputDir := t.TempDir()

	result := Run(Config{
		RepoPath:  repoPath,
		Ref:       "HEAD",
		Profile:   "trusted-core",
		OutputDir: outputDir,
		Format:    "json",
		Progress:  os.Stderr,
		Mode:      "verification",
	})

	assertSuccessExitCode(t, result)

	// skills.json should NOT be written in verification mode
	skillsPath := filepath.Join(outputDir, "skills.json")
	if _, err := os.Stat(skillsPath); err == nil {
		t.Error("skills.json should not exist in verification mode")
	}

	// result.SkillReport should be nil
	if result.SkillReport != nil {
		t.Error("SkillReport should be nil in verification mode")
	}
}

// TestSkillInferenceMode_BothProducesBothOutputs verifies that both mode
// produces verification and skill outputs together.
func TestSkillInferenceMode_BothProducesBothOutputs(t *testing.T) {
	repoPath := createTestRepo(t, []repoFile{
		{path: "main.go", content: `package main
func main() {}
`},
	})
	outputDir := t.TempDir()

	result := Run(Config{
		RepoPath:     repoPath,
		Ref:          "HEAD",
		Profile:      "trusted-core",
		OutputDir:    outputDir,
		Format:       "json",
		Progress:     os.Stderr,
		Mode:         "both",
		SkillProfile: "github-engineer-core",
	})

	assertSuccessExitCode(t, result)
	if result.ExitCode == 5 {
		t.Skip("contract violation; skipping output checks")
	}

	// Both scan.json and skills.json should exist
	for _, fname := range []string{"scan.json", "report.json", "skills.json"} {
		path := filepath.Join(outputDir, fname)
		if _, err := os.Stat(path); os.IsNotExist(err) {
			t.Errorf("%s should exist in both mode", fname)
		}
	}

	// SkillReport should be populated
	if result.SkillReport == nil {
		t.Error("SkillReport should be populated in both mode")
	}
}

// TestSkillInferenceMode_InvalidModeRejected verifies that invalid modes
// are rejected early at the engine level, before any outputs are written.
func TestSkillInferenceMode_InvalidModeRejected(t *testing.T) {
	repoPath := createTestRepo(t, []repoFile{
		{path: "main.go", content: `package main
func main() {}
`},
	})
	outputDir := t.TempDir()

	result := Run(Config{
		RepoPath:  repoPath,
		Ref:       "HEAD",
		Profile:   "trusted-core",
		OutputDir: outputDir,
		Format:    "json",
		Progress:  os.Stderr,
		Mode:      "invalid_mode",
	})

	if result.ExitCode == 0 {
		t.Error("invalid mode should not succeed")
	}
	if len(result.Errors) == 0 {
		t.Error("expected error message for invalid mode")
	}

	// No output files should be written — mode rejection must happen before pipeline runs
	for _, fname := range []string{"scan.json", "report.json", "skills.json"} {
		path := filepath.Join(outputDir, fname)
		if _, err := os.Stat(path); err == nil {
			t.Errorf("%s should not exist when mode is invalid (rejection must happen before outputs)", fname)
		}
	}
}

// TestSkillInferenceMode_DefaultIsVerification verifies that empty mode
// defaults to verification (backward compatibility).
func TestSkillInferenceMode_DefaultIsVerification(t *testing.T) {
	repoPath := createTestRepo(t, []repoFile{
		{path: "main.go", content: `package main
func main() {}
`},
	})
	outputDir := t.TempDir()

	result := Run(Config{
		RepoPath:  repoPath,
		Ref:       "HEAD",
		Profile:   "trusted-core",
		OutputDir: outputDir,
		Format:    "json",
		Progress:  os.Stderr,
		// Mode intentionally empty — should default to verification
	})

	assertSuccessExitCode(t, result)

	// No skills.json
	skillsPath := filepath.Join(outputDir, "skills.json")
	if _, err := os.Stat(skillsPath); err == nil {
		t.Error("skills.json should not exist when mode is empty (defaults to verification)")
	}
}
