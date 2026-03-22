package rules

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/verabase/code-verification-engine/internal/facts"
)

// goldenFile represents the expected outcome for a benchmark scenario.
type goldenFile struct {
	RuleID                     string `json:"rule_id"`
	Scenario                   string `json:"scenario"`
	ExpectedStatus             string `json:"expected_status"`
	ExpectedTrustClass         string `json:"expected_trust_class"`
	ExpectedHasEvidence        bool   `json:"expected_has_evidence"`
	ExpectedVerificationLevel  string `json:"expected_verification_level,omitempty"`
	Description                string `json:"description"`
}

// scenarioEntry groups a golden expectation with the directory containing test files.
type scenarioEntry struct {
	ruleID      string
	scenario    string
	scenarioDir string
	golden      goldenFile
}

func TestBenchmarkTrustedCore(t *testing.T) {
	corpusRoot := filepath.Join("..", "..", "testdata", "benchmark", "trusted-core")

	// Discover all scenario directories.
	scenarios := discoverScenarios(t, corpusRoot)
	if len(scenarios) == 0 {
		t.Fatal("no benchmark scenarios found under", corpusRoot)
	}

	// Collect rules from ALL profiles so that benchmark scenarios for rules
	// not yet in trusted-core (e.g. ARCH rules pending matcher upgrades) can
	// still be exercised at the unit level.
	rulesByID := make(map[string]Rule)
	for _, p := range AllProfiles() {
		for _, r := range p.Rules {
			if _, exists := rulesByID[r.ID]; !exists {
				rulesByID[r.ID] = r
			}
		}
	}

	engine := NewEngine()

	for _, sc := range scenarios {
		t.Run(sc.ruleID+"/"+sc.scenario, func(t *testing.T) {
			rule, ok := rulesByID[sc.golden.RuleID]
			if !ok {
				t.Fatalf("rule %s not found in trusted-core profile", sc.golden.RuleID)
			}

			// Build a FactSet from the scenario directory.
			fs := buildFactSetForScenario(t, sc)

			// Determine repo languages based on the rule.
			repoLanguages := rule.Languages

			// Execute the single rule via the engine.
			rf := &RuleFile{
				Version: "0.1",
				Profile: "trusted-core",
				Rules:   []Rule{rule},
			}
			result := engine.Execute(rf, fs, repoLanguages)

			if len(result.Findings) == 0 {
				t.Fatal("expected at least one finding, got zero (rule may have been skipped)")
			}

			finding := result.Findings[0]

			// Apply trust normalization (as the real pipeline does).
			NormalizeTrust(&finding)

			// Check status.
			expectedStatus := Status(sc.golden.ExpectedStatus)
			if finding.Status != expectedStatus {
				t.Errorf("status: got %q, want %q (description: %s)",
					finding.Status, expectedStatus, sc.golden.Description)
			}

			// Check trust class.
			expectedTrust := TrustClass(sc.golden.ExpectedTrustClass)
			if finding.TrustClass != expectedTrust {
				t.Errorf("trust_class: got %q, want %q", finding.TrustClass, expectedTrust)
			}

			// Check evidence presence.
			hasEvidence := len(finding.Evidence) > 0
			if hasEvidence != sc.golden.ExpectedHasEvidence {
				t.Errorf("has_evidence: got %v, want %v (evidence count: %d)",
					hasEvidence, sc.golden.ExpectedHasEvidence, len(finding.Evidence))
			}

			// Check verification level (if specified in golden).
			if sc.golden.ExpectedVerificationLevel != "" {
				expectedVL := VerificationLevel(sc.golden.ExpectedVerificationLevel)
				if finding.VerificationLevel != expectedVL {
					t.Errorf("verification_level: got %q, want %q",
						finding.VerificationLevel, expectedVL)
				}
			}
		})
	}
}

// discoverScenarios walks the corpus root and collects all scenario entries
// that have a golden.json file.
func discoverScenarios(t *testing.T, corpusRoot string) []scenarioEntry {
	t.Helper()
	var scenarios []scenarioEntry

	ruleEntries, err := os.ReadDir(corpusRoot)
	if err != nil {
		t.Fatalf("cannot read corpus root %s: %v", corpusRoot, err)
	}

	for _, ruleEntry := range ruleEntries {
		if !ruleEntry.IsDir() {
			continue
		}
		ruleID := ruleEntry.Name()
		ruleDir := filepath.Join(corpusRoot, ruleID)

		scenarioEntries, err := os.ReadDir(ruleDir)
		if err != nil {
			t.Fatalf("cannot read rule dir %s: %v", ruleDir, err)
		}

		for _, scenEntry := range scenarioEntries {
			if !scenEntry.IsDir() {
				continue
			}
			scenarioName := scenEntry.Name()
			scenarioDir := filepath.Join(ruleDir, scenarioName)

			goldenPath := filepath.Join(scenarioDir, "golden.json")
			data, err := os.ReadFile(goldenPath)
			if err != nil {
				t.Logf("skipping %s/%s: no golden.json", ruleID, scenarioName)
				continue
			}

			var golden goldenFile
			if err := json.Unmarshal(data, &golden); err != nil {
				t.Fatalf("invalid golden.json at %s: %v", goldenPath, err)
			}

			scenarios = append(scenarios, scenarioEntry{
				ruleID:      ruleID,
				scenario:    scenarioName,
				scenarioDir: scenarioDir,
				golden:      golden,
			})
		}
	}
	return scenarios
}

// buildFactSetForScenario constructs a FactSet that the rule matchers can
// evaluate. Since we are not running the full analyzer pipeline, we manually
// build facts based on the rule being tested and the files present.
func buildFactSetForScenario(t *testing.T, sc scenarioEntry) *FactSet {
	t.Helper()

	switch sc.golden.RuleID {
	case "SEC-SECRET-001":
		return buildSecretFactSet(t, sc)
	case "SEC-SECRET-003":
		return buildEnvFileFactSet(t, sc)
	case "ARCH-LAYER-001":
		return buildArchLayerFactSet(t, sc)
	case "ARCH-PATTERN-001":
		return buildArchPatternFactSet(t, sc)
	case "FE-DEP-001":
		return buildFEDepFactSet(t, sc)
	default:
		t.Fatalf("no FactSet builder for rule %s", sc.golden.RuleID)
		return nil
	}
}

// buildSecretFactSet builds facts for SEC-SECRET-001 scenarios.
// For the fail case, we simulate what the Go analyzer would produce when it
// detects hardcoded credentials.
func buildSecretFactSet(t *testing.T, sc scenarioEntry) *FactSet {
	t.Helper()
	fs := &FactSet{}

	// Walk the scenario directory for .go files and register them as FileFacts.
	goFiles := findFilesByExt(t, sc.scenarioDir, ".go")
	for _, f := range goFiles {
		relPath := mustRelPath(t, sc.scenarioDir, f)
		fs.Files = append(fs.Files, facts.FileFact{
			Language: facts.LangGo,
			File:     relPath,
			Quality:  facts.QualityProof,
		})
		// Add a minimal symbol so hasMinimalFactsForNotExists is satisfied.
		fs.Symbols = append(fs.Symbols, facts.SymbolFact{
			Language: facts.LangGo,
			File:     relPath,
			Span:     facts.Span{Start: 1, End: 1},
			Name:     "main",
			Kind:     "function",
		})
	}

	// For the fail scenario, add SecretFacts to simulate detected credentials.
	// Quality=proof because real analyzers (Go AST) produce proof-grade facts.
	if sc.scenario == "fail" {
		fs.Secrets = append(fs.Secrets, facts.SecretFact{
			Language: facts.LangGo,
			File:     "main.go",
			Span:     facts.Span{Start: 10, End: 10},
			Kind:     "api_key",
			Quality:  facts.QualityProof,
		})
		fs.Secrets = append(fs.Secrets, facts.SecretFact{
			Language: facts.LangGo,
			File:     "main.go",
			Span:     facts.Span{Start: 11, End: 11},
			Kind:     "password",
			Quality:  facts.QualityProof,
		})
	}

	return fs
}

// buildEnvFileFactSet builds facts for SEC-SECRET-003 scenarios.
// The matcher checks for .env files in the FileFact list.
func buildEnvFileFactSet(t *testing.T, sc scenarioEntry) *FactSet {
	t.Helper()
	fs := &FactSet{}

	// Collect all files in the scenario directory.
	allFiles := findAllFiles(t, sc.scenarioDir)
	for _, f := range allFiles {
		relPath := mustRelPath(t, sc.scenarioDir, f)
		lang := detectLanguage(relPath)
		fs.Files = append(fs.Files, facts.FileFact{
			Language: lang,
			File:     relPath,
			Quality:  facts.QualityProof,
		})
	}

	// Add a symbol so hasMinimalFactsForNotExists (default case) is satisfied.
	goFiles := findFilesByExt(t, sc.scenarioDir, ".go")
	for _, f := range goFiles {
		relPath := mustRelPath(t, sc.scenarioDir, f)
		fs.Symbols = append(fs.Symbols, facts.SymbolFact{
			Language: facts.LangGo,
			File:     relPath,
			Span:     facts.Span{Start: 1, End: 1},
			Name:     "main",
			Kind:     "function",
			Quality:  facts.QualityProof,
		})
	}

	return fs
}

// buildArchLayerFactSet builds facts for ARCH-LAYER-001 scenarios.
// The matcher looks for DataAccessFact entries in controller files.
func buildArchLayerFactSet(t *testing.T, sc scenarioEntry) *FactSet {
	t.Helper()
	fs := &FactSet{}

	goFiles := findFilesByExt(t, sc.scenarioDir, ".go")
	for _, f := range goFiles {
		relPath := mustRelPath(t, sc.scenarioDir, f)
		fs.Files = append(fs.Files, facts.FileFact{
			Language: facts.LangGo,
			File:     relPath,
		})
		fs.Symbols = append(fs.Symbols, facts.SymbolFact{
			Language: facts.LangGo,
			File:     relPath,
			Span:     facts.Span{Start: 1, End: 1},
			Name:     filepath.Base(relPath),
			Kind:     "file",
		})
	}

	// For the fail scenario, add DataAccessFact in the controller file.
	if sc.scenario == "fail" {
		fs.DataAccess = append(fs.DataAccess, facts.DataAccessFact{
			Language:  facts.LangGo,
			File:      "controller/handler.go",
			Span:      facts.Span{Start: 23, End: 23},
			Operation: "db.QueryRow",
			Backend:   "sql",
		})
	}

	// For service-db-access scenario, add DataAccessFact in the service file.
	// The matcher only flags controller/handler files, so service-layer DB
	// access should NOT produce a violation.
	if sc.scenario == "service-db-access" {
		fs.DataAccess = append(fs.DataAccess, facts.DataAccessFact{
			Language:  facts.LangGo,
			File:      "service/user_service.go",
			Span:      facts.Span{Start: 22, End: 22},
			Operation: "db.QueryRow",
			Backend:   "sql",
		})
	}

	return fs
}

// buildArchPatternFactSet builds facts for ARCH-PATTERN-001 scenarios.
// The matcher looks for DataAccessFact entries outside repository-layer files.
func buildArchPatternFactSet(t *testing.T, sc scenarioEntry) *FactSet {
	t.Helper()
	fs := &FactSet{}

	goFiles := findFilesByExt(t, sc.scenarioDir, ".go")
	for _, f := range goFiles {
		relPath := mustRelPath(t, sc.scenarioDir, f)
		fs.Files = append(fs.Files, facts.FileFact{
			Language: facts.LangGo,
			File:     relPath,
		})
		fs.Symbols = append(fs.Symbols, facts.SymbolFact{
			Language: facts.LangGo,
			File:     relPath,
			Span:     facts.Span{Start: 1, End: 1},
			Name:     filepath.Base(relPath),
			Kind:     "file",
		})
	}

	if sc.scenario == "pass" || sc.scenario == "false-positive-guard" {
		// Data access only in repo/ files — this should pass.
		// For false-positive-guard, handler/ exists with NO data access,
		// but repo/ has legitimate data access. The matcher should only
		// flag data access OUTSIDE repo layer.
		fs.DataAccess = append(fs.DataAccess, facts.DataAccessFact{
			Language:  facts.LangGo,
			File:      "repo/user_repo.go",
			Span:      facts.Span{Start: 18, End: 18},
			Operation: "db.QueryRow",
			Backend:   "sql",
		})
	} else if sc.scenario == "fail" {
		// Data access in handler/ files — outside repo layer.
		fs.DataAccess = append(fs.DataAccess, facts.DataAccessFact{
			Language:  facts.LangGo,
			File:      "handler/user_handler.go",
			Span:      facts.Span{Start: 24, End: 24},
			Operation: "db.Query",
			Backend:   "sql",
		})
	}

	return fs
}

// buildFEDepFactSet builds facts for FE-DEP-001 scenarios.
// The matcher checks for lockfile entries in FileFact.
func buildFEDepFactSet(t *testing.T, sc scenarioEntry) *FactSet {
	t.Helper()
	fs := &FactSet{}

	allFiles := findAllFiles(t, sc.scenarioDir)
	for _, f := range allFiles {
		relPath := mustRelPath(t, sc.scenarioDir, f)
		lang := detectLanguage(relPath)
		fs.Files = append(fs.Files, facts.FileFact{
			Language: lang,
			File:     relPath,
			Quality:  facts.QualityProof,
		})
	}

	return fs
}

// --- helpers ---

// findFilesByExt returns absolute paths of files matching the given extension.
func findFilesByExt(t *testing.T, root, ext string) []string {
	t.Helper()
	var result []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && filepath.Ext(path) == ext {
			result = append(result, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking %s for %s files: %v", root, ext, err)
	}
	return result
}

// findAllFiles returns absolute paths of all non-directory entries.
func findAllFiles(t *testing.T, root string) []string {
	t.Helper()
	var result []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && filepath.Base(path) != "golden.json" {
			result = append(result, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking %s: %v", root, err)
	}
	return result
}

// mustRelPath returns the path relative to root or fails.
func mustRelPath(t *testing.T, root, abs string) string {
	t.Helper()
	rel, err := filepath.Rel(root, abs)
	if err != nil {
		t.Fatalf("cannot compute relative path from %s to %s: %v", root, abs, err)
	}
	return rel
}

// detectLanguage returns a facts.Language based on file extension.
func detectLanguage(path string) facts.Language {
	ext := filepath.Ext(path)
	switch ext {
	case ".go":
		return facts.LangGo
	case ".js":
		return facts.LangJavaScript
	case ".ts", ".tsx":
		return facts.LangTypeScript
	case ".py":
		return facts.LangPython
	default:
		// Use JavaScript as a generic fallback for config files (package.json, etc.)
		return facts.LangJavaScript
	}
}
