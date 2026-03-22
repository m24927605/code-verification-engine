package skills

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/verabase/code-verification-engine/internal/rules"
)

// goldenSpec defines the golden.json schema for skill fixtures.
type goldenSpec struct {
	Profile         string             `json:"profile"`
	Scenario        string             `json:"scenario"`
	RequiredSignals []goldenSignal     `json:"required_signals"`
	ForbiddenSignals []goldenForbidden `json:"forbidden_signals"`
	Summary         goldenSummary      `json:"summary"`
	Description     string             `json:"description"`
}

type goldenSignal struct {
	SkillID           string   `json:"skill_id"`
	Status            string   `json:"status,omitempty"`
	TrustClass        string   `json:"trust_class,omitempty"`
	MinEvidenceCount  int      `json:"min_evidence_count,omitempty"`
	AllowedConfidence []string `json:"allowed_confidence,omitempty"`
	Category          string   `json:"category,omitempty"`
}

type goldenForbidden struct {
	SkillID    string `json:"skill_id"`
	Status     string `json:"status,omitempty"`
	TrustClass string `json:"trust_class,omitempty"`
	Category   string `json:"category,omitempty"`
}

type goldenSummary struct {
	MinObserved    int `json:"min_observed,omitempty"`
	MinInferred    int `json:"min_inferred,omitempty"`
	MinUnsupported int `json:"min_unsupported,omitempty"`
}

// scenarioFindings returns synthetic verification findings for each fixture scenario.
// This simulates what the verification engine would produce for each scenario.
func scenarioFindings(scenario string) []rules.Finding {
	switch scenario {
	case "backend-auth-observed":
		return []rules.Finding{
			{RuleID: "SEC-AUTH-001", Status: rules.StatusPass, TrustClass: rules.TrustAdvisory,
				Evidence: []rules.Evidence{{File: "middleware/auth.go", LineStart: 10, LineEnd: 25, Symbol: "authMiddleware"}}},
		}
	case "middleware-binding-advisory":
		return []rules.Finding{
			{RuleID: "SEC-AUTH-002", Status: rules.StatusPass, TrustClass: rules.TrustHumanOrRuntimeRequired,
				Evidence: []rules.Evidence{{File: "routes/api.go", LineStart: 15, LineEnd: 20}}},
		}
	case "secret-hygiene-clean":
		return []rules.Finding{
			{RuleID: "SEC-SECRET-001", Status: rules.StatusPass, TrustClass: rules.TrustMachineTrusted,
				Evidence: []rules.Evidence{{File: "main.go", LineStart: 1, LineEnd: 1}}},
		}
	case "secret-hygiene-violation":
		return []rules.Finding{
			{RuleID: "SEC-SECRET-001", Status: rules.StatusFail, TrustClass: rules.TrustMachineTrusted,
				Evidence: []rules.Evidence{{File: "config.go", LineStart: 5, LineEnd: 5, Symbol: "API_KEY"}}},
		}
	case "db-layering-structural":
		return []rules.Finding{
			{RuleID: "ARCH-LAYER-001", Status: rules.StatusPass, TrustClass: rules.TrustAdvisory,
				Evidence: []rules.Evidence{{File: "internal/repo/user.go", LineStart: 10, LineEnd: 20}}},
		}
	case "error-handling-advisory":
		return []rules.Finding{
			{RuleID: "ARCH-ERR-001", Status: rules.StatusPass, TrustClass: rules.TrustAdvisory,
				Evidence: []rules.Evidence{{File: "middleware/error.go", LineStart: 5, LineEnd: 15}}},
		}
	case "graceful-shutdown-advisory":
		return []rules.Finding{
			{RuleID: "QUAL-SHUTDOWN-001", Status: rules.StatusPass, TrustClass: rules.TrustAdvisory,
				Evidence: []rules.Evidence{{File: "cmd/server.go", LineStart: 30, LineEnd: 45}}},
		}
	case "frontend-xss-sensitive-api":
		return []rules.Finding{
			{RuleID: "FE-XSS-001", Status: rules.StatusFail, TrustClass: rules.TrustAdvisory,
				Evidence: []rules.Evidence{{File: "components/RichText.tsx", LineStart: 12, LineEnd: 12}}},
		}
	case "frontend-route-guarding":
		return []rules.Finding{
			{RuleID: "FE-AUTH-001", Status: rules.StatusPass, TrustClass: rules.TrustAdvisory,
				Evidence: []rules.Evidence{{File: "routes/PrivateRoute.tsx", LineStart: 8, LineEnd: 15}}},
		}
	case "auth-tests-present":
		return []rules.Finding{
			{RuleID: "TEST-AUTH-001", Status: rules.StatusPass, TrustClass: rules.TrustAdvisory,
				Evidence: []rules.Evidence{{File: "tests/auth_test.go", LineStart: 1, LineEnd: 30}}},
		}
	case "request-logging-advisory":
		return []rules.Finding{
			{RuleID: "QUAL-LOG-002", Status: rules.StatusPass, TrustClass: rules.TrustAdvisory,
				Evidence: []rules.Evidence{{File: "middleware/logger.go", LineStart: 5, LineEnd: 20}}},
		}
	case "unsupported-minimal":
		return nil // no findings -> all unsupported
	default:
		return nil
	}
}

func TestFixtureScenarios(t *testing.T) {
	fixtureRoot := filepath.Join("..", "..", "testdata", "skills", "github-engineer-core")

	entries, err := os.ReadDir(fixtureRoot)
	if err != nil {
		t.Fatalf("cannot read fixture root %s: %v", fixtureRoot, err)
	}

	if len(entries) == 0 {
		t.Fatal("no fixture scenarios found")
	}

	profile, ok := GetProfile("github-engineer-core")
	if !ok {
		t.Fatal("github-engineer-core profile not found")
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		scenario := entry.Name()
		goldenPath := filepath.Join(fixtureRoot, scenario, "golden.json")

		data, err := os.ReadFile(goldenPath)
		if err != nil {
			t.Logf("skipping %s: no golden.json", scenario)
			continue
		}

		var golden goldenSpec
		if err := json.Unmarshal(data, &golden); err != nil {
			t.Fatalf("invalid golden.json for %s: %v", scenario, err)
		}

		t.Run(scenario, func(t *testing.T) {
			findings := scenarioFindings(scenario)
			report := Evaluate(findings, profile, "/test/repo")

			// Validate contract
			if contractErrs := ValidateReport(report); len(contractErrs) > 0 {
				for _, e := range contractErrs {
					t.Errorf("contract violation: %v", e)
				}
			}

			// Build signal index
			signalIdx := make(map[string]*Signal)
			for i := range report.Signals {
				signalIdx[report.Signals[i].SkillID] = &report.Signals[i]
			}

			// Assert required signals
			for _, req := range golden.RequiredSignals {
				sig, exists := signalIdx[req.SkillID]
				if !exists {
					t.Errorf("required signal %q not found in output", req.SkillID)
					continue
				}

				if req.Status != "" && string(sig.Status) != req.Status {
					t.Errorf("signal %q: status = %q, want %q", req.SkillID, sig.Status, req.Status)
				}

				if req.TrustClass != "" && sig.TrustClass != req.TrustClass {
					t.Errorf("signal %q: trust_class = %q, want %q", req.SkillID, sig.TrustClass, req.TrustClass)
				}

				if req.MinEvidenceCount > 0 && len(sig.Evidence) < req.MinEvidenceCount {
					t.Errorf("signal %q: evidence count = %d, want >= %d", req.SkillID, len(sig.Evidence), req.MinEvidenceCount)
				}

				if len(req.AllowedConfidence) > 0 {
					allowed := false
					for _, ac := range req.AllowedConfidence {
						if string(sig.Confidence) == ac {
							allowed = true
							break
						}
					}
					if !allowed {
						t.Errorf("signal %q: confidence = %q, want one of %v", req.SkillID, sig.Confidence, req.AllowedConfidence)
					}
				}

				if req.Category != "" && string(sig.Category) != req.Category {
					t.Errorf("signal %q: category = %q, want %q", req.SkillID, sig.Category, req.Category)
				}
			}

			// Assert forbidden signals
			for _, fb := range golden.ForbiddenSignals {
				sig, exists := signalIdx[fb.SkillID]
				if !exists {
					continue // signal not present -> not forbidden
				}
				// Check if the specific forbidden combination exists
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
					t.Errorf("forbidden signal match: %q with status=%q trust=%q category=%q",
						fb.SkillID, sig.Status, sig.TrustClass, sig.Category)
				}
			}

			// Assert summary minimums
			if golden.Summary.MinObserved > 0 && report.Summary.Observed < golden.Summary.MinObserved {
				t.Errorf("summary.observed = %d, want >= %d", report.Summary.Observed, golden.Summary.MinObserved)
			}
			if golden.Summary.MinInferred > 0 && report.Summary.Inferred < golden.Summary.MinInferred {
				t.Errorf("summary.inferred = %d, want >= %d", report.Summary.Inferred, golden.Summary.MinInferred)
			}
			if golden.Summary.MinUnsupported > 0 && report.Summary.Unsupported < golden.Summary.MinUnsupported {
				t.Errorf("summary.unsupported = %d, want >= %d", report.Summary.Unsupported, golden.Summary.MinUnsupported)
			}
		})
	}
}
