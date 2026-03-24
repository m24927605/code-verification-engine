package skills

import (
	"testing"

	"github.com/verabase/code-verification-engine/internal/facts"
	"github.com/verabase/code-verification-engine/internal/rules"
)

func testProfile() *Profile {
	p, _ := GetProfile("github-engineer-core")
	return p
}

func TestEvaluate_NoFindings_AllUnsupported(t *testing.T) {
	r := Evaluate(nil, testProfile(), "/test/repo")
	if r.SchemaVersion != SkillReportVersion {
		t.Errorf("schema_version = %q, want %q", r.SchemaVersion, SkillReportVersion)
	}
	if r.Profile != "github-engineer-core" {
		t.Errorf("profile = %q, want github-engineer-core", r.Profile)
	}
	// All signals should be unsupported
	for _, s := range r.Signals {
		if s.Status != StatusUnsupported {
			t.Errorf("signal %q: status = %q, want unsupported (no findings)", s.SkillID, s.Status)
		}
	}
	if r.Summary.Unsupported != len(r.Signals) {
		t.Errorf("summary.unsupported = %d, want %d", r.Summary.Unsupported, len(r.Signals))
	}
	// Should pass contract validation
	if errs := ValidateReport(r); len(errs) > 0 {
		for _, e := range errs {
			t.Errorf("contract violation: %v", e)
		}
	}
}

func TestEvaluate_DerivesSimplifiedArrays(t *testing.T) {
	findings := []rules.Finding{
		{
			RuleID:     "SEC-AUTH-001",
			Status:     rules.StatusPass,
			TrustClass: rules.TrustAdvisory,
			Evidence:   []rules.Evidence{{File: "middleware.go", LineStart: 10, LineEnd: 20}},
		},
	}
	fs := &rules.FactSet{
		Imports: []facts.ImportFact{
			{ImportPath: "express"},
			{ImportPath: "react"},
			{ImportPath: "react-router-dom"},
			{ImportPath: "@prisma/client"},
			{ImportPath: "express"},
		},
	}

	r := Evaluate(findings, testProfile(), "/test", WithFactSet(fs), WithLanguages([]string{"typescript", "javascript", "typescript"}))

	if len(r.Skills) != 1 || r.Skills[0] != "backend_auth.jwt_middleware" {
		t.Fatalf("skills = %v, want [backend_auth.jwt_middleware]", r.Skills)
	}
	if got, want := len(r.Languages), 2; got != want {
		t.Fatalf("languages len = %d, want %d (%v)", got, want, r.Languages)
	}
	if r.Languages[0] != "javascript" || r.Languages[1] != "typescript" {
		t.Fatalf("languages = %v, want [javascript typescript]", r.Languages)
	}
	if got, want := len(r.Frameworks), 1; got != want {
		t.Fatalf("frameworks len = %d, want %d (%v)", got, want, r.Frameworks)
	}
	if r.Frameworks[0] != "express" {
		t.Fatalf("frameworks = %v, want [express]", r.Frameworks)
	}
	if len(r.Technologies) != 4 {
		t.Fatalf("technologies = %v, want 4 entries", r.Technologies)
	}
	wantTech := map[string]string{
		"express":      "framework",
		"react":        "library",
		"react-router": "router",
		"prisma":       "orm",
	}
	for _, tech := range r.Technologies {
		if wantKind, ok := wantTech[tech.Name]; ok {
			if tech.Kind != wantKind {
				t.Fatalf("technology %s kind = %s, want %s", tech.Name, tech.Kind, wantKind)
			}
			delete(wantTech, tech.Name)
		}
	}
	if len(wantTech) != 0 {
		t.Fatalf("missing technologies: %v", wantTech)
	}
}

func TestEvaluate_JWTMiddleware_Observed(t *testing.T) {
	findings := []rules.Finding{
		{
			RuleID:     "SEC-AUTH-001",
			Status:     rules.StatusPass,
			TrustClass: rules.TrustAdvisory,
			Evidence:   []rules.Evidence{{File: "middleware.go", LineStart: 10, LineEnd: 20}},
		},
	}
	r := Evaluate(findings, testProfile(), "/test")
	found := false
	for _, s := range r.Signals {
		if s.SkillID == "backend_auth.jwt_middleware" {
			found = true
			if s.Status != StatusObserved {
				t.Errorf("status = %q, want observed", s.Status)
			}
			if s.TrustClass != "advisory" {
				t.Errorf("trust_class = %q, want advisory", s.TrustClass)
			}
			if len(s.Evidence) == 0 {
				t.Error("expected evidence")
			}
		}
	}
	if !found {
		t.Error("backend_auth.jwt_middleware signal not found")
	}
	if errs := ValidateReport(r); len(errs) > 0 {
		for _, e := range errs {
			t.Errorf("contract violation: %v", e)
		}
	}
}

func TestEvaluate_SecretViolation_RiskExposure(t *testing.T) {
	findings := []rules.Finding{
		{
			RuleID:     "SEC-SECRET-001",
			Status:     rules.StatusFail,
			TrustClass: rules.TrustMachineTrusted,
			Evidence:   []rules.Evidence{{File: "config.go", LineStart: 5, LineEnd: 5}},
		},
	}
	r := Evaluate(findings, testProfile(), "/test")
	for _, s := range r.Signals {
		if s.SkillID == "backend_security.secret_hygiene" {
			if s.Category != CategoryRiskExposure {
				t.Errorf("category = %q, want risk_exposure", s.Category)
			}
			// Must NOT be a positive hygiene signal with machine_trusted
			if s.Status == StatusObserved && s.TrustClass == "machine_trusted" && s.Category == CategoryHygiene {
				t.Error("secret violation must not produce positive machine_trusted hygiene signal")
			}
			return
		}
	}
	// It's also acceptable if the signal is unsupported (not mapped for fail)
}

func TestEvaluate_SecretClean_PositiveHygiene(t *testing.T) {
	findings := []rules.Finding{
		{
			RuleID:     "SEC-SECRET-001",
			Status:     rules.StatusPass,
			TrustClass: rules.TrustMachineTrusted,
			Evidence:   []rules.Evidence{{File: "main.go", LineStart: 1, LineEnd: 1}},
		},
	}
	r := Evaluate(findings, testProfile(), "/test")
	for _, s := range r.Signals {
		if s.SkillID == "backend_security.secret_hygiene" {
			if s.Status != StatusObserved {
				t.Errorf("status = %q, want observed", s.Status)
			}
			if s.Category != CategoryHygiene {
				t.Errorf("category = %q, want hygiene", s.Category)
			}
			return
		}
	}
	t.Error("expected backend_security.secret_hygiene signal")
}

func TestEvaluate_HeuristicOnly_NeverHighConfidence(t *testing.T) {
	// A single advisory heuristic signal should never be high confidence observed
	findings := []rules.Finding{
		{
			RuleID:     "QUAL-LOG-002",
			Status:     rules.StatusPass,
			TrustClass: rules.TrustAdvisory,
			Evidence:   []rules.Evidence{{File: "logger.go", LineStart: 1, LineEnd: 1}},
		},
	}
	r := Evaluate(findings, testProfile(), "/test")
	for _, s := range r.Signals {
		if s.SkillID == "observability.request_logging" {
			if s.Confidence == ConfidenceHigh {
				t.Error("heuristic-only advisory signal should not produce high confidence")
			}
			return
		}
	}
}

func TestEvaluate_MixedTrust_FloorApplied(t *testing.T) {
	// Two findings mapping to the same skill with different trust classes
	findings := []rules.Finding{
		{
			RuleID:     "FE-XSS-001",
			Status:     rules.StatusFail,
			TrustClass: rules.TrustAdvisory,
			Evidence:   []rules.Evidence{{File: "comp.tsx", LineStart: 10, LineEnd: 10}},
		},
		{
			RuleID:     "FE-XSS-002",
			Status:     rules.StatusFail,
			TrustClass: rules.TrustHumanOrRuntimeRequired,
			Evidence:   []rules.Evidence{{File: "comp2.tsx", LineStart: 5, LineEnd: 5}},
		},
	}
	r := Evaluate(findings, testProfile(), "/test")
	for _, s := range r.Signals {
		if s.SkillID == "frontend_security.xss_sensitive_api_usage" {
			// Trust floor should be the weaker one
			if s.TrustClass != "human_or_runtime_required" {
				t.Errorf("trust_class = %q, want human_or_runtime_required (floor)", s.TrustClass)
			}
			return
		}
	}
}

func TestEvaluate_DBLayering_StructuralSignal(t *testing.T) {
	findings := []rules.Finding{
		{
			RuleID:     "ARCH-LAYER-001",
			Status:     rules.StatusPass,
			TrustClass: rules.TrustAdvisory,
			Evidence:   []rules.Evidence{{File: "repo/user.go", LineStart: 1, LineEnd: 10}},
		},
	}
	r := Evaluate(findings, testProfile(), "/test")
	for _, s := range r.Signals {
		if s.SkillID == "backend_architecture.db_layering" {
			if s.Status != StatusObserved {
				t.Errorf("status = %q, want observed", s.Status)
			}
			if s.EvidenceStrength != EvidenceStructural {
				t.Errorf("evidence_strength = %q, want structural", s.EvidenceStrength)
			}
			return
		}
	}
	t.Error("expected backend_architecture.db_layering signal")
}

func TestEvaluate_DBLayeringFail_Inferred(t *testing.T) {
	// ARCH-LAYER-001 fail should produce inferred (contact evidence)
	findings := []rules.Finding{
		{RuleID: "ARCH-LAYER-001", Status: rules.StatusFail, TrustClass: rules.TrustAdvisory,
			Evidence: []rules.Evidence{{File: "controller/handler.go", LineStart: 23, LineEnd: 23}}},
	}
	r := Evaluate(findings, testProfile(), "/test")
	for _, s := range r.Signals {
		if s.SkillID == "backend_architecture.db_layering" {
			if s.Status != StatusInferred {
				t.Errorf("ARCH-LAYER-001 fail should produce inferred, got %q", s.Status)
			}
			if s.Confidence != ConfidenceLow {
				t.Errorf("inferred signal should have low confidence, got %q", s.Confidence)
			}
			return
		}
	}
	t.Error("expected db_layering signal")
}

func TestEvaluate_GracefulShutdown_Observed(t *testing.T) {
	findings := []rules.Finding{
		{RuleID: "QUAL-SHUTDOWN-001", Status: rules.StatusPass, TrustClass: rules.TrustAdvisory,
			Evidence: []rules.Evidence{{File: "main.go", LineStart: 30, LineEnd: 45}}},
	}
	r := Evaluate(findings, testProfile(), "/test")
	for _, s := range r.Signals {
		if s.SkillID == "backend_runtime.graceful_shutdown" {
			if s.Status != StatusObserved {
				t.Errorf("status = %q, want observed", s.Status)
			}
			return
		}
	}
	t.Error("expected graceful_shutdown signal")
}

func TestEvaluate_ErrorHandling_Observed(t *testing.T) {
	findings := []rules.Finding{
		{RuleID: "ARCH-ERR-001", Status: rules.StatusPass, TrustClass: rules.TrustAdvisory,
			Evidence: []rules.Evidence{{File: "middleware.go", LineStart: 1, LineEnd: 10}}},
	}
	r := Evaluate(findings, testProfile(), "/test")
	for _, s := range r.Signals {
		if s.SkillID == "backend_runtime.error_handling" {
			if s.Status != StatusObserved {
				t.Errorf("status = %q, want observed", s.Status)
			}
			return
		}
	}
	t.Error("expected error_handling signal")
}

func TestEvaluate_FrontendRouteGuarding(t *testing.T) {
	findings := []rules.Finding{
		{RuleID: "FE-AUTH-001", Status: rules.StatusPass, TrustClass: rules.TrustAdvisory,
			Evidence: []rules.Evidence{{File: "PrivateRoute.tsx", LineStart: 1, LineEnd: 15}}},
	}
	r := Evaluate(findings, testProfile(), "/test")
	for _, s := range r.Signals {
		if s.SkillID == "frontend_auth.route_guarding" {
			if s.Status != StatusObserved {
				t.Errorf("status = %q, want observed", s.Status)
			}
			return
		}
	}
	t.Error("expected route_guarding signal")
}

func TestEvaluate_TestAuthModuleTests(t *testing.T) {
	findings := []rules.Finding{
		{RuleID: "TEST-AUTH-001", Status: rules.StatusPass, TrustClass: rules.TrustAdvisory,
			Evidence: []rules.Evidence{{File: "auth_test.go", LineStart: 1, LineEnd: 30}}},
	}
	r := Evaluate(findings, testProfile(), "/test")
	for _, s := range r.Signals {
		if s.SkillID == "testing.auth_module_tests" {
			if s.Status != StatusObserved {
				t.Errorf("status = %q, want observed", s.Status)
			}
			return
		}
	}
	t.Error("expected auth_module_tests signal")
}

func TestEvaluate_RequestLogging(t *testing.T) {
	findings := []rules.Finding{
		{RuleID: "QUAL-LOG-002", Status: rules.StatusPass, TrustClass: rules.TrustAdvisory,
			Evidence: []rules.Evidence{{File: "logger.go", LineStart: 1, LineEnd: 10}}},
	}
	r := Evaluate(findings, testProfile(), "/test")
	for _, s := range r.Signals {
		if s.SkillID == "observability.request_logging" {
			if s.Status != StatusObserved {
				t.Errorf("status = %q, want observed", s.Status)
			}
			return
		}
	}
	t.Error("expected request_logging signal")
}

func TestEvaluate_ContractAlwaysValid(t *testing.T) {
	// Any report from Evaluate should pass contract validation
	cases := []struct {
		name     string
		findings []rules.Finding
	}{
		{"empty", nil},
		{"mixed", []rules.Finding{
			{RuleID: "SEC-AUTH-001", Status: rules.StatusPass, TrustClass: rules.TrustAdvisory,
				Evidence: []rules.Evidence{{File: "a.go", LineStart: 1, LineEnd: 1}}},
			{RuleID: "SEC-SECRET-001", Status: rules.StatusFail, TrustClass: rules.TrustMachineTrusted,
				Evidence: []rules.Evidence{{File: "b.go", LineStart: 2, LineEnd: 2}}},
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := Evaluate(tc.findings, testProfile(), "/test")
			if errs := ValidateReport(r); len(errs) > 0 {
				for _, e := range errs {
					t.Errorf("contract violation: %v", e)
				}
			}
		})
	}
}
