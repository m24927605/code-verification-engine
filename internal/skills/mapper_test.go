package skills

import (
	"testing"

	"github.com/verabase/code-verification-engine/internal/facts"
	"github.com/verabase/code-verification-engine/internal/rules"
)

func TestMapFindings_PassProducesObserved(t *testing.T) {
	profile := testProfile()
	findings := []rules.Finding{
		{
			RuleID:     "SEC-AUTH-001",
			Status:     rules.StatusPass,
			TrustClass: rules.TrustAdvisory,
			Evidence:   []rules.Evidence{{File: "auth.go", LineStart: 1, LineEnd: 10}},
		},
	}
	candidates := MapFindings(findings, profile)
	if len(candidates) == 0 {
		t.Fatal("expected at least one candidate")
	}
	c := candidates[0]
	if c.SkillID != "backend_auth.jwt_middleware" {
		t.Errorf("skill_id = %q, want backend_auth.jwt_middleware", c.SkillID)
	}
	if c.Status != StatusObserved {
		t.Errorf("status = %q, want observed", c.Status)
	}
}

func TestMapFindings_FailOnSecretProducesNegative(t *testing.T) {
	profile := testProfile()
	findings := []rules.Finding{
		{
			RuleID:     "SEC-SECRET-001",
			Status:     rules.StatusFail,
			TrustClass: rules.TrustMachineTrusted,
			Evidence:   []rules.Evidence{{File: "config.go", LineStart: 5, LineEnd: 5}},
		},
	}
	candidates := MapFindings(findings, profile)
	if len(candidates) == 0 {
		t.Fatal("expected candidate for secret violation")
	}
	c := candidates[0]
	if c.Category != CategoryRiskExposure {
		t.Errorf("category = %q, want risk_exposure", c.Category)
	}
}

func TestMapFindings_FailOnMissingAuth_Ignored(t *testing.T) {
	profile := testProfile()
	findings := []rules.Finding{
		{
			RuleID:     "SEC-AUTH-001",
			Status:     rules.StatusFail,
			TrustClass: rules.TrustAdvisory,
		},
	}
	candidates := MapFindings(findings, profile)
	for _, c := range candidates {
		if c.SkillID == "backend_auth.jwt_middleware" {
			t.Error("fail on auth should not produce a positive implementation signal")
		}
	}
}

func TestMapFindings_UnknownStatus_Skipped(t *testing.T) {
	profile := testProfile()
	findings := []rules.Finding{
		{RuleID: "SEC-AUTH-001", Status: rules.StatusUnknown, TrustClass: rules.TrustAdvisory},
	}
	candidates := MapFindings(findings, profile)
	if len(candidates) != 0 {
		t.Errorf("expected 0 candidates for unknown status, got %d", len(candidates))
	}
}

func TestMapFindings_UnmappedRule_Ignored(t *testing.T) {
	profile := testProfile()
	findings := []rules.Finding{
		{RuleID: "CUSTOM-RULE-999", Status: rules.StatusPass, TrustClass: rules.TrustAdvisory},
	}
	candidates := MapFindings(findings, profile)
	if len(candidates) != 0 {
		t.Errorf("expected 0 candidates for unmapped rule, got %d", len(candidates))
	}
}

func TestCapTrustClass(t *testing.T) {
	tests := []struct {
		actual, ceiling, want string
	}{
		{"machine_trusted", "advisory", "advisory"},
		{"advisory", "machine_trusted", "advisory"},
		{"advisory", "advisory", "advisory"},
		{"human_or_runtime_required", "advisory", "human_or_runtime_required"},
		{"machine_trusted", "machine_trusted", "machine_trusted"},
	}
	for _, tt := range tests {
		got := capTrustClass(tt.actual, tt.ceiling)
		if got != tt.want {
			t.Errorf("capTrustClass(%q, %q) = %q, want %q", tt.actual, tt.ceiling, got, tt.want)
		}
	}
}

// --- Direct fact-to-signal mapping tests ---

func TestMapFacts_JWTMiddleware(t *testing.T) {
	profile := testProfile()
	fs := &rules.FactSet{
		Middlewares: []facts.MiddlewareFact{
			{Name: "jwtAuth", Kind: "auth", File: "auth.go", Language: facts.LangGo,
				Span: facts.Span{Start: 5, End: 20}, Quality: facts.QualityProof},
		},
	}
	candidates := MapFacts(fs, profile)
	found := false
	for _, c := range candidates {
		if c.SkillID == "backend_auth.jwt_middleware" && c.Status == StatusObserved {
			found = true
			if c.EvidenceStrength != EvidenceDirect {
				t.Errorf("proof-quality middleware should produce direct evidence, got %q", c.EvidenceStrength)
			}
		}
	}
	if !found {
		t.Error("expected jwt_middleware signal from middleware fact")
	}
}

func TestMapFacts_RouteBinding(t *testing.T) {
	profile := testProfile()
	fs := &rules.FactSet{
		RouteBindings: []facts.RouteBindingFact{
			{Method: "GET", Path: "/api/users", Handler: "getUsers",
				Middlewares: []string{"authMiddleware"},
				File: "routes.go", Language: facts.LangGo, Span: facts.Span{Start: 10, End: 10}},
		},
	}
	candidates := MapFacts(fs, profile)
	found := false
	for _, c := range candidates {
		if c.SkillID == "backend_routing.middleware_binding" {
			found = true
		}
	}
	if !found {
		t.Error("expected middleware_binding signal from route binding fact")
	}
}

func TestMapFacts_AuthTests(t *testing.T) {
	profile := testProfile()
	fs := &rules.FactSet{
		Tests: []facts.TestFact{
			{TestName: "TestAuthMiddleware", File: "auth_test.go", Language: facts.LangGo,
				Span: facts.Span{Start: 1, End: 20}},
		},
	}
	candidates := MapFacts(fs, profile)
	found := false
	for _, c := range candidates {
		if c.SkillID == "testing.auth_module_tests" {
			found = true
		}
	}
	if !found {
		t.Error("expected auth_module_tests signal from test fact")
	}
}

func TestMapFacts_NilFactSet(t *testing.T) {
	profile := testProfile()
	candidates := MapFacts(nil, profile)
	if len(candidates) != 0 {
		t.Errorf("nil FactSet should produce 0 candidates, got %d", len(candidates))
	}
}

func TestMapFacts_DBLayeringWithFileRoles(t *testing.T) {
	profile := testProfile()
	fs := &rules.FactSet{
		DataAccess: []facts.DataAccessFact{
			{Operation: "db.QueryRow", Backend: "sql", File: "repo/user.go",
				Language: facts.LangGo, Span: facts.Span{Start: 10, End: 10}},
		},
		FileRoles: []facts.FileRoleFact{
			{Role: "repository", File: "repo/user.go", Language: facts.LangGo},
		},
	}
	candidates := MapFacts(fs, profile)
	found := false
	for _, c := range candidates {
		if c.SkillID == "backend_architecture.db_layering" {
			found = true
			if c.EvidenceStrength != EvidenceStructural {
				t.Errorf("expected structural evidence, got %q", c.EvidenceStrength)
			}
		}
	}
	if !found {
		t.Error("expected db_layering signal from DataAccess + FileRole facts")
	}
}

func TestMapFacts_DBLayeringWithoutFileRoles(t *testing.T) {
	profile := testProfile()
	fs := &rules.FactSet{
		DataAccess: []facts.DataAccessFact{
			{Operation: "db.QueryRow", Backend: "sql", File: "handler.go",
				Language: facts.LangGo, Span: facts.Span{Start: 10, End: 10}},
		},
		// No FileRoles — should NOT produce db_layering signal
	}
	candidates := MapFacts(fs, profile)
	for _, c := range candidates {
		if c.SkillID == "backend_architecture.db_layering" {
			t.Error("should not produce db_layering without repository-layer FileRoles")
		}
	}
}

func TestMapFacts_ConfigReadsHygiene(t *testing.T) {
	profile := testProfile()
	fs := &rules.FactSet{
		ConfigReads: []facts.ConfigReadFact{
			{Key: "DATABASE_URL", SourceKind: "env", File: "config.go",
				Language: facts.LangGo, Span: facts.Span{Start: 5, End: 5}},
		},
		// No secrets — clean config
	}
	candidates := MapFacts(fs, profile)
	found := false
	for _, c := range candidates {
		if c.SkillID == "backend_security.secret_hygiene" {
			found = true
			if c.Status != StatusInferred {
				t.Errorf("env config without secrets should produce inferred, got %q", c.Status)
			}
		}
	}
	if !found {
		t.Error("expected secret_hygiene signal from env-based ConfigReads")
	}
}

func TestMapFacts_ConfigReadsWithSecrets(t *testing.T) {
	profile := testProfile()
	fs := &rules.FactSet{
		ConfigReads: []facts.ConfigReadFact{
			{Key: "DB_URL", SourceKind: "env", File: "config.go",
				Language: facts.LangGo, Span: facts.Span{Start: 5, End: 5}},
		},
		Secrets: []facts.SecretFact{
			{Kind: "api_key", File: "config.go", Language: facts.LangGo,
				Span: facts.Span{Start: 10, End: 10}},
		},
	}
	candidates := MapFacts(fs, profile)
	for _, c := range candidates {
		if c.SkillID == "backend_security.secret_hygiene" && c.Category == CategoryHygiene {
			t.Error("should not produce hygiene signal when secrets exist")
		}
	}
}

func TestMapFacts_EvidenceStrengthFromQuality(t *testing.T) {
	tests := []struct {
		quality facts.FactQuality
		want    EvidenceStrength
	}{
		{facts.QualityProof, EvidenceDirect},
		{facts.QualityStructural, EvidenceStructural},
		{facts.QualityHeuristic, EvidenceHeuristic},
		{"", EvidenceHeuristic},
	}
	for _, tt := range tests {
		got := evidenceStrengthFromQuality(tt.quality)
		if got != tt.want {
			t.Errorf("evidenceStrengthFromQuality(%q) = %q, want %q", tt.quality, got, tt.want)
		}
	}
}

func TestMapFindings_XSSFail_RiskExposure(t *testing.T) {
	profile := testProfile()
	findings := []rules.Finding{
		{RuleID: "FE-XSS-001", Status: rules.StatusFail, TrustClass: rules.TrustAdvisory,
			Evidence: []rules.Evidence{{File: "comp.tsx", LineStart: 5, LineEnd: 5}}},
	}
	candidates := MapFindings(findings, profile)
	found := false
	for _, c := range candidates {
		if c.SkillID == "frontend_security.xss_sensitive_api_usage" {
			found = true
			if c.Category != CategoryRiskExposure {
				t.Errorf("XSS fail should be risk_exposure, got %q", c.Category)
			}
		}
	}
	if !found {
		t.Error("expected xss signal from FE-XSS-001 fail")
	}
}

func TestMapFindings_PassWithoutEvidence_ProducesInferred(t *testing.T) {
	profile := testProfile()
	findings := []rules.Finding{
		{RuleID: "SEC-AUTH-001", Status: rules.StatusPass, TrustClass: rules.TrustAdvisory},
		// No evidence
	}
	candidates := MapFindings(findings, profile)
	for _, c := range candidates {
		if c.SkillID == "backend_auth.jwt_middleware" {
			if c.Status != StatusInferred {
				t.Errorf("pass without evidence should produce inferred, got %q", c.Status)
			}
			return
		}
	}
	t.Error("expected jwt_middleware candidate")
}

func TestEvaluate_WithFactSet(t *testing.T) {
	profile := testProfile()
	fs := &rules.FactSet{
		Middlewares: []facts.MiddlewareFact{
			{Name: "jwtGuard", Kind: "auth", File: "guard.go", Language: facts.LangGo,
				Span: facts.Span{Start: 1, End: 10}},
		},
	}
	// No findings, but facts should produce signals
	r := Evaluate(nil, profile, "/test", WithFactSet(fs))
	found := false
	for _, s := range r.Signals {
		if s.SkillID == "backend_auth.jwt_middleware" && s.Status == StatusObserved {
			found = true
		}
	}
	if !found {
		t.Error("fact-to-signal mapping should produce jwt_middleware observed signal")
	}
	// Contract should still pass
	if errs := ValidateReport(r); len(errs) > 0 {
		for _, e := range errs {
			t.Errorf("contract violation: %v", e)
		}
	}
}
