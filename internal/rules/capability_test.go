package rules

import (
	"strings"
	"testing"

	"github.com/verabase/code-verification-engine/internal/facts"
)

// --- CapabilityMatrix unit tests ---

func TestCapabilityMatrix_GoSupported(t *testing.T) {
	m := NewCapabilityMatrix()
	targets := []string{
		"auth.jwt_middleware",
		"secret.hardcoded_credential",
		"secret.env_file_committed",
		"db.direct_access_from_controller",
		"layer.repository",
		"layer.service",
		"pattern.repository_encapsulation",
		"pattern.singleton_mutable_global",
		"security.sql_injection_pattern",
		"security.sensitive_data_in_logs",
		"dep.lockfile_present",
	}
	for _, target := range targets {
		level := m.GetSupportLevel("go", target)
		if level != Supported {
			t.Errorf("go/%s = %v, want supported", target, level)
		}
	}
}

func TestCapabilityMatrix_GoPartiallySupported(t *testing.T) {
	m := NewCapabilityMatrix()
	targets := []string{
		"pattern.dto_separation",
		"security.input_validation",
		"architecture.dependency_injection",
	}
	for _, target := range targets {
		level := m.GetSupportLevel("go", target)
		if level != PartiallySup {
			t.Errorf("go/%s = %v, want partially_supported", target, level)
		}
	}
}

func TestCapabilityMatrix_JSFrontendPartial(t *testing.T) {
	// JS frontend targets are regex-based (symbol-name heuristic), so partially_supported.
	m := NewCapabilityMatrix()
	targets := []string{
		"frontend.xss_dangerous_html",
		"frontend.xss_innerhtml",
		"frontend.token_in_localstorage",
		"frontend.env_exposes_secret",
		"frontend.console_log_in_production",
	}
	for _, target := range targets {
		level := m.GetSupportLevel("javascript", target)
		if level != PartiallySup {
			t.Errorf("javascript/%s = %v, want partially_supported (regex-based)", target, level)
		}
	}
}

func TestCapabilityMatrix_JSMechanicallySupported(t *testing.T) {
	// File-existence targets and AST-backed mechanically-sound targets are fully supported for JS
	m := NewCapabilityMatrix()
	targets := []string{
		"secret.env_file_committed",
		"secret.hardcoded_credential", // AST extracts const assignments with secret-pattern names
		"dep.lockfile_present",
		"frontend.lockfile_exists",
	}
	for _, target := range targets {
		level := m.GetSupportLevel("javascript", target)
		if level != Supported {
			t.Errorf("javascript/%s = %v, want supported", target, level)
		}
	}
}

func TestCapabilityMatrix_TSMatchesJS(t *testing.T) {
	m := NewCapabilityMatrix()
	// TypeScript should have the same capabilities as JavaScript.
	jsTargets := m.SupportedTargets("javascript")
	tsTargets := m.SupportedTargets("typescript")

	jsSet := make(map[string]bool, len(jsTargets))
	for _, t := range jsTargets {
		jsSet[t] = true
	}
	tsSet := make(map[string]bool, len(tsTargets))
	for _, t := range tsTargets {
		tsSet[t] = true
	}
	for target := range jsSet {
		if !tsSet[target] {
			t.Errorf("typescript missing target %s that javascript supports", target)
		}
	}
	for target := range tsSet {
		if !jsSet[target] {
			t.Errorf("javascript missing target %s that typescript supports", target)
		}
	}
}

func TestCapabilityMatrix_PythonPartialAndUnsupported(t *testing.T) {
	m := NewCapabilityMatrix()
	// Python has partial support for many backend targets.
	partials := []string{
		"auth.jwt_middleware",
		"db.direct_access_from_controller",
		"layer.repository",
		"layer.service",
	}
	for _, target := range partials {
		level := m.GetSupportLevel("python", target)
		if level != PartiallySup {
			t.Errorf("python/%s = %v, want partially_supported", target, level)
		}
	}

	// Python does not support frontend targets.
	unsupported := []string{
		"frontend.xss_dangerous_html",
		"frontend.xss_innerhtml",
		"frontend.token_in_localstorage",
		"frontend.env_exposes_secret",
		"frontend.console_log_in_production",
	}
	for _, target := range unsupported {
		level := m.GetSupportLevel("python", target)
		if level != Unsupported {
			t.Errorf("python/%s = %v, want unsupported", target, level)
		}
	}
}

func TestCapabilityMatrix_GoFrontendUnsupported(t *testing.T) {
	m := NewCapabilityMatrix()
	targets := []string{
		"frontend.xss_dangerous_html",
		"frontend.xss_innerhtml",
		"frontend.token_in_localstorage",
		"frontend.env_exposes_secret",
		"frontend.console_log_in_production",
	}
	for _, target := range targets {
		level := m.GetSupportLevel("go", target)
		if level != Unsupported {
			t.Errorf("go/%s = %v, want unsupported", target, level)
		}
	}
}

func TestCapabilityMatrix_UnknownLanguage(t *testing.T) {
	m := NewCapabilityMatrix()
	level := m.GetSupportLevel("rust", "auth.jwt_middleware")
	if level != Unsupported {
		t.Errorf("rust/auth.jwt_middleware = %v, want unsupported", level)
	}
}

func TestCapabilityMatrix_UnknownTarget(t *testing.T) {
	m := NewCapabilityMatrix()
	level := m.GetSupportLevel("go", "nonexistent.target")
	if level != Unsupported {
		t.Errorf("go/nonexistent.target = %v, want unsupported", level)
	}
}

func TestCapabilityMatrix_SupportedTargets(t *testing.T) {
	m := NewCapabilityMatrix()
	targets := m.SupportedTargets("go")
	if len(targets) == 0 {
		t.Fatal("go should have supported targets")
	}
	// Verify auth.jwt_middleware is in the list.
	found := false
	for _, tgt := range targets {
		if tgt == "auth.jwt_middleware" {
			found = true
			break
		}
	}
	if !found {
		t.Error("auth.jwt_middleware not in SupportedTargets for go")
	}
}

func TestCapabilityMatrix_SupportedTargetsUnknownLanguage(t *testing.T) {
	m := NewCapabilityMatrix()
	targets := m.SupportedTargets("ruby")
	if targets != nil {
		t.Errorf("ruby targets = %v, want nil", targets)
	}
}

// --- CheckCapability tests ---

func TestCheckCapability_FullySupported(t *testing.T) {
	m := NewCapabilityMatrix()
	level, detail := m.CheckCapability("auth.jwt_middleware", []string{"go"}, []string{"go"})
	if level != Supported {
		t.Errorf("level = %v, want supported", level)
	}
	if detail != "" {
		t.Errorf("detail = %q, want empty", detail)
	}
}

func TestCheckCapability_WorstCaseWhenMixedLanguages(t *testing.T) {
	m := NewCapabilityMatrix()
	// Go supports auth.jwt_middleware fully, Python only partially.
	// Worst-case semantics: partial wins because Python is partial.
	level, detail := m.CheckCapability("auth.jwt_middleware", []string{"go", "python"}, []string{"go", "python"})
	if level != PartiallySup {
		t.Errorf("level = %v, want partially_supported (Python is partial)", level)
	}
	if !strings.Contains(detail, "python") {
		t.Errorf("detail %q should mention python", detail)
	}
}

func TestCheckCapability_PartiallySupported(t *testing.T) {
	m := NewCapabilityMatrix()
	// Python only partially supports auth.jwt_middleware.
	level, detail := m.CheckCapability("auth.jwt_middleware", []string{"python"}, []string{"python"})
	if level != PartiallySup {
		t.Errorf("level = %v, want partially_supported", level)
	}
	if !strings.Contains(detail, "python") {
		t.Errorf("detail %q should mention python", detail)
	}
}

func TestCheckCapability_Unsupported(t *testing.T) {
	m := NewCapabilityMatrix()
	// Go does not support frontend.xss_dangerous_html.
	level, detail := m.CheckCapability("frontend.xss_dangerous_html", []string{"go"}, []string{"go"})
	if level != Unsupported {
		t.Errorf("level = %v, want unsupported", level)
	}
	if !strings.Contains(detail, "go") {
		t.Errorf("detail %q should mention go", detail)
	}
}

func TestCheckCapability_NoRepoLanguageOverlap(t *testing.T) {
	m := NewCapabilityMatrix()
	level, detail := m.CheckCapability("auth.jwt_middleware", []string{"go"}, []string{"python"})
	if level != Unsupported {
		t.Errorf("level = %v, want unsupported (no overlap)", level)
	}
	if detail == "" {
		t.Error("detail should not be empty for unsupported")
	}
}

// --- intersectLanguages tests ---

func TestIntersectLanguages(t *testing.T) {
	tests := []struct {
		a, b []string
		want int
	}{
		{[]string{"go", "python"}, []string{"go"}, 1},
		{[]string{"go"}, []string{"python"}, 0},
		{[]string{"go", "python"}, []string{"go", "python"}, 2},
		{nil, []string{"go"}, 0},
	}
	for _, tt := range tests {
		got := intersectLanguages(tt.a, tt.b)
		if len(got) != tt.want {
			t.Errorf("intersect(%v, %v) = %v (len %d), want len %d", tt.a, tt.b, got, len(got), tt.want)
		}
	}
}

// --- Engine integration tests ---

func TestEngine_UnsupportedCapabilityProducesUnknown(t *testing.T) {
	rf := &RuleFile{
		Version: "0.1",
		Profile: "test",
		Rules: []Rule{
			{
				ID: "FE-XSS-001", Title: "No dangerous HTML",
				Category: "security", Severity: "critical",
				Languages: []string{"go"}, // Go doesn't support this frontend target
				Type:      "not_exists", Target: "frontend.xss_dangerous_html",
				Message: "No dangerouslySetInnerHTML.",
			},
		},
	}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("main", "function", "main.go", facts.LangGo, false, 1, 5),
		},
	}
	engine := NewEngine()
	result := engine.Execute(rf, fs, []string{"go"})

	// Should have a finding with unknown status.
	if len(result.Findings) != 1 {
		t.Fatalf("findings count = %d, want 1", len(result.Findings))
	}
	f := result.Findings[0]
	if f.Status != StatusUnknown {
		t.Errorf("status = %v, want unknown", f.Status)
	}
	foundReason := false
	for _, r := range f.UnknownReasons {
		if r == UnknownCapabilityUnsupported {
			foundReason = true
		}
	}
	if !foundReason {
		t.Errorf("unknown_reasons = %v, want to contain %q", f.UnknownReasons, UnknownCapabilityUnsupported)
	}

	// Should also be in SkippedRules.
	if len(result.SkippedRules) != 1 {
		t.Fatalf("skipped count = %d, want 1", len(result.SkippedRules))
	}
	if !strings.Contains(result.SkippedRules[0].Reason, "capability_unsupported") {
		t.Errorf("skipped reason = %q, want to contain 'capability_unsupported'", result.SkippedRules[0].Reason)
	}
}

func TestEngine_PartiallySupportedAnnotatesFinding(t *testing.T) {
	rf := &RuleFile{
		Version: "0.1",
		Profile: "test",
		Rules: []Rule{
			{
				ID: "ARCH-LAYER-002", Title: "Repo layer exists",
				Category: "architecture", Severity: "medium",
				Languages: []string{"python"}, Type: "exists", Target: "layer.repository",
				Message: "A repository layer should exist.",
			},
		},
	}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("UserRepository", "class", "repos/user.py", facts.LangPython, true, 1, 20),
		},
	}
	engine := NewEngine()
	result := engine.Execute(rf, fs, []string{"python"})

	if len(result.Findings) != 1 {
		t.Fatalf("findings count = %d, want 1", len(result.Findings))
	}
	f := result.Findings[0]
	// The matcher still runs, so we get a normal status, but with partial annotation.
	foundPartial := false
	for _, r := range f.UnknownReasons {
		if r == UnknownCapabilityPartial {
			foundPartial = true
		}
	}
	if !foundPartial {
		t.Errorf("unknown_reasons = %v, want to contain %q", f.UnknownReasons, UnknownCapabilityPartial)
	}
}

func TestEngine_SupportedCapabilityNoInterference(t *testing.T) {
	rf := &RuleFile{
		Version: "0.1",
		Profile: "test",
		Rules: []Rule{
			{
				ID: "AUTH-001", Title: "JWT auth", Category: "security", Severity: "high",
				Languages: []string{"go"}, Type: "exists", Target: "auth.jwt_middleware",
				Message: "JWT must exist.",
			},
		},
	}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("VerifyToken", "function", "auth/jwt.go", facts.LangGo, true, 10, 30),
		},
		Middlewares: []facts.MiddlewareFact{
			mw("JWTMiddleware", "auth", "auth/jwt.go", facts.LangGo),
		},
		Imports: []facts.ImportFact{
			imp("github.com/golang-jwt/jwt/v5", "", "auth/jwt.go", facts.LangGo),
		},
	}
	engine := NewEngine()
	result := engine.Execute(rf, fs, []string{"go"})

	if len(result.Findings) != 1 {
		t.Fatalf("findings count = %d, want 1", len(result.Findings))
	}
	f := result.Findings[0]
	if f.Status != StatusPass {
		t.Errorf("status = %v, want pass", f.Status)
	}
	// No capability-related unknown reasons should be present.
	for _, r := range f.UnknownReasons {
		if r == UnknownCapabilityUnsupported || r == UnknownCapabilityPartial {
			t.Errorf("unexpected capability unknown reason %q for supported target", r)
		}
	}
	if len(result.SkippedRules) != 0 {
		t.Errorf("skipped count = %d, want 0", len(result.SkippedRules))
	}
}

// --- CapabilityDetail tests ---

func TestCapabilityDetail_FrameworkLevel(t *testing.T) {
	m := NewCapabilityMatrix()

	// JavaScript auth.jwt_middleware should have framework-level details
	d := m.GetCapabilityDetail("javascript", "auth.jwt_middleware")
	if d.Level != PartiallySup {
		t.Errorf("javascript/auth.jwt_middleware level = %v, want partially_supported", d.Level)
	}
	if d.Frameworks == nil {
		t.Fatal("javascript/auth.jwt_middleware should have framework details")
	}
	// Express should be partially supported
	if level, ok := d.Frameworks["express"]; !ok || level != PartiallySup {
		t.Errorf("express framework level = %v (exists=%v), want partially_supported", level, ok)
	}
	// Hapi should be unsupported
	if level, ok := d.Frameworks["hapi"]; !ok || level != Unsupported {
		t.Errorf("hapi framework level = %v (exists=%v), want unsupported", level, ok)
	}

	// Python auth.jwt_middleware should also have framework details
	pd := m.GetCapabilityDetail("python", "auth.jwt_middleware")
	if pd.Frameworks == nil {
		t.Fatal("python/auth.jwt_middleware should have framework details")
	}
	if level, ok := pd.Frameworks["fastapi"]; !ok || level != PartiallySup {
		t.Errorf("fastapi framework level = %v (exists=%v), want partially_supported", level, ok)
	}
	if level, ok := pd.Frameworks["starlette"]; !ok || level != Unsupported {
		t.Errorf("starlette framework level = %v (exists=%v), want unsupported", level, ok)
	}

	// TypeScript should match JavaScript frameworks
	td := m.GetCapabilityDetail("typescript", "auth.jwt_middleware")
	if len(td.Frameworks) != len(d.Frameworks) {
		t.Errorf("typescript frameworks count = %d, want %d (same as JS)", len(td.Frameworks), len(d.Frameworks))
	}

	// Go auth.jwt_middleware should have no framework overrides (fully supported)
	gd := m.GetCapabilityDetail("go", "auth.jwt_middleware")
	if gd.Level != Supported {
		t.Errorf("go/auth.jwt_middleware level = %v, want supported", gd.Level)
	}
	if len(gd.Frameworks) != 0 {
		t.Errorf("go/auth.jwt_middleware should have no framework overrides, got %d", len(gd.Frameworks))
	}
}

func TestCapabilityDetail_ASTBacked(t *testing.T) {
	m := NewCapabilityMatrix()

	// JavaScript auth.jwt_middleware is AST-backed
	d := m.GetCapabilityDetail("javascript", "auth.jwt_middleware")
	if !d.ASTBacked {
		t.Error("javascript/auth.jwt_middleware should be AST-backed")
	}

	// JavaScript db.direct_access_from_controller is AST-backed (CallerName from AST function spans)
	dd := m.GetCapabilityDetail("javascript", "db.direct_access_from_controller")
	if !dd.ASTBacked {
		t.Error("javascript/db.direct_access_from_controller should be AST-backed (CallerName from function spans)")
	}

	// Python auth.jwt_middleware is AST-backed
	pd := m.GetCapabilityDetail("python", "auth.jwt_middleware")
	if !pd.ASTBacked {
		t.Error("python/auth.jwt_middleware should be AST-backed")
	}

	// Go auth.jwt_middleware is AST-backed
	gd := m.GetCapabilityDetail("go", "auth.jwt_middleware")
	if !gd.ASTBacked {
		t.Error("go/auth.jwt_middleware should be AST-backed")
	}

	// A target with no detail registered should default to ASTBacked=false
	nd := m.GetCapabilityDetail("javascript", "config.env_based")
	if nd.ASTBacked {
		t.Error("javascript/config.env_based should not be AST-backed (no detail registered)")
	}
}

func TestCapabilityDetail_RuntimeDep(t *testing.T) {
	m := NewCapabilityMatrix()

	// Python targets should have python3 runtime dependency
	pd := m.GetCapabilityDetail("python", "auth.jwt_middleware")
	if pd.RuntimeDep != "python3" {
		t.Errorf("python/auth.jwt_middleware RuntimeDep = %q, want 'python3'", pd.RuntimeDep)
	}

	// JavaScript targets should have no runtime dependency
	jd := m.GetCapabilityDetail("javascript", "auth.jwt_middleware")
	if jd.RuntimeDep != "" {
		t.Errorf("javascript/auth.jwt_middleware RuntimeDep = %q, want empty", jd.RuntimeDep)
	}

	// Go targets should have no runtime dependency
	gd := m.GetCapabilityDetail("go", "auth.jwt_middleware")
	if gd.RuntimeDep != "" {
		t.Errorf("go/auth.jwt_middleware RuntimeDep = %q, want empty", gd.RuntimeDep)
	}
}

func TestDegradeLanguage_WithReason(t *testing.T) {
	m := NewCapabilityMatrix()

	// Before degradation, python secret.hardcoded_credential is Supported
	level := m.GetSupportLevel("python", "secret.hardcoded_credential")
	if level != Supported {
		t.Fatalf("before degrade: python/secret.hardcoded_credential = %v, want supported", level)
	}

	// No reason should be recorded before degradation
	if reason := m.GetDegradeReason("python"); reason != "" {
		t.Errorf("before degrade: reason = %q, want empty", reason)
	}

	// Degrade with a reason
	m.DegradeLanguage("python", "python3 unavailable")

	// After degradation, level should be PartiallySup
	level = m.GetSupportLevel("python", "secret.hardcoded_credential")
	if level != PartiallySup {
		t.Errorf("after degrade: python/secret.hardcoded_credential = %v, want partially_supported", level)
	}

	// Reason should be preserved
	reason := m.GetDegradeReason("python")
	if reason != "python3 unavailable" {
		t.Errorf("after degrade: reason = %q, want 'python3 unavailable'", reason)
	}

	// Non-degraded language should have no reason
	if reason := m.GetDegradeReason("go"); reason != "" {
		t.Errorf("go should not have degrade reason, got %q", reason)
	}
}

func TestCheckCapability_DegradedDetail(t *testing.T) {
	m := NewCapabilityMatrix()

	// Degrade Python with a reason
	m.DegradeLanguage("python", "python3 unavailable")

	// CheckCapability for a target that was Supported (now PartiallySup after degradation)
	level, detail := m.CheckCapability("secret.hardcoded_credential", []string{"python"}, []string{"python"})
	if level != PartiallySup {
		t.Errorf("level = %v, want partially_supported (degraded)", level)
	}
	if !strings.Contains(detail, "python") {
		t.Errorf("detail %q should mention python", detail)
	}
	if !strings.Contains(detail, "python3 unavailable") {
		t.Errorf("detail %q should mention degradation reason 'python3 unavailable'", detail)
	}

	// Build a rule engine and test that findings include degradation info
	engine := NewEngine()
	engine.capabilities.DegradeLanguage("python", "python3 unavailable")

	rf := &RuleFile{
		Version: "0.1",
		Profile: "test",
		Rules: []Rule{
			{
				ID: "SECRET-001", Title: "No hardcoded creds",
				Category: "security", Severity: "critical",
				Languages: []string{"python"}, Type: "not_exists", Target: "secret.hardcoded_credential",
				Message: "No hardcoded credentials.",
			},
		},
	}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("main", "function", "main.py", facts.LangPython, false, 1, 5),
		},
	}
	result := engine.Execute(rf, fs, []string{"python"})

	if len(result.Findings) != 1 {
		t.Fatalf("findings count = %d, want 1", len(result.Findings))
	}
	f := result.Findings[0]

	// Finding should contain the degraded reason code
	hasDegraded := false
	for _, r := range f.UnknownReasons {
		if r == UnknownCapabilityDegraded {
			hasDegraded = true
		}
	}
	if !hasDegraded {
		t.Errorf("unknown_reasons = %v, want to contain %q", f.UnknownReasons, UnknownCapabilityDegraded)
	}

	// Detail string should contain degradation reason
	hasReasonInDetail := false
	for _, r := range f.UnknownReasons {
		if strings.Contains(r, "python3 unavailable") {
			hasReasonInDetail = true
		}
	}
	if !hasReasonInDetail {
		t.Errorf("unknown_reasons = %v, want at least one entry containing 'python3 unavailable'", f.UnknownReasons)
	}
}

func TestEngine_MixedLanguagesPartialAndSupported(t *testing.T) {
	// Rule applies to go+python, repo has both.
	// Go fully supports auth.jwt_middleware, Python only partially.
	// Worst-case semantics: should report partial since Python is partial.
	rf := &RuleFile{
		Version: "0.1",
		Profile: "test",
		Rules: []Rule{
			{
				ID: "AUTH-001", Title: "JWT auth", Category: "security", Severity: "high",
				Languages: []string{"go", "python"}, Type: "exists", Target: "auth.jwt_middleware",
				Message: "JWT must exist.",
			},
		},
	}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("VerifyToken", "function", "auth/jwt.go", facts.LangGo, true, 10, 30),
		},
		Middlewares: []facts.MiddlewareFact{
			mw("JWTMiddleware", "auth", "auth/jwt.go", facts.LangGo),
		},
		Imports: []facts.ImportFact{
			imp("github.com/golang-jwt/jwt/v5", "", "auth/jwt.go", facts.LangGo),
		},
	}
	engine := NewEngine()
	result := engine.Execute(rf, fs, []string{"go", "python"})

	if len(result.Findings) != 1 {
		t.Fatalf("findings count = %d, want 1", len(result.Findings))
	}
	f := result.Findings[0]
	// With worst-case semantics, Python's partial support should annotate the finding.
	hasPartial := false
	for _, r := range f.UnknownReasons {
		if r == UnknownCapabilityPartial {
			hasPartial = true
		}
	}
	if !hasPartial {
		t.Error("expected UnknownCapabilityPartial annotation because Python only partially supports auth.jwt_middleware")
	}
}

func TestEngine_AllLanguagesUnsupportedSkips(t *testing.T) {
	// A rule targeting frontend.xss_dangerous_html for go+python only (both unsupported).
	rf := &RuleFile{
		Version: "0.1",
		Profile: "test",
		Rules: []Rule{
			{
				ID: "FE-XSS-001", Title: "No dangerous HTML",
				Category: "security", Severity: "critical",
				Languages: []string{"go", "python"},
				Type:      "not_exists", Target: "frontend.xss_dangerous_html",
				Message: "No dangerouslySetInnerHTML.",
			},
		},
	}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("main", "function", "main.go", facts.LangGo, false, 1, 5),
		},
	}
	engine := NewEngine()
	result := engine.Execute(rf, fs, []string{"go", "python"})

	if len(result.Findings) != 1 {
		t.Fatalf("findings count = %d, want 1", len(result.Findings))
	}
	if result.Findings[0].Status != StatusUnknown {
		t.Errorf("status = %v, want unknown", result.Findings[0].Status)
	}
	if len(result.SkippedRules) != 1 {
		t.Fatalf("skipped count = %d, want 1", len(result.SkippedRules))
	}
}
