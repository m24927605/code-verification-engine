package rules

import (
	"testing"

	"github.com/verabase/code-verification-engine/internal/facts"
)

// ---------------------------------------------------------------------------
// inferIssueCategoryFromRuleID — 40% coverage
// ---------------------------------------------------------------------------

func TestInferIssueCategoryFromRuleID(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		ruleID   string
		expected string
	}{
		{"security prefix", "SEC-001", "security"},
		{"architecture prefix", "ARCH-LAYER-001", "architecture"},
		{"frontend security xss", "FE-XSS-001", "frontend_security"},
		{"frontend security token", "FE-TOKEN-001", "frontend_security"},
		{"frontend security env", "FE-ENV-001", "frontend_security"},
		{"frontend security auth", "FE-AUTH-001", "frontend_security"},
		{"frontend security csp", "FE-CSP-001", "frontend_security"},
		{"frontend quality", "FE-DEP-001", "frontend_quality"},
		{"pattern in name", "ARCH-PATTERN-001", "architecture"},
		{"quality prefix", "QUAL-LOG-001", "quality"},
		{"testing prefix", "TEST-AUTH-001", "testing"},
		{"default bug", "UNKNOWN-001", "bug"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := inferIssueCategoryFromRuleID(tt.ruleID)
			if got != tt.expected {
				t.Errorf("inferIssueCategoryFromRuleID(%q) = %q, want %q", tt.ruleID, got, tt.expected)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// normalizeIssueCategory — 66.7% coverage
// ---------------------------------------------------------------------------

func TestNormalizeIssueCategory(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		category string
		ruleID   string
		expected string
	}{
		{"security", "security", "SEC-001", "security"},
		{"architecture", "architecture", "ARCH-001", "architecture"},
		{"architectural alias", "architectural", "ARCH-001", "architecture"},
		{"design for arch rule", "design", "ARCH-001", "architecture"},
		{"design for non-arch rule", "design", "PATTERN-001", "design"},
		{"quality", "quality", "QUAL-001", "quality"},
		{"testing", "testing", "TEST-001", "testing"},
		{"test alias", "test", "TEST-001", "testing"},
		{"frontend_security", "frontend_security", "FE-XSS-001", "frontend_security"},
		{"frontend_quality", "frontend_quality", "FE-DEP-001", "frontend_quality"},
		{"unknown falls back to rule ID inference", "unknown_category", "SEC-001", "security"},
		{"whitespace trimmed", "  Security  ", "SEC-001", "security"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizeIssueCategory(tt.category, tt.ruleID)
			if got != tt.expected {
				t.Errorf("normalizeIssueCategory(%q, %q) = %q, want %q", tt.category, tt.ruleID, got, tt.expected)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// CanonicalIssueSeverity — 62.5% coverage
// ---------------------------------------------------------------------------

func TestCanonicalIssueSeverity_AllBranches(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		rule       Rule
		trustClass TrustClass
		status     Status
		expected   string
	}{
		{"explicit severity", Rule{Severity: "Critical"}, TrustAdvisory, StatusFail, "critical"},
		{"explicit with whitespace", Rule{Severity: "  High  "}, TrustAdvisory, StatusFail, "high"},
		{"machine trusted fail", Rule{}, TrustMachineTrusted, StatusFail, "high"},
		{"machine trusted pass", Rule{}, TrustMachineTrusted, StatusPass, "medium"},
		{"advisory", Rule{}, TrustAdvisory, StatusFail, "medium"},
		{"human or runtime required", Rule{}, TrustHumanOrRuntimeRequired, StatusFail, "low"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CanonicalIssueSeverity(tt.rule, tt.trustClass, tt.status)
			if got != tt.expected {
				t.Errorf("CanonicalIssueSeverity() = %q, want %q", got, tt.expected)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// RuleMigrationState — cover default branch (66.7%)
// ---------------------------------------------------------------------------

func TestRuleMigrationState_DefaultBranch(t *testing.T) {
	t.Parallel()

	got := RuleMigrationState(Rule{ID: "UNKNOWN-001", MatcherClass: ""})
	if got != MigrationLegacyOnly {
		t.Errorf("expected MigrationLegacyOnly for unknown matcher class, got %q", got)
	}
}

func TestRuleMigrationState_StructuralNotAudited(t *testing.T) {
	t.Parallel()

	got := RuleMigrationState(Rule{ID: "UNKNOWN-002", MatcherClass: MatcherStructural})
	if got != MigrationSeedNative {
		t.Errorf("expected MigrationSeedNative for structural matcher, got %q", got)
	}
}

// ---------------------------------------------------------------------------
// RuleMigrationAuditForRule — cover all fallback branches (33.3%)
// ---------------------------------------------------------------------------

func TestRuleMigrationAuditForRule_AllFallbacks(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		rule          Rule
		expectedState MigrationState
		expectedSub   string
	}{
		{
			"fallback seed_native for structural",
			Rule{ID: "CUSTOM-001", MatcherClass: MatcherStructural},
			MigrationSeedNative,
			"rule-level issue-native audit is incomplete",
		},
		{
			"fallback finding_bridged for heuristic",
			Rule{ID: "CUSTOM-002", MatcherClass: MatcherHeuristic},
			MigrationFindingBridged,
			"finding-derived issue semantics",
		},
		{
			"fallback legacy_only for unknown matcher",
			Rule{ID: "CUSTOM-003", MatcherClass: ""},
			MigrationLegacyOnly,
			"no native v2 migration audit recorded",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			audit := RuleMigrationAuditForRule(tt.rule)
			if audit.State != tt.expectedState {
				t.Errorf("state = %q, want %q", audit.State, tt.expectedState)
			}
			if !containsFold(audit.Reason, tt.expectedSub) {
				t.Errorf("reason = %q, want substring %q", audit.Reason, tt.expectedSub)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// RuleIndexFromFile — nil case (83.3%)
// ---------------------------------------------------------------------------

func TestRuleIndexFromFile_Nil(t *testing.T) {
	t.Parallel()

	got := RuleIndexFromFile(nil)
	if got != nil {
		t.Errorf("expected nil for nil RuleFile, got %v", got)
	}
}

// ---------------------------------------------------------------------------
// issue_seed.go — issueSeedStatus, issueSeedQuality, maxInt, dedupeStringsSorted
// ---------------------------------------------------------------------------

func TestIssueSeedStatus_AllBranches(t *testing.T) {
	t.Parallel()

	tests := []struct {
		status   Status
		expected string
	}{
		{StatusFail, "open"},
		{StatusUnknown, "unknown"},
		{StatusPass, "resolved"},
		{"custom", "resolved"},
	}

	for _, tt := range tests {
		got := issueSeedStatus(tt.status)
		if got != tt.expected {
			t.Errorf("issueSeedStatus(%q) = %q, want %q", tt.status, got, tt.expected)
		}
	}
}

func TestIssueSeedQuality_AllBranches(t *testing.T) {
	t.Parallel()

	tests := []struct {
		quality  string
		expected float64
	}{
		{"proof", 1.0},
		{"structural", 0.7},
		{"heuristic", 0.4},
		{"", 0.4},
	}

	for _, tt := range tests {
		got := issueSeedQuality(tt.quality)
		if got != tt.expected {
			t.Errorf("issueSeedQuality(%q) = %f, want %f", tt.quality, got, tt.expected)
		}
	}
}

func TestMaxInt(t *testing.T) {
	t.Parallel()

	tests := []struct {
		a, b, expected int
	}{
		{1, 2, 2},
		{5, 3, 5},
		{0, 0, 0},
		{-1, 1, 1},
	}

	for _, tt := range tests {
		got := maxInt(tt.a, tt.b)
		if got != tt.expected {
			t.Errorf("maxInt(%d, %d) = %d, want %d", tt.a, tt.b, got, tt.expected)
		}
	}
}

func TestDedupeStringsSorted(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    []string
		expected int
	}{
		{"nil input", nil, 0},
		{"empty input", []string{}, 0},
		{"with empty strings", []string{"", "", "a"}, 1},
		{"duplicates", []string{"b", "a", "b", "c", "a"}, 3},
		{"all empty", []string{"", ""}, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := dedupeStringsSorted(tt.input)
			if len(got) != tt.expected {
				t.Errorf("dedupeStringsSorted() returned %d items, want %d", len(got), tt.expected)
			}
		})
	}
}

func TestPrimaryIssueSeedLocation_NoEvidence(t *testing.T) {
	t.Parallel()

	f := Finding{Status: StatusFail}
	file, symbol, startLine, endLine := primaryIssueSeedLocation(f)
	if file != "unknown" || symbol != "" || startLine != 1 || endLine != 1 {
		t.Errorf("unexpected location for no evidence: %s %s %d %d", file, symbol, startLine, endLine)
	}
}

func TestPrimaryIssueSeedLocation_MultipleEvidence(t *testing.T) {
	t.Parallel()

	f := Finding{
		Status: StatusFail,
		Evidence: []Evidence{
			{File: "b.go", LineStart: 10, LineEnd: 20, Symbol: "funcB"},
			{File: "a.go", LineStart: 5, LineEnd: 15, Symbol: "funcA"},
		},
	}
	file, symbol, startLine, endLine := primaryIssueSeedLocation(f)
	if file != "a.go" || symbol != "funcA" || startLine != 5 || endLine != 15 {
		t.Errorf("unexpected location: %s %s %d %d", file, symbol, startLine, endLine)
	}
}

func TestPrimaryIssueSeedLocation_ZeroLineStart(t *testing.T) {
	t.Parallel()

	f := Finding{
		Status: StatusFail,
		Evidence: []Evidence{
			{File: "a.go", LineStart: 0, LineEnd: 0, Symbol: "x"},
		},
	}
	file, _, startLine, endLine := primaryIssueSeedLocation(f)
	if file != "a.go" {
		t.Errorf("expected a.go, got %s", file)
	}
	// maxInt(1, 0) = 1 for startLine
	if startLine != 1 {
		t.Errorf("expected startLine=1 for zero, got %d", startLine)
	}
	// maxInt(0, 0) = 0; endLine stays 0 since both inputs are zero
	if endLine != 0 {
		t.Errorf("expected endLine=0, got %d", endLine)
	}
}

func TestIssueSeedEvidenceIDs_GeneratesWhenMissing(t *testing.T) {
	t.Parallel()

	f := Finding{
		Evidence: []Evidence{
			{File: "a.go", LineStart: 1, LineEnd: 1, Symbol: "x"},
			{File: "a.go", LineStart: 1, LineEnd: 1, Symbol: "x"},
		},
	}
	ids := issueSeedEvidenceIDs(f)
	if len(ids) != 1 {
		t.Errorf("expected 1 deduplicated ID, got %d", len(ids))
	}
}

func TestIssueSeedEvidenceIDs_Empty(t *testing.T) {
	t.Parallel()

	f := Finding{}
	ids := issueSeedEvidenceIDs(f)
	if ids != nil {
		t.Errorf("expected nil for no evidence, got %v", ids)
	}
}

// ---------------------------------------------------------------------------
// RefreshIssueSeeds — nil result (66.7%)
// ---------------------------------------------------------------------------

func TestRefreshIssueSeeds_NilResult(t *testing.T) {
	t.Parallel()

	rf := &RuleFile{Rules: []Rule{{ID: "X"}}}
	RefreshIssueSeeds(rf, nil)
}

// ---------------------------------------------------------------------------
// FinalizeExecutionResult — nil result (87.5%)
// ---------------------------------------------------------------------------

func TestFinalizeExecutionResult_NilResult(t *testing.T) {
	t.Parallel()

	rf := &RuleFile{Rules: []Rule{{ID: "X"}}}
	FinalizeExecutionResult(rf, nil)
}

// ---------------------------------------------------------------------------
// allEvidenceFromTestScope — empty evidence (83.3%)
// ---------------------------------------------------------------------------

func TestAllEvidenceFromTestScope_EmptyEvidence(t *testing.T) {
	t.Parallel()

	got := allEvidenceFromTestScope(nil)
	if got {
		t.Error("expected false for nil evidence")
	}
	got = allEvidenceFromTestScope([]Evidence{})
	if got {
		t.Error("expected false for empty evidence")
	}
}

// ---------------------------------------------------------------------------
// classifySecretPriority — cover more branches (83.3%)
// ---------------------------------------------------------------------------

func TestClassifySecretPriority(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name             string
		secret           facts.SecretFact
		expectedPriority secretPriority
		expectedClass    string
	}{
		{
			"test fixture",
			facts.SecretFact{File: "test/fixtures/auth_test.go", Value: "supersecret", Kind: "password"},
			secretPriorityTestFixture, "test_fixture",
		},
		{
			"sample file",
			facts.SecretFact{File: "sample_config.go", Value: "testkey", Kind: "api_key"},
			secretPriorityTestFixture, "test_fixture",
		},
		{
			"harmless label - key name",
			facts.SecretFact{File: "auth.go", Value: "my_auth_key_name", Kind: "api_key"},
			secretPriorityHarmlessLabel, "storage_key_label",
		},
		{
			"production fallback in main",
			facts.SecretFact{File: "main.ts", Value: "secretvalue", Kind: "jwt_secret"},
			secretPriorityProductionFallback, "production_fallback",
		},
		{
			"production fallback in config",
			facts.SecretFact{File: "config.ts", Value: "secretvalue", Kind: "jwt_secret"},
			secretPriorityProductionFallback, "production_fallback",
		},
		{
			"production fallback in module",
			facts.SecretFact{File: "auth.module.ts", Value: "secret", Kind: "jwt_secret"},
			secretPriorityProductionFallback, "production_fallback",
		},
		{
			"production fallback in strategy",
			facts.SecretFact{File: "jwt.strategy.ts", Value: "secret", Kind: "jwt_secret"},
			secretPriorityProductionFallback, "production_fallback",
		},
		{
			"production fallback in bootstrap",
			facts.SecretFact{File: "bootstrap.ts", Value: "secret", Kind: "jwt_secret"},
			secretPriorityProductionFallback, "production_fallback",
		},
		{
			"default value pattern",
			facts.SecretFact{File: "service.ts", Value: "change_me_default", Kind: "password"},
			secretPriorityProductionFallback, "production_fallback",
		},
		{
			"real credential",
			facts.SecretFact{File: "service.go", Value: "aB3k9$lkR2mNfQwPx7Y!sT", Kind: "password"},
			secretPriorityRealCredential, "embedded_credential",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			priority, class := classifySecretPriority(tt.secret)
			if priority != tt.expectedPriority {
				t.Errorf("priority = %d, want %d", priority, tt.expectedPriority)
			}
			if class != tt.expectedClass {
				t.Errorf("class = %q, want %q", class, tt.expectedClass)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// findRateLimitMiddleware — cover class definition + binding path (78.3%)
// ---------------------------------------------------------------------------

func TestFindRateLimitMiddleware_ClassWithBinding(t *testing.T) {
	t.Parallel()

	rule := Rule{
		ID: "SEC-RATE-001", Type: "exists", Target: "rate_limit.middleware",
		Languages: []string{"typescript"}, Message: "Rate limit required.",
	}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			{Name: "RateLimitInterceptor", Kind: "class", File: "rate-limit.interceptor.ts",
				Language: facts.LangTypeScript, Exported: true, Span: facts.Span{Start: 1, End: 20}},
			{Name: "APP_INTERCEPTOR", Kind: "provider_registration", File: "app.module.ts",
				Language: facts.LangTypeScript, Exported: true, Span: facts.Span{Start: 5, End: 5}},
		},
		Middlewares: []facts.MiddlewareFact{},
	}
	evidence := findRateLimitMiddleware(rule, fs)
	if len(evidence) == 0 {
		t.Error("expected evidence from class definition with binding")
	}
}

func TestFindRateLimitMiddleware_ClassWithoutBinding(t *testing.T) {
	t.Parallel()

	rule := Rule{
		ID: "SEC-RATE-001", Type: "exists", Target: "rate_limit.middleware",
		Languages: []string{"typescript"}, Message: "Rate limit required.",
	}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			{Name: "ThrottleGuard", Kind: "class", File: "throttle.guard.ts",
				Language: facts.LangTypeScript, Exported: true, Span: facts.Span{Start: 1, End: 20}},
		},
		Middlewares: []facts.MiddlewareFact{},
	}
	evidence := findRateLimitMiddleware(rule, fs)
	if len(evidence) != 0 {
		t.Error("expected no evidence from class definition without binding")
	}
}

func TestFindRateLimitMiddleware_SkipTestFiles(t *testing.T) {
	t.Parallel()

	rule := Rule{
		ID: "SEC-RATE-001", Type: "exists", Target: "rate_limit.middleware",
		Languages: []string{"go"}, Message: "Rate limit required.",
	}
	fs := &FactSet{
		Middlewares: []facts.MiddlewareFact{
			mw("rateLimit", "middleware", "rate_test.go", facts.LangGo),
		},
		Symbols: []facts.SymbolFact{
			sym("main", "function", "main.go", facts.LangGo, false, 1, 5),
		},
	}
	evidence := findRateLimitMiddleware(rule, fs)
	if len(evidence) != 0 {
		t.Error("expected no evidence from test files")
	}
}

// ---------------------------------------------------------------------------
// findRequestLogging — cover NestJS interceptor path (71.4%)
// ---------------------------------------------------------------------------

func TestFindRequestLogging_NestJSInterceptorWithBinding(t *testing.T) {
	t.Parallel()

	rule := Rule{
		ID: "QUAL-LOG-002", Type: "exists", Target: "logging.request_logging",
		Languages: []string{"typescript"}, Message: "Request logging needed.",
	}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			{Name: "LoggingInterceptor", Kind: "class", File: "logging.interceptor.ts",
				Language: facts.LangTypeScript, Exported: true, Span: facts.Span{Start: 1, End: 20}},
			{Name: "APP_INTERCEPTOR", Kind: "provider_registration", File: "app.module.ts",
				Language: facts.LangTypeScript, Exported: true, Span: facts.Span{Start: 5, End: 5}},
		},
		Middlewares: []facts.MiddlewareFact{},
		Imports:     []facts.ImportFact{},
	}
	evidence := findRequestLogging(rule, fs)
	if len(evidence) == 0 {
		t.Error("expected evidence from NestJS interceptor with binding")
	}
}

func TestFindRequestLogging_NestJSInterceptorWithoutBinding(t *testing.T) {
	t.Parallel()

	rule := Rule{
		ID: "QUAL-LOG-002", Type: "exists", Target: "logging.request_logging",
		Languages: []string{"typescript"}, Message: "Request logging needed.",
	}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			{Name: "MetricsInterceptor", Kind: "class", File: "metrics.interceptor.ts",
				Language: facts.LangTypeScript, Exported: true, Span: facts.Span{Start: 1, End: 20}},
		},
		Middlewares: []facts.MiddlewareFact{},
		Imports:     []facts.ImportFact{},
	}
	evidence := findRequestLogging(rule, fs)
	if len(evidence) != 0 {
		t.Error("expected no evidence from interceptor without binding")
	}
}

func TestFindRequestLogging_SkipTestFiles(t *testing.T) {
	t.Parallel()

	rule := Rule{
		ID: "QUAL-LOG-002", Type: "exists", Target: "logging.request_logging",
		Languages: []string{"go"}, Message: "Request logging needed.",
	}
	fs := &FactSet{
		Middlewares: []facts.MiddlewareFact{
			mw("logger", "middleware", "test/fixtures/log_test.go", facts.LangGo),
		},
		Imports: []facts.ImportFact{
			imp("morgan", "", "test/fixtures/setup.js", facts.LangGo),
		},
		Symbols: []facts.SymbolFact{},
	}
	evidence := findRequestLogging(rule, fs)
	if len(evidence) != 0 {
		t.Error("expected no evidence from test files")
	}
}

// ---------------------------------------------------------------------------
// findEnvFileCommitted — cover .env.example exclusion (87.5%)
// ---------------------------------------------------------------------------

func TestFindEnvFileCommitted_ExcludesExamples(t *testing.T) {
	t.Parallel()

	rule := Rule{
		ID: "SEC-SECRET-003", Type: "not_exists", Target: "secret.env_file_committed",
		Languages: []string{"go"}, Message: ".env files must not be committed.",
	}
	fs := &FactSet{
		Files: []facts.FileFact{
			fileFact(".env.example", facts.LangGo),
			fileFact(".env.template", facts.LangGo),
			fileFact(".env.sample", facts.LangGo),
		},
	}
	evidence := findEnvFileCommitted(rule, fs)
	if len(evidence) != 0 {
		t.Errorf("expected no evidence for example/template/sample files, got %d", len(evidence))
	}
}

func TestFindEnvFileCommitted_DetectsRealEnvFiles(t *testing.T) {
	t.Parallel()

	rule := Rule{
		ID: "SEC-SECRET-003", Type: "not_exists", Target: "secret.env_file_committed",
		Languages: []string{"go"}, Message: ".env files must not be committed.",
	}
	fs := &FactSet{
		Files: []facts.FileFact{
			fileFact(".env", facts.LangGo),
			fileFact(".env.local", facts.LangGo),
			fileFact(".env.production", facts.LangGo),
			fileFact(".env.development", facts.LangGo),
		},
	}
	evidence := findEnvFileCommitted(rule, fs)
	if len(evidence) != 4 {
		t.Errorf("expected 4 env file findings, got %d", len(evidence))
	}
}

// ---------------------------------------------------------------------------
// findJWTMiddlewareResult — cover binding evidence path (88.9%)
// ---------------------------------------------------------------------------

func TestFindJWTMiddlewareResult_BindingEvidence(t *testing.T) {
	t.Parallel()

	rule := Rule{
		ID: "SEC-AUTH-001", Type: "exists", Target: "auth.jwt_middleware",
		Languages: []string{"typescript"}, Message: "JWT must exist.",
	}
	fs := &FactSet{
		AppBindings: []facts.AppBindingFact{
			{Name: "JwtAuthGuard", Kind: "guard", File: "app.module.ts",
				Language: facts.LangTypeScript, Span: facts.Span{Start: 1, End: 1}},
		},
		Symbols: []facts.SymbolFact{
			sym("main", "function", "main.ts", facts.LangTypeScript, false, 1, 5),
		},
	}
	result := findJWTMiddlewareResult(rule, fs)
	if len(result.Evidence) == 0 {
		t.Error("expected binding evidence for JWT middleware")
	}
	if result.VerificationLevel != VerificationStrongInference {
		t.Errorf("expected strong_inference, got %v", result.VerificationLevel)
	}
}

func TestFindJWTMiddlewareResult_FallbackToImportsAndSymbols(t *testing.T) {
	t.Parallel()

	rule := Rule{
		ID: "SEC-AUTH-001", Type: "exists", Target: "auth.jwt_middleware",
		Languages: []string{"go"}, Message: "JWT must exist.",
	}
	fs := &FactSet{
		Imports: []facts.ImportFact{
			imp("github.com/golang-jwt/jwt", "", "auth.go", facts.LangGo),
		},
		Symbols: []facts.SymbolFact{
			sym("verifyToken", "function", "auth.go", facts.LangGo, true, 10, 20),
		},
		Middlewares: []facts.MiddlewareFact{},
	}
	result := findJWTMiddlewareResult(rule, fs)
	if len(result.Evidence) == 0 {
		t.Error("expected evidence from JWT imports and symbols fallback")
	}
	if result.VerificationLevel != VerificationWeakInference {
		t.Errorf("expected weak_inference for fallback, got %v", result.VerificationLevel)
	}
}

// ---------------------------------------------------------------------------
// findExistsEvidenceResult — cover env_based path (83.3%)
// ---------------------------------------------------------------------------

func TestFindExistsEvidenceResult_EnvBased(t *testing.T) {
	t.Parallel()

	rule := Rule{
		ID: "SEC-SECRET-002", Type: "exists", Target: "config.env_based",
		Languages: []string{"go"}, Message: "Env config must exist.",
	}
	fs := &FactSet{
		Imports: []facts.ImportFact{
			imp("github.com/joho/godotenv", "", "main.go", facts.LangGo),
		},
		Symbols: []facts.SymbolFact{
			sym("main", "function", "main.go", facts.LangGo, false, 1, 5),
		},
	}
	result := findExistsEvidenceResult(rule, fs)
	if len(result.Evidence) == 0 {
		t.Error("expected evidence for env-based config")
	}
}

// ---------------------------------------------------------------------------
// findEnvBasedConfigResult — cover ConfigReads path (88.9%)
// ---------------------------------------------------------------------------

func TestFindEnvBasedConfigResult_WithConfigReads(t *testing.T) {
	t.Parallel()

	rule := Rule{
		ID: "SEC-SECRET-002", Type: "exists", Target: "config.env_based",
		Languages: []string{"go"}, Message: "Env config must exist.",
	}
	fs := &FactSet{
		ConfigReads: []facts.ConfigReadFact{
			{Key: "DATABASE_URL", SourceKind: "env", File: "config.go",
				Language: facts.LangGo, Span: facts.Span{Start: 1, End: 1}},
		},
		Symbols: []facts.SymbolFact{
			sym("main", "function", "main.go", facts.LangGo, false, 1, 5),
		},
	}
	result := findEnvBasedConfigResult(rule, fs)
	if len(result.Evidence) == 0 {
		t.Error("expected evidence from ConfigReads")
	}
	if result.VerificationLevel != VerificationStrongInference {
		t.Errorf("expected strong_inference for ConfigReads path, got %v", result.VerificationLevel)
	}
}

func TestFindEnvBasedConfigResult_ConfigReadsNoEnv(t *testing.T) {
	t.Parallel()

	rule := Rule{
		ID: "SEC-SECRET-002", Type: "exists", Target: "config.env_based",
		Languages: []string{"go"}, Message: "Env config must exist.",
	}
	fs := &FactSet{
		ConfigReads: []facts.ConfigReadFact{
			{Key: "API_KEY", SourceKind: "file", File: "config.go",
				Language: facts.LangGo, Span: facts.Span{Start: 1, End: 1}},
		},
		Imports: []facts.ImportFact{
			imp("github.com/joho/godotenv", "", "config.go", facts.LangGo),
		},
		Symbols: []facts.SymbolFact{
			sym("main", "function", "main.go", facts.LangGo, false, 1, 5),
		},
	}
	result := findEnvBasedConfigResult(rule, fs)
	if result.VerificationLevel != VerificationVerified {
		t.Errorf("expected verified for heuristic fallback, got %v", result.VerificationLevel)
	}
}

// ---------------------------------------------------------------------------
// findCORSPermissive — exact match (87.5%)
// ---------------------------------------------------------------------------

func TestFindCORSPermissive_NoMatch(t *testing.T) {
	t.Parallel()

	rule := Rule{
		ID: "SEC-CORS-001", Type: "exists", Target: "security.cors_configuration",
		Languages: []string{"go"}, Message: "CORS must be configured.",
	}
	fs := &FactSet{
		Middlewares: []facts.MiddlewareFact{
			mw("cors", "middleware", "server.go", facts.LangGo),
		},
	}
	evidence := findCORSPermissive(rule, fs)
	if len(evidence) != 0 {
		t.Errorf("expected no permissive evidence, got %d", len(evidence))
	}
}

// ---------------------------------------------------------------------------
// hasRuntimeBindingEvidence — cover all kinds (83.3%)
// ---------------------------------------------------------------------------

func TestHasRuntimeBindingEvidence_GlobalRegistration(t *testing.T) {
	t.Parallel()

	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			{Name: "APP_FILTER", Kind: "global_registration", File: "app.module.ts",
				Language: facts.LangTypeScript, Span: facts.Span{Start: 1, End: 1}},
		},
	}
	if !hasRuntimeBindingEvidence(fs, []string{"typescript"}) {
		t.Error("expected binding evidence for global_registration")
	}
}

func TestHasRuntimeBindingEvidence_MiddlewareRegistration(t *testing.T) {
	t.Parallel()

	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			{Name: "consumer.apply", Kind: "middleware_registration", File: "app.module.ts",
				Language: facts.LangTypeScript, Span: facts.Span{Start: 1, End: 1}},
		},
	}
	if !hasRuntimeBindingEvidence(fs, []string{"typescript"}) {
		t.Error("expected binding evidence for middleware_registration")
	}
}

func TestHasRuntimeBindingEvidence_NoBinding(t *testing.T) {
	t.Parallel()

	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			{Name: "MyClass", Kind: "class", File: "my.ts",
				Language: facts.LangTypeScript, Span: facts.Span{Start: 1, End: 1}},
		},
	}
	if hasRuntimeBindingEvidence(fs, []string{"typescript"}) {
		t.Error("expected no binding evidence for regular class")
	}
}

// ---------------------------------------------------------------------------
// findAPIKeyValidation — cover pattern match (88.9%)
// ---------------------------------------------------------------------------

func TestFindAPIKeyValidation_MatchesApiKeyPattern(t *testing.T) {
	t.Parallel()

	rule := Rule{
		ID: "SEC-AUTH-003", Type: "exists", Target: "auth.api_key_validation",
		Languages: []string{"go"}, Message: "API key validation needed.",
	}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("ValidateAPIKey", "function", "auth.go", facts.LangGo, true, 1, 10),
		},
	}
	evidence := findAPIKeyValidation(rule, fs)
	if len(evidence) == 0 {
		t.Error("expected evidence for API key validation")
	}
}

// ---------------------------------------------------------------------------
// findJWTByImportsAndSymbols — no JWT imports (89.5%)
// ---------------------------------------------------------------------------

func TestFindJWTByImportsAndSymbols_NoJWTImports(t *testing.T) {
	t.Parallel()

	rule := Rule{
		ID: "SEC-AUTH-001", Type: "exists", Target: "auth.jwt_middleware",
		Languages: []string{"go"}, Message: "JWT must exist.",
	}
	fs := &FactSet{
		Imports: []facts.ImportFact{
			imp("fmt", "", "main.go", facts.LangGo),
		},
		Symbols: []facts.SymbolFact{
			sym("main", "function", "main.go", facts.LangGo, false, 1, 5),
		},
	}
	evidence := findJWTByImportsAndSymbols(rule, fs)
	if len(evidence) != 0 {
		t.Errorf("expected no evidence when no JWT imports, got %d", len(evidence))
	}
}

// ---------------------------------------------------------------------------
// findStructuredLogging — skip test files (90.9%)
// ---------------------------------------------------------------------------

func TestFindStructuredLogging_SkipsTestFiles(t *testing.T) {
	t.Parallel()

	rule := Rule{
		ID: "QUAL-LOG-001", Type: "exists", Target: "logging.structured",
		Languages: []string{"go"}, Message: "Structured logging needed.",
	}
	fs := &FactSet{
		Imports: []facts.ImportFact{
			imp("go.uber.org/zap", "", "test/fixtures/log_test.go", facts.LangGo),
		},
	}
	evidence := findStructuredLogging(rule, fs)
	if len(evidence) != 0 {
		t.Error("expected no evidence from test files")
	}
}

// ---------------------------------------------------------------------------
// findGlobalErrorHandler — cover class-based with/without binding (91.3%)
// ---------------------------------------------------------------------------

func TestFindGlobalErrorHandler_ClassWithBinding(t *testing.T) {
	t.Parallel()

	rule := Rule{
		ID: "ARCH-ERR-001", Type: "exists", Target: "error.global_handler",
		Languages: []string{"typescript"}, Message: "Error handler needed.",
	}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			{Name: "HttpExceptionFilter", Kind: "class", File: "exception.filter.ts",
				Language: facts.LangTypeScript, Exported: true, Span: facts.Span{Start: 1, End: 20}},
			{Name: "APP_FILTER", Kind: "provider_registration", File: "app.module.ts",
				Language: facts.LangTypeScript, Exported: true, Span: facts.Span{Start: 5, End: 5}},
		},
		Middlewares: []facts.MiddlewareFact{},
	}
	evidence := findGlobalErrorHandler(rule, fs)
	if len(evidence) == 0 {
		t.Error("expected evidence from exception filter class with binding")
	}
}

func TestFindGlobalErrorHandler_ClassWithoutBinding(t *testing.T) {
	t.Parallel()

	rule := Rule{
		ID: "ARCH-ERR-001", Type: "exists", Target: "error.global_handler",
		Languages: []string{"typescript"}, Message: "Error handler needed.",
	}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			{Name: "HttpExceptionFilter", Kind: "class", File: "exception.filter.ts",
				Language: facts.LangTypeScript, Exported: true, Span: facts.Span{Start: 1, End: 20}},
		},
		Middlewares: []facts.MiddlewareFact{},
	}
	evidence := findGlobalErrorHandler(rule, fs)
	if len(evidence) != 0 {
		t.Error("expected no evidence from class without binding")
	}
}

func TestFindGlobalErrorHandler_SkipTestFiles(t *testing.T) {
	t.Parallel()

	rule := Rule{
		ID: "ARCH-ERR-001", Type: "exists", Target: "error.global_handler",
		Languages: []string{"go"}, Message: "Error handler needed.",
	}
	fs := &FactSet{
		Middlewares: []facts.MiddlewareFact{
			mw("errorHandler", "middleware", "test/fixtures/setup.go", facts.LangGo),
		},
		Symbols: []facts.SymbolFact{
			{Name: "ExceptionHandler", Kind: "class", File: "test/handler_test.go",
				Language: facts.LangGo, Exported: true, Span: facts.Span{Start: 1, End: 20}},
		},
	}
	evidence := findGlobalErrorHandler(rule, fs)
	if len(evidence) != 0 {
		t.Error("expected no evidence from test files")
	}
}

// ---------------------------------------------------------------------------
// findInputValidation — provider_registration coverage (92.7%)
// ---------------------------------------------------------------------------

func TestFindInputValidation_ProviderRegistration(t *testing.T) {
	t.Parallel()

	rule := Rule{
		ID: "SEC-INPUT-001", Type: "exists", Target: "security.input_validation",
		Languages: []string{"typescript"}, Message: "Input validation needed.",
	}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			{Name: "ValidationPipe", Kind: "provider_registration", File: "app.module.ts",
				Language: facts.LangTypeScript, Exported: true, Span: facts.Span{Start: 5, End: 5}},
		},
		Imports: []facts.ImportFact{},
	}
	evidence := findInputValidation(rule, fs)
	if len(evidence) == 0 {
		t.Error("expected evidence from provider_registration")
	}
}

// ---------------------------------------------------------------------------
// filepathToSlash — backslash conversion
// ---------------------------------------------------------------------------

func TestFilepathToSlash(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input    string
		expected string
	}{
		{`src\main.go`, "src/main.go"},
		{`src/main.go`, "src/main.go"},
	}

	for _, tt := range tests {
		got := filepathToSlash(tt.input)
		if got != tt.expected {
			t.Errorf("filepathToSlash(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

// ---------------------------------------------------------------------------
// ClassifyMiddlewareName — session special rule (92.9%)
// ---------------------------------------------------------------------------

func TestClassifyMiddlewareName_SessionWithAuth(t *testing.T) {
	t.Parallel()

	hasAuth, hasContra := ClassifyMiddlewareName("sessionAuth")
	if !hasAuth {
		t.Error("expected hasAuth=true for sessionAuth")
	}
	if hasContra {
		t.Error("expected hasContradictory=false when auth overrides")
	}
}

func TestClassifyMiddlewareName_SessionOnly(t *testing.T) {
	t.Parallel()

	hasAuth, hasContra := ClassifyMiddlewareName("sessionMiddleware")
	if hasAuth {
		t.Error("expected hasAuth=false for session-only middleware")
	}
	if !hasContra {
		t.Error("expected hasContradictory=true for session-only middleware")
	}
}

// ---------------------------------------------------------------------------
// analyzerCoverageForRule — empty relevant languages (92.3%)
// ---------------------------------------------------------------------------

func TestAnalyzerCoverageForRule_NoRelevantLanguages(t *testing.T) {
	t.Parallel()

	fs := &FactSet{
		AnalyzerStatus: map[string]string{"go": "ok"},
	}
	got := analyzerCoverageForRule(fs, []string{"python"}, []string{"go"})
	if got != analyzerCoverageOK {
		t.Errorf("expected OK when no relevant languages, got %v", got)
	}
}

// ---------------------------------------------------------------------------
// findSecurityHeaders — match "secure" exact segment (95.2%)
// ---------------------------------------------------------------------------

func TestFindSecurityHeaders_ExactSecurePackage(t *testing.T) {
	t.Parallel()

	rule := Rule{
		ID: "SEC-HELMET-001", Type: "exists", Target: "security.headers_middleware",
		Languages: []string{"go"}, Message: "Security headers needed.",
	}
	fs := &FactSet{
		Imports: []facts.ImportFact{
			imp("github.com/unrolled/secure", "", "server.go", facts.LangGo),
		},
		Symbols: []facts.SymbolFact{
			sym("main", "function", "main.go", facts.LangGo, false, 1, 5),
		},
	}
	evidence := findSecurityHeaders(rule, fs)
	if len(evidence) == 0 {
		t.Error("expected evidence for exact 'secure' package")
	}
}

// ---------------------------------------------------------------------------
// matchRule — default unsupported type (from matchers.go)
// ---------------------------------------------------------------------------

func TestMatchRule_UnsupportedType(t *testing.T) {
	t.Parallel()

	rule := Rule{
		ID: "TEST-001", Type: "custom_type", Target: "something",
		Languages: []string{"go"}, Message: "Test.",
	}
	fs := &FactSet{}
	finding := matchRule(rule, fs, []string{"go"})
	if finding.Status != StatusUnknown {
		t.Errorf("expected unknown for unsupported type, got %v", finding.Status)
	}
}

// ---------------------------------------------------------------------------
// hasMinimalFacts — cover nil and RouteFact/FileFact branches
// ---------------------------------------------------------------------------

func TestHasMinimalFacts_NilFactSet(t *testing.T) {
	t.Parallel()

	if hasMinimalFacts(nil, []string{"SymbolFact"}) {
		t.Error("expected false for nil FactSet")
	}
}

func TestHasMinimalFacts_RouteFactPresent(t *testing.T) {
	t.Parallel()

	fs := &FactSet{
		Routes: []facts.RouteFact{
			route("GET", "/health", "handler", "routes.go", facts.LangGo, nil),
		},
	}
	if !hasMinimalFacts(fs, []string{"RouteFact"}) {
		t.Error("expected true when RouteFact present")
	}
}

func TestHasMinimalFacts_RouteFactAbsent(t *testing.T) {
	t.Parallel()

	fs := &FactSet{}
	if hasMinimalFacts(fs, []string{"RouteFact"}) {
		t.Error("expected false when RouteFact missing")
	}
}

func TestHasMinimalFacts_FileFactPresent(t *testing.T) {
	t.Parallel()

	fs := &FactSet{
		Files: []facts.FileFact{
			fileFact("main.go", facts.LangGo),
		},
	}
	if !hasMinimalFacts(fs, []string{"FileFact"}) {
		t.Error("expected true when FileFact present")
	}
}

func TestHasMinimalFacts_FileFactAbsent(t *testing.T) {
	t.Parallel()

	fs := &FactSet{}
	if hasMinimalFacts(fs, []string{"FileFact"}) {
		t.Error("expected false when FileFact missing")
	}
}

// ---------------------------------------------------------------------------
// findEnvBasedConfig — cover ConfigReads with env entries (95.7%)
// ---------------------------------------------------------------------------

func TestFindEnvBasedConfig_ConfigReadsEnv(t *testing.T) {
	t.Parallel()

	rule := Rule{
		ID: "SEC-SECRET-002", Type: "exists", Target: "config.env_based",
		Languages: []string{"go"}, Message: "Env config must exist.",
	}
	fs := &FactSet{
		ConfigReads: []facts.ConfigReadFact{
			{Key: "DB_URL", SourceKind: "env", File: "config.go",
				Language: facts.LangGo, Span: facts.Span{Start: 1, End: 1}},
		},
	}
	evidence := findEnvBasedConfig(rule, fs)
	if len(evidence) == 0 {
		t.Error("expected evidence from ConfigReads env entries")
	}
}

// ---------------------------------------------------------------------------
// findAuthBindingEvidence — cover RouteBindings guards path (95.2%)
// ---------------------------------------------------------------------------

func TestFindAuthBindingEvidence_RouteBindingGuards(t *testing.T) {
	t.Parallel()

	rule := Rule{
		ID: "SEC-AUTH-001", Type: "exists", Target: "auth.jwt_middleware",
		Languages: []string{"typescript"}, Message: "JWT must exist.",
	}
	fs := &FactSet{
		RouteBindings: []facts.RouteBindingFact{
			{Handler: "getUsers", Guards: []string{"JwtAuthGuard"}, File: "users.controller.ts",
				Language: facts.LangTypeScript, Span: facts.Span{Start: 1, End: 1}},
		},
	}
	evidence := findAuthBindingEvidence(rule, fs)
	if len(evidence) == 0 {
		t.Error("expected evidence from route binding guards")
	}
}

func TestFindAuthBindingEvidence_RouteBindingMiddlewares(t *testing.T) {
	t.Parallel()

	rule := Rule{
		ID: "SEC-AUTH-001", Type: "exists", Target: "auth.jwt_middleware",
		Languages: []string{"typescript"}, Message: "JWT must exist.",
	}
	fs := &FactSet{
		RouteBindings: []facts.RouteBindingFact{
			{Handler: "getUsers", Middlewares: []string{"authMiddleware"}, File: "users.controller.ts",
				Language: facts.LangTypeScript, Span: facts.Span{Start: 1, End: 1}},
		},
	}
	evidence := findAuthBindingEvidence(rule, fs)
	if len(evidence) == 0 {
		t.Error("expected evidence from route binding middlewares")
	}
}
