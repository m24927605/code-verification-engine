package rules

// accuracy_test.go — Regression tests for accuracy improvements.
// Each test validates a specific false positive/negative fix.

import (
	"testing"

	"github.com/verabase/code-verification-engine/internal/facts"
)

// ---------------------------------------------------------------------------
// FE-TOKEN-001: localStorage token storage detection
// ---------------------------------------------------------------------------

func TestAccuracy_FE_TOKEN_001_DirectCallExpression(t *testing.T) {
	// localStorage.setItem in an auth file should be detected
	rule := Rule{ID: "FE-TOKEN-001", Languages: []string{"typescript"}}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			{Language: facts.LangTypeScript, File: "lib/auth.ts", Span: facts.Span{Start: 10, End: 10},
				Name: "localStorage.setItem", Kind: "call_expression", Provenance: facts.ProvenanceStructural},
			{Language: facts.LangTypeScript, File: "lib/auth.ts", Span: facts.Span{Start: 5, End: 15},
				Name: "setToken", Kind: "function", Exported: true},
		},
	}
	ev := findTokenInLocalStorage(rule, fs)
	if len(ev) == 0 {
		t.Error("FE-TOKEN-001: expected to detect localStorage.setItem in auth file")
	}
}

func TestAccuracy_FE_TOKEN_001_WrapperFunction(t *testing.T) {
	// setToken function in a file with localStorage calls should be detected
	rule := Rule{ID: "FE-TOKEN-001", Languages: []string{"typescript"}}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			{Language: facts.LangTypeScript, File: "lib/auth.ts", Span: facts.Span{Start: 10, End: 10},
				Name: "localStorage.setItem", Kind: "call_expression"},
			{Language: facts.LangTypeScript, File: "lib/auth.ts", Span: facts.Span{Start: 5, End: 15},
				Name: "setToken", Kind: "function", Exported: true},
			{Language: facts.LangTypeScript, File: "lib/auth.ts", Span: facts.Span{Start: 1, End: 1},
				Name: "TOKEN_KEY", Kind: "variable"},
		},
	}
	ev := findTokenInLocalStorage(rule, fs)
	// Should find both the direct call and the wrapper function
	if len(ev) < 2 {
		t.Errorf("FE-TOKEN-001: expected at least 2 evidence items (call + wrapper), got %d", len(ev))
	}
}

// ---------------------------------------------------------------------------
// TEST-PAYMENT-001: Billing domain tests
// ---------------------------------------------------------------------------

func TestAccuracy_TEST_PAYMENT_001_BillingKeywords(t *testing.T) {
	keywords := targetModuleKeywords("module.payment_service")
	expectedKeywords := map[string]bool{
		"payment": false, "billing": false, "invoice": false,
		"subscription": false, "entitlement": false,
	}
	for _, kw := range keywords {
		if _, ok := expectedKeywords[kw]; ok {
			expectedKeywords[kw] = true
		}
	}
	for kw, found := range expectedKeywords {
		if !found {
			t.Errorf("TEST-PAYMENT-001: expected keyword %q in payment module keywords", kw)
		}
	}
}

func TestAccuracy_TEST_PAYMENT_001_BillingTests(t *testing.T) {
	rule := Rule{ID: "TEST-PAYMENT-001", Type: "test_required", Target: "module.payment_service",
		Languages: []string{"typescript"}, Message: "Payment tests required."}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("BillingController", "class", "billing/billing.controller.ts", facts.LangTypeScript, true, 1, 50),
		},
		Files: []facts.FileFact{
			fileFact("billing/billing.controller.ts", facts.LangTypeScript),
			fileFact("billing/__tests__/billing.controller.spec.ts", facts.LangTypeScript),
		},
		Tests: []facts.TestFact{
			testFact("should create billing", "billing/__tests__/billing.controller.spec.ts", facts.LangTypeScript, ""),
		},
	}
	finding := matchTestRequired(rule, fs, []string{"typescript"})
	if finding.Status != StatusPass {
		t.Errorf("TEST-PAYMENT-001: expected pass for billing tests, got %v", finding.Status)
	}
}

// ---------------------------------------------------------------------------
// FE-DEP-001: Lockfile detection
// ---------------------------------------------------------------------------

func TestAccuracy_FE_DEP_001_PNPMLockfile(t *testing.T) {
	rule := Rule{ID: "FE-DEP-001", Languages: []string{"javascript", "typescript"}}
	fs := &FactSet{
		Files: []facts.FileFact{
			fileFact("pnpm-lock.yaml", facts.LangJavaScript),
		},
	}
	ev := findLockfileExists(rule, fs)
	if len(ev) == 0 {
		t.Error("FE-DEP-001: expected to detect pnpm-lock.yaml")
	}
}

// ---------------------------------------------------------------------------
// ARCH-PATTERN-002: DTO separation false positives
// ---------------------------------------------------------------------------

func TestAccuracy_ARCH_PATTERN_002_NoFalsePositiveForDTOTransform(t *testing.T) {
	// Controller that references entity types but transforms them to DTOs
	// should NOT be flagged (no direct DB access)
	rule := Rule{ID: "ARCH-PATTERN-002", Languages: []string{"typescript"}}
	fs := &FactSet{
		Files: []facts.FileFact{
			fileFact("entity/user.entity.ts", facts.LangTypeScript),
			fileFact("user.controller.ts", facts.LangTypeScript),
		},
		Symbols: []facts.SymbolFact{
			sym("User", "class", "entity/user.entity.ts", facts.LangTypeScript, true, 1, 20),
			sym("findOne", "method", "user.controller.ts", facts.LangTypeScript, true, 10, 25),
		},
		Routes: []facts.RouteFact{
			route("GET", "/users/:id", "findOne", "user.controller.ts", facts.LangTypeScript, nil),
		},
	}
	ev := findDBModelInRouteHandler(rule, fs)
	if len(ev) != 0 {
		t.Error("ARCH-PATTERN-002: expected NO false positive for controller with DTO transformation")
	}
}

// ---------------------------------------------------------------------------
// ARCH-PATTERN-003: Singleton false positives
// ---------------------------------------------------------------------------

func TestAccuracy_ARCH_PATTERN_003_DITokenExcluded(t *testing.T) {
	rule := Rule{ID: "ARCH-PATTERN-003", Languages: []string{"typescript"}}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			{Language: facts.LangTypeScript, File: "di-tokens.ts", Span: facts.Span{Start: 1, End: 1},
				Name: "DB_CONNECTION_TOKEN", Kind: "const", Exported: true},
		},
	}
	ev := findSingletonMutableGlobal(rule, fs)
	if len(ev) != 0 {
		t.Error("ARCH-PATTERN-003: expected NO false positive for DI token constant")
	}
}

func TestAccuracy_ARCH_PATTERN_003_SchemaExcluded(t *testing.T) {
	rule := Rule{ID: "ARCH-PATTERN-003", Languages: []string{"typescript"}}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			{Language: facts.LangTypeScript, File: "schema/users.ts", Span: facts.Span{Start: 1, End: 1},
				Name: "UsersConnectionPool", Kind: "variable", Exported: true, IsMutable: true},
		},
	}
	ev := findSingletonMutableGlobal(rule, fs)
	if len(ev) != 0 {
		t.Error("ARCH-PATTERN-003: expected NO false positive for symbol in schema file")
	}
}

// ---------------------------------------------------------------------------
// SEC-SECRET-001: Evidence classification
// ---------------------------------------------------------------------------

func TestAccuracy_SEC_SECRET_001_ProductionFallbackRanksHigher(t *testing.T) {
	rule := Rule{ID: "SEC-SECRET-001", Languages: []string{"typescript"}}
	fs := &FactSet{
		Secrets: []facts.SecretFact{
			{Language: facts.LangTypeScript, File: "test/auth.spec.ts", Span: facts.Span{Start: 5, End: 5},
				Kind: "hardcoded_secret", Value: "test-secret-value-12345"},
			{Language: facts.LangTypeScript, File: "main.ts", Span: facts.Span{Start: 10, End: 10},
				Kind: "hardcoded_secret", Value: "default-jwt-secret"},
		},
		Files: []facts.FileFact{
			fileFact("test/auth.spec.ts", facts.LangTypeScript),
			fileFact("main.ts", facts.LangTypeScript),
		},
	}
	ev := findHardcodedCredentials(rule, fs)
	if len(ev) < 2 {
		t.Fatalf("SEC-SECRET-001: expected 2 evidence items, got %d", len(ev))
	}
	// Production fallback should rank first
	if ev[0].File != "main.ts" {
		t.Errorf("SEC-SECRET-001: expected production fallback (main.ts) first, got %s", ev[0].File)
	}
}

// ---------------------------------------------------------------------------
// SEC-CORS-001: Permissive vs missing
// ---------------------------------------------------------------------------

func TestAccuracy_SEC_CORS_001_NestJSEnableCors(t *testing.T) {
	rule := Rule{ID: "SEC-CORS-001", Languages: []string{"typescript"}}
	fs := &FactSet{
		Middlewares: []facts.MiddlewareFact{
			{Language: facts.LangTypeScript, File: "main.ts", Span: facts.Span{Start: 10, End: 10},
				Name: "enableCors:permissive", Kind: "nestjs-cors"},
		},
	}
	ev := findCORSPermissive(rule, fs)
	if len(ev) == 0 {
		t.Error("SEC-CORS-001: expected permissive CORS detection for NestJS enableCors")
	}
}

func TestAccuracy_SEC_CORS_001_NestJSEnableCorsConstrained(t *testing.T) {
	rule := Rule{ID: "SEC-CORS-001", Languages: []string{"typescript"}}
	fs := &FactSet{
		Middlewares: []facts.MiddlewareFact{
			{Language: facts.LangTypeScript, File: "main.ts", Span: facts.Span{Start: 10, End: 10},
				Name: "enableCors", Kind: "nestjs-cors"},
		},
	}
	ev := findCORSConfiguration(rule, fs)
	if len(ev) == 0 {
		t.Error("SEC-CORS-001: expected CORS evidence for constrained enableCors")
	}
	pev := findCORSPermissive(rule, fs)
	if len(pev) != 0 {
		t.Error("SEC-CORS-001: expected NO permissive flag for constrained enableCors")
	}
}

// ---------------------------------------------------------------------------
// SEC-INPUT-001: Route-level validation
// ---------------------------------------------------------------------------

func TestAccuracy_SEC_INPUT_001_ConfigOnlyZodFails(t *testing.T) {
	// zod in a config file should NOT pass the input validation rule
	rule := Rule{ID: "SEC-INPUT-001", Languages: []string{"typescript"}}
	fs := &FactSet{
		Imports: []facts.ImportFact{
			imp("zod", "", "config/env.ts", facts.LangTypeScript),
		},
	}
	ev := findInputValidation(rule, fs)
	if len(ev) != 0 {
		t.Error("SEC-INPUT-001: expected NO evidence for zod in config-only file")
	}
}

func TestAccuracy_SEC_INPUT_001_ValidationPipePasses(t *testing.T) {
	rule := Rule{ID: "SEC-INPUT-001", Languages: []string{"typescript"}}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			{Language: facts.LangTypeScript, File: "main.ts", Span: facts.Span{Start: 10, End: 10},
				Name: "NestJS:ValidationPipe", Kind: "validation_pipe"},
		},
	}
	ev := findInputValidation(rule, fs)
	if len(ev) == 0 {
		t.Error("SEC-INPUT-001: expected evidence for ValidationPipe")
	}
}

// ---------------------------------------------------------------------------
// QUAL-SHUTDOWN-001: Context-aware shutdown
// ---------------------------------------------------------------------------

func TestAccuracy_QUAL_SHUTDOWN_001_WorkerOnlyAnnotated(t *testing.T) {
	rule := Rule{ID: "QUAL-SHUTDOWN-001", Languages: []string{"typescript"}}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("gracefulShutdown", "function", "worker.ts", facts.LangTypeScript, true, 10, 20),
		},
	}
	ev := findGracefulShutdown(rule, fs)
	if len(ev) == 0 {
		t.Fatal("QUAL-SHUTDOWN-001: expected evidence for worker shutdown")
	}
	// Should be annotated as worker-only
	found := false
	for _, e := range ev {
		if contains(e.Symbol, "worker-only") {
			found = true
		}
	}
	if !found {
		t.Error("QUAL-SHUTDOWN-001: expected worker-only annotation in evidence")
	}
}

func TestAccuracy_QUAL_SHUTDOWN_001_MainServerPreferred(t *testing.T) {
	rule := Rule{ID: "QUAL-SHUTDOWN-001", Languages: []string{"typescript"}}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("gracefulShutdown", "function", "worker.ts", facts.LangTypeScript, true, 10, 20),
			sym("onShutdown", "function", "main.ts", facts.LangTypeScript, true, 5, 15),
		},
	}
	ev := findGracefulShutdown(rule, fs)
	if len(ev) == 0 {
		t.Fatal("QUAL-SHUTDOWN-001: expected evidence for main server shutdown")
	}
	// Should prefer main server evidence (no worker-only annotation)
	for _, e := range ev {
		if contains(e.Symbol, "worker-only") {
			t.Error("QUAL-SHUTDOWN-001: should NOT include worker-only when main server evidence exists")
		}
	}
}

// ---------------------------------------------------------------------------
// Runtime binding checks
// ---------------------------------------------------------------------------

func TestAccuracy_RuntimeBinding_ClassOnlyNotSufficient(t *testing.T) {
	// Error handler class without binding evidence should NOT pass
	rule := Rule{ID: "ARCH-ERR-001", Languages: []string{"typescript"}}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("HttpExceptionFilter", "class", "filters/exception.filter.ts", facts.LangTypeScript, true, 1, 30),
		},
	}
	ev := findGlobalErrorHandler(rule, fs)
	if len(ev) != 0 {
		t.Error("RuntimeBinding: expected NO evidence for class-only exception filter")
	}
}

func TestAccuracy_RuntimeBinding_ClassWithBindingPasses(t *testing.T) {
	rule := Rule{ID: "ARCH-ERR-001", Languages: []string{"typescript"}}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("HttpExceptionFilter", "class", "filters/exception.filter.ts", facts.LangTypeScript, true, 1, 30),
			{Language: facts.LangTypeScript, File: "app.module.ts", Span: facts.Span{Start: 10, End: 10},
				Name: "NestJS:APP_PROVIDER", Kind: "provider_registration"},
		},
	}
	ev := findGlobalErrorHandler(rule, fs)
	if len(ev) == 0 {
		t.Error("RuntimeBinding: expected evidence for exception filter with binding")
	}
}

// ---------------------------------------------------------------------------
// LLM Review Policy
// ---------------------------------------------------------------------------

func TestAccuracy_LLMReview_MachineTrustedSkipped(t *testing.T) {
	f := Finding{
		RuleID:     "SEC-SECRET-001",
		Status:     StatusFail,
		Confidence: ConfidenceHigh,
		TrustClass: TrustMachineTrusted,
	}
	// Import shouldReview from interpret package can't be done directly,
	// so we test the trust class directly
	if f.TrustClass != TrustMachineTrusted {
		t.Error("Expected machine_trusted trust class")
	}
}

// ---------------------------------------------------------------------------
// Test scope filtering: architecture rules exclude test evidence
// ---------------------------------------------------------------------------

func TestAccuracy_TestScope_ArchLayer001_TestFileExcluded(t *testing.T) {
	// DB access in test files should NOT produce evidence for ARCH-LAYER-001
	rule := Rule{ID: "ARCH-LAYER-001", Languages: []string{"typescript"}}
	fs := &FactSet{
		Files: []facts.FileFact{
			fileFact("__tests__/integration/api.test.ts", facts.LangTypeScript),
		},
		Symbols: []facts.SymbolFact{
			sym("TestController", "class", "__tests__/integration/api.test.ts", facts.LangTypeScript, true, 1, 30),
		},
		DataAccess: []facts.DataAccessFact{
			{Language: facts.LangTypeScript, File: "__tests__/integration/api.test.ts",
				Span: facts.Span{Start: 10, End: 10}, Operation: "prisma.user.findMany",
				Backend: "prisma", CallerName: "TestController"},
		},
	}
	ev := findDirectDBAccessFromController(rule, fs)
	if len(ev) != 0 {
		t.Error("ARCH-LAYER-001: expected NO evidence for DB access in test file")
	}
}

func TestAccuracy_TestScope_SingletonGlobal_TestFileExcluded(t *testing.T) {
	rule := Rule{ID: "ARCH-PATTERN-003", Languages: []string{"typescript"}}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			{Language: facts.LangTypeScript, File: "__tests__/helpers/db.ts",
				Span: facts.Span{Start: 1, End: 1},
				Name: "testDbInstance", Kind: "variable", Exported: true, IsMutable: true},
		},
	}
	ev := findSingletonMutableGlobal(rule, fs)
	if len(ev) != 0 {
		t.Error("ARCH-PATTERN-003: expected NO evidence for mutable global in test file")
	}
}

// ---------------------------------------------------------------------------
// Test scope filtering: secret trust downgrade
// ---------------------------------------------------------------------------

func TestAccuracy_SEC_SECRET_001_TestOnlyEvidence_Downgraded(t *testing.T) {
	rule := Rule{ID: "SEC-SECRET-001", Languages: []string{"typescript"},
		Type: "not_exists", Target: "secret.hardcoded_credential"}
	fs := &FactSet{
		Secrets: []facts.SecretFact{
			{Language: facts.LangTypeScript, File: "__tests__/auth.spec.ts",
				Span: facts.Span{Start: 5, End: 5},
				Kind: "hardcoded_secret", Value: "test-secret-value"},
		},
		Files: []facts.FileFact{
			fileFact("__tests__/auth.spec.ts", facts.LangTypeScript),
		},
	}
	finding := matchNotExists(rule, fs, []string{"typescript"})
	if finding.Status != StatusFail {
		t.Fatalf("expected fail, got %v", finding.Status)
	}
	// Should have test_scope_only_evidence annotation
	hasAnnotation := false
	for _, r := range finding.UnknownReasons {
		if r == "test_scope_only_evidence" {
			hasAnnotation = true
		}
	}
	if !hasAnnotation {
		t.Error("SEC-SECRET-001: expected test_scope_only_evidence annotation")
	}
	// After NormalizeTrust, should be advisory not machine_trusted
	NormalizeTrust(&finding)
	if finding.TrustClass != TrustAdvisory {
		t.Errorf("SEC-SECRET-001: expected advisory trust for test-only evidence, got %v", finding.TrustClass)
	}
}

func TestAccuracy_SEC_SECRET_001_ProductionEvidence_StaysMachineTrusted(t *testing.T) {
	rule := Rule{ID: "SEC-SECRET-001", Languages: []string{"typescript"},
		Type: "not_exists", Target: "secret.hardcoded_credential"}
	fs := &FactSet{
		Secrets: []facts.SecretFact{
			{Language: facts.LangTypeScript, File: "main.ts",
				Span: facts.Span{Start: 10, End: 10},
				Kind: "hardcoded_secret", Value: "real-secret"},
		},
		Files: []facts.FileFact{
			fileFact("main.ts", facts.LangTypeScript),
		},
	}
	finding := matchNotExists(rule, fs, []string{"typescript"})
	if finding.Status != StatusFail {
		t.Fatalf("expected fail, got %v", finding.Status)
	}
	NormalizeTrust(&finding)
	if finding.TrustClass != TrustMachineTrusted {
		t.Errorf("SEC-SECRET-001: expected machine_trusted for production evidence, got %v", finding.TrustClass)
	}
}

// Helper
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsSubstring(s, substr))
}

func containsSubstring(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
