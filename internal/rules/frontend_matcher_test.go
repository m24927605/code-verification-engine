package rules

import (
	"testing"

	"github.com/verabase/code-verification-engine/internal/facts"
)

// --- findDangerousHTML ---

func TestFindDangerousHTML_Positive(t *testing.T) {
	rule := Rule{ID: "T-001", Languages: []string{"javascript"}}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("dangerouslySetInnerHTML", "property", "App.jsx", facts.LangJavaScript, false, 10, 10),
		},
	}
	ev := findDangerousHTML(rule, fs)
	if len(ev) == 0 {
		t.Error("expected evidence for dangerouslySetInnerHTML")
	}
}

func TestFindDangerousHTML_VHtml(t *testing.T) {
	rule := Rule{ID: "T-001", Languages: []string{"javascript"}}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("v-html", "directive", "Comp.vue", facts.LangJavaScript, false, 5, 5),
		},
	}
	ev := findDangerousHTML(rule, fs)
	if len(ev) == 0 {
		t.Error("expected evidence for v-html")
	}
}

func TestFindDangerousHTML_BypassSecurityTrustHtml(t *testing.T) {
	rule := Rule{ID: "T-001", Languages: []string{"typescript"}}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("bypassSecurityTrustHtml", "method", "app.ts", facts.LangTypeScript, false, 1, 1),
		},
	}
	ev := findDangerousHTML(rule, fs)
	if len(ev) == 0 {
		t.Error("expected evidence for bypassSecurityTrustHtml")
	}
}

func TestFindDangerousHTML_Negative(t *testing.T) {
	rule := Rule{ID: "T-001", Languages: []string{"javascript"}}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("SafeComponent", "class", "Safe.jsx", facts.LangJavaScript, true, 1, 10),
		},
	}
	ev := findDangerousHTML(rule, fs)
	if len(ev) != 0 {
		t.Errorf("expected no evidence, got %d", len(ev))
	}
}

func TestFindDangerousHTML_WrongLanguage(t *testing.T) {
	rule := Rule{ID: "T-001", Languages: []string{"javascript"}}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("dangerouslySetInnerHTML", "property", "main.go", facts.LangGo, false, 1, 1),
		},
	}
	ev := findDangerousHTML(rule, fs)
	if len(ev) != 0 {
		t.Errorf("expected no evidence for wrong language, got %d", len(ev))
	}
}

// --- findInnerHTMLUsage ---

func TestFindInnerHTMLUsage_Positive(t *testing.T) {
	rule := Rule{ID: "T-002", Languages: []string{"javascript"}}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("element.innerHTML", "property", "dom.js", facts.LangJavaScript, false, 20, 20),
		},
	}
	ev := findInnerHTMLUsage(rule, fs)
	if len(ev) == 0 {
		t.Error("expected evidence for innerHTML usage")
	}
}

func TestFindInnerHTMLUsage_Negative(t *testing.T) {
	rule := Rule{ID: "T-002", Languages: []string{"javascript"}}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("textContent", "property", "dom.js", facts.LangJavaScript, false, 5, 5),
		},
	}
	ev := findInnerHTMLUsage(rule, fs)
	if len(ev) != 0 {
		t.Errorf("expected no evidence, got %d", len(ev))
	}
}

func TestFindInnerHTMLUsage_WrongLanguage(t *testing.T) {
	rule := Rule{ID: "T-002", Languages: []string{"javascript"}}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("innerHTML", "property", "main.py", facts.LangPython, false, 1, 1),
		},
	}
	ev := findInnerHTMLUsage(rule, fs)
	if len(ev) != 0 {
		t.Errorf("expected no evidence for wrong language, got %d", len(ev))
	}
}

// --- findTokenInLocalStorage ---

func TestFindTokenInLocalStorage_Positive(t *testing.T) {
	rule := Rule{ID: "T-003", Languages: []string{"javascript"}}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("localStorageSetToken", "function", "auth.js", facts.LangJavaScript, false, 10, 15),
		},
	}
	ev := findTokenInLocalStorage(rule, fs)
	if len(ev) == 0 {
		t.Error("expected evidence for localStorage + token")
	}
}

func TestFindTokenInLocalStorage_JWT(t *testing.T) {
	rule := Rule{ID: "T-003", Languages: []string{"javascript"}}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("saveJwtToLocalStorage", "function", "auth.js", facts.LangJavaScript, false, 10, 15),
		},
	}
	ev := findTokenInLocalStorage(rule, fs)
	if len(ev) == 0 {
		t.Error("expected evidence for localStorage + jwt")
	}
}

func TestFindTokenInLocalStorage_Negative_NoToken(t *testing.T) {
	rule := Rule{ID: "T-003", Languages: []string{"javascript"}}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("localStorageSetTheme", "function", "theme.js", facts.LangJavaScript, false, 1, 1),
		},
	}
	ev := findTokenInLocalStorage(rule, fs)
	if len(ev) != 0 {
		t.Errorf("expected no evidence, got %d", len(ev))
	}
}

func TestFindTokenInLocalStorage_Negative_NoLocalStorage(t *testing.T) {
	rule := Rule{ID: "T-003", Languages: []string{"javascript"}}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("saveTokenToCookie", "function", "auth.js", facts.LangJavaScript, false, 1, 1),
		},
	}
	ev := findTokenInLocalStorage(rule, fs)
	if len(ev) != 0 {
		t.Errorf("expected no evidence without localStorage, got %d", len(ev))
	}
}

func TestFindTokenInLocalStorage_WrongLanguage(t *testing.T) {
	rule := Rule{ID: "T-003", Languages: []string{"javascript"}}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("localStorageSetToken", "function", "main.go", facts.LangGo, false, 1, 1),
		},
	}
	ev := findTokenInLocalStorage(rule, fs)
	if len(ev) != 0 {
		t.Errorf("expected no evidence for wrong language, got %d", len(ev))
	}
}

// --- findEnvExposesSecret ---

func TestFindEnvExposesSecret_Positive_NextPublic(t *testing.T) {
	rule := Rule{ID: "T-004", Languages: []string{"javascript"}}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("NEXT_PUBLIC_SECRET_KEY", "variable", "env.js", facts.LangJavaScript, true, 1, 1),
		},
	}
	ev := findEnvExposesSecret(rule, fs)
	if len(ev) == 0 {
		t.Error("expected evidence for NEXT_PUBLIC_ + secret")
	}
}

func TestFindEnvExposesSecret_Positive_Vite(t *testing.T) {
	rule := Rule{ID: "T-004", Languages: []string{"javascript"}}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("VITE_API_TOKEN", "variable", "config.js", facts.LangJavaScript, true, 1, 1),
		},
	}
	ev := findEnvExposesSecret(rule, fs)
	if len(ev) == 0 {
		t.Error("expected evidence for VITE_ + token")
	}
}

func TestFindEnvExposesSecret_Positive_ReactApp(t *testing.T) {
	rule := Rule{ID: "T-004", Languages: []string{"javascript"}}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("REACT_APP_PASSWORD", "variable", "config.js", facts.LangJavaScript, true, 1, 1),
		},
	}
	ev := findEnvExposesSecret(rule, fs)
	if len(ev) == 0 {
		t.Error("expected evidence for REACT_APP_ + password")
	}
}

func TestFindEnvExposesSecret_Negative_NoSensitiveKeyword(t *testing.T) {
	rule := Rule{ID: "T-004", Languages: []string{"javascript"}}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("NEXT_PUBLIC_API_URL", "variable", "env.js", facts.LangJavaScript, true, 1, 1),
		},
	}
	ev := findEnvExposesSecret(rule, fs)
	if len(ev) != 0 {
		t.Errorf("expected no evidence without sensitive keyword, got %d", len(ev))
	}
}

func TestFindEnvExposesSecret_Negative_NoPublicPrefix(t *testing.T) {
	rule := Rule{ID: "T-004", Languages: []string{"javascript"}}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("DB_SECRET_KEY", "variable", "env.js", facts.LangJavaScript, true, 1, 1),
		},
	}
	ev := findEnvExposesSecret(rule, fs)
	if len(ev) != 0 {
		t.Errorf("expected no evidence without public prefix, got %d", len(ev))
	}
}

func TestFindEnvExposesSecret_WrongLanguage(t *testing.T) {
	rule := Rule{ID: "T-004", Languages: []string{"javascript"}}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("NEXT_PUBLIC_SECRET_KEY", "variable", "main.go", facts.LangGo, true, 1, 1),
		},
	}
	ev := findEnvExposesSecret(rule, fs)
	if len(ev) != 0 {
		t.Errorf("expected no evidence for wrong language, got %d", len(ev))
	}
}

// --- findAuthGuard ---

func TestFindAuthGuard_PositiveSymbol(t *testing.T) {
	rule := Rule{ID: "T-005", Languages: []string{"javascript"}}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("ProtectedRoute", "component", "routes.jsx", facts.LangJavaScript, true, 5, 20),
		},
	}
	ev := findAuthGuard(rule, fs)
	if len(ev) == 0 {
		t.Error("expected evidence for ProtectedRoute symbol")
	}
}

func TestFindAuthGuard_PositiveImport(t *testing.T) {
	rule := Rule{ID: "T-005", Languages: []string{"javascript"}}
	fs := &FactSet{
		Imports: []facts.ImportFact{
			imp("next-auth", "", "auth.js", facts.LangJavaScript),
		},
	}
	ev := findAuthGuard(rule, fs)
	if len(ev) == 0 {
		t.Error("expected evidence for next-auth import")
	}
}

func TestFindAuthGuard_PositiveAuth0Import(t *testing.T) {
	rule := Rule{ID: "T-005", Languages: []string{"typescript"}}
	fs := &FactSet{
		Imports: []facts.ImportFact{
			imp("@auth0/nextjs-auth0", "", "auth.ts", facts.LangTypeScript),
		},
	}
	ev := findAuthGuard(rule, fs)
	if len(ev) == 0 {
		t.Error("expected evidence for @auth0 import")
	}
}

func TestFindAuthGuard_UseAuth(t *testing.T) {
	rule := Rule{ID: "T-005", Languages: []string{"javascript"}}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("useAuth", "function", "hooks.js", facts.LangJavaScript, false, 1, 10),
		},
	}
	ev := findAuthGuard(rule, fs)
	if len(ev) == 0 {
		t.Error("expected evidence for useAuth symbol")
	}
}

func TestFindAuthGuard_Negative(t *testing.T) {
	rule := Rule{ID: "T-005", Languages: []string{"javascript"}}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("PublicRoute", "component", "routes.jsx", facts.LangJavaScript, true, 1, 10),
		},
		Imports: []facts.ImportFact{
			imp("react-router-dom", "", "routes.jsx", facts.LangJavaScript),
		},
	}
	ev := findAuthGuard(rule, fs)
	if len(ev) != 0 {
		t.Errorf("expected no evidence, got %d", len(ev))
	}
}

func TestFindAuthGuard_WrongLanguage(t *testing.T) {
	rule := Rule{ID: "T-005", Languages: []string{"javascript"}}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("AuthGuard", "struct", "guard.go", facts.LangGo, true, 1, 1),
		},
	}
	ev := findAuthGuard(rule, fs)
	if len(ev) != 0 {
		t.Errorf("expected no evidence for wrong language, got %d", len(ev))
	}
}

// --- findAPIErrorHandling ---

func TestFindAPIErrorHandling_PositiveImport(t *testing.T) {
	rule := Rule{ID: "T-006", Languages: []string{"javascript"}}
	fs := &FactSet{
		Imports: []facts.ImportFact{
			imp("axios", "", "api.js", facts.LangJavaScript),
		},
	}
	ev := findAPIErrorHandling(rule, fs)
	if len(ev) == 0 {
		t.Error("expected evidence for axios import")
	}
}

func TestFindAPIErrorHandling_PositiveErrorBoundaryImport(t *testing.T) {
	rule := Rule{ID: "T-006", Languages: []string{"javascript"}}
	fs := &FactSet{
		Imports: []facts.ImportFact{
			imp("react-error-boundary", "", "App.jsx", facts.LangJavaScript),
		},
	}
	ev := findAPIErrorHandling(rule, fs)
	if len(ev) == 0 {
		t.Error("expected evidence for react-error-boundary import")
	}
}

func TestFindAPIErrorHandling_PositiveSymbol(t *testing.T) {
	rule := Rule{ID: "T-006", Languages: []string{"javascript"}}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("ErrorBoundary", "class", "ErrorBoundary.jsx", facts.LangJavaScript, true, 1, 50),
		},
	}
	ev := findAPIErrorHandling(rule, fs)
	if len(ev) == 0 {
		t.Error("expected evidence for ErrorBoundary symbol")
	}
}

func TestFindAPIErrorHandling_PositiveErrorHandler(t *testing.T) {
	rule := Rule{ID: "T-006", Languages: []string{"javascript"}}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("apiErrorHandler", "function", "errors.js", facts.LangJavaScript, false, 1, 10),
		},
	}
	ev := findAPIErrorHandling(rule, fs)
	if len(ev) == 0 {
		t.Error("expected evidence for error+handler symbol")
	}
}

func TestFindAPIErrorHandling_Negative(t *testing.T) {
	rule := Rule{ID: "T-006", Languages: []string{"javascript"}}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("fetchData", "function", "api.js", facts.LangJavaScript, false, 1, 10),
		},
		Imports: []facts.ImportFact{
			imp("lodash", "", "util.js", facts.LangJavaScript),
		},
	}
	ev := findAPIErrorHandling(rule, fs)
	if len(ev) != 0 {
		t.Errorf("expected no evidence, got %d", len(ev))
	}
}

func TestFindAPIErrorHandling_WrongLanguage(t *testing.T) {
	rule := Rule{ID: "T-006", Languages: []string{"javascript"}}
	fs := &FactSet{
		Imports: []facts.ImportFact{
			imp("axios", "", "main.py", facts.LangPython),
		},
	}
	ev := findAPIErrorHandling(rule, fs)
	if len(ev) != 0 {
		t.Errorf("expected no evidence for wrong language, got %d", len(ev))
	}
}

// --- findCSPConfigured ---

func TestFindCSPConfigured_PositiveImport(t *testing.T) {
	rule := Rule{ID: "T-007", Languages: []string{"javascript"}}
	fs := &FactSet{
		Imports: []facts.ImportFact{
			imp("helmet", "", "server.js", facts.LangJavaScript),
		},
	}
	ev := findCSPConfigured(rule, fs)
	if len(ev) == 0 {
		t.Error("expected evidence for helmet import")
	}
}

func TestFindCSPConfigured_PositiveSymbol(t *testing.T) {
	rule := Rule{ID: "T-007", Languages: []string{"javascript"}}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("contentSecurityPolicy", "variable", "config.js", facts.LangJavaScript, false, 1, 5),
		},
	}
	ev := findCSPConfigured(rule, fs)
	if len(ev) == 0 {
		t.Error("expected evidence for contentSecurityPolicy symbol")
	}
}

func TestFindCSPConfigured_PositiveCSPSymbol(t *testing.T) {
	rule := Rule{ID: "T-007", Languages: []string{"javascript"}}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("cspConfig", "variable", "security.js", facts.LangJavaScript, false, 1, 1),
		},
	}
	ev := findCSPConfigured(rule, fs)
	if len(ev) == 0 {
		t.Error("expected evidence for csp symbol")
	}
}

func TestFindCSPConfigured_Negative(t *testing.T) {
	rule := Rule{ID: "T-007", Languages: []string{"javascript"}}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("appConfig", "variable", "config.js", facts.LangJavaScript, false, 1, 1),
		},
		Imports: []facts.ImportFact{
			imp("express", "", "server.js", facts.LangJavaScript),
		},
	}
	ev := findCSPConfigured(rule, fs)
	if len(ev) != 0 {
		t.Errorf("expected no evidence, got %d", len(ev))
	}
}

func TestFindCSPConfigured_WrongLanguage(t *testing.T) {
	rule := Rule{ID: "T-007", Languages: []string{"javascript"}}
	fs := &FactSet{
		Imports: []facts.ImportFact{
			imp("helmet", "", "main.go", facts.LangGo),
		},
	}
	ev := findCSPConfigured(rule, fs)
	if len(ev) != 0 {
		t.Errorf("expected no evidence for wrong language, got %d", len(ev))
	}
}

// --- findLockfileExists ---

func TestFindLockfileExists_Positive_PackageLock(t *testing.T) {
	rule := Rule{ID: "T-008", Languages: []string{"javascript"}}
	fs := &FactSet{
		Files: []facts.FileFact{
			fileFact("package-lock.json", facts.LangJavaScript),
		},
	}
	ev := findLockfileExists(rule, fs)
	if len(ev) == 0 {
		t.Error("expected evidence for package-lock.json")
	}
}

func TestFindLockfileExists_Positive_YarnLock(t *testing.T) {
	rule := Rule{ID: "T-008", Languages: []string{"javascript"}}
	fs := &FactSet{
		Files: []facts.FileFact{
			fileFact("yarn.lock", facts.LangJavaScript),
		},
	}
	ev := findLockfileExists(rule, fs)
	if len(ev) == 0 {
		t.Error("expected evidence for yarn.lock")
	}
}

func TestFindLockfileExists_Positive_PnpmLock(t *testing.T) {
	rule := Rule{ID: "T-008", Languages: []string{"javascript"}}
	fs := &FactSet{
		Files: []facts.FileFact{
			fileFact("pnpm-lock.yaml", facts.LangJavaScript),
		},
	}
	ev := findLockfileExists(rule, fs)
	if len(ev) == 0 {
		t.Error("expected evidence for pnpm-lock.yaml")
	}
}

func TestFindLockfileExists_Negative(t *testing.T) {
	rule := Rule{ID: "T-008", Languages: []string{"javascript"}}
	fs := &FactSet{
		Files: []facts.FileFact{
			fileFact("package.json", facts.LangJavaScript),
			fileFact("tsconfig.json", facts.LangTypeScript),
		},
	}
	ev := findLockfileExists(rule, fs)
	if len(ev) != 0 {
		t.Errorf("expected no evidence, got %d", len(ev))
	}
}

// --- findConsoleLogInProduction ---

func TestFindConsoleLogInProduction_ReturnsNil(t *testing.T) {
	rule := Rule{ID: "T-009", Languages: []string{"javascript"}}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("console.log", "call", "app.js", facts.LangJavaScript, false, 1, 1),
		},
	}
	ev := findConsoleLogInProduction(rule, fs)
	if ev != nil {
		t.Errorf("expected nil, got %v", ev)
	}
}

// --- findFormValidation ---

func TestFindFormValidation_PositiveImport(t *testing.T) {
	rule := Rule{ID: "T-010", Languages: []string{"javascript"}}
	fs := &FactSet{
		Imports: []facts.ImportFact{
			imp("react-hook-form", "", "Form.jsx", facts.LangJavaScript),
		},
	}
	ev := findFormValidation(rule, fs)
	if len(ev) == 0 {
		t.Error("expected evidence for react-hook-form import")
	}
}

func TestFindFormValidation_PositiveZodImport(t *testing.T) {
	rule := Rule{ID: "T-010", Languages: []string{"typescript"}}
	fs := &FactSet{
		Imports: []facts.ImportFact{
			imp("zod", "", "schema.ts", facts.LangTypeScript),
		},
	}
	ev := findFormValidation(rule, fs)
	if len(ev) == 0 {
		t.Error("expected evidence for zod import")
	}
}

func TestFindFormValidation_PositiveSymbol(t *testing.T) {
	rule := Rule{ID: "T-010", Languages: []string{"javascript"}}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("useForm", "function", "hooks.js", facts.LangJavaScript, false, 1, 10),
		},
	}
	ev := findFormValidation(rule, fs)
	if len(ev) == 0 {
		t.Error("expected evidence for useForm symbol")
	}
}

func TestFindFormValidation_PositiveValidateForm(t *testing.T) {
	rule := Rule{ID: "T-010", Languages: []string{"javascript"}}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("validateForm", "function", "validation.js", facts.LangJavaScript, false, 1, 5),
		},
	}
	ev := findFormValidation(rule, fs)
	if len(ev) == 0 {
		t.Error("expected evidence for validateForm symbol")
	}
}

func TestFindFormValidation_Negative(t *testing.T) {
	rule := Rule{ID: "T-010", Languages: []string{"javascript"}}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("submitForm", "function", "form.js", facts.LangJavaScript, false, 1, 5),
		},
		Imports: []facts.ImportFact{
			imp("react", "", "App.jsx", facts.LangJavaScript),
		},
	}
	ev := findFormValidation(rule, fs)
	if len(ev) != 0 {
		t.Errorf("expected no evidence, got %d", len(ev))
	}
}

func TestFindFormValidation_WrongLanguage(t *testing.T) {
	rule := Rule{ID: "T-010", Languages: []string{"javascript"}}
	fs := &FactSet{
		Imports: []facts.ImportFact{
			imp("zod", "", "main.go", facts.LangGo),
		},
	}
	ev := findFormValidation(rule, fs)
	if len(ev) != 0 {
		t.Errorf("expected no evidence for wrong language, got %d", len(ev))
	}
}

// --- findDangerousHTML import branch (sanitizer skip + wrong lang) ---

func TestFindDangerousHTML_WithSanitizer(t *testing.T) {
	rule := Rule{ID: "T-001", Languages: []string{"javascript"}}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("dangerouslySetInnerHTML", "property", "App.jsx", facts.LangJavaScript, false, 10, 10),
		},
		Imports: []facts.ImportFact{
			imp("dompurify", "", "App.jsx", facts.LangJavaScript),
		},
	}
	ev := findDangerousHTML(rule, fs)
	// Sanitizer import is noted but doesn't suppress the symbol match
	if len(ev) == 0 {
		t.Error("expected evidence even with sanitizer import")
	}
}

func TestFindDangerousHTML_SanitizeHTMLImport(t *testing.T) {
	rule := Rule{ID: "T-001", Languages: []string{"javascript"}}
	fs := &FactSet{
		Imports: []facts.ImportFact{
			imp("sanitize-html", "", "util.js", facts.LangJavaScript),
		},
	}
	ev := findDangerousHTML(rule, fs)
	// No dangerous symbols, just a sanitizer import
	if len(ev) != 0 {
		t.Errorf("expected no evidence with only sanitizer import, got %d", len(ev))
	}
}

func TestFindDangerousHTML_NonSanitizerImport(t *testing.T) {
	rule := Rule{ID: "T-001", Languages: []string{"javascript"}}
	fs := &FactSet{
		Imports: []facts.ImportFact{
			imp("react", "", "App.jsx", facts.LangJavaScript),
		},
	}
	ev := findDangerousHTML(rule, fs)
	if len(ev) != 0 {
		t.Errorf("expected no evidence for regular import, got %d", len(ev))
	}
}

func TestFindDangerousHTML_ImportWrongLanguage(t *testing.T) {
	rule := Rule{ID: "T-001", Languages: []string{"javascript"}}
	fs := &FactSet{
		Imports: []facts.ImportFact{
			imp("dompurify", "", "main.go", facts.LangGo),
		},
	}
	ev := findDangerousHTML(rule, fs)
	if len(ev) != 0 {
		t.Errorf("expected no evidence for wrong language import, got %d", len(ev))
	}
}

func TestFindDangerousHTML_InnerHTMLDirective(t *testing.T) {
	rule := Rule{ID: "T-001", Languages: []string{"typescript"}}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("[innerHTML]", "directive", "comp.ts", facts.LangTypeScript, false, 1, 1),
		},
	}
	ev := findDangerousHTML(rule, fs)
	if len(ev) == 0 {
		t.Error("expected evidence for [innerHTML]")
	}
}

// --- findEnvExposesSecret file loop branch ---

func TestFindEnvExposesSecret_FileWithEnv(t *testing.T) {
	rule := Rule{ID: "T-004", Languages: []string{"javascript"}}
	fs := &FactSet{
		Files: []facts.FileFact{
			fileFact(".env.local", facts.LangJavaScript),
		},
	}
	ev := findEnvExposesSecret(rule, fs)
	// No symbols match, just file loop runs
	if len(ev) != 0 {
		t.Errorf("expected no evidence without matching symbols, got %d", len(ev))
	}
}

func TestFindEnvExposesSecret_FileWithoutEnv(t *testing.T) {
	rule := Rule{ID: "T-004", Languages: []string{"javascript"}}
	fs := &FactSet{
		Files: []facts.FileFact{
			fileFact("config.json", facts.LangJavaScript),
		},
	}
	ev := findEnvExposesSecret(rule, fs)
	if len(ev) != 0 {
		t.Errorf("expected no evidence without .env file, got %d", len(ev))
	}
}

// --- findFormValidation symbol: formValidation ---

func TestFindFormValidation_FormValidationSymbol(t *testing.T) {
	rule := Rule{ID: "T-010", Languages: []string{"javascript"}}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("formValidation", "function", "form.js", facts.LangJavaScript, false, 1, 5),
		},
	}
	ev := findFormValidation(rule, fs)
	if len(ev) == 0 {
		t.Error("expected evidence for formValidation symbol")
	}
}

// --- findAuthGuard: isAuthenticated ---

func TestFindAuthGuard_IsAuthenticated(t *testing.T) {
	rule := Rule{ID: "T-005", Languages: []string{"javascript"}}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("isAuthenticated", "function", "auth.js", facts.LangJavaScript, false, 1, 10),
		},
	}
	ev := findAuthGuard(rule, fs)
	if len(ev) == 0 {
		t.Error("expected evidence for isAuthenticated symbol")
	}
}

func TestFindAuthGuard_ImportWrongLanguage(t *testing.T) {
	rule := Rule{ID: "T-005", Languages: []string{"javascript"}}
	fs := &FactSet{
		Imports: []facts.ImportFact{
			imp("next-auth", "", "auth.go", facts.LangGo),
		},
	}
	ev := findAuthGuard(rule, fs)
	if len(ev) != 0 {
		t.Errorf("expected no evidence for import wrong language, got %d", len(ev))
	}
}

// --- findAPIErrorHandling: interceptor symbol ---

func TestFindAPIErrorHandling_Interceptor(t *testing.T) {
	rule := Rule{ID: "T-006", Languages: []string{"javascript"}}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("axiosInterceptor", "function", "api.js", facts.LangJavaScript, false, 1, 10),
		},
	}
	ev := findAPIErrorHandling(rule, fs)
	if len(ev) == 0 {
		t.Error("expected evidence for interceptor symbol")
	}
}

func TestFindAPIErrorHandling_SymbolWrongLanguage(t *testing.T) {
	rule := Rule{ID: "T-006", Languages: []string{"javascript"}}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("ErrorBoundary", "class", "main.go", facts.LangGo, true, 1, 50),
		},
	}
	ev := findAPIErrorHandling(rule, fs)
	if len(ev) != 0 {
		t.Errorf("expected no evidence for symbol wrong language, got %d", len(ev))
	}
}

// --- findCSPConfigured: symbol wrong language ---

func TestFindCSPConfigured_SymbolWrongLanguage(t *testing.T) {
	rule := Rule{ID: "T-007", Languages: []string{"javascript"}}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("cspConfig", "variable", "main.go", facts.LangGo, false, 1, 1),
		},
	}
	ev := findCSPConfigured(rule, fs)
	if len(ev) != 0 {
		t.Errorf("expected no evidence for symbol wrong language, got %d", len(ev))
	}
}

// --- findFormValidation: symbol wrong language ---

func TestFindFormValidation_SymbolWrongLanguage(t *testing.T) {
	rule := Rule{ID: "T-010", Languages: []string{"javascript"}}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("useForm", "function", "main.go", facts.LangGo, false, 1, 10),
		},
	}
	ev := findFormValidation(rule, fs)
	if len(ev) != 0 {
		t.Errorf("expected no evidence for symbol wrong language, got %d", len(ev))
	}
}
