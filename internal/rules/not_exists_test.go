package rules

import (
	"testing"

	"github.com/verabase/code-verification-engine/internal/facts"
)

func TestNotExistsMatcherPass(t *testing.T) {
	rule := Rule{
		ID: "ARCH-001", Type: "not_exists", Target: "db.direct_access_from_controller",
		Languages: []string{"go"}, Message: "No direct DB access from controllers.",
	}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("UserController", "function", "internal/controller/user.go", facts.LangGo, true, 5, 20),
		},
		Files: []facts.FileFact{
			fileFact("internal/controller/user.go", facts.LangGo),
		},
	}
	finding := matchNotExists(rule, fs, []string{"go"})
	if finding.Status != StatusPass {
		t.Errorf("status = %v, want pass", finding.Status)
	}
}

func TestNotExistsMatcherFail(t *testing.T) {
	rule := Rule{
		ID: "ARCH-001", Type: "not_exists", Target: "db.direct_access_from_controller",
		Languages: []string{"go"}, Message: "No direct DB access from controllers.",
	}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("getUserController", "function", "internal/controller/user.go", facts.LangGo, true, 10, 25),
		},
		DataAccess: []facts.DataAccessFact{
			dataAccess("direct_query", "internal/controller/user.go", facts.LangGo),
		},
		Files: []facts.FileFact{
			fileFact("internal/controller/user.go", facts.LangGo),
		},
	}
	finding := matchNotExists(rule, fs, []string{"go"})
	if finding.Status != StatusFail {
		t.Errorf("status = %v, want fail", finding.Status)
	}
	if len(finding.Evidence) == 0 {
		t.Error("expected evidence for fail")
	}
}

func TestNotExistsMatcherUnknown(t *testing.T) {
	rule := Rule{
		ID: "ARCH-001", Type: "not_exists", Target: "db.direct_access_from_controller",
		Languages: []string{"go"}, Message: "No direct DB access from controllers.",
	}
	fs := &FactSet{}
	finding := matchNotExists(rule, fs, []string{"go"})
	if finding.Status != StatusUnknown {
		t.Errorf("status = %v, want unknown", finding.Status)
	}
}

func TestNotExistsHardcodedCredentialFail(t *testing.T) {
	rule := Rule{
		ID: "SEC-001", Type: "not_exists", Target: "secret.hardcoded_credential",
		Languages: []string{"go"}, Message: "No hardcoded creds.",
	}
	fs := &FactSet{
		Secrets: []facts.SecretFact{
			secret("password", "config.go", facts.LangGo, 15),
		},
	}
	finding := matchNotExists(rule, fs, []string{"go"})
	if finding.Status != StatusFail {
		t.Errorf("status = %v, want fail", finding.Status)
	}
}

func TestNotExistsHardcodedCredentialPass(t *testing.T) {
	rule := Rule{
		ID: "SEC-001", Type: "not_exists", Target: "secret.hardcoded_credential",
		Languages: []string{"go"}, Message: "No hardcoded creds.",
	}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("main", "function", "main.go", facts.LangGo, false, 1, 5),
		},
		Files: []facts.FileFact{
			fileFact("main.go", facts.LangGo),
		},
	}
	finding := matchNotExists(rule, fs, []string{"go"})
	if finding.Status != StatusPass {
		t.Errorf("status = %v, want pass", finding.Status)
	}
}

func TestNotExistsNilFactSet(t *testing.T) {
	rule := Rule{
		ID: "ARCH-001", Type: "not_exists", Target: "db.direct_access_from_controller",
		Languages: []string{"go"}, Message: "x",
	}
	finding := matchNotExists(rule, nil, []string{"go"})
	if finding.Status != StatusUnknown {
		t.Errorf("status = %v, want unknown for nil FactSet", finding.Status)
	}
}

// ---------------------------------------------------------------------------
// findNotExistsEvidence — switch case coverage
// ---------------------------------------------------------------------------

func TestFindNotExistsEvidence_EnvFileCommitted(t *testing.T) {
	rule := Rule{ID: "SEC-002", Target: "secret.env_file_committed", Languages: []string{"javascript"}}
	fs := &FactSet{
		Files: []facts.FileFact{
			fileFact(".env", facts.LangJavaScript),
		},
	}
	ev := findNotExistsEvidence(rule, fs)
	if len(ev) == 0 {
		t.Error("expected evidence for .env committed")
	}
}

func TestFindNotExistsEvidence_SQLInjection(t *testing.T) {
	rule := Rule{ID: "SEC-003", Target: "security.sql_injection_pattern", Languages: []string{"go"}}
	fs := &FactSet{
		DataAccess: []facts.DataAccessFact{
			dataAccess("raw_query", "handler.go", facts.LangGo),
		},
	}
	ev := findNotExistsEvidence(rule, fs)
	if len(ev) == 0 {
		t.Error("expected evidence for SQL injection pattern")
	}
}

func TestFindNotExistsEvidence_SensitiveDataInLogs(t *testing.T) {
	rule := Rule{ID: "SEC-004", Target: "security.sensitive_data_in_logs", Languages: []string{"go"}}
	fs := &FactSet{}
	ev := findNotExistsEvidence(rule, fs)
	if ev != nil {
		t.Errorf("expected nil for sensitive_data_in_logs, got %v", ev)
	}
}

func TestFindNotExistsEvidence_XSSDangerousHTML(t *testing.T) {
	rule := Rule{ID: "FE-001", Target: "frontend.xss_dangerous_html", Languages: []string{"javascript"}}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("dangerouslySetInnerHTML", "property", "App.jsx", facts.LangJavaScript, false, 10, 10),
		},
	}
	ev := findNotExistsEvidence(rule, fs)
	if len(ev) == 0 {
		t.Error("expected evidence for xss_dangerous_html")
	}
}

func TestFindNotExistsEvidence_XSSInnerHTML(t *testing.T) {
	rule := Rule{ID: "FE-002", Target: "frontend.xss_innerhtml", Languages: []string{"javascript"}}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("element.innerHTML", "property", "dom.js", facts.LangJavaScript, false, 20, 20),
		},
	}
	ev := findNotExistsEvidence(rule, fs)
	if len(ev) == 0 {
		t.Error("expected evidence for xss_innerhtml")
	}
}

func TestFindNotExistsEvidence_TokenInLocalStorage(t *testing.T) {
	rule := Rule{ID: "FE-003", Target: "frontend.token_in_localstorage", Languages: []string{"javascript"}}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("localStorageSetToken", "function", "auth.js", facts.LangJavaScript, false, 10, 15),
		},
	}
	ev := findNotExistsEvidence(rule, fs)
	if len(ev) == 0 {
		t.Error("expected evidence for token_in_localstorage")
	}
}

func TestFindNotExistsEvidence_EnvExposesSecret(t *testing.T) {
	rule := Rule{ID: "FE-004", Target: "frontend.env_exposes_secret", Languages: []string{"javascript"}}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("NEXT_PUBLIC_SECRET_KEY", "variable", "env.js", facts.LangJavaScript, true, 1, 1),
		},
	}
	ev := findNotExistsEvidence(rule, fs)
	if len(ev) == 0 {
		t.Error("expected evidence for env_exposes_secret")
	}
}

func TestFindNotExistsEvidence_ConsoleLogInProduction(t *testing.T) {
	rule := Rule{ID: "FE-005", Target: "frontend.console_log_in_production", Languages: []string{"javascript"}}
	fs := &FactSet{}
	ev := findNotExistsEvidence(rule, fs)
	if ev != nil {
		t.Errorf("expected nil for console_log_in_production, got %v", ev)
	}
}

func TestFindNotExistsEvidence_RepoEncapsulation(t *testing.T) {
	rule := Rule{ID: "PAT-001", Target: "pattern.repository_encapsulation", Languages: []string{"go"}}
	fs := &FactSet{
		Files: []facts.FileFact{
			fileFact("handlers/user.go", facts.LangGo),
		},
		DataAccess: []facts.DataAccessFact{
			dataAccess("db.Query", "handlers/user.go", facts.LangGo),
		},
	}
	ev := findNotExistsEvidence(rule, fs)
	if len(ev) == 0 {
		t.Error("expected evidence for repository_encapsulation violation")
	}
}

func TestFindNotExistsEvidence_DTOSeparation(t *testing.T) {
	// DTO separation now requires:
	// 1. Handler file imports a model/entity module
	// 2. Handler file has DataAccess facts (direct DB access)
	rule := Rule{ID: "PAT-002", Target: "pattern.dto_separation", Languages: []string{"go"}}
	fs := &FactSet{
		Files: []facts.FileFact{
			fileFact("model/user.go", facts.LangGo),
			fileFact("handler/user_handler.go", facts.LangGo),
		},
		Symbols: []facts.SymbolFact{
			sym("User", "struct", "model/user.go", facts.LangGo, true, 1, 10),
			sym("GetUser", "function", "handler/user_handler.go", facts.LangGo, true, 1, 20),
		},
		Imports: []facts.ImportFact{
			imp("./model/user", "", "handler/user_handler.go", facts.LangGo),
		},
		Routes: []facts.RouteFact{
			route("GET", "/users", "GetUser", "handler/user_handler.go", facts.LangGo, nil),
		},
		DataAccess: []facts.DataAccessFact{
			{
				Language:  facts.LangGo,
				File:      "handler/user_handler.go",
				Span:      facts.Span{Start: 10, End: 10},
				Operation: "db.Query",
				Backend:   "database/sql",
			},
		},
	}
	ev := findNotExistsEvidence(rule, fs)
	if len(ev) == 0 {
		t.Error("expected evidence for dto_separation violation")
	}
}

func TestFindNotExistsEvidence_DTOSeparation_NoFalsePositive(t *testing.T) {
	// Controller that references model symbols but does NOT have direct DB access
	// should NOT be flagged (it's doing DTO transformation)
	rule := Rule{ID: "PAT-002", Target: "pattern.dto_separation", Languages: []string{"go"}}
	fs := &FactSet{
		Files: []facts.FileFact{
			fileFact("model/user.go", facts.LangGo),
			fileFact("handler/user_handler.go", facts.LangGo),
		},
		Symbols: []facts.SymbolFact{
			sym("User", "struct", "model/user.go", facts.LangGo, true, 1, 10),
			sym("GetUser", "function", "handler/user_handler.go", facts.LangGo, true, 1, 20),
		},
		Routes: []facts.RouteFact{
			route("GET", "/users", "GetUser", "handler/user_handler.go", facts.LangGo, nil),
		},
	}
	ev := findNotExistsEvidence(rule, fs)
	if len(ev) != 0 {
		t.Error("expected NO evidence — controller does DTO transformation, no direct DB access")
	}
}

func TestFindNotExistsEvidence_SingletonMutableGlobal(t *testing.T) {
	rule := Rule{ID: "PAT-003", Target: "pattern.singleton_mutable_global", Languages: []string{"go"}}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("DBInstance", "variable", "pkg/globals.go", facts.LangGo, true, 1, 5),
		},
	}
	ev := findNotExistsEvidence(rule, fs)
	if len(ev) == 0 {
		t.Error("expected evidence for singleton_mutable_global")
	}
}

func TestFindNotExistsEvidence_UnknownTarget(t *testing.T) {
	rule := Rule{ID: "X-001", Target: "unknown.nonexistent", Languages: []string{"go"}}
	fs := &FactSet{}
	ev := findNotExistsEvidence(rule, fs)
	if ev != nil {
		t.Errorf("expected nil for unknown target, got %v", ev)
	}
}

// ---------------------------------------------------------------------------
// hasMinimalFactsForNotExists — branch coverage
// ---------------------------------------------------------------------------

func TestHasMinimalFactsForNotExists_NilFactSet(t *testing.T) {
	if hasMinimalFactsForNotExists(nil, "db.direct_access_from_controller") {
		t.Error("expected false for nil FactSet")
	}
}

func TestHasMinimalFactsForNotExists_DBDirectAccess(t *testing.T) {
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("main", "function", "main.go", facts.LangGo, false, 1, 5),
		},
	}
	if !hasMinimalFactsForNotExists(fs, "db.direct_access_from_controller") {
		t.Error("expected true with symbols")
	}
	if !hasMinimalFactsForNotExists(&FactSet{Files: []facts.FileFact{fileFact("a.go", facts.LangGo)}}, "db.direct_access_from_controller") {
		t.Error("expected true with files")
	}
	if hasMinimalFactsForNotExists(&FactSet{}, "db.direct_access_from_controller") {
		t.Error("expected false with empty")
	}
}

func TestHasMinimalFactsForNotExists_HardcodedCredential(t *testing.T) {
	if !hasMinimalFactsForNotExists(&FactSet{Secrets: []facts.SecretFact{secret("pw", "a.go", facts.LangGo, 1)}}, "secret.hardcoded_credential") {
		t.Error("expected true with secrets")
	}
	if !hasMinimalFactsForNotExists(&FactSet{Files: []facts.FileFact{fileFact("a.go", facts.LangGo)}}, "secret.hardcoded_credential") {
		t.Error("expected true with files")
	}
}

func TestHasMinimalFactsForNotExists_EnvExposesSecret(t *testing.T) {
	if !hasMinimalFactsForNotExists(&FactSet{Files: []facts.FileFact{fileFact("a.go", facts.LangGo)}}, "frontend.env_exposes_secret") {
		t.Error("expected true with files")
	}
	if hasMinimalFactsForNotExists(&FactSet{}, "frontend.env_exposes_secret") {
		t.Error("expected false with empty")
	}
}

func TestHasMinimalFactsForNotExists_XSSDangerousHTML(t *testing.T) {
	if !hasMinimalFactsForNotExists(&FactSet{Imports: []facts.ImportFact{imp("x", "", "a.js", facts.LangJavaScript)}}, "frontend.xss_dangerous_html") {
		t.Error("expected true with imports")
	}
	if hasMinimalFactsForNotExists(&FactSet{}, "frontend.xss_dangerous_html") {
		t.Error("expected false with empty")
	}
}

func TestHasMinimalFactsForNotExists_XSSInnerHTML(t *testing.T) {
	if !hasMinimalFactsForNotExists(&FactSet{Symbols: []facts.SymbolFact{sym("x", "v", "a.js", facts.LangJavaScript, false, 1, 1)}}, "frontend.xss_innerhtml") {
		t.Error("expected true with symbols")
	}
	if hasMinimalFactsForNotExists(&FactSet{}, "frontend.xss_innerhtml") {
		t.Error("expected false with empty")
	}
}

func TestHasMinimalFactsForNotExists_TokenInLocalStorage(t *testing.T) {
	if !hasMinimalFactsForNotExists(&FactSet{Symbols: []facts.SymbolFact{sym("x", "v", "a.js", facts.LangJavaScript, false, 1, 1)}}, "frontend.token_in_localstorage") {
		t.Error("expected true with symbols")
	}
}

func TestHasMinimalFactsForNotExists_ConsoleLog(t *testing.T) {
	if !hasMinimalFactsForNotExists(&FactSet{Symbols: []facts.SymbolFact{sym("x", "v", "a.js", facts.LangJavaScript, false, 1, 1)}}, "frontend.console_log_in_production") {
		t.Error("expected true with symbols")
	}
}

func TestHasMinimalFactsForNotExists_RepoEncapsulation(t *testing.T) {
	if !hasMinimalFactsForNotExists(&FactSet{DataAccess: []facts.DataAccessFact{dataAccess("q", "a.go", facts.LangGo)}}, "pattern.repository_encapsulation") {
		t.Error("expected true with data access")
	}
	if hasMinimalFactsForNotExists(&FactSet{}, "pattern.repository_encapsulation") {
		t.Error("expected false with empty")
	}
}

func TestHasMinimalFactsForNotExists_DTOSeparation(t *testing.T) {
	fs := &FactSet{
		Symbols: []facts.SymbolFact{sym("x", "v", "a.go", facts.LangGo, false, 1, 1)},
		Routes:  []facts.RouteFact{route("GET", "/a", "h", "a.go", facts.LangGo, nil)},
	}
	if !hasMinimalFactsForNotExists(fs, "pattern.dto_separation") {
		t.Error("expected true with symbols + routes")
	}
	if hasMinimalFactsForNotExists(&FactSet{Symbols: []facts.SymbolFact{sym("x", "v", "a.go", facts.LangGo, false, 1, 1)}}, "pattern.dto_separation") {
		t.Error("expected false without routes")
	}
}

func TestHasMinimalFactsForNotExists_SingletonMutableGlobal(t *testing.T) {
	if !hasMinimalFactsForNotExists(&FactSet{Symbols: []facts.SymbolFact{sym("x", "v", "a.go", facts.LangGo, false, 1, 1)}}, "pattern.singleton_mutable_global") {
		t.Error("expected true with symbols")
	}
}

func TestHasMinimalFactsForNotExists_Default(t *testing.T) {
	if !hasMinimalFactsForNotExists(&FactSet{Symbols: []facts.SymbolFact{sym("x", "v", "a.go", facts.LangGo, false, 1, 1)}}, "unknown.target") {
		t.Error("expected true for default case with symbols")
	}
	if hasMinimalFactsForNotExists(&FactSet{}, "unknown.target") {
		t.Error("expected false for default case with empty")
	}
}

// ---------------------------------------------------------------------------
// isControllerFile
// ---------------------------------------------------------------------------

func TestIsControllerFile(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"internal/controller/user.go", true},
		{"handlers/api.go", true},
		{"api/endpoint/v1.go", true},
		{"service/user.go", false},
		{"model/data.go", false},
	}
	for _, tc := range tests {
		got := isControllerFile(tc.path)
		if got != tc.want {
			t.Errorf("isControllerFile(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}
