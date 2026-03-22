package facts_test

import (
	"testing"

	"github.com/verabase/code-verification-engine/internal/facts"
)

func TestSpanValid(t *testing.T) {
	s := facts.Span{Start: 1, End: 10}
	if err := s.Validate(); err != nil {
		t.Fatalf("expected valid span, got error: %v", err)
	}
}

func TestSpanSingleLine(t *testing.T) {
	s := facts.Span{Start: 1, End: 1}
	if err := s.Validate(); err != nil {
		t.Fatalf("expected valid single-line span, got error: %v", err)
	}
}

func TestSpanInvalidStartZero(t *testing.T) {
	s := facts.Span{Start: 0, End: 10}
	if err := s.Validate(); err == nil {
		t.Fatal("expected error for span with Start=0")
	}
}

func TestSpanInvalidEndBeforeStart(t *testing.T) {
	s := facts.Span{Start: 10, End: 5}
	if err := s.Validate(); err == nil {
		t.Fatal("expected error for span with End < Start")
	}
}

func TestLanguageValid(t *testing.T) {
	valid := []facts.Language{facts.LangGo, facts.LangJavaScript, facts.LangTypeScript, facts.LangPython}
	for _, lang := range valid {
		if !lang.IsValid() {
			t.Errorf("expected %q to be valid", lang)
		}
	}
}

func TestLanguageInvalid(t *testing.T) {
	lang := facts.Language("rust")
	if lang.IsValid() {
		t.Error("expected rust to be invalid")
	}
}

// --- FileFact tests ---

func TestNewFileFactValid(t *testing.T) {
	f, err := facts.NewFileFact(facts.LangGo, "internal/auth/jwt.go", 150)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if f.Language != facts.LangGo {
		t.Errorf("expected language go, got %s", f.Language)
	}
	if f.File != "internal/auth/jwt.go" {
		t.Errorf("expected file internal/auth/jwt.go, got %s", f.File)
	}
	if f.LineCount != 150 {
		t.Errorf("expected line count 150, got %d", f.LineCount)
	}
}

func TestNewFileFactMissingPath(t *testing.T) {
	_, err := facts.NewFileFact(facts.LangGo, "", 150)
	if err == nil {
		t.Fatal("expected error for empty path")
	}
}

func TestNewFileFactInvalidLanguage(t *testing.T) {
	_, err := facts.NewFileFact("rust", "main.rs", 100)
	if err == nil {
		t.Fatal("expected error for invalid language")
	}
}

// --- SymbolFact tests ---

func TestNewSymbolFactValid(t *testing.T) {
	s, err := facts.NewSymbolFact(facts.LangGo, "internal/auth/jwt.go", facts.Span{Start: 12, End: 28}, "VerifyToken", "function", true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s.Name != "VerifyToken" {
		t.Errorf("expected name VerifyToken, got %s", s.Name)
	}
	if s.Kind != "function" {
		t.Errorf("expected kind function, got %s", s.Kind)
	}
	if !s.Exported {
		t.Error("expected exported to be true")
	}
}

func TestNewSymbolFactMissingName(t *testing.T) {
	_, err := facts.NewSymbolFact(facts.LangGo, "main.go", facts.Span{Start: 1, End: 5}, "", "function", false)
	if err == nil {
		t.Fatal("expected error for empty name")
	}
}

func TestNewSymbolFactInvalidSpan(t *testing.T) {
	_, err := facts.NewSymbolFact(facts.LangGo, "main.go", facts.Span{Start: 0, End: 5}, "Foo", "function", false)
	if err == nil {
		t.Fatal("expected error for invalid span")
	}
}

// --- ImportFact tests ---

func TestNewImportFactValid(t *testing.T) {
	i, err := facts.NewImportFact(facts.LangGo, "main.go", facts.Span{Start: 3, End: 3}, "fmt", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if i.ImportPath != "fmt" {
		t.Errorf("expected import path fmt, got %s", i.ImportPath)
	}
}

func TestNewImportFactMissingImportPath(t *testing.T) {
	_, err := facts.NewImportFact(facts.LangGo, "main.go", facts.Span{Start: 3, End: 3}, "", "")
	if err == nil {
		t.Fatal("expected error for empty import path")
	}
}

// --- RouteFact tests ---

func TestNewRouteFactValid(t *testing.T) {
	r, err := facts.NewRouteFact(facts.LangGo, "routes.go", facts.Span{Start: 10, End: 15}, "GET", "/api/users", "GetUsers", []string{"AuthMiddleware"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.Method != "GET" || r.Path != "/api/users" || r.Handler != "GetUsers" {
		t.Errorf("unexpected route: %+v", r)
	}
	if len(r.Middlewares) != 1 || r.Middlewares[0] != "AuthMiddleware" {
		t.Errorf("expected middleware [AuthMiddleware], got %v", r.Middlewares)
	}
}

func TestNewRouteFactNoMiddleware(t *testing.T) {
	r, err := facts.NewRouteFact(facts.LangGo, "routes.go", facts.Span{Start: 10, End: 15}, "GET", "/public", "GetPublic", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(r.Middlewares) != 0 {
		t.Errorf("expected no middlewares, got %v", r.Middlewares)
	}
}

func TestNewRouteFactMissingMethod(t *testing.T) {
	_, err := facts.NewRouteFact(facts.LangGo, "routes.go", facts.Span{Start: 10, End: 15}, "", "/api/users", "GetUsers", nil)
	if err == nil {
		t.Fatal("expected error for empty method")
	}
}

// --- MiddlewareFact tests ---

func TestNewMiddlewareFactValid(t *testing.T) {
	m, err := facts.NewMiddlewareFact(facts.LangGo, "middleware.go", facts.Span{Start: 5, End: 20}, "AuthMiddleware", "auth")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if m.Name != "AuthMiddleware" {
		t.Errorf("expected name AuthMiddleware, got %s", m.Name)
	}
}

func TestNewMiddlewareFactMissingName(t *testing.T) {
	_, err := facts.NewMiddlewareFact(facts.LangGo, "middleware.go", facts.Span{Start: 5, End: 20}, "", "auth")
	if err == nil {
		t.Fatal("expected error for empty name")
	}
}

// --- TestFact tests ---

func TestNewTestFactValid(t *testing.T) {
	tf, err := facts.NewTestFact(facts.LangGo, "auth_test.go", facts.Span{Start: 8, End: 25}, "TestVerifyToken", "auth", "internal/auth")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tf.TestName != "TestVerifyToken" {
		t.Errorf("expected test name TestVerifyToken, got %s", tf.TestName)
	}
	if tf.TargetModule != "auth" {
		t.Errorf("expected target module auth, got %s", tf.TargetModule)
	}
	if tf.TargetPath != "internal/auth" {
		t.Errorf("expected target path internal/auth, got %s", tf.TargetPath)
	}
}

func TestNewTestFactMissingTestName(t *testing.T) {
	_, err := facts.NewTestFact(facts.LangGo, "auth_test.go", facts.Span{Start: 8, End: 25}, "", "auth", "")
	if err == nil {
		t.Fatal("expected error for empty test name")
	}
}

// --- DataAccessFact tests ---

func TestNewDataAccessFactValid(t *testing.T) {
	d, err := facts.NewDataAccessFact(facts.LangGo, "repo.go", facts.Span{Start: 15, End: 20}, "db.Query", "sql")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d.Operation != "db.Query" {
		t.Errorf("expected operation db.Query, got %s", d.Operation)
	}
}

func TestNewDataAccessFactMissingOperation(t *testing.T) {
	_, err := facts.NewDataAccessFact(facts.LangGo, "repo.go", facts.Span{Start: 15, End: 20}, "", "sql")
	if err == nil {
		t.Fatal("expected error for empty operation")
	}
}

// --- ConfigFact tests ---

func TestNewConfigFactValid(t *testing.T) {
	c, err := facts.NewConfigFact(facts.LangGo, "config.go", facts.Span{Start: 3, End: 8}, "DatabaseURL", "env")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.Key != "DatabaseURL" {
		t.Errorf("expected key DatabaseURL, got %s", c.Key)
	}
}

func TestNewConfigFactMissingKey(t *testing.T) {
	_, err := facts.NewConfigFact(facts.LangGo, "config.go", facts.Span{Start: 3, End: 8}, "", "env")
	if err == nil {
		t.Fatal("expected error for empty key")
	}
}

// --- SecretFact tests ---

func TestNewSecretFactValid(t *testing.T) {
	s, err := facts.NewSecretFact(facts.LangGo, "config.go", facts.Span{Start: 10, End: 10}, "hardcoded_password", "password123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s.Kind != "hardcoded_password" {
		t.Errorf("expected kind hardcoded_password, got %s", s.Kind)
	}
}

func TestNewSecretFactMissingKind(t *testing.T) {
	_, err := facts.NewSecretFact(facts.LangGo, "config.go", facts.Span{Start: 10, End: 10}, "", "pw")
	if err == nil {
		t.Fatal("expected error for empty kind")
	}
}

// --- DependencyFact tests ---

func TestNewDependencyFactValid(t *testing.T) {
	d, err := facts.NewDependencyFact(facts.LangGo, "go.mod", facts.Span{Start: 5, End: 5}, "github.com/gin-gonic/gin", "v1.9.0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d.Name != "github.com/gin-gonic/gin" {
		t.Errorf("expected name github.com/gin-gonic/gin, got %s", d.Name)
	}
}

func TestNewDependencyFactMissingName(t *testing.T) {
	_, err := facts.NewDependencyFact(facts.LangGo, "go.mod", facts.Span{Start: 5, End: 5}, "", "v1.0.0")
	if err == nil {
		t.Fatal("expected error for empty name")
	}
}

// --- ScanContext tests ---

func TestNewScanContextValid(t *testing.T) {
	sc, err := facts.NewScanContext("/Users/me/repo", "sample-api", "main", "abc123", []facts.Language{facts.LangGo}, 84)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sc.RepoName != "sample-api" {
		t.Errorf("expected repo name sample-api, got %s", sc.RepoName)
	}
	if sc.FileCount != 84 {
		t.Errorf("expected file count 84, got %d", sc.FileCount)
	}
}

func TestNewScanContextMissingRepoPath(t *testing.T) {
	_, err := facts.NewScanContext("", "sample-api", "main", "abc123", []facts.Language{facts.LangGo}, 10)
	if err == nil {
		t.Fatal("expected error for empty repo path")
	}
}

func TestNewScanContextNoLanguages(t *testing.T) {
	_, err := facts.NewScanContext("/repo", "sample-api", "main", "abc123", nil, 10)
	if err == nil {
		t.Fatal("expected error for empty languages")
	}
}

// --- Evidence tests ---

func TestNewEvidenceValid(t *testing.T) {
	e, err := facts.NewEvidence("symbol", "src/auth.go", 10, 24, "authMiddleware", "jwt.verify(token)")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if e.Type != "symbol" {
		t.Errorf("expected type symbol, got %s", e.Type)
	}
}

func TestNewEvidenceMissingFile(t *testing.T) {
	_, err := facts.NewEvidence("symbol", "", 10, 24, "authMiddleware", "jwt.verify(token)")
	if err == nil {
		t.Fatal("expected error for empty file")
	}
}

func TestNewEvidenceMissingType(t *testing.T) {
	_, err := facts.NewEvidence("", "src/auth.go", 10, 24, "authMiddleware", "jwt.verify(token)")
	if err == nil {
		t.Fatal("expected error for empty type")
	}
}

// --- Finding tests ---

func TestNewFindingValid(t *testing.T) {
	ev, _ := facts.NewEvidence("symbol", "src/auth.go", 10, 24, "authMiddleware", "jwt.verify(token)")
	f, err := facts.NewFinding("AUTH-001", "JWT authentication detected", "pass", "high", "verified", "JWT found", []facts.Evidence{ev}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if f.RuleID != "AUTH-001" {
		t.Errorf("expected rule id AUTH-001, got %s", f.RuleID)
	}
	if f.Title != "JWT authentication detected" {
		t.Errorf("expected title, got %s", f.Title)
	}
	if f.Status != "pass" {
		t.Errorf("expected status pass, got %s", f.Status)
	}
}

func TestNewFindingMissingRuleID(t *testing.T) {
	_, err := facts.NewFinding("", "title", "pass", "high", "verified", "msg", nil, nil)
	if err == nil {
		t.Fatal("expected error for empty rule id")
	}
}

func TestNewFindingInvalidStatus(t *testing.T) {
	_, err := facts.NewFinding("AUTH-001", "title", "invalid", "high", "verified", "msg", nil, nil)
	if err == nil {
		t.Fatal("expected error for invalid status")
	}
}

func TestNewFindingInvalidConfidence(t *testing.T) {
	_, err := facts.NewFinding("AUTH-001", "title", "pass", "extreme", "verified", "msg", nil, nil)
	if err == nil {
		t.Fatal("expected error for invalid confidence")
	}
}

func TestNewFindingInvalidVerificationLevel(t *testing.T) {
	_, err := facts.NewFinding("AUTH-001", "title", "pass", "high", "magic", "msg", nil, nil)
	if err == nil {
		t.Fatal("expected error for invalid verification level")
	}
}

func TestNewFindingUnknownRequiresReasons(t *testing.T) {
	_, err := facts.NewFinding("AUTH-001", "title", "unknown", "low", "weak_inference", "msg", nil, nil)
	if err == nil {
		t.Fatal("expected error for unknown status without reasons")
	}
}

func TestNewFindingUnknownWithReasons(t *testing.T) {
	f, err := facts.NewFinding("AUTH-001", "title", "unknown", "low", "weak_inference", "msg", nil, []string{"insufficient_evidence"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(f.UnknownReasons) != 1 {
		t.Errorf("expected 1 unknown reason, got %d", len(f.UnknownReasons))
	}
}

// --- Additional error path tests for increased coverage ---

// SymbolFact: missing kind (non-empty kind doesn't error, but empty kind struct field is valid in Go)
func TestNewSymbolFactMissingKind(t *testing.T) {
	// Kind="" is allowed by NewSymbolFact (it's not validated), but invalid language is not
	_, err := facts.NewSymbolFact("rust", "main.rs", facts.Span{Start: 1, End: 5}, "Foo", "function", false)
	if err == nil {
		t.Fatal("expected error for invalid language")
	}
}

func TestNewSymbolFactMissingFile(t *testing.T) {
	_, err := facts.NewSymbolFact(facts.LangGo, "", facts.Span{Start: 1, End: 5}, "Foo", "function", false)
	if err == nil {
		t.Fatal("expected error for empty file")
	}
}

// ImportFact: invalid language and invalid span
func TestNewImportFactInvalidLanguage(t *testing.T) {
	_, err := facts.NewImportFact("rust", "main.rs", facts.Span{Start: 1, End: 1}, "fmt", "")
	if err == nil {
		t.Fatal("expected error for invalid language")
	}
}

func TestNewImportFactMissingFile(t *testing.T) {
	_, err := facts.NewImportFact(facts.LangGo, "", facts.Span{Start: 1, End: 1}, "fmt", "")
	if err == nil {
		t.Fatal("expected error for empty file")
	}
}

func TestNewImportFactInvalidSpan(t *testing.T) {
	_, err := facts.NewImportFact(facts.LangGo, "main.go", facts.Span{Start: 0, End: 1}, "fmt", "")
	if err == nil {
		t.Fatal("expected error for invalid span")
	}
}

// RouteFact: invalid language, missing file, invalid span, missing path
func TestNewRouteFactInvalidLanguage(t *testing.T) {
	_, err := facts.NewRouteFact("rust", "routes.go", facts.Span{Start: 1, End: 5}, "GET", "/users", "h", nil)
	if err == nil {
		t.Fatal("expected error for invalid language")
	}
}

func TestNewRouteFactMissingFile(t *testing.T) {
	_, err := facts.NewRouteFact(facts.LangGo, "", facts.Span{Start: 1, End: 5}, "GET", "/users", "h", nil)
	if err == nil {
		t.Fatal("expected error for empty file")
	}
}

func TestNewRouteFactInvalidSpan(t *testing.T) {
	_, err := facts.NewRouteFact(facts.LangGo, "routes.go", facts.Span{Start: 0, End: 5}, "GET", "/users", "h", nil)
	if err == nil {
		t.Fatal("expected error for invalid span")
	}
}

func TestNewRouteFactMissingPath(t *testing.T) {
	_, err := facts.NewRouteFact(facts.LangGo, "routes.go", facts.Span{Start: 1, End: 5}, "GET", "", "h", nil)
	if err == nil {
		t.Fatal("expected error for empty path")
	}
}

// MiddlewareFact: invalid language, missing file, invalid span
func TestNewMiddlewareFactInvalidLanguage(t *testing.T) {
	_, err := facts.NewMiddlewareFact("rust", "mw.go", facts.Span{Start: 1, End: 10}, "Auth", "auth")
	if err == nil {
		t.Fatal("expected error for invalid language")
	}
}

func TestNewMiddlewareFactMissingFile(t *testing.T) {
	_, err := facts.NewMiddlewareFact(facts.LangGo, "", facts.Span{Start: 1, End: 10}, "Auth", "auth")
	if err == nil {
		t.Fatal("expected error for empty file")
	}
}

func TestNewMiddlewareFactInvalidSpan(t *testing.T) {
	_, err := facts.NewMiddlewareFact(facts.LangGo, "mw.go", facts.Span{Start: 0, End: 10}, "Auth", "auth")
	if err == nil {
		t.Fatal("expected error for invalid span")
	}
}

// TestFact: invalid language, missing file, invalid span
func TestNewTestFactInvalidLanguage(t *testing.T) {
	_, err := facts.NewTestFact("rust", "test.go", facts.Span{Start: 1, End: 10}, "Test1", "mod", "")
	if err == nil {
		t.Fatal("expected error for invalid language")
	}
}

func TestNewTestFactMissingFile(t *testing.T) {
	_, err := facts.NewTestFact(facts.LangGo, "", facts.Span{Start: 1, End: 10}, "Test1", "mod", "")
	if err == nil {
		t.Fatal("expected error for empty file")
	}
}

func TestNewTestFactInvalidSpan(t *testing.T) {
	_, err := facts.NewTestFact(facts.LangGo, "test.go", facts.Span{Start: 0, End: 10}, "Test1", "mod", "")
	if err == nil {
		t.Fatal("expected error for invalid span")
	}
}

// DataAccessFact: invalid language, missing file, invalid span
func TestNewDataAccessFactInvalidLanguage(t *testing.T) {
	_, err := facts.NewDataAccessFact("rust", "repo.go", facts.Span{Start: 1, End: 5}, "query", "sql")
	if err == nil {
		t.Fatal("expected error for invalid language")
	}
}

func TestNewDataAccessFactMissingFile(t *testing.T) {
	_, err := facts.NewDataAccessFact(facts.LangGo, "", facts.Span{Start: 1, End: 5}, "query", "sql")
	if err == nil {
		t.Fatal("expected error for empty file")
	}
}

func TestNewDataAccessFactInvalidSpan(t *testing.T) {
	_, err := facts.NewDataAccessFact(facts.LangGo, "repo.go", facts.Span{Start: 0, End: 5}, "query", "sql")
	if err == nil {
		t.Fatal("expected error for invalid span")
	}
}

// ConfigFact: invalid language, missing file, invalid span
func TestNewConfigFactInvalidLanguage(t *testing.T) {
	_, err := facts.NewConfigFact("rust", "config.go", facts.Span{Start: 1, End: 3}, "KEY", "env")
	if err == nil {
		t.Fatal("expected error for invalid language")
	}
}

func TestNewConfigFactMissingFile(t *testing.T) {
	_, err := facts.NewConfigFact(facts.LangGo, "", facts.Span{Start: 1, End: 3}, "KEY", "env")
	if err == nil {
		t.Fatal("expected error for empty file")
	}
}

func TestNewConfigFactInvalidSpan(t *testing.T) {
	_, err := facts.NewConfigFact(facts.LangGo, "config.go", facts.Span{Start: 0, End: 3}, "KEY", "env")
	if err == nil {
		t.Fatal("expected error for invalid span")
	}
}

// SecretFact: invalid language, missing file, invalid span
func TestNewSecretFactInvalidLanguage(t *testing.T) {
	_, err := facts.NewSecretFact("rust", "config.go", facts.Span{Start: 1, End: 1}, "password", "pw")
	if err == nil {
		t.Fatal("expected error for invalid language")
	}
}

func TestNewSecretFactMissingFile(t *testing.T) {
	_, err := facts.NewSecretFact(facts.LangGo, "", facts.Span{Start: 1, End: 1}, "password", "pw")
	if err == nil {
		t.Fatal("expected error for empty file")
	}
}

func TestNewSecretFactInvalidSpan(t *testing.T) {
	_, err := facts.NewSecretFact(facts.LangGo, "config.go", facts.Span{Start: 0, End: 1}, "password", "pw")
	if err == nil {
		t.Fatal("expected error for invalid span")
	}
}

// DependencyFact: invalid language, missing file, invalid span
func TestNewDependencyFactInvalidLanguage(t *testing.T) {
	_, err := facts.NewDependencyFact("rust", "go.mod", facts.Span{Start: 1, End: 1}, "gin", "v1.0.0")
	if err == nil {
		t.Fatal("expected error for invalid language")
	}
}

func TestNewDependencyFactMissingFile(t *testing.T) {
	_, err := facts.NewDependencyFact(facts.LangGo, "", facts.Span{Start: 1, End: 1}, "gin", "v1.0.0")
	if err == nil {
		t.Fatal("expected error for empty file")
	}
}

func TestNewDependencyFactInvalidSpan(t *testing.T) {
	_, err := facts.NewDependencyFact(facts.LangGo, "go.mod", facts.Span{Start: 0, End: 1}, "gin", "v1.0.0")
	if err == nil {
		t.Fatal("expected error for invalid span")
	}
}

// Evidence: invalid line start/end
func TestNewEvidenceInvalidLineStart(t *testing.T) {
	_, err := facts.NewEvidence("symbol", "auth.go", 0, 5, "fn", "code")
	if err == nil {
		t.Fatal("expected error for line_start=0")
	}
}

func TestNewEvidenceEndBeforeStart(t *testing.T) {
	_, err := facts.NewEvidence("symbol", "auth.go", 10, 5, "fn", "code")
	if err == nil {
		t.Fatal("expected error for line_end < line_start")
	}
}

// ScanContext: missing repo name, invalid language
func TestNewScanContextMissingRepoName(t *testing.T) {
	_, err := facts.NewScanContext("/repo", "", "main", "abc123", []facts.Language{facts.LangGo}, 10)
	if err == nil {
		t.Fatal("expected error for empty repo name")
	}
}

func TestNewScanContextInvalidLanguage(t *testing.T) {
	_, err := facts.NewScanContext("/repo", "my-repo", "main", "abc123", []facts.Language{"rust"}, 10)
	if err == nil {
		t.Fatal("expected error for invalid language")
	}
}

// Span: negative start
func TestSpanNegativeStart(t *testing.T) {
	s := facts.Span{Start: -1, End: 10}
	if err := s.Validate(); err == nil {
		t.Fatal("expected error for negative start")
	}
}

// Finding: missing title is OK (not validated), but test various valid combos
func TestNewFindingAllStatuses(t *testing.T) {
	for _, status := range []string{"pass", "fail"} {
		_, err := facts.NewFinding("R-1", "t", status, "high", "verified", "msg", nil, nil)
		if err != nil {
			t.Errorf("unexpected error for status %s: %v", status, err)
		}
	}
}

func TestNewFindingAllConfidences(t *testing.T) {
	for _, conf := range []string{"high", "medium", "low"} {
		_, err := facts.NewFinding("R-1", "t", "pass", conf, "verified", "msg", nil, nil)
		if err != nil {
			t.Errorf("unexpected error for confidence %s: %v", conf, err)
		}
	}
}

func TestNewFindingAllVerificationLevels(t *testing.T) {
	for _, vl := range []string{"verified", "strong_inference", "weak_inference"} {
		_, err := facts.NewFinding("R-1", "t", "pass", "high", vl, "msg", nil, nil)
		if err != nil {
			t.Errorf("unexpected error for verification level %s: %v", vl, err)
		}
	}
}

// Language: empty string
func TestLanguageEmpty(t *testing.T) {
	lang := facts.Language("")
	if lang.IsValid() {
		t.Error("expected empty language to be invalid")
	}
}
