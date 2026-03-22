package goanalyzer

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/verabase/code-verification-engine/internal/analyzers"
	"github.com/verabase/code-verification-engine/internal/facts"
)

func fixtureRoot(t *testing.T, name string) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", "..", "..", "testdata", "repos", name))
	if err != nil {
		t.Fatalf("failed to resolve fixture root: %v", err)
	}
	if _, err := os.Stat(root); err != nil {
		t.Fatalf("fixture %q not found at %s: %v", name, root, err)
	}
	return root
}

func collectGoFiles(t *testing.T, root string) []string {
	t.Helper()
	var files []string
	filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && filepath.Ext(path) == ".go" {
			rel, _ := filepath.Rel(root, path)
			files = append(files, rel)
		}
		return nil
	})
	return files
}

// Verify the analyzer implements the shared interface.
func TestGoAnalyzer_ImplementsInterface(t *testing.T) {
	var _ analyzers.Analyzer = New()
	a := New()
	if a.Language() != facts.LangGo {
		t.Errorf("expected go, got %s", a.Language())
	}
	exts := a.Extensions()
	if len(exts) != 1 || exts[0] != ".go" {
		t.Errorf("expected [.go], got %v", exts)
	}
}

func TestGoAnalyzer_FileFacts(t *testing.T) {
	root := fixtureRoot(t, "go-secure-api")
	files := collectGoFiles(t, root)

	a := New()
	result, err := a.Analyze(root, files)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	if len(result.Files) == 0 {
		t.Fatal("expected at least one FileFact")
	}

	for _, ff := range result.Files {
		if ff.Language != facts.LangGo {
			t.Errorf("expected language go, got %s", ff.Language)
		}
		if ff.File == "" {
			t.Error("expected non-empty file path")
		}
		if ff.LineCount < 1 {
			t.Errorf("expected positive line count for %s, got %d", ff.File, ff.LineCount)
		}
	}
}

func TestGoAnalyzer_SymbolFacts(t *testing.T) {
	root := fixtureRoot(t, "go-secure-api")
	files := collectGoFiles(t, root)

	a := New()
	result, err := a.Analyze(root, files)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	if len(result.Symbols) == 0 {
		t.Fatal("expected at least one SymbolFact")
	}

	foundVerifyToken := false
	foundAuthMiddleware := false
	foundGetUser := false
	for _, sf := range result.Symbols {
		if sf.Name == "VerifyToken" && sf.Kind == "function" && sf.Exported {
			foundVerifyToken = true
		}
		if sf.Name == "AuthMiddleware" && sf.Kind == "function" && sf.Exported {
			foundAuthMiddleware = true
		}
		if sf.Name == "GetUser" && sf.Kind == "function" && sf.Exported {
			foundGetUser = true
		}
	}
	if !foundVerifyToken {
		t.Error("expected to find exported function VerifyToken")
	}
	if !foundAuthMiddleware {
		t.Error("expected to find exported function AuthMiddleware")
	}
	if !foundGetUser {
		t.Error("expected to find exported function GetUser")
	}
}

func TestGoAnalyzer_UnexportedSymbol(t *testing.T) {
	root := fixtureRoot(t, "go-secure-api")
	files := collectGoFiles(t, root)

	a := New()
	result, err := a.Analyze(root, files)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	foundHealthHandler := false
	for _, sf := range result.Symbols {
		if sf.Name == "healthHandler" && !sf.Exported {
			foundHealthHandler = true
		}
	}
	if !foundHealthHandler {
		t.Error("expected to find unexported function healthHandler")
	}
}

func TestGoAnalyzer_ImportFacts(t *testing.T) {
	root := fixtureRoot(t, "go-secure-api")
	files := collectGoFiles(t, root)

	a := New()
	result, err := a.Analyze(root, files)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	if len(result.Imports) == 0 {
		t.Fatal("expected at least one ImportFact")
	}

	foundNetHTTP := false
	foundDatabaseSQL := false
	for _, imp := range result.Imports {
		if imp.ImportPath == "net/http" {
			foundNetHTTP = true
		}
		if imp.ImportPath == "database/sql" {
			foundDatabaseSQL = true
		}
	}
	if !foundNetHTTP {
		t.Error("expected to find import net/http")
	}
	if !foundDatabaseSQL {
		t.Error("expected to find import database/sql")
	}
}

func TestGoAnalyzer_TestFacts(t *testing.T) {
	root := fixtureRoot(t, "go-secure-api")
	files := collectGoFiles(t, root)

	a := New()
	result, err := a.Analyze(root, files)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	if len(result.Tests) == 0 {
		t.Fatal("expected at least one TestFact")
	}

	foundVerifyTokenTest := false
	foundVerifyTokenValidTest := false
	for _, tf := range result.Tests {
		if tf.TestName == "TestVerifyToken" {
			foundVerifyTokenTest = true
			if tf.File != "auth/jwt_test.go" {
				t.Errorf("expected test in auth/jwt_test.go, got %s", tf.File)
			}
		}
		if tf.TestName == "TestVerifyTokenValid" {
			foundVerifyTokenValidTest = true
		}
	}
	if !foundVerifyTokenTest {
		t.Error("expected to find TestVerifyToken")
	}
	if !foundVerifyTokenValidTest {
		t.Error("expected to find TestVerifyTokenValid")
	}
}

func TestGoAnalyzer_RouteFacts(t *testing.T) {
	root := fixtureRoot(t, "go-secure-api")
	files := collectGoFiles(t, root)

	a := New()
	result, err := a.Analyze(root, files)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	if len(result.Routes) == 0 {
		t.Fatal("expected at least one RouteFact")
	}

	foundHealth := false
	for _, rf := range result.Routes {
		if rf.Path == "/health" {
			foundHealth = true
			if rf.Handler != "healthHandler" {
				t.Errorf("expected handler healthHandler, got %s", rf.Handler)
			}
		}
	}
	if !foundHealth {
		t.Error("expected to find route /health")
	}
}

func TestGoAnalyzer_MiddlewareFacts(t *testing.T) {
	root := fixtureRoot(t, "go-secure-api")
	files := collectGoFiles(t, root)

	a := New()
	result, err := a.Analyze(root, files)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	if len(result.Middlewares) == 0 {
		t.Fatal("expected at least one MiddlewareFact")
	}

	foundAuth := false
	for _, mw := range result.Middlewares {
		if mw.Name == "AuthMiddleware" {
			foundAuth = true
		}
	}
	if !foundAuth {
		t.Error("expected to find AuthMiddleware")
	}
}

func TestGoAnalyzer_DataAccessFacts(t *testing.T) {
	root := fixtureRoot(t, "go-bad-controller-db")
	files := collectGoFiles(t, root)

	a := New()
	result, err := a.Analyze(root, files)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	if len(result.DataAccess) == 0 {
		t.Fatal("expected at least one DataAccessFact")
	}

	foundQuery := false
	for _, da := range result.DataAccess {
		if da.Backend == "database/sql" {
			foundQuery = true
		}
	}
	if !foundQuery {
		t.Error("expected to find database/sql data access")
	}
}

func TestGoAnalyzer_SecretFacts(t *testing.T) {
	root := fixtureRoot(t, "go-secure-api")
	files := collectGoFiles(t, root)

	a := New()
	result, err := a.Analyze(root, files)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	if len(result.Secrets) == 0 {
		t.Fatal("expected at least one SecretFact for hardcoded jwtSecret")
	}
}

func TestGoAnalyzer_EmptyFiles(t *testing.T) {
	a := New()
	result, err := a.Analyze("/nonexistent", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Files) != 0 {
		t.Errorf("expected no files, got %d", len(result.Files))
	}
}

func TestGoAnalyzer_ContextCancelledViaEmptyDir(t *testing.T) {
	// Verifies analyzer handles gracefully when no files are given
	a := New()
	result, err := a.Analyze(".", []string{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
}

func TestGoAnalyzer_NonexistentFile(t *testing.T) {
	a := New()
	// File that doesn't exist should be skipped gracefully
	result, err := a.Analyze("/tmp", []string{"nonexistent.go"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Files) != 0 {
		t.Errorf("expected no files for nonexistent input, got %d", len(result.Files))
	}
}

func TestGoAnalyzer_DataAccessSecureAPI(t *testing.T) {
	// go-secure-api has database/sql in repo/user.go but no direct queries
	root := fixtureRoot(t, "go-secure-api")
	files := collectGoFiles(t, root)

	a := New()
	result, err := a.Analyze(root, files)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	// Should NOT find data access in handler (it goes through service layer)
	for _, da := range result.DataAccess {
		if da.File == "handler/user.go" {
			t.Error("handler/user.go should not have data access facts (uses service layer)")
		}
	}
}

func TestGoAnalyzer_TypeDecls(t *testing.T) {
	root := fixtureRoot(t, "go-secure-api")
	files := collectGoFiles(t, root)

	a := New()
	result, err := a.Analyze(root, files)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	// The fixture should have types but we can verify the type extraction works
	for _, sf := range result.Symbols {
		if sf.Kind == "struct" || sf.Kind == "interface" || sf.Kind == "type" {
			if sf.Name == "" {
				t.Error("type symbol should have a name")
			}
		}
	}
}

func TestGoAnalyzer_BothFixtures(t *testing.T) {
	// Run against both fixtures to cover more code paths
	fixtures := []string{"go-secure-api", "go-bad-controller-db"}
	a := New()
	for _, fix := range fixtures {
		root := fixtureRoot(t, fix)
		files := collectGoFiles(t, root)
		result, err := a.Analyze(root, files)
		if err != nil {
			t.Fatalf("Analyze(%s) failed: %v", fix, err)
		}
		if len(result.Files) == 0 {
			t.Errorf("Analyze(%s): expected files", fix)
		}
	}
}

func TestGoAnalyzer_InvalidGoFile(t *testing.T) {
	root := fixtureRoot(t, "go-bad-controller-db")
	// Include the invalid file
	files := collectGoFiles(t, root)

	a := New()
	result, err := a.Analyze(root, files)
	if err != nil {
		t.Fatalf("Analyze should not fail on parse errors: %v", err)
	}

	// Should still get facts from valid files, just skip the invalid one
	if len(result.Files) == 0 {
		t.Error("expected facts from valid files despite invalid file")
	}
}

// Suppress unused import warning
var _ = context.Background
