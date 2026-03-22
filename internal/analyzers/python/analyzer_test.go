package python

import (
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

func collectPythonFiles(t *testing.T, root string) []string {
	t.Helper()
	var files []string
	filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && filepath.Ext(path) == ".py" {
			rel, _ := filepath.Rel(root, path)
			files = append(files, rel)
		}
		return nil
	})
	return files
}

func TestPythonAnalyzer_ImplementsInterface(t *testing.T) {
	var _ analyzers.Analyzer = New()
	a := New()
	if a.Language() != facts.LangPython {
		t.Errorf("expected python, got %s", a.Language())
	}
	exts := a.Extensions()
	if len(exts) != 1 || exts[0] != ".py" {
		t.Errorf("expected [.py], got %v", exts)
	}
}

func TestPythonAnalyzer_FileFacts(t *testing.T) {
	root := fixtureRoot(t, "python-fastapi-clean")
	files := collectPythonFiles(t, root)

	a := New()
	result, err := a.Analyze(root, files)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	if len(result.Files) == 0 {
		t.Fatal("expected at least one FileFact")
	}
	for _, ff := range result.Files {
		if ff.Language != facts.LangPython {
			t.Errorf("expected language python, got %s", ff.Language)
		}
		if ff.File == "" {
			t.Error("expected non-empty file path")
		}
		if ff.LineCount < 1 {
			t.Errorf("expected positive line count for %s, got %d", ff.File, ff.LineCount)
		}
	}
}

func TestPythonAnalyzer_SymbolFacts(t *testing.T) {
	root := fixtureRoot(t, "python-fastapi-clean")
	files := collectPythonFiles(t, root)

	a := New()
	result, err := a.Analyze(root, files)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	if len(result.Symbols) == 0 {
		t.Fatal("expected at least one SymbolFact")
	}

	foundVerifyToken := false
	foundUserService := false
	foundUserRepository := false
	for _, sf := range result.Symbols {
		if sf.Name == "verify_token" && sf.Kind == "function" {
			foundVerifyToken = true
		}
		if sf.Name == "UserService" && sf.Kind == "class" {
			foundUserService = true
		}
		if sf.Name == "UserRepository" && sf.Kind == "class" {
			foundUserRepository = true
		}
	}
	if !foundVerifyToken {
		t.Error("expected to find function verify_token")
	}
	if !foundUserService {
		t.Error("expected to find class UserService")
	}
	if !foundUserRepository {
		t.Error("expected to find class UserRepository")
	}
}

func TestPythonAnalyzer_ImportFacts(t *testing.T) {
	root := fixtureRoot(t, "python-fastapi-clean")
	files := collectPythonFiles(t, root)

	a := New()
	result, err := a.Analyze(root, files)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	if len(result.Imports) == 0 {
		t.Fatal("expected at least one ImportFact")
	}

	foundFastAPI := false
	foundSQLAlchemy := false
	for _, imp := range result.Imports {
		if imp.ImportPath == "fastapi" {
			foundFastAPI = true
		}
		if imp.ImportPath == "sqlalchemy.orm" {
			foundSQLAlchemy = true
		}
	}
	if !foundFastAPI {
		t.Error("expected to find fastapi import")
	}
	if !foundSQLAlchemy {
		t.Error("expected to find sqlalchemy.orm import")
	}
}

func TestPythonAnalyzer_TestFacts(t *testing.T) {
	root := fixtureRoot(t, "python-fastapi-clean")
	files := collectPythonFiles(t, root)

	a := New()
	result, err := a.Analyze(root, files)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	if len(result.Tests) == 0 {
		t.Fatal("expected at least one TestFact")
	}

	foundTokenTest := false
	foundEmptyTest := false
	for _, tf := range result.Tests {
		if tf.TestName == "test_verify_token_invalid" {
			foundTokenTest = true
		}
		if tf.TestName == "test_verify_token_empty" {
			foundEmptyTest = true
		}
	}
	if !foundTokenTest {
		t.Error("expected to find test_verify_token_invalid")
	}
	if !foundEmptyTest {
		t.Error("expected to find test_verify_token_empty")
	}
}

func TestPythonAnalyzer_RouteFacts(t *testing.T) {
	root := fixtureRoot(t, "python-fastapi-clean")
	files := collectPythonFiles(t, root)

	a := New()
	result, err := a.Analyze(root, files)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	if len(result.Routes) == 0 {
		t.Fatal("expected at least one RouteFact")
	}

	foundHealth := false
	foundGetUser := false
	foundPostUser := false
	for _, rf := range result.Routes {
		if rf.Path == "/health" && rf.Method == "GET" {
			foundHealth = true
		}
		if rf.Path == "/users/{user_id}" && rf.Method == "GET" {
			foundGetUser = true
		}
		if rf.Path == "/users" && rf.Method == "POST" {
			foundPostUser = true
		}
	}
	if !foundHealth {
		t.Error("expected to find GET /health route")
	}
	if !foundGetUser {
		t.Error("expected to find GET /users/{user_id} route")
	}
	if !foundPostUser {
		t.Error("expected to find POST /users route")
	}
}

func TestPythonAnalyzer_MiddlewareFacts(t *testing.T) {
	root := fixtureRoot(t, "python-fastapi-clean")
	files := collectPythonFiles(t, root)

	a := New()
	result, err := a.Analyze(root, files)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	if len(result.Middlewares) == 0 {
		t.Fatal("expected at least one MiddlewareFact for Depends-based auth")
	}

	foundAuth := false
	for _, mw := range result.Middlewares {
		if mw.Name == "require_auth" {
			foundAuth = true
		}
	}
	if !foundAuth {
		t.Error("expected to find require_auth middleware")
	}
}

func TestPythonAnalyzer_DataAccessFacts(t *testing.T) {
	root := fixtureRoot(t, "python-fastapi-clean")
	files := collectPythonFiles(t, root)

	a := New()
	result, err := a.Analyze(root, files)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	if len(result.DataAccess) == 0 {
		t.Fatal("expected at least one DataAccessFact for sqlalchemy usage")
	}

	foundSQLAlchemy := false
	for _, da := range result.DataAccess {
		if da.Backend == "sqlalchemy" {
			foundSQLAlchemy = true
		}
	}
	if !foundSQLAlchemy {
		t.Error("expected sqlalchemy backend")
	}
}

func TestPythonAnalyzer_SecretFacts(t *testing.T) {
	root := fixtureRoot(t, "python-fastapi-hardcoded-secret")
	files := collectPythonFiles(t, root)

	a := New()
	result, err := a.Analyze(root, files)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	if len(result.Secrets) == 0 {
		t.Fatal("expected at least one SecretFact")
	}

	// Should find SECRET_KEY, API_KEY, JWT_SECRET, DATABASE_URL (has password in URL)
	if len(result.Secrets) < 3 {
		t.Errorf("expected at least 3 secrets, got %d", len(result.Secrets))
	}
}

func TestPythonAnalyzer_EmptyFiles(t *testing.T) {
	a := New()
	result, err := a.Analyze("/nonexistent", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Files) != 0 {
		t.Errorf("expected no files, got %d", len(result.Files))
	}
}

func TestPythonAnalyzer_EmptyFileList(t *testing.T) {
	a := New()
	result, err := a.Analyze(".", []string{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
}

func TestPythonAnalyzer_NonexistentFile(t *testing.T) {
	a := New()
	result, err := a.Analyze("/tmp", []string{"nonexistent.py"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Files) != 0 {
		t.Errorf("expected no files for nonexistent input, got %d", len(result.Files))
	}
}

func TestPythonAnalyzer_CleanAppNoSecrets(t *testing.T) {
	// The clean FastAPI app uses os.environ.get, which should NOT be flagged
	root := fixtureRoot(t, "python-fastapi-clean")
	files := collectPythonFiles(t, root)

	a := New()
	result, err := a.Analyze(root, files)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	for _, s := range result.Secrets {
		if s.File == "auth/jwt.py" {
			t.Error("auth/jwt.py uses os.environ.get, should NOT trigger secret detection")
		}
	}
}

func TestPythonAnalyzer_TestMethodInClass(t *testing.T) {
	root := fixtureRoot(t, "python-fastapi-clean")
	files := collectPythonFiles(t, root)

	a := New()
	result, err := a.Analyze(root, files)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	foundClassMethod := false
	for _, tf := range result.Tests {
		if tf.TestName == "test_require_auth_missing" {
			foundClassMethod = true
		}
	}
	if !foundClassMethod {
		t.Error("expected to find test_require_auth_missing from TestAuthMiddleware class")
	}
}

func TestPythonAnalyzer_BothFixtures(t *testing.T) {
	fixtures := []string{"python-fastapi-clean", "python-fastapi-hardcoded-secret"}
	a := New()
	for _, fix := range fixtures {
		root := fixtureRoot(t, fix)
		files := collectPythonFiles(t, root)
		result, err := a.Analyze(root, files)
		if err != nil {
			t.Fatalf("Analyze(%s) failed: %v", fix, err)
		}
		if len(result.Files) == 0 {
			t.Errorf("Analyze(%s): expected files", fix)
		}
	}
}

func TestPythonAnalyzer_PrivateSymbol(t *testing.T) {
	root := fixtureRoot(t, "python-fastapi-clean")
	files := collectPythonFiles(t, root)

	a := New()
	result, err := a.Analyze(root, files)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	// Public symbols should be exported
	for _, sf := range result.Symbols {
		if sf.Name == "health" {
			if !sf.Exported {
				t.Error("expected public function 'health' to be exported")
			}
		}
	}
}
