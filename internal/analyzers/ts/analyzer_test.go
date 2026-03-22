package ts_test

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/verabase/code-verification-engine/internal/analyzers/ts"
	"github.com/verabase/code-verification-engine/internal/facts"
)

func fixtureDir() string {
	_, filename, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(filename), "..", "..", "..", "testdata", "repos", "ts-express-auth")
}

func collectFiles(dir string) []string {
	var files []string
	filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if !info.IsDir() && (filepath.Ext(path) == ".ts" || filepath.Ext(path) == ".tsx") {
			rel, _ := filepath.Rel(dir, path)
			files = append(files, rel)
		}
		return nil
	})
	return files
}

func analyzeFixture(t *testing.T) *ts.TypeScriptAnalyzer {
	t.Helper()
	return ts.New()
}

func TestTypeScriptAnalyzerLanguage(t *testing.T) {
	a := ts.New()
	if a.Language() != facts.LangTypeScript {
		t.Errorf("expected typescript, got %s", a.Language())
	}
}

func TestTypeScriptAnalyzerExtensions(t *testing.T) {
	a := ts.New()
	exts := a.Extensions()
	if len(exts) != 2 {
		t.Fatalf("expected 2 extensions, got %d", len(exts))
	}
	if exts[0] != ".ts" || exts[1] != ".tsx" {
		t.Errorf("expected [.ts .tsx], got %v", exts)
	}
}

func TestTypeScriptAnalyzerFileFacts(t *testing.T) {
	a := analyzeFixture(t)
	dir := fixtureDir()
	files := collectFiles(dir)
	result, err := a.Analyze(dir, files)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}
	// 8 .ts files: index, auth route, users route, middleware/auth, userService, db/prisma, config, tests/auth.test
	if len(result.Files) < 8 {
		t.Errorf("expected at least 8 file facts, got %d", len(result.Files))
	}
	for _, f := range result.Files {
		if f.Language != facts.LangTypeScript {
			t.Errorf("expected language typescript, got %s for %s", f.Language, f.File)
		}
	}
}

func TestTypeScriptAnalyzerImports(t *testing.T) {
	a := analyzeFixture(t)
	dir := fixtureDir()
	files := collectFiles(dir)
	result, err := a.Analyze(dir, files)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	importPaths := make(map[string]bool)
	for _, imp := range result.Imports {
		importPaths[imp.ImportPath] = true
	}
	for _, expected := range []string{"express", "jsonwebtoken", "@prisma/client", "cors"} {
		if !importPaths[expected] {
			t.Errorf("expected import %q not found. have: %v", expected, importPaths)
		}
	}
}

func TestTypeScriptAnalyzerSymbols(t *testing.T) {
	a := analyzeFixture(t)
	dir := fixtureDir()
	files := collectFiles(dir)
	result, err := a.Analyze(dir, files)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	symbolNames := make(map[string]string)
	for _, s := range result.Symbols {
		symbolNames[s.Name] = s.Kind
	}

	expected := map[string]string{
		"authMiddleware": "function",
		"getConfig":      "function",
		"UserService":    "class",
		"AuthRequest":    "interface",
		"AppConfig":      "interface",
	}
	for name, kind := range expected {
		if got, ok := symbolNames[name]; !ok {
			t.Errorf("expected symbol %q not found", name)
		} else if got != kind {
			t.Errorf("symbol %q: expected kind %q, got %q", name, kind, got)
		}
	}
}

func TestTypeScriptAnalyzerExportedSymbols(t *testing.T) {
	a := analyzeFixture(t)
	dir := fixtureDir()
	files := collectFiles(dir)
	result, err := a.Analyze(dir, files)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	exportedSymbols := make(map[string]bool)
	for _, s := range result.Symbols {
		if s.Exported {
			exportedSymbols[s.Name] = true
		}
	}

	// These should be exported
	for _, name := range []string{"authMiddleware", "getConfig", "UserService", "AuthRequest", "AppConfig"} {
		if !exportedSymbols[name] {
			t.Errorf("expected symbol %q to be exported", name)
		}
	}
}

func TestTypeScriptAnalyzerRoutes(t *testing.T) {
	a := analyzeFixture(t)
	dir := fixtureDir()
	files := collectFiles(dir)
	result, err := a.Analyze(dir, files)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	if len(result.Routes) < 4 {
		t.Errorf("expected at least 4 routes, got %d", len(result.Routes))
	}

	// Check specific routes
	routeMap := make(map[string]string)
	for _, r := range result.Routes {
		routeMap[r.Method+" "+r.Path] = r.File
	}

	for _, key := range []string{"POST /login", "POST /register", "GET /profile", "DELETE /account"} {
		if _, ok := routeMap[key]; !ok {
			t.Errorf("expected route %q not found", key)
		}
	}
}

func TestTypeScriptAnalyzerMiddleware(t *testing.T) {
	a := analyzeFixture(t)
	dir := fixtureDir()
	files := collectFiles(dir)
	result, err := a.Analyze(dir, files)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	mwNames := make(map[string]bool)
	for _, m := range result.Middlewares {
		mwNames[m.Name] = true
	}

	for _, expected := range []string{"cors", "authMiddleware"} {
		if !mwNames[expected] {
			t.Errorf("expected middleware %q not found", expected)
		}
	}
}

func TestTypeScriptAnalyzerDataAccess(t *testing.T) {
	a := analyzeFixture(t)
	dir := fixtureDir()
	files := collectFiles(dir)
	result, err := a.Analyze(dir, files)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	if len(result.DataAccess) < 1 {
		t.Fatal("expected at least 1 data access fact (prisma)")
	}

	found := false
	for _, d := range result.DataAccess {
		if d.Backend == "prisma" {
			found = true
		}
	}
	if !found {
		t.Error("expected prisma data access not found")
	}
}

func TestTypeScriptAnalyzerSecrets(t *testing.T) {
	a := analyzeFixture(t)
	dir := fixtureDir()
	files := collectFiles(dir)
	result, err := a.Analyze(dir, files)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	if len(result.Secrets) < 1 {
		t.Error("expected at least 1 secret fact")
	}

	// Should detect JWT_SECRET and API_KEY
	kinds := make(map[string]bool)
	for _, s := range result.Secrets {
		kinds[s.Kind] = true
	}
	if !kinds["hardcoded_secret"] && !kinds["hardcoded_api_key"] {
		t.Errorf("expected hardcoded_secret or hardcoded_api_key, got kinds: %v", kinds)
	}
}

func TestTypeScriptAnalyzerTests(t *testing.T) {
	a := analyzeFixture(t)
	dir := fixtureDir()
	files := collectFiles(dir)
	result, err := a.Analyze(dir, files)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	if len(result.Tests) < 1 {
		t.Error("expected at least 1 test fact")
	}

	for _, tf := range result.Tests {
		if tf.Language != facts.LangTypeScript {
			t.Errorf("expected test language typescript, got %s", tf.Language)
		}
	}

	// Should find describe and it blocks
	testNames := make(map[string]bool)
	for _, tf := range result.Tests {
		testNames[tf.TestName] = true
	}
	if !testNames["authMiddleware"] {
		t.Error("expected test 'authMiddleware' (describe block) not found")
	}
}

func TestTypeScriptAnalyzerEmptyFiles(t *testing.T) {
	a := ts.New()
	result, err := a.Analyze("/nonexistent", nil)
	if err != nil {
		t.Fatalf("Analyze with nil files should not error: %v", err)
	}
	if len(result.Files) != 0 {
		t.Errorf("expected 0 files, got %d", len(result.Files))
	}
}

func TestTypeScriptAnalyzerSkipsUnreadableFiles(t *testing.T) {
	a := ts.New()
	result, err := a.Analyze("/tmp", []string{"nonexistent.ts"})
	if err != nil {
		t.Fatalf("Analyze should not error on unreadable files: %v", err)
	}
	if len(result.Files) != 0 {
		t.Errorf("expected 0 files for unreadable input, got %d", len(result.Files))
	}
}
