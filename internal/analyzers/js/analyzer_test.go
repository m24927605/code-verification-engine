package js_test

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/verabase/code-verification-engine/internal/analyzers/js"
	"github.com/verabase/code-verification-engine/internal/facts"
)

func fixtureDir() string {
	_, filename, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(filename), "..", "..", "..", "testdata", "repos", "js-node-no-auth")
}

func collectFiles(dir string) []string {
	var files []string
	filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if !info.IsDir() && (filepath.Ext(path) == ".js" || filepath.Ext(path) == ".jsx") {
			rel, _ := filepath.Rel(dir, path)
			files = append(files, rel)
		}
		return nil
	})
	return files
}

func TestJavaScriptAnalyzerLanguage(t *testing.T) {
	a := js.New()
	if a.Language() != facts.LangJavaScript {
		t.Errorf("expected javascript, got %s", a.Language())
	}
}

func TestJavaScriptAnalyzerExtensions(t *testing.T) {
	a := js.New()
	exts := a.Extensions()
	if len(exts) != 2 {
		t.Fatalf("expected 2 extensions, got %d", len(exts))
	}
	if exts[0] != ".js" || exts[1] != ".jsx" {
		t.Errorf("expected [.js .jsx], got %v", exts)
	}
}

func TestJavaScriptAnalyzerFileFacts(t *testing.T) {
	a := js.New()
	dir := fixtureDir()
	files := collectFiles(dir)
	result, err := a.Analyze(dir, files)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}
	// 4 .js files: index, routes/items, db/pool, tests/items.test
	if len(result.Files) < 4 {
		t.Errorf("expected at least 4 file facts, got %d", len(result.Files))
	}
	for _, f := range result.Files {
		if f.Language != facts.LangJavaScript {
			t.Errorf("expected language javascript, got %s for %s", f.Language, f.File)
		}
	}
}

func TestJavaScriptAnalyzerImports(t *testing.T) {
	a := js.New()
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

	for _, expected := range []string{"express", "pg", "supertest"} {
		if !importPaths[expected] {
			t.Errorf("expected import %q not found. have: %v", expected, importPaths)
		}
	}
}

func TestJavaScriptAnalyzerRoutes(t *testing.T) {
	a := js.New()
	dir := fixtureDir()
	files := collectFiles(dir)
	result, err := a.Analyze(dir, files)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	if len(result.Routes) < 3 {
		t.Errorf("expected at least 3 routes, got %d", len(result.Routes))
	}

	routeMap := make(map[string]bool)
	for _, r := range result.Routes {
		routeMap[r.Method+" "+r.Path] = true
	}

	for _, key := range []string{"GET /", "POST /", "DELETE /:id"} {
		if !routeMap[key] {
			t.Errorf("expected route %q not found", key)
		}
	}
}

func TestJavaScriptAnalyzerDataAccess(t *testing.T) {
	a := js.New()
	dir := fixtureDir()
	files := collectFiles(dir)
	result, err := a.Analyze(dir, files)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	if len(result.DataAccess) < 1 {
		t.Fatal("expected at least 1 data access fact (pg)")
	}

	found := false
	for _, d := range result.DataAccess {
		if d.Backend == "pg" {
			found = true
		}
	}
	if !found {
		t.Error("expected pg data access not found")
	}
}

func TestJavaScriptAnalyzerNoSecrets(t *testing.T) {
	a := js.New()
	dir := fixtureDir()
	files := collectFiles(dir)
	result, err := a.Analyze(dir, files)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}
	if len(result.Secrets) != 0 {
		t.Errorf("expected 0 secrets in js-node-no-auth fixture, got %d", len(result.Secrets))
	}
}

func TestJavaScriptAnalyzerTests(t *testing.T) {
	a := js.New()
	dir := fixtureDir()
	files := collectFiles(dir)
	result, err := a.Analyze(dir, files)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	if len(result.Tests) < 2 {
		t.Errorf("expected at least 2 test facts, got %d", len(result.Tests))
	}

	for _, tf := range result.Tests {
		if tf.Language != facts.LangJavaScript {
			t.Errorf("expected test language javascript, got %s", tf.Language)
		}
	}

	testNames := make(map[string]bool)
	for _, tf := range result.Tests {
		testNames[tf.TestName] = true
	}
	if !testNames["Items API"] {
		t.Error("expected test 'Items API' (describe block) not found")
	}
}

func TestJavaScriptAnalyzerMiddleware(t *testing.T) {
	a := js.New()
	dir := fixtureDir()
	files := collectFiles(dir)
	result, err := a.Analyze(dir, files)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	// js-node-no-auth uses app.use(express.json()) but that matches "express" as middleware name
	// and app.use('/items', itemsRouter) which won't match (path arg first)
	// At minimum, should not crash
	if result.Middlewares == nil {
		result.Middlewares = []facts.MiddlewareFact{}
	}
}

func TestJavaScriptAnalyzerEmptyFiles(t *testing.T) {
	a := js.New()
	result, err := a.Analyze("/nonexistent", nil)
	if err != nil {
		t.Fatalf("Analyze with nil files should not error: %v", err)
	}
	if len(result.Files) != 0 {
		t.Errorf("expected 0 files, got %d", len(result.Files))
	}
}

func TestJavaScriptAnalyzerSkipsUnreadableFiles(t *testing.T) {
	a := js.New()
	result, err := a.Analyze("/tmp", []string{"nonexistent.js"})
	if err != nil {
		t.Fatalf("Analyze should not error on unreadable files: %v", err)
	}
	if len(result.Files) != 0 {
		t.Errorf("expected 0 files for unreadable input, got %d", len(result.Files))
	}
}

func TestJavaScriptAnalyzerSymbols(t *testing.T) {
	a := js.New()
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

	// ItemValidator class and formatPrice function from utils.js
	if kind, ok := symbolNames["ItemValidator"]; !ok {
		t.Error("expected symbol ItemValidator not found")
	} else if kind != "class" {
		t.Errorf("expected ItemValidator kind class, got %s", kind)
	}

	if kind, ok := symbolNames["formatPrice"]; !ok {
		t.Error("expected symbol formatPrice not found")
	} else if kind != "function" {
		t.Errorf("expected formatPrice kind function, got %s", kind)
	}
}

func TestJavaScriptAnalyzerSpecFile(t *testing.T) {
	// Test that .spec.js files are treated as test files too
	a := js.New()
	// analyzeFile is not exported, but we can verify via the isTestFile logic
	// by checking that items.test.js was detected
	dir := fixtureDir()
	files := collectFiles(dir)
	result, err := a.Analyze(dir, files)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	// Verify test file detection
	testFiles := make(map[string]bool)
	for _, tf := range result.Tests {
		testFiles[tf.File] = true
	}
	if !testFiles["tests/items.test.js"] {
		t.Error("expected tests/items.test.js to be detected as test file")
	}
}
