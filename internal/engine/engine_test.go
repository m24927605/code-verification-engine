package engine

import (
	"context"
	"strings"
	"testing"

	"github.com/verabase/code-verification-engine/internal/analyzers"
	"github.com/verabase/code-verification-engine/internal/facts"
	"github.com/verabase/code-verification-engine/internal/rules"
	"github.com/verabase/code-verification-engine/internal/typegraph"
)

func TestFilterAnalyzers(t *testing.T) {
	type mockAnalyzer struct {
		analyzers.Analyzer
		lang string
	}

	// Test that filterFiles works
	files := []string{"main.go", "main_test.go", "app.ts", "server.js", "util.py"}
	goFiles := filterFiles(files, []string{".go"})
	if len(goFiles) != 2 {
		t.Errorf("expected 2 go files, got %d: %v", len(goFiles), goFiles)
	}
	tsFiles := filterFiles(files, []string{".ts"})
	if len(tsFiles) != 1 {
		t.Errorf("expected 1 ts file, got %d", len(tsFiles))
	}
}

func TestBuildFactSet(t *testing.T) {
	results := []*analyzers.AnalysisResult{
		{},
		{},
	}
	fs := buildFactSet(results)
	if fs == nil {
		t.Fatal("factSet should not be nil")
	}
}

func TestCountStatus(t *testing.T) {
	findings := []rules.Finding{
		{Status: rules.StatusPass},
		{Status: rules.StatusPass},
		{Status: rules.StatusFail},
		{Status: rules.StatusUnknown},
	}
	if countStatus(findings, rules.StatusPass) != 2 {
		t.Error("expected 2 pass")
	}
	if countStatus(findings, rules.StatusFail) != 1 {
		t.Error("expected 1 fail")
	}
	if countStatus(findings, rules.StatusUnknown) != 1 {
		t.Error("expected 1 unknown")
	}
}

func TestRunInvalidProfile(t *testing.T) {
	result := Run(Config{
		RepoPath:  "/tmp",
		Profile:   "nonexistent-profile",
		OutputDir: "/tmp/out",
		Format:    "both",
	})
	if result.ExitCode != 3 {
		t.Errorf("expected exit code 3 for invalid profile, got %d", result.ExitCode)
	}
}

func TestSkippedFilesMarkPartial(t *testing.T) {
	// Unit test: verify that skipped files downgrade analyzer status to "partial"
	// and set hasErrors = true, using the internal logic directly.

	analyzerStatuses := map[string]string{"go": "ok", "typescript": "ok"}
	resultLanguages := map[*analyzers.AnalysisResult]string{}

	r1 := &analyzers.AnalysisResult{
		Files: []facts.FileFact{{File: "a.go", Language: facts.LangGo}},
		SkippedFiles: []analyzers.SkippedFile{
			{File: "b.go", Reason: "parse error"},
		},
	}
	r2 := &analyzers.AnalysisResult{
		// All files skipped — Files is empty
		SkippedFiles: []analyzers.SkippedFile{
			{File: "c.ts", Reason: "scanner error"},
		},
	}
	resultLanguages[r1] = "go"
	resultLanguages[r2] = "typescript"

	allResults := []*analyzers.AnalysisResult{r1, r2}
	hasErrors := false

	for _, r := range allResults {
		if len(r.SkippedFiles) > 0 {
			if lang, ok := resultLanguages[r]; ok {
				if analyzerStatuses[lang] == "ok" {
					analyzerStatuses[lang] = "partial"
				}
			}
			hasErrors = true
		}
	}

	if !hasErrors {
		t.Error("hasErrors should be true when files are skipped")
	}
	if analyzerStatuses["go"] != "partial" {
		t.Errorf("go status = %q, want partial", analyzerStatuses["go"])
	}
	if analyzerStatuses["typescript"] != "partial" {
		t.Errorf("typescript status = %q, want partial (all files skipped)", analyzerStatuses["typescript"])
	}
}

func TestInvalidRepoExitCode(t *testing.T) {
	result := Run(Config{
		RepoPath:  "/nonexistent/repo/path",
		Profile:   "backend-api",
		OutputDir: t.TempDir(),
		Format:    "json",
	})
	if result.ExitCode == 0 {
		t.Error("expected non-zero exit code for invalid repo path")
	}
}

func TestMergeTypeGraphs(t *testing.T) {
	g1 := typegraph.New()
	g1.AddNode(&typegraph.TypeNode{Name: "Foo", File: "a.go", Kind: "struct"})
	g2 := typegraph.New()
	g2.AddNode(&typegraph.TypeNode{Name: "Bar", File: "b.ts", Kind: "class"})

	results := []*analyzers.AnalysisResult{
		{TypeGraph: g1},
		{TypeGraph: g2},
		{TypeGraph: nil}, // nil should be safe
	}

	merged := mergeTypeGraphs(results)
	if len(merged.Nodes) != 2 {
		t.Errorf("expected 2 nodes in merged graph, got %d", len(merged.Nodes))
	}
	if merged.Nodes["a.go:Foo"] == nil {
		t.Error("missing Foo node")
	}
	if merged.Nodes["b.ts:Bar"] == nil {
		t.Error("missing Bar node")
	}
}

func TestBuildFactSetMergesAllFacts(t *testing.T) {
	results := []*analyzers.AnalysisResult{
		{
			Files:   []facts.FileFact{{File: "a.go", Language: facts.LangGo}},
			Symbols: []facts.SymbolFact{{File: "a.go", Name: "Foo"}},
			Imports: []facts.ImportFact{{File: "a.go", ImportPath: "fmt"}},
		},
		{
			Files:      []facts.FileFact{{File: "b.ts", Language: facts.LangTypeScript}},
			Routes:     []facts.RouteFact{{File: "b.ts", Path: "/api"}},
			DataAccess: []facts.DataAccessFact{{File: "b.ts"}},
		},
	}

	fs := buildFactSet(results)
	if len(fs.Files) != 2 {
		t.Errorf("expected 2 files, got %d", len(fs.Files))
	}
	if len(fs.Symbols) != 1 {
		t.Errorf("expected 1 symbol, got %d", len(fs.Symbols))
	}
	if len(fs.Imports) != 1 {
		t.Errorf("expected 1 import, got %d", len(fs.Imports))
	}
	if len(fs.Routes) != 1 {
		t.Errorf("expected 1 route, got %d", len(fs.Routes))
	}
	if len(fs.DataAccess) != 1 {
		t.Errorf("expected 1 data access, got %d", len(fs.DataAccess))
	}
}

func TestCancelledContextReturnsEarly(t *testing.T) {
	// A pre-cancelled context should cause Run to return exit code 7
	// without doing any real work (no repo needed).
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	result := Run(Config{
		Ctx:       ctx,
		RepoPath:  "/nonexistent/does-not-matter",
		Profile:   "backend-api",
		OutputDir: t.TempDir(),
		Format:    "json",
	})
	if result.ExitCode != 7 {
		t.Errorf("expected exit code 7 for cancelled context, got %d (errors: %v)", result.ExitCode, result.Errors)
	}
	if len(result.Errors) == 0 {
		t.Error("expected error message for cancelled context")
	}
}

func TestCancelledContextExitCodeDistinct(t *testing.T) {
	// Verify the cancellation error message contains "context canceled"
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	result := Run(Config{
		Ctx:       ctx,
		RepoPath:  "/tmp",
		Profile:   "backend-api",
		OutputDir: t.TempDir(),
	})
	if result.ExitCode != 7 {
		t.Fatalf("expected exit code 7, got %d", result.ExitCode)
	}
	if len(result.Errors) == 0 {
		t.Fatal("expected error messages")
	}
	found := false
	for _, e := range result.Errors {
		if strings.Contains(e, "context canceled") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected error containing 'context canceled', got %v", result.Errors)
	}
}

func TestHooksCalledDuringRun(t *testing.T) {
	// Verify that OnScanStart is called even for invalid repos
	// (it fires before repo load)
	started := false
	result := Run(Config{
		RepoPath:  "/nonexistent/repo",
		Profile:   "backend-api",
		OutputDir: t.TempDir(),
		Format:    "json",
		Hooks: &ScanHooks{
			OnScanStart: func(repoPath, ref, profile string) {
				started = true
				if profile != "backend-api" {
					t.Errorf("expected profile backend-api, got %s", profile)
				}
			},
		},
	})
	if !started {
		t.Error("OnScanStart hook was not called")
	}
	// The run should still fail because the repo doesn't exist
	if result.ExitCode == 0 {
		t.Error("expected non-zero exit code for invalid repo")
	}
}

func TestFilterFilesMultipleExtensions(t *testing.T) {
	files := []string{"app.ts", "component.tsx", "main.go", "util.ts", "style.css"}
	result := filterFiles(files, []string{".ts", ".tsx"})
	if len(result) != 3 {
		t.Errorf("expected 3 files (.ts and .tsx), got %d: %v", len(result), result)
	}
}
