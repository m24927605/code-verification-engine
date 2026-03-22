package analyzers

import (
	"testing"

	"github.com/verabase/code-verification-engine/internal/facts"
	"github.com/verabase/code-verification-engine/internal/typegraph"
)

func TestDiscardFactsForFile(t *testing.T) {
	result := &AnalysisResult{
		Files: []facts.FileFact{
			{File: "a.go", Language: facts.LangGo},
			{File: "b.go", Language: facts.LangGo},
		},
		Symbols: []facts.SymbolFact{
			{File: "a.go", Name: "Foo"},
			{File: "b.go", Name: "Bar"},
			{File: "a.go", Name: "Baz"},
		},
		Imports: []facts.ImportFact{
			{File: "a.go", ImportPath: "fmt"},
			{File: "b.go", ImportPath: "os"},
		},
		Routes: []facts.RouteFact{
			{File: "a.go", Path: "/api"},
		},
	}

	result.DiscardFactsForFile("a.go")

	if len(result.Files) != 1 || result.Files[0].File != "b.go" {
		t.Errorf("Files: expected only b.go, got %v", result.Files)
	}
	if len(result.Symbols) != 1 || result.Symbols[0].Name != "Bar" {
		t.Errorf("Symbols: expected only Bar, got %v", result.Symbols)
	}
	if len(result.Imports) != 1 || result.Imports[0].ImportPath != "os" {
		t.Errorf("Imports: expected only os, got %v", result.Imports)
	}
	if len(result.Routes) != 0 {
		t.Errorf("Routes: expected empty, got %v", result.Routes)
	}
}

func TestDiscardFactsForFileNoMatch(t *testing.T) {
	result := &AnalysisResult{
		Files: []facts.FileFact{
			{File: "a.go", Language: facts.LangGo},
		},
		Symbols: []facts.SymbolFact{
			{File: "a.go", Name: "Foo"},
		},
	}

	result.DiscardFactsForFile("nonexistent.go")

	if len(result.Files) != 1 {
		t.Error("Files should be unchanged")
	}
	if len(result.Symbols) != 1 {
		t.Error("Symbols should be unchanged")
	}
}

func TestDiscardFactsForFile_AllTypes(t *testing.T) {
	tg := typegraph.New()
	tg.AddNode(&typegraph.TypeNode{Name: "Foo", File: "a.go"})
	tg.AddNode(&typegraph.TypeNode{Name: "Bar", File: "b.go"})

	result := &AnalysisResult{
		Files: []facts.FileFact{
			{File: "a.go", Language: facts.LangGo},
			{File: "b.go", Language: facts.LangGo},
		},
		Symbols: []facts.SymbolFact{
			{File: "a.go", Name: "FooFunc"},
			{File: "b.go", Name: "BarFunc"},
		},
		Imports: []facts.ImportFact{
			{File: "a.go", ImportPath: "fmt"},
			{File: "b.go", ImportPath: "os"},
		},
		Tests: []facts.TestFact{
			{File: "a.go", TestName: "TestFoo"},
			{File: "b.go", TestName: "TestBar"},
		},
		Routes: []facts.RouteFact{
			{File: "a.go", Path: "/api/a"},
			{File: "b.go", Path: "/api/b"},
		},
		Middlewares: []facts.MiddlewareFact{
			{File: "a.go", Name: "auth"},
			{File: "b.go", Name: "logging"},
		},
		DataAccess: []facts.DataAccessFact{
			{File: "a.go", Operation: "query", Backend: "sql"},
			{File: "b.go", Operation: "insert", Backend: "sql"},
		},
		Secrets: []facts.SecretFact{
			{File: "a.go", Kind: "hardcoded_secret"},
			{File: "b.go", Kind: "env_variable"},
		},
		TypeGraph: tg,
	}

	result.DiscardFactsForFile("a.go")

	// Files
	if len(result.Files) != 1 || result.Files[0].File != "b.go" {
		t.Errorf("Files: expected only b.go, got %v", result.Files)
	}
	// Symbols
	if len(result.Symbols) != 1 || result.Symbols[0].Name != "BarFunc" {
		t.Errorf("Symbols: expected only BarFunc, got %v", result.Symbols)
	}
	// Imports
	if len(result.Imports) != 1 || result.Imports[0].ImportPath != "os" {
		t.Errorf("Imports: expected only os, got %v", result.Imports)
	}
	// Tests
	if len(result.Tests) != 1 || result.Tests[0].TestName != "TestBar" {
		t.Errorf("Tests: expected only TestBar, got %v", result.Tests)
	}
	// Routes
	if len(result.Routes) != 1 || result.Routes[0].Path != "/api/b" {
		t.Errorf("Routes: expected only /api/b, got %v", result.Routes)
	}
	// Middlewares
	if len(result.Middlewares) != 1 || result.Middlewares[0].Name != "logging" {
		t.Errorf("Middlewares: expected only logging, got %v", result.Middlewares)
	}
	// DataAccess
	if len(result.DataAccess) != 1 || result.DataAccess[0].Operation != "insert" {
		t.Errorf("DataAccess: expected only insert, got %v", result.DataAccess)
	}
	// Secrets
	if len(result.Secrets) != 1 || result.Secrets[0].Kind != "env_variable" {
		t.Errorf("Secrets: expected only env_variable, got %v", result.Secrets)
	}
	// TypeGraph - should only have Bar node remaining
	if len(result.TypeGraph.Nodes) != 1 {
		t.Errorf("TypeGraph: expected 1 node, got %d", len(result.TypeGraph.Nodes))
	}
	if node, ok := result.TypeGraph.Nodes["b.go:Bar"]; !ok || node.Name != "Bar" {
		t.Errorf("TypeGraph: expected Bar node for b.go, got %v", result.TypeGraph.Nodes)
	}
}
