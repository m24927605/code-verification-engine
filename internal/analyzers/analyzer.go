package analyzers

import (
	"github.com/verabase/code-verification-engine/internal/facts"
	"github.com/verabase/code-verification-engine/internal/typegraph"
)

// SkippedFile records a file that could not be fully analyzed.
type SkippedFile struct {
	File   string
	Reason string
}

// AnalysisResult holds all facts extracted by an analyzer.
type AnalysisResult struct {
	Files        []facts.FileFact
	Symbols      []facts.SymbolFact
	Imports      []facts.ImportFact
	Tests        []facts.TestFact
	Routes       []facts.RouteFact
	Middlewares  []facts.MiddlewareFact
	DataAccess   []facts.DataAccessFact
	Secrets      []facts.SecretFact
	TypeGraph    *typegraph.TypeGraph
	SkippedFiles []SkippedFile
}

// DiscardFactsForFile removes all facts associated with a specific file from the result.
// This is used when a file scan fails mid-way — partial facts must be discarded
// to prevent false verified passes on not_exists rules.
func (r *AnalysisResult) DiscardFactsForFile(file string) {
	r.Files = filterFileFacts(r.Files, file)
	r.Symbols = filterSymbolFacts(r.Symbols, file)
	r.Imports = filterImportFacts(r.Imports, file)
	r.Tests = filterTestFacts(r.Tests, file)
	r.Routes = filterRouteFacts(r.Routes, file)
	r.Middlewares = filterMiddlewareFacts(r.Middlewares, file)
	r.DataAccess = filterDataAccessFacts(r.DataAccess, file)
	r.Secrets = filterSecretFacts(r.Secrets, file)
	if r.TypeGraph != nil {
		for key, node := range r.TypeGraph.Nodes {
			if node.File == file {
				delete(r.TypeGraph.Nodes, key)
			}
		}
	}
}

func filterFileFacts(s []facts.FileFact, file string) []facts.FileFact {
	n := s[:0]
	for _, f := range s {
		if f.File != file {
			n = append(n, f)
		}
	}
	return n
}

func filterSymbolFacts(s []facts.SymbolFact, file string) []facts.SymbolFact {
	n := s[:0]
	for _, f := range s {
		if f.File != file {
			n = append(n, f)
		}
	}
	return n
}

func filterImportFacts(s []facts.ImportFact, file string) []facts.ImportFact {
	n := s[:0]
	for _, f := range s {
		if f.File != file {
			n = append(n, f)
		}
	}
	return n
}

func filterTestFacts(s []facts.TestFact, file string) []facts.TestFact {
	n := s[:0]
	for _, f := range s {
		if f.File != file {
			n = append(n, f)
		}
	}
	return n
}

func filterRouteFacts(s []facts.RouteFact, file string) []facts.RouteFact {
	n := s[:0]
	for _, f := range s {
		if f.File != file {
			n = append(n, f)
		}
	}
	return n
}

func filterMiddlewareFacts(s []facts.MiddlewareFact, file string) []facts.MiddlewareFact {
	n := s[:0]
	for _, f := range s {
		if f.File != file {
			n = append(n, f)
		}
	}
	return n
}

func filterDataAccessFacts(s []facts.DataAccessFact, file string) []facts.DataAccessFact {
	n := s[:0]
	for _, f := range s {
		if f.File != file {
			n = append(n, f)
		}
	}
	return n
}

func filterSecretFacts(s []facts.SecretFact, file string) []facts.SecretFact {
	n := s[:0]
	for _, f := range s {
		if f.File != file {
			n = append(n, f)
		}
	}
	return n
}

// Analyzer is the interface all language analyzers must implement.
type Analyzer interface {
	// Language returns the language this analyzer handles.
	Language() facts.Language
	// Extensions returns file extensions this analyzer handles (e.g. ".ts", ".tsx").
	Extensions() []string
	// Analyze processes files rooted at dir and returns extracted facts.
	Analyze(dir string, files []string) (*AnalysisResult, error)
}
