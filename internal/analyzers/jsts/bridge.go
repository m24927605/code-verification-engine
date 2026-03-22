package jsts

import (
	"strings"

	"github.com/verabase/code-verification-engine/internal/facts"
)

// BridgeResult holds facts converted from AST results.
type BridgeResult struct {
	Imports     []facts.ImportFact
	Symbols     []facts.SymbolFact
	Routes      []facts.RouteFact
	Middlewares []facts.MiddlewareFact
	Secrets     []facts.SecretFact
}

// ConvertToFacts converts an ASTResult into fact types with ProvenanceAST.
func ConvertToFacts(result *ASTResult, lang facts.Language, file string) BridgeResult {
	var br BridgeResult
	if result == nil {
		return br
	}

	for _, imp := range result.Imports {
		if fact, err := facts.NewImportFact(lang, file, facts.Span{Start: imp.Line, End: imp.Line}, imp.Source, ""); err == nil {
			fact.Provenance = facts.ProvenanceAST
			br.Imports = append(br.Imports, fact)
		}
	}

	for _, sym := range result.Symbols {
		if fact, err := facts.NewSymbolFact(lang, file, facts.Span{Start: sym.Line, End: sym.EndLine}, sym.Name, sym.Kind, sym.Exported); err == nil {
			fact.Provenance = facts.ProvenanceAST
			br.Symbols = append(br.Symbols, fact)
		}
	}

	resolvedRoutes := ResolveRouteBindings(result)
	for _, rt := range resolvedRoutes {
		// Middlewares already include Guards (merged by ResolveRouteBindings).
		middlewares := rt.Middlewares
		if len(middlewares) == 0 {
			middlewares = nil
		}
		if fact, err := facts.NewRouteFact(lang, file, facts.Span{Start: rt.Line, End: rt.Line}, rt.Method, rt.Path, rt.Handler, middlewares); err == nil {
			fact.Provenance = facts.ProvenanceAST
			br.Routes = append(br.Routes, fact)
		}
	}

	for _, mw := range result.Middlewares {
		if fact, err := facts.NewMiddlewareFact(lang, file, facts.Span{Start: mw.Line, End: mw.Line}, mw.Name, mw.Framework); err == nil {
			fact.Provenance = facts.ProvenanceAST
			br.Middlewares = append(br.Middlewares, fact)
		}
	}

	for _, sec := range result.Secrets {
		kind := classifySecret(sec.Name)
		if fact, err := facts.NewSecretFact(lang, file, facts.Span{Start: sec.Line, End: sec.Line}, kind, ""); err == nil {
			fact.Provenance = facts.ProvenanceAST
			br.Secrets = append(br.Secrets, fact)
		}
	}

	return br
}

// HasImport returns true if the bridge result contains an import with the given path.
func (br *BridgeResult) HasImport(path string) bool {
	for _, imp := range br.Imports {
		if imp.ImportPath == path {
			return true
		}
	}
	return false
}

// HasRoute returns true if the bridge result contains a route with the given method and path.
func (br *BridgeResult) HasRoute(method, path string) bool {
	for _, rt := range br.Routes {
		if strings.EqualFold(rt.Method, method) && rt.Path == path {
			return true
		}
	}
	return false
}
