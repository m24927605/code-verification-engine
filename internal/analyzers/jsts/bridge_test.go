package jsts

import (
	"testing"

	"github.com/verabase/code-verification-engine/internal/facts"
)

func TestConvertToFacts_Nil(t *testing.T) {
	br := ConvertToFacts(nil, facts.LangJavaScript, "file.js")
	if len(br.Imports) != 0 || len(br.Symbols) != 0 || len(br.Routes) != 0 || len(br.Middlewares) != 0 || len(br.Secrets) != 0 {
		t.Error("expected empty BridgeResult for nil input")
	}
}

func TestConvertToFacts_Imports(t *testing.T) {
	result := &ASTResult{
		Imports: []ASTImport{
			{Source: "express", Line: 1},
			{Source: "path", Line: 2},
		},
	}
	br := ConvertToFacts(result, facts.LangJavaScript, "app.js")

	if len(br.Imports) != 2 {
		t.Fatalf("expected 2 imports, got %d", len(br.Imports))
	}
	for _, imp := range br.Imports {
		if imp.Provenance != facts.ProvenanceAST {
			t.Errorf("expected ProvenanceAST, got %q", imp.Provenance)
		}
	}
	if br.Imports[0].ImportPath != "express" {
		t.Errorf("expected import path 'express', got %q", br.Imports[0].ImportPath)
	}
}

func TestConvertToFacts_Symbols(t *testing.T) {
	result := &ASTResult{
		Symbols: []ASTSymbol{
			{Name: "handler", Kind: "function", Exported: true, Line: 5, EndLine: 10},
			{Name: "MyClass", Kind: "class", Exported: false, Line: 12, EndLine: 20},
		},
	}
	br := ConvertToFacts(result, facts.LangTypeScript, "app.ts")

	if len(br.Symbols) != 2 {
		t.Fatalf("expected 2 symbols, got %d", len(br.Symbols))
	}
	for _, sym := range br.Symbols {
		if sym.Provenance != facts.ProvenanceAST {
			t.Errorf("expected ProvenanceAST, got %q", sym.Provenance)
		}
	}
}

func TestConvertToFacts_Routes(t *testing.T) {
	result := &ASTResult{
		Routes: []ASTRoute{
			{Method: "GET", Path: "/users", Handler: "getUsers", Middlewares: []string{"auth"}, Line: 8},
		},
	}
	br := ConvertToFacts(result, facts.LangJavaScript, "routes.js")

	if len(br.Routes) != 1 {
		t.Fatalf("expected 1 route, got %d", len(br.Routes))
	}
	rt := br.Routes[0]
	if rt.Method != "GET" || rt.Path != "/users" {
		t.Errorf("unexpected route: %s %s", rt.Method, rt.Path)
	}
	if rt.Provenance != facts.ProvenanceAST {
		t.Errorf("expected ProvenanceAST, got %q", rt.Provenance)
	}
}

func TestConvertToFacts_RoutesWithEmptyMiddlewares(t *testing.T) {
	result := &ASTResult{
		Routes: []ASTRoute{
			{Method: "GET", Path: "/health", Handler: "health", Middlewares: []string{}, Line: 3},
		},
	}
	br := ConvertToFacts(result, facts.LangJavaScript, "app.js")

	if len(br.Routes) != 1 {
		t.Fatalf("expected 1 route, got %d", len(br.Routes))
	}
	// Empty middlewares should become nil in the fact
	if len(br.Routes[0].Middlewares) != 0 {
		t.Errorf("expected empty middlewares, got %v", br.Routes[0].Middlewares)
	}
}

func TestConvertToFacts_Middlewares(t *testing.T) {
	result := &ASTResult{
		Middlewares: []ASTMiddleware{
			{Name: "cors", Framework: "express", Line: 3},
			{Name: "helmet", Framework: "express", Line: 4},
		},
	}
	br := ConvertToFacts(result, facts.LangJavaScript, "server.js")

	if len(br.Middlewares) != 2 {
		t.Fatalf("expected 2 middlewares, got %d", len(br.Middlewares))
	}
	for _, mw := range br.Middlewares {
		if mw.Provenance != facts.ProvenanceAST {
			t.Errorf("expected ProvenanceAST, got %q", mw.Provenance)
		}
	}
}

func TestConvertToFacts_Secrets(t *testing.T) {
	result := &ASTResult{
		Secrets: []ASTSecret{
			{Name: "API_KEY", Value: "sk-live-1234567890", Line: 2},
			{Name: "JWT_SECRET", Value: "mysecret", Line: 3},
		},
	}
	br := ConvertToFacts(result, facts.LangJavaScript, "config.js")

	if len(br.Secrets) != 2 {
		t.Fatalf("expected 2 secrets, got %d", len(br.Secrets))
	}
	for _, sec := range br.Secrets {
		if sec.Provenance != facts.ProvenanceAST {
			t.Errorf("expected ProvenanceAST, got %q", sec.Provenance)
		}
	}
}

func TestConvertToFacts_Full(t *testing.T) {
	result := &ASTResult{
		Imports: []ASTImport{{Source: "express", Line: 1}},
		Symbols: []ASTSymbol{{Name: "app", Kind: "variable", Line: 3, EndLine: 3}},
		Routes:  []ASTRoute{{Method: "GET", Path: "/", Handler: "root", Line: 5}},
		Middlewares: []ASTMiddleware{{Name: "cors", Framework: "express", Line: 4}},
		Secrets: []ASTSecret{{Name: "API_KEY", Value: "sk-abc", Line: 6}},
	}
	br := ConvertToFacts(result, facts.LangJavaScript, "server.js")

	if len(br.Imports) != 1 {
		t.Errorf("expected 1 import, got %d", len(br.Imports))
	}
	if len(br.Symbols) != 1 {
		t.Errorf("expected 1 symbol, got %d", len(br.Symbols))
	}
	if len(br.Routes) != 1 {
		t.Errorf("expected 1 route, got %d", len(br.Routes))
	}
	if len(br.Middlewares) != 1 {
		t.Errorf("expected 1 middleware, got %d", len(br.Middlewares))
	}
	if len(br.Secrets) != 1 {
		t.Errorf("expected 1 secret, got %d", len(br.Secrets))
	}
}

func TestHasImport_True(t *testing.T) {
	br := BridgeResult{}
	result := &ASTResult{
		Imports: []ASTImport{{Source: "express", Line: 1}},
	}
	br = ConvertToFacts(result, facts.LangJavaScript, "app.js")

	if !br.HasImport("express") {
		t.Error("expected HasImport('express') to return true")
	}
}

func TestHasImport_False(t *testing.T) {
	br := BridgeResult{}
	result := &ASTResult{
		Imports: []ASTImport{{Source: "express", Line: 1}},
	}
	br = ConvertToFacts(result, facts.LangJavaScript, "app.js")

	if br.HasImport("react") {
		t.Error("expected HasImport('react') to return false")
	}
}

func TestHasImport_Empty(t *testing.T) {
	br := BridgeResult{}
	if br.HasImport("express") {
		t.Error("expected HasImport on empty BridgeResult to return false")
	}
}

func TestHasRoute_True(t *testing.T) {
	result := &ASTResult{
		Routes: []ASTRoute{{Method: "GET", Path: "/users", Handler: "handler", Line: 1}},
	}
	br := ConvertToFacts(result, facts.LangJavaScript, "app.js")

	if !br.HasRoute("GET", "/users") {
		t.Error("expected HasRoute('GET', '/users') to return true")
	}
}

func TestHasRoute_CaseInsensitive(t *testing.T) {
	result := &ASTResult{
		Routes: []ASTRoute{{Method: "GET", Path: "/users", Handler: "handler", Line: 1}},
	}
	br := ConvertToFacts(result, facts.LangJavaScript, "app.js")

	if !br.HasRoute("get", "/users") {
		t.Error("expected HasRoute('get', '/users') to be case-insensitive")
	}
}

func TestHasRoute_False(t *testing.T) {
	result := &ASTResult{
		Routes: []ASTRoute{{Method: "GET", Path: "/users", Handler: "handler", Line: 1}},
	}
	br := ConvertToFacts(result, facts.LangJavaScript, "app.js")

	if br.HasRoute("POST", "/users") {
		t.Error("expected HasRoute('POST', '/users') to return false")
	}
	if br.HasRoute("GET", "/items") {
		t.Error("expected HasRoute('GET', '/items') to return false")
	}
}

func TestHasRoute_Empty(t *testing.T) {
	br := BridgeResult{}
	if br.HasRoute("GET", "/users") {
		t.Error("expected HasRoute on empty BridgeResult to return false")
	}
}
