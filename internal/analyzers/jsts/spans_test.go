package jsts

import (
	"testing"
)

// Test 1: Top-level function produces a span with correct lines.
func TestBuildFunctionSpans_TopLevelFunction(t *testing.T) {
	result := &ASTResult{
		Symbols: []ASTSymbol{
			{Name: "handleRequest", Kind: "function", Line: 5, EndLine: 20},
		},
	}
	spans := BuildFunctionSpans(result)
	if len(spans) != 1 {
		t.Fatalf("expected 1 span, got %d", len(spans))
	}
	s := spans[0]
	if s.Name != "handleRequest" {
		t.Errorf("expected Name %q, got %q", "handleRequest", s.Name)
	}
	if s.Kind != "function" {
		t.Errorf("expected Kind %q, got %q", "function", s.Kind)
	}
	if s.StartLine != 5 {
		t.Errorf("expected StartLine 5, got %d", s.StartLine)
	}
	if s.EndLine != 20 {
		t.Errorf("expected EndLine 20, got %d", s.EndLine)
	}
}

// Test 2: Class methods are included; class-kind spans are excluded.
func TestBuildFunctionSpans_ClassMethodsIncludedClassExcluded(t *testing.T) {
	result := &ASTResult{
		Symbols: []ASTSymbol{
			{Name: "UserService", Kind: "class", Line: 1, EndLine: 50},
			{Name: "getUser", Kind: "method", Line: 5, EndLine: 15},
			{Name: "createUser", Kind: "method", Line: 20, EndLine: 30},
		},
	}
	spans := BuildFunctionSpans(result)
	if len(spans) != 2 {
		t.Fatalf("expected 2 spans (methods only), got %d", len(spans))
	}
	for _, s := range spans {
		if s.Kind == "class" {
			t.Errorf("class span should be excluded, got Name=%q Kind=%q", s.Name, s.Kind)
		}
	}
	names := make(map[string]bool)
	for _, s := range spans {
		names[s.Name] = true
	}
	if !names["getUser"] || !names["createUser"] {
		t.Errorf("expected getUser and createUser in spans, got %v", names)
	}
}

// Test 3: FindEnclosingSpan returns the narrowest span containing the given line.
func TestFindEnclosingSpan_ReturnsNarrowest(t *testing.T) {
	spans := []FunctionSpan{
		{Name: "outerFn", Kind: "function", StartLine: 1, EndLine: 100},
		{Name: "innerMethod", Kind: "method", StartLine: 10, EndLine: 30},
	}
	name, kind := FindEnclosingSpan(spans, 15)
	if name != "innerMethod" {
		t.Errorf("expected narrowest span %q, got %q", "innerMethod", name)
	}
	if kind != "method" {
		t.Errorf("expected kind %q, got %q", "method", kind)
	}
}

// Test 4: Line outside all spans returns empty strings.
func TestFindEnclosingSpan_OutsideAllSpans(t *testing.T) {
	spans := []FunctionSpan{
		{Name: "someFunc", Kind: "function", StartLine: 10, EndLine: 20},
	}
	name, kind := FindEnclosingSpan(spans, 5)
	if name != "" || kind != "" {
		t.Errorf("expected empty strings for line outside spans, got name=%q kind=%q", name, kind)
	}
}

// Test 5: Anonymous functions (empty name) are skipped.
func TestBuildFunctionSpans_SkipsAnonymousFunctions(t *testing.T) {
	result := &ASTResult{
		Symbols: []ASTSymbol{
			{Name: "", Kind: "function", Line: 1, EndLine: 10},
			{Name: "namedFunc", Kind: "function", Line: 15, EndLine: 25},
		},
	}
	spans := BuildFunctionSpans(result)
	if len(spans) != 1 {
		t.Fatalf("expected 1 span (anonymous skipped), got %d", len(spans))
	}
	if spans[0].Name != "namedFunc" {
		t.Errorf("expected namedFunc, got %q", spans[0].Name)
	}
}

// Test 6: Symbols where EndLine <= Line are skipped (invalid span).
func TestBuildFunctionSpans_SkipsInvalidSpans(t *testing.T) {
	result := &ASTResult{
		Symbols: []ASTSymbol{
			{Name: "badFunc", Kind: "function", Line: 10, EndLine: 10}, // EndLine == Line
			{Name: "worseFunc", Kind: "function", Line: 15, EndLine: 5}, // EndLine < Line
			{Name: "goodFunc", Kind: "function", Line: 20, EndLine: 30},
		},
	}
	spans := BuildFunctionSpans(result)
	if len(spans) != 1 {
		t.Fatalf("expected 1 span (invalid spans skipped), got %d", len(spans))
	}
	if spans[0].Name != "goodFunc" {
		t.Errorf("expected goodFunc, got %q", spans[0].Name)
	}
}

// Test: Variable-kind symbols are skipped (not function or method).
func TestBuildFunctionSpans_SkipsVariableKind(t *testing.T) {
	result := &ASTResult{
		Symbols: []ASTSymbol{
			{Name: "myConst", Kind: "variable", Line: 1, EndLine: 10},
			{Name: "myFunc", Kind: "function", Line: 15, EndLine: 25},
		},
	}
	spans := BuildFunctionSpans(result)
	if len(spans) != 1 {
		t.Fatalf("expected 1 span (variable skipped), got %d", len(spans))
	}
	if spans[0].Name != "myFunc" {
		t.Errorf("expected myFunc, got %q", spans[0].Name)
	}
}

// --- HasDBImport ---

func TestHasDBImport_KnownPackages(t *testing.T) {
	knownPkgs := []string{
		"sequelize", "typeorm", "prisma", "@prisma/client", "mongoose",
		"mongodb", "knex", "pg", "mysql", "mysql2",
		"better-sqlite3", "drizzle-orm", "mikro-orm",
	}
	for _, pkg := range knownPkgs {
		result := &ASTResult{
			Imports: []ASTImport{{Source: pkg, Line: 1}},
		}
		if !HasDBImport(result) {
			t.Errorf("expected HasDBImport=true for package %q", pkg)
		}
	}
}

func TestHasDBImport_UnknownPackage(t *testing.T) {
	result := &ASTResult{
		Imports: []ASTImport{{Source: "express", Line: 1}},
	}
	if HasDBImport(result) {
		t.Error("expected HasDBImport=false for non-DB package 'express'")
	}
}

func TestHasDBImport_NoImports(t *testing.T) {
	result := &ASTResult{}
	if HasDBImport(result) {
		t.Error("expected HasDBImport=false when no imports")
	}
}

func TestHasDBImport_MixedImports(t *testing.T) {
	result := &ASTResult{
		Imports: []ASTImport{
			{Source: "express", Line: 1},
			{Source: "pg", Line: 2},
		},
	}
	if !HasDBImport(result) {
		t.Error("expected HasDBImport=true when at least one DB package is imported")
	}
}

// Additional edge case: FindEnclosingSpan with line exactly on boundaries.
func TestFindEnclosingSpan_BoundaryLines(t *testing.T) {
	spans := []FunctionSpan{
		{Name: "myFunc", Kind: "function", StartLine: 5, EndLine: 15},
	}
	// Line at start boundary
	name, kind := FindEnclosingSpan(spans, 5)
	if name != "myFunc" || kind != "function" {
		t.Errorf("expected myFunc at start boundary, got name=%q kind=%q", name, kind)
	}
	// Line at end boundary
	name, kind = FindEnclosingSpan(spans, 15)
	if name != "myFunc" || kind != "function" {
		t.Errorf("expected myFunc at end boundary, got name=%q kind=%q", name, kind)
	}
}
