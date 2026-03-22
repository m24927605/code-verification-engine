package jsts

import (
	"testing"
)

// --- extractMiddlewareName coverage ---

func TestExtractMiddlewareName_Ident(t *testing.T) {
	// Access extractMiddlewareName via Parse; app.use(cors) exercises this path
	src := `app.use(cors);`
	r := Parse(src)
	if len(r.Middlewares) == 0 {
		t.Fatal("expected middleware cors to be extracted")
	}
	found := false
	for _, mw := range r.Middlewares {
		if mw.Name == "cors" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected cors, got %+v", r.Middlewares)
	}
}

func TestExtractMiddlewareName_DotNotation(t *testing.T) {
	// express.json() - tests the dot-notation branch in extractMiddlewareName
	src := `app.use(express.json());`
	r := Parse(src)
	if len(r.Middlewares) == 0 {
		t.Fatal("expected middleware express to be extracted")
	}
	found := false
	for _, mw := range r.Middlewares {
		if mw.Name == "express" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected express middleware, got %+v", r.Middlewares)
	}
}

// TestExtractMiddlewareName_Direct directly tests the extractMiddlewareName method
// via the package-internal parser struct (same package tests).
func TestExtractMiddlewareName_Direct_Ident(t *testing.T) {
	toks := Tokenize("cors")
	p := &parser{toks: toks, res: &ASTResult{}}
	name := p.extractMiddlewareName()
	if name != "cors" {
		t.Errorf("expected 'cors', got %q", name)
	}
}

func TestExtractMiddlewareName_Direct_DotNotation(t *testing.T) {
	// express.json() — has dot after ident
	toks := Tokenize("express.json()")
	p := &parser{toks: toks, res: &ASTResult{}}
	name := p.extractMiddlewareName()
	if name != "express" {
		t.Errorf("expected 'express', got %q", name)
	}
}

func TestExtractMiddlewareName_Direct_Empty(t *testing.T) {
	// No ident — returns empty string
	toks := Tokenize("'string'")
	p := &parser{toks: toks, res: &ASTResult{}}
	name := p.extractMiddlewareName()
	if name != "" {
		t.Errorf("expected empty string for non-ident, got %q", name)
	}
}

// --- parseExport coverage ---

func TestParse_ExportNamedConst(t *testing.T) {
	src := `export const MY_CONST = 42;`
	r := Parse(src)
	found := false
	for _, s := range r.Symbols {
		if s.Name == "MY_CONST" && s.Exported {
			found = true
		}
	}
	if !found {
		t.Errorf("expected exported MY_CONST, got: %+v", r.Symbols)
	}
}

func TestParse_ExportLet(t *testing.T) {
	src := `export let counter = 0;`
	r := Parse(src)
	found := false
	for _, s := range r.Symbols {
		if s.Name == "counter" && s.Exported {
			found = true
		}
	}
	if !found {
		t.Errorf("expected exported counter, got: %+v", r.Symbols)
	}
}

func TestParse_ExportVar(t *testing.T) {
	src := `export var legacy = true;`
	r := Parse(src)
	found := false
	for _, s := range r.Symbols {
		if s.Name == "legacy" && s.Exported {
			found = true
		}
	}
	if !found {
		t.Errorf("expected exported legacy, got: %+v", r.Symbols)
	}
}

func TestParse_ExportType(t *testing.T) {
	src := `export type MyType = string;`
	r := Parse(src)
	found := false
	for _, s := range r.Symbols {
		if s.Name == "MyType" && s.Kind == "type" && s.Exported {
			found = true
		}
	}
	if !found {
		t.Errorf("expected exported type MyType, got: %+v", r.Symbols)
	}
}

func TestParse_ExportEnum(t *testing.T) {
	src := `export enum Direction { Up, Down, Left, Right }`
	r := Parse(src)
	found := false
	for _, s := range r.Symbols {
		if s.Name == "Direction" && s.Kind == "enum" && s.Exported {
			found = true
		}
	}
	if !found {
		t.Errorf("expected exported enum Direction, got: %+v", r.Symbols)
	}
}

func TestParse_ExportAbstractClass(t *testing.T) {
	src := `export abstract class Animal {}`
	r := Parse(src)
	found := false
	for _, s := range r.Symbols {
		if s.Name == "Animal" && s.Kind == "class" && s.Exported {
			found = true
		}
	}
	if !found {
		t.Errorf("expected exported abstract class Animal, got: %+v", r.Symbols)
	}
}

func TestParse_ExportDefaultExpression(t *testing.T) {
	// export default expr — should parse without panic
	src := `export default 42;`
	r := Parse(src)
	if r == nil {
		t.Fatal("expected non-nil result")
	}
}

func TestParse_ExportInterface(t *testing.T) {
	src := `export interface User {
  name: string;
  age: number;
}`
	r := Parse(src)
	found := false
	for _, s := range r.Symbols {
		if s.Name == "User" && s.Kind == "interface" && s.Exported {
			found = true
		}
	}
	if !found {
		t.Errorf("expected exported interface User, got: %+v", r.Symbols)
	}
}

// --- parseImport coverage ---

func TestParse_ImportDefaultAndNamed(t *testing.T) {
	// import X, { A, B } from 'mod'
	src := `import React, { useState, useEffect } from 'react';`
	r := Parse(src)
	if len(r.Imports) != 1 {
		t.Fatalf("expected 1 import, got %d", len(r.Imports))
	}
	if r.Imports[0].Source != "react" {
		t.Errorf("expected source 'react', got %q", r.Imports[0].Source)
	}
	nameSet := map[string]bool{}
	for _, n := range r.Imports[0].Names {
		nameSet[n] = true
	}
	if !nameSet["useState"] {
		t.Error("expected named import useState")
	}
	if !nameSet["useEffect"] {
		t.Error("expected named import useEffect")
	}
}

func TestParse_ImportDefaultAndNamespace(t *testing.T) {
	// import X, * as Y from 'mod'
	src := `import lib, * as libAll from 'mylib';`
	r := Parse(src)
	if len(r.Imports) != 1 {
		t.Fatalf("expected 1 import, got %d", len(r.Imports))
	}
	if r.Imports[0].Source != "mylib" {
		t.Errorf("expected source 'mylib', got %q", r.Imports[0].Source)
	}
}

func TestParse_ImportType(t *testing.T) {
	// import type { Foo } from 'mod'
	src := `import type { Foo } from 'mymodule';`
	r := Parse(src)
	if len(r.Imports) != 1 {
		t.Fatalf("expected 1 import for import type, got %d", len(r.Imports))
	}
	if r.Imports[0].Source != "mymodule" {
		t.Errorf("expected source 'mymodule', got %q", r.Imports[0].Source)
	}
}

func TestParse_ImportNamedWithAlias(t *testing.T) {
	src := `import { foo as bar, baz as qux } from 'utils';`
	r := Parse(src)
	if len(r.Imports) != 1 {
		t.Fatalf("expected 1 import, got %d", len(r.Imports))
	}
	// Original names are stored
	nameSet := map[string]bool{}
	for _, n := range r.Imports[0].Names {
		nameSet[n] = true
	}
	if !nameSet["foo"] {
		t.Error("expected named import foo (before alias)")
	}
	if !nameSet["baz"] {
		t.Error("expected named import baz (before alias)")
	}
}

func TestParse_NamedImports_WithKeyword(t *testing.T) {
	// import { default as X } -- "default" is a keyword
	src := `import { default as MyDefault } from 'somemod';`
	r := Parse(src)
	if len(r.Imports) != 1 {
		t.Fatalf("expected 1 import, got %d", len(r.Imports))
	}
}

func TestParse_NamedImports_UnknownToken(t *testing.T) {
	// A named import block with something unexpected like a number
	// This tests the else branch in parseNamedImports
	src := "import { 42, foo } from 'mod';"
	r := Parse(src)
	// Should not panic; may or may not find 'foo'
	if r == nil {
		t.Fatal("expected non-nil result")
	}
}

// --- parseVarDecl coverage ---

func TestParse_VarDecl_NoAssignment(t *testing.T) {
	src := `let x;`
	r := Parse(src)
	found := false
	for _, s := range r.Symbols {
		if s.Name == "x" && s.Kind == "variable" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected variable x, got: %+v", r.Symbols)
	}
}

func TestParse_VarDecl_WithTypeAnnotation(t *testing.T) {
	src := `const x: string = "hello";`
	r := Parse(src)
	found := false
	for _, s := range r.Symbols {
		if s.Name == "x" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected variable x with type annotation, got: %+v", r.Symbols)
	}
}

func TestParse_VarDecl_FunctionExpression(t *testing.T) {
	src := `const handler = function myFn() { return 1; };`
	r := Parse(src)
	found := false
	for _, s := range r.Symbols {
		if s.Name == "handler" && s.Kind == "function" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected function symbol 'handler', got: %+v", r.Symbols)
	}
}

func TestParse_VarDecl_AnonymousFunctionExpression(t *testing.T) {
	src := `const doWork = function() { return 42; };`
	r := Parse(src)
	found := false
	for _, s := range r.Symbols {
		if s.Name == "doWork" && s.Kind == "function" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected function symbol 'doWork', got: %+v", r.Symbols)
	}
}

func TestParse_VarDecl_NumberValue(t *testing.T) {
	src := `const count = 42;`
	r := Parse(src)
	found := false
	for _, s := range r.Symbols {
		if s.Name == "count" && s.Kind == "variable" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected variable count, got: %+v", r.Symbols)
	}
}

func TestParse_VarDecl_Destructuring(t *testing.T) {
	// Destructuring pattern — should not panic
	src := `const { a, b } = obj;`
	r := Parse(src)
	if r == nil {
		t.Fatal("expected non-nil result")
	}
}

// --- parseRequire coverage ---

func TestParse_RequireWithoutParens(t *testing.T) {
	// require without parens (odd but possible)
	src := `const x = require;`
	r := Parse(src)
	// Should not panic
	if r == nil {
		t.Fatal("expected non-nil result")
	}
}

func TestParse_RequireNonStringArg(t *testing.T) {
	// require with non-string argument
	src := `const x = require(moduleName);`
	r := Parse(src)
	// Should not create an import fact but also not panic
	if r == nil {
		t.Fatal("expected non-nil result")
	}
	for _, imp := range r.Imports {
		if imp.Source == "moduleName" {
			t.Error("should not create import for non-string require arg")
		}
	}
}

// --- isArrowFunction / skipArrowFunction coverage ---

func TestParse_ArrowFunction_WithParams(t *testing.T) {
	src := `const add = (a, b) => a + b;`
	r := Parse(src)
	found := false
	for _, s := range r.Symbols {
		if s.Name == "add" && s.Kind == "function" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected function symbol 'add', got: %+v", r.Symbols)
	}
}

func TestParse_ArrowFunction_Async(t *testing.T) {
	src := `const fetch = async (url) => {
  return data;
};`
	r := Parse(src)
	found := false
	for _, s := range r.Symbols {
		if s.Name == "fetch" && s.Kind == "function" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected function symbol 'fetch', got: %+v", r.Symbols)
	}
}

func TestParse_ArrowFunction_SingleParam(t *testing.T) {
	// x => expr  (no parens around single param)
	src := `const double = x => x * 2;`
	r := Parse(src)
	found := false
	for _, s := range r.Symbols {
		if s.Name == "double" && s.Kind == "function" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected function symbol 'double', got: %+v", r.Symbols)
	}
}

func TestParse_ArrowFunction_WithReturnType(t *testing.T) {
	// TypeScript: (x: number): number => x * 2
	src := `const triple = (x: number): number => x * 3;`
	r := Parse(src)
	found := false
	for _, s := range r.Symbols {
		if s.Name == "triple" && s.Kind == "function" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected function symbol 'triple', got: %+v", r.Symbols)
	}
}

func TestParse_ArrowFunction_WithBlockBody(t *testing.T) {
	src := `const process = (data) => {
  const result = data * 2;
  return result;
};`
	r := Parse(src)
	found := false
	for _, s := range r.Symbols {
		if s.Name == "process" && s.Kind == "function" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected function symbol 'process', got: %+v", r.Symbols)
	}
}

func TestParse_ArrowFunction_AsyncWithBlockBody(t *testing.T) {
	src := `const loadData = async () => {
  const res = await fetch('/api');
  return res.json();
};`
	r := Parse(src)
	found := false
	for _, s := range r.Symbols {
		if s.Name == "loadData" && s.Kind == "function" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected function symbol 'loadData', got: %+v", r.Symbols)
	}
}

// --- parseClassDecl coverage ---

func TestParse_ClassWithExtends(t *testing.T) {
	src := `class Dog extends Animal {
  bark() {}
}`
	r := Parse(src)
	found := false
	for _, s := range r.Symbols {
		if s.Name == "Dog" && s.Kind == "class" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected class Dog, got: %+v", r.Symbols)
	}
}

func TestParse_ClassWithImplements(t *testing.T) {
	src := `class Cat implements Animal {
  speak() {}
}`
	r := Parse(src)
	found := false
	for _, s := range r.Symbols {
		if s.Name == "Cat" && s.Kind == "class" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected class Cat, got: %+v", r.Symbols)
	}
}

func TestParse_ClassNoName(t *testing.T) {
	// anonymous class assignment - edge case for empty class name
	src := `const X = class {};`
	r := Parse(src)
	// Should not panic
	if r == nil {
		t.Fatal("expected non-nil result")
	}
}

// --- parseInterfaceDecl coverage ---

func TestParse_InterfaceWithExtends(t *testing.T) {
	// Exported interface with extends
	src := `export interface Animal extends Creature {
  name: string;
}`
	r := Parse(src)
	found := false
	for _, s := range r.Symbols {
		if s.Name == "Animal" && s.Kind == "interface" && s.Exported {
			found = true
		}
	}
	if !found {
		t.Errorf("expected exported interface Animal, got: %+v", r.Symbols)
	}
}

func TestParse_Interface_ExportedNoBody(t *testing.T) {
	// interface without opening brace (malformed/edge case)
	src := `export interface Foo`
	r := Parse(src)
	// Should not panic
	if r == nil {
		t.Fatal("expected non-nil result")
	}
}

// --- routeMatchesPrefix coverage ---

func TestRouteMatchesPrefix_EmptyPrefix(t *testing.T) {
	if !routeMatchesPrefix("/anything", "") {
		t.Error("empty prefix should match everything")
	}
}

func TestRouteMatchesPrefix_ExactMatch(t *testing.T) {
	if !routeMatchesPrefix("/admin", "/admin") {
		t.Error("exact path should match prefix")
	}
}

func TestRouteMatchesPrefix_PrefixMatch(t *testing.T) {
	if !routeMatchesPrefix("/admin/users", "/admin") {
		t.Error("/admin/users should match /admin prefix")
	}
}

func TestRouteMatchesPrefix_NonMatch(t *testing.T) {
	if routeMatchesPrefix("/public/data", "/admin") {
		t.Error("/public/data should NOT match /admin prefix")
	}
}

func TestRouteMatchesPrefix_TrailingSlash(t *testing.T) {
	// Trailing slash normalization
	if !routeMatchesPrefix("/admin/", "/admin") {
		t.Error("/admin/ should match /admin prefix (trailing slash stripped)")
	}
}

func TestRouteMatchesPrefix_PrefixWithTrailingSlash(t *testing.T) {
	if !routeMatchesPrefix("/admin/settings", "/admin/") {
		t.Error("/admin/settings should match /admin/ prefix (trailing slash stripped)")
	}
}

func TestRouteMatchesPrefix_PartialWordShouldNotMatch(t *testing.T) {
	// /adminpanel should NOT match /admin prefix
	if routeMatchesPrefix("/adminpanel", "/admin") {
		t.Error("/adminpanel should NOT match /admin prefix (not at slash boundary)")
	}
}

// --- Additional parser edge cases ---

func TestParse_FunctionGenerator(t *testing.T) {
	src := `function* generator() { yield 1; }`
	r := Parse(src)
	found := false
	for _, s := range r.Symbols {
		if s.Name == "generator" && s.Kind == "function" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected generator function, got: %+v", r.Symbols)
	}
}

func TestParse_FunctionWithReturnType(t *testing.T) {
	src := `function greet(name: string): string { return "hello"; }`
	r := Parse(src)
	found := false
	for _, s := range r.Symbols {
		if s.Name == "greet" && s.Kind == "function" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected function greet, got: %+v", r.Symbols)
	}
}

func TestParse_SkipTypeAnnotation_GenericType(t *testing.T) {
	// TypeScript generic type annotation: x: Map<string, number>
	src := `const map: Map<string, number> = new Map();`
	r := Parse(src)
	found := false
	for _, s := range r.Symbols {
		if s.Name == "map" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected variable map, got: %+v", r.Symbols)
	}
}

func TestParse_ArrowFunction_NotArrow(t *testing.T) {
	// Looks like might be arrow but is actually an assignment
	src := `const x = someFunction();`
	r := Parse(src)
	found := false
	for _, s := range r.Symbols {
		if s.Name == "x" && s.Kind == "variable" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected variable x, got: %+v", r.Symbols)
	}
}

func TestParse_NestJSInterceptors(t *testing.T) {
	src := `@UseInterceptors(LoggingInterceptor)
@Get('/data')
getData() {}
`
	r := Parse(src)
	found := false
	for _, mw := range r.Middlewares {
		if mw.Name == "LoggingInterceptor" && mw.Framework == "nestjs-interceptor" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected LoggingInterceptor middleware, got: %+v", r.Middlewares)
	}
}

func TestParse_NestJSInterceptors_String(t *testing.T) {
	src := `@UseInterceptors('loggingInterceptor')
@Get('/data')
getData() {}
`
	r := Parse(src)
	found := false
	for _, mw := range r.Middlewares {
		if mw.Name == "loggingInterceptor" && mw.Framework == "nestjs-interceptor" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected loggingInterceptor middleware, got: %+v", r.Middlewares)
	}
}

func TestParse_ClassBodyWithDecorators(t *testing.T) {
	// Decorators inside class body (method-level)
	src := `@Controller('products')
export class ProductsController {
  @UseGuards(AdminGuard)
  @Delete(':id')
  remove() {}
}
`
	r := Parse(src)
	// Should find DELETE route with guard
	var deleteRoute *ASTRoute
	for i := range r.Routes {
		if r.Routes[i].Method == "DELETE" {
			deleteRoute = &r.Routes[i]
			break
		}
	}
	if deleteRoute == nil {
		t.Fatalf("expected DELETE route, got routes: %+v", r.Routes)
	}
	if len(deleteRoute.Guards) == 0 || deleteRoute.Guards[0] != "AdminGuard" {
		t.Errorf("expected AdminGuard in route.Guards, got %v", deleteRoute.Guards)
	}
}

func TestParse_HapiPlugin(t *testing.T) {
	src := `server.register(hapiAuth);`
	r := Parse(src)
	if len(r.Middlewares) != 1 {
		t.Fatalf("expected 1 middleware, got %d", len(r.Middlewares))
	}
	if r.Middlewares[0].Framework != "hapi-plugin" {
		t.Errorf("expected hapi-plugin framework, got %q", r.Middlewares[0].Framework)
	}
}

func TestParse_RouteObject_WithAny(t *testing.T) {
	// route object without method should default to ANY
	src := `server.route({ url: '/any', handler: anyHandler });`
	r := Parse(src)
	found := false
	for _, rt := range r.Routes {
		if rt.Path == "/any" && rt.Method == "ANY" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected ANY /any route, got: %+v", r.Routes)
	}
}

func TestParse_SecretPassword(t *testing.T) {
	src := `const DB_PASSWORD = "supersecretpassword";`
	r := Parse(src)
	if len(r.Secrets) == 0 {
		t.Fatal("expected at least 1 secret")
	}
	found := false
	for _, s := range r.Secrets {
		if s.Name == "DB_PASSWORD" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected DB_PASSWORD secret, got: %+v", r.Secrets)
	}
}

func TestParse_SecretApiSecret(t *testing.T) {
	src := `const MY_API_SECRET = "abcdefgh1234";`
	r := Parse(src)
	if len(r.Secrets) == 0 {
		t.Fatal("expected at least 1 secret")
	}
	found := false
	for _, s := range r.Secrets {
		if s.Name == "MY_API_SECRET" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected MY_API_SECRET secret, got: %+v", r.Secrets)
	}
}

func TestParse_VarDeclAtEnd(t *testing.T) {
	// Test parseVarDecl when atEnd after consuming keyword
	src := `const`
	r := Parse(src)
	if r == nil {
		t.Fatal("expected non-nil result")
	}
}

func TestParse_UseCallWithMultipleArgs(t *testing.T) {
	// app.use(express.json(), bodyParser.urlencoded()) - multiple middlewares
	src := `app.use(express.json(), bodyParser.urlencoded());`
	r := Parse(src)
	if len(r.Middlewares) < 1 {
		t.Error("expected at least 1 middleware")
	}
}

func TestParse_SkipTypeAnnotation_StopsAtEquals(t *testing.T) {
	// Type annotation with = stops correctly
	src := `const val: number = 10;`
	r := Parse(src)
	found := false
	for _, s := range r.Symbols {
		if s.Name == "val" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected variable val, got: %+v", r.Symbols)
	}
}

func TestParse_SkipTypeAnnotation_StopsAtSemicolon(t *testing.T) {
	src := `let x: string;`
	r := Parse(src)
	found := false
	for _, s := range r.Symbols {
		if s.Name == "x" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected variable x with type annotation, got: %+v", r.Symbols)
	}
}

func TestParse_SkipTypeAnnotation_StopsAtKeyword(t *testing.T) {
	src := `let x: string
const y = 1;`
	r := Parse(src)
	found := false
	for _, s := range r.Symbols {
		if s.Name == "y" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected variable y, got: %+v", r.Symbols)
	}
}

func TestParse_SkipTypeAnnotation_StopsAtCloseParen(t *testing.T) {
	// function with typed params
	src := `function foo(x: number) { return x; }`
	r := Parse(src)
	found := false
	for _, s := range r.Symbols {
		if s.Name == "foo" && s.Kind == "function" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected function foo, got: %+v", r.Symbols)
	}
}

// --- Parser internal helper coverage ---

func TestParser_Peek_AtEnd(t *testing.T) {
	// When pos is past end, peek() returns TokEOF
	toks := Tokenize("")
	p := &parser{toks: toks, res: &ASTResult{}}
	p.pos = len(p.toks) + 10 // way past end
	tok := p.peek()
	if tok.Kind != TokEOF {
		t.Errorf("expected TokEOF, got kind=%v", tok.Kind)
	}
}

func TestParser_PeekIs_AtEnd(t *testing.T) {
	// When pos is past end, peekIs() returns false
	toks := Tokenize("")
	p := &parser{toks: toks, res: &ASTResult{}}
	p.pos = len(p.toks) + 10
	if p.peekIs(TokKeyword, "const") {
		t.Error("expected peekIs to return false when past end")
	}
}

func TestParse_ExprStatement_NonIdentStart(t *testing.T) {
	// A number at top level isn't an ident, should be skipped gracefully
	src := `42;
const x = 1;`
	r := Parse(src)
	// Should not panic; x should still be found
	found := false
	for _, s := range r.Symbols {
		if s.Name == "x" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected x symbol after non-ident top-level, got: %+v", r.Symbols)
	}
}

func TestParse_ExprStatement_NoDot(t *testing.T) {
	// An identifier without a dot - just an expression statement
	src := `someIdentifier;
const y = 1;`
	r := Parse(src)
	found := false
	for _, s := range r.Symbols {
		if s.Name == "y" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected y symbol after ident-only statement, got: %+v", r.Symbols)
	}
}

func TestParse_ExprStatement_DotThenNonIdent(t *testing.T) {
	// obj.123 - dot followed by non-ident
	// This is tricky to produce in valid JS; test via parser directly
	toks := []Tok{
		{Kind: TokIdent, Value: "obj"},
		{Kind: TokPunct, Value: "."},
		{Kind: TokNumber, Value: "123"},
		{Kind: TokEOF},
	}
	p := &parser{toks: toks, res: &ASTResult{}}
	result := p.parseExprStatement()
	// Should return true without panicking
	if !result {
		t.Error("expected parseExprStatement to return true")
	}
}

func TestParse_ExprStatement_DotIdentNoParen(t *testing.T) {
	// obj.prop without following ( - should not try to parse as call
	toks := []Tok{
		{Kind: TokIdent, Value: "obj"},
		{Kind: TokPunct, Value: "."},
		{Kind: TokIdent, Value: "prop"},
		{Kind: TokPunct, Value: ";"},
		{Kind: TokEOF},
	}
	p := &parser{toks: toks, res: &ASTResult{}}
	result := p.parseExprStatement()
	if !result {
		t.Error("expected parseExprStatement to return true for obj.prop")
	}
}

func TestParse_SkipTypeAnnotation_CommaAtDepth0(t *testing.T) {
	// Generic function parameter with comma
	src := `function foo<T>(x: Map<string, number>, y: string) { }`
	r := Parse(src)
	found := false
	for _, s := range r.Symbols {
		if s.Name == "foo" && s.Kind == "function" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected function foo with generic param, got: %+v", r.Symbols)
	}
}

func TestParse_SkipTypeAnnotation_ArrowAtDepth0(t *testing.T) {
	// Return type annotation stops at =>
	src := `const fn = (): void => {};`
	r := Parse(src)
	found := false
	for _, s := range r.Symbols {
		if s.Name == "fn" && s.Kind == "function" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected function fn with void return type, got: %+v", r.Symbols)
	}
}

func TestParse_IsArrowFunction_EmptyParens(t *testing.T) {
	// () => at start of token stream
	toks := Tokenize("() => 1")
	p := &parser{toks: toks, res: &ASTResult{}}
	if !p.isArrowFunction() {
		t.Error("expected () => to be detected as arrow function")
	}
}

func TestParse_IsArrowFunction_SingleParamParen(t *testing.T) {
	// (x) => at start
	toks := Tokenize("(x) => x + 1")
	p := &parser{toks: toks, res: &ASTResult{}}
	if !p.isArrowFunction() {
		t.Error("expected (x) => to be detected as arrow function")
	}
}

func TestParse_IsArrowFunction_AsyncEmpty(t *testing.T) {
	// async () =>
	toks := Tokenize("async () => {}")
	p := &parser{toks: toks, res: &ASTResult{}}
	if !p.isArrowFunction() {
		t.Error("expected async () => to be detected as arrow function")
	}
}

func TestParse_IsArrowFunction_NotArrow_JustParen(t *testing.T) {
	// (x) without => is not arrow
	toks := Tokenize("(x)")
	p := &parser{toks: toks, res: &ASTResult{}}
	if p.isArrowFunction() {
		t.Error("expected (x) without => to NOT be arrow function")
	}
}

func TestParse_IsArrowFunction_SingleParamNoArrow(t *testing.T) {
	// "x" followed by something that isn't => is not arrow
	toks := Tokenize("x + 1")
	p := &parser{toks: toks, res: &ASTResult{}}
	if p.isArrowFunction() {
		t.Error("expected x + 1 to NOT be arrow function")
	}
}

func TestParse_SkipArrowFunction_SingleParamNoParens(t *testing.T) {
	// Arrow with single param without parens: x => expr
	src := `const square = x => x * x;`
	r := Parse(src)
	found := false
	for _, s := range r.Symbols {
		if s.Name == "square" && s.Kind == "function" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected function square, got: %+v", r.Symbols)
	}
}

func TestParse_SkipArrowFunction_WithReturnTypeAnnotation(t *testing.T) {
	// Arrow with return type: () : string => "hello"
	toks := []Tok{
		{Kind: TokPunct, Value: "("},
		{Kind: TokPunct, Value: ")"},
		{Kind: TokPunct, Value: ":"},
		{Kind: TokIdent, Value: "string"},
		{Kind: TokPunct, Value: "=>"},
		{Kind: TokString, Value: "hello"},
		{Kind: TokEOF},
	}
	p := &parser{toks: toks, res: &ASTResult{}}
	endLine := p.skipArrowFunction()
	if endLine < 0 {
		t.Error("expected valid endLine")
	}
}

func TestParse_ParseCallExpr_UnknownMethod(t *testing.T) {
	// An unknown method call should be gracefully skipped
	src := `app.unknown('something');`
	r := Parse(src)
	// Should not panic; no routes/middlewares added
	if len(r.Routes) != 0 {
		t.Errorf("expected no routes for unknown method, got %+v", r.Routes)
	}
}

func TestParse_ParseCallExpr_RouteWithNonSlashPath(t *testing.T) {
	// Route path starting with : (like :id)
	src := `router.get(':id', handler);`
	r := Parse(src)
	found := false
	for _, rt := range r.Routes {
		if rt.Path == ":id" && rt.Method == "GET" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected GET :id route, got: %+v", r.Routes)
	}
}

func TestParse_ParseClassDecl_NoBody(t *testing.T) {
	// Class declaration that hits EOF before { -- edge case
	src := `class Foo`
	r := Parse(src)
	// Should not panic; Foo may or may not be in symbols depending on impl
	if r == nil {
		t.Fatal("expected non-nil result")
	}
}

func TestParse_ParseClassBody_NestedBraces(t *testing.T) {
	// Class with nested objects in method
	src := `class Config {
  getSettings() {
    return { debug: true, level: 2 };
  }
}`
	r := Parse(src)
	found := false
	for _, s := range r.Symbols {
		if s.Name == "Config" && s.Kind == "class" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected class Config, got: %+v", r.Symbols)
	}
}

func TestParse_ParseInterfaceDecl_ReturnFalse(t *testing.T) {
	// Test parseInterfaceDecl when not at interface keyword
	toks := Tokenize("const x = 1;")
	p := &parser{toks: toks, res: &ASTResult{}}
	result := p.parseInterfaceDecl(false)
	if result {
		t.Error("expected parseInterfaceDecl to return false when not at interface keyword")
	}
}

func TestParse_SkipBraces_NotAtBrace(t *testing.T) {
	// skipBraces when not at { — should return current line
	toks := Tokenize("return x;")
	p := &parser{toks: toks, res: &ASTResult{}}
	line := p.skipBraces()
	// Should return current token's line without advancing
	if line < 0 {
		t.Error("expected non-negative line")
	}
}

func TestParse_SkipToCloseParen_Nested(t *testing.T) {
	// Test skipToCloseParen with nested parens
	toks := []Tok{
		{Kind: TokPunct, Value: "("},
		{Kind: TokPunct, Value: "("},
		{Kind: TokPunct, Value: ")"},
		{Kind: TokPunct, Value: ")"},
		{Kind: TokEOF},
	}
	p := &parser{toks: toks, res: &ASTResult{}}
	// skipToCloseParen assumes opening paren already consumed
	p.skipToCloseParen()
	// Should not panic and should be at EOF
}

func TestParse_ParseRouteObject_WithBraceNesting(t *testing.T) {
	// Route object with nested object - tests brace nesting in parseRouteObject
	src := `fastify.route({ method: 'GET', url: '/nested', config: { auth: true }, handler: h });`
	r := Parse(src)
	found := false
	for _, rt := range r.Routes {
		if rt.Path == "/nested" && rt.Method == "GET" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected GET /nested, got: %+v", r.Routes)
	}
}

func TestParse_ParseDecorator_AtController_NoArg(t *testing.T) {
	// @Controller() with no argument - prefix should be "/"
	src := `@Controller()
export class RootController {}
`
	r := Parse(src)
	found := false
	for _, rt := range r.Routes {
		if rt.Method == "PREFIX" && rt.Path == "/" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected PREFIX / route, got: %+v", r.Routes)
	}
}

func TestParse_ParseDecorator_AtGetNoPath(t *testing.T) {
	// @Get() with no arg - path defaults to "/"
	src := `@Controller('root')
export class RootCtrl {
  @Get()
  index() {}
}
`
	r := Parse(src)
	found := false
	for _, rt := range r.Routes {
		if rt.Method == "GET" && rt.Path == "/" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected GET / route, got: %+v", r.Routes)
	}
}

func TestParse_ParseDecorator_UseGuardsMultiple(t *testing.T) {
	// @UseGuards(Auth, Role) - multiple guards
	src := `@Controller('admin')
export class AdminController {
  @UseGuards(AuthGuard, RoleGuard, PermGuard)
  @Get('users')
  listUsers() {}
}
`
	r := Parse(src)
	guardNames := map[string]bool{}
	for _, mw := range r.Middlewares {
		if mw.Framework == "nestjs-guard" {
			guardNames[mw.Name] = true
		}
	}
	for _, name := range []string{"AuthGuard", "RoleGuard", "PermGuard"} {
		if !guardNames[name] {
			t.Errorf("expected guard %q, got: %+v", name, r.Middlewares)
		}
	}
}

func TestParse_ParseImport_NamespaceAlias(t *testing.T) {
	// import * from 'mod' without 'as alias' - edge case
	toks := []Tok{
		{Kind: TokKeyword, Value: "import"},
		{Kind: TokPunct, Value: "*"},
		// No 'as' keyword
		{Kind: TokKeyword, Value: "from"},
		{Kind: TokString, Value: "somemod"},
		{Kind: TokEOF},
	}
	p := &parser{toks: toks, res: &ASTResult{}}
	result := p.parseImport()
	if !result {
		t.Error("expected parseImport to return true")
	}
	if len(p.res.Imports) != 1 {
		t.Errorf("expected 1 import, got %d", len(p.res.Imports))
	}
}
