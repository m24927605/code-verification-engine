package jsts

import (
	"testing"
)

func TestParse_ESImports(t *testing.T) {
	src := `import express from 'express';
import React from "react";
`
	r := Parse(src)
	if len(r.Imports) < 2 {
		t.Fatalf("expected at least 2 imports, got %d", len(r.Imports))
	}
	sources := map[string]bool{}
	for _, imp := range r.Imports {
		sources[imp.Source] = true
	}
	for _, s := range []string{"express", "react"} {
		if !sources[s] {
			t.Errorf("expected import source %q not found", s)
		}
	}
}

func TestParse_RequireImports(t *testing.T) {
	src := `const express = require('express');
const path = require("path");
`
	r := Parse(src)
	if len(r.Imports) < 2 {
		t.Fatalf("expected at least 2 imports, got %d", len(r.Imports))
	}
	sources := map[string]bool{}
	for _, imp := range r.Imports {
		sources[imp.Source] = true
	}
	if !sources["express"] {
		t.Error("expected require('express') import")
	}
	if !sources["path"] {
		t.Error("expected require('path') import")
	}
}

func TestParse_NamedImports(t *testing.T) {
	src := `import { Router, Request, Response } from 'express';
`
	r := Parse(src)
	if len(r.Imports) != 1 {
		t.Fatalf("expected 1 import, got %d", len(r.Imports))
	}
	imp := r.Imports[0]
	if imp.Source != "express" {
		t.Errorf("expected source 'express', got %q", imp.Source)
	}
	if len(imp.Names) != 3 {
		t.Errorf("expected 3 named imports, got %d: %v", len(imp.Names), imp.Names)
	}
	nameSet := map[string]bool{}
	for _, n := range imp.Names {
		nameSet[n] = true
	}
	for _, expected := range []string{"Router", "Request", "Response"} {
		if !nameSet[expected] {
			t.Errorf("expected named import %q", expected)
		}
	}
}

func TestParse_FunctionDecl(t *testing.T) {
	src := `function foo() {
  return 1;
}
`
	r := Parse(src)
	found := false
	for _, s := range r.Symbols {
		if s.Name == "foo" && s.Kind == "function" {
			found = true
			if s.Exported {
				t.Error("expected foo to not be exported")
			}
		}
	}
	if !found {
		t.Error("expected symbol foo")
	}
}

func TestParse_ClassDecl(t *testing.T) {
	src := `class Foo {
  method() {}
  bar() {}
}
`
	r := Parse(src)
	found := false
	for _, s := range r.Symbols {
		if s.Name == "Foo" && s.Kind == "class" {
			found = true
		}
	}
	if !found {
		t.Error("expected symbol Foo (class)")
	}
}

func TestParse_ArrowFunction(t *testing.T) {
	src := `const foo = () => {
  return 1;
};
`
	r := Parse(src)
	found := false
	for _, s := range r.Symbols {
		if s.Name == "foo" && s.Kind == "function" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected symbol foo (function via arrow), got: %+v", r.Symbols)
	}
}

func TestParse_ExportedSymbols(t *testing.T) {
	src := `export function bar() {}
export class Baz {}
export const qux = () => {};
`
	r := Parse(src)
	exported := map[string]bool{}
	for _, s := range r.Symbols {
		if s.Exported {
			exported[s.Name] = true
		}
	}
	for _, name := range []string{"bar", "Baz", "qux"} {
		if !exported[name] {
			t.Errorf("expected %q to be exported", name)
		}
	}
}

func TestParse_ExpressRoutes(t *testing.T) {
	src := `app.get('/users', handler);
router.post('/items', createItem);
app.delete('/:id', deleteHandler);
`
	r := Parse(src)
	if len(r.Routes) < 3 {
		t.Fatalf("expected at least 3 routes, got %d", len(r.Routes))
	}
	routeMap := map[string]bool{}
	for _, rt := range r.Routes {
		routeMap[rt.Method+" "+rt.Path] = true
	}
	for _, key := range []string{"GET /users", "POST /items", "DELETE /:id"} {
		if !routeMap[key] {
			t.Errorf("expected route %q not found", key)
		}
	}
}

func TestParse_Middleware(t *testing.T) {
	src := `app.use(cors());
app.use(helmet);
`
	r := Parse(src)
	if len(r.Middlewares) < 2 {
		t.Fatalf("expected at least 2 middlewares, got %d", len(r.Middlewares))
	}
	names := map[string]bool{}
	for _, mw := range r.Middlewares {
		names[mw.Name] = true
	}
	if !names["cors"] {
		t.Error("expected middleware cors")
	}
	if !names["helmet"] {
		t.Error("expected middleware helmet")
	}
}

func TestParse_Decorators(t *testing.T) {
	src := `@Controller('users')
export class UsersController {
  @Get(':id')
  findOne() {}
}
`
	r := Parse(src)
	routeMap := map[string]bool{}
	for _, rt := range r.Routes {
		routeMap[rt.Method+" "+rt.Path] = true
	}
	if !routeMap["PREFIX /users"] {
		t.Errorf("expected PREFIX /users, got routes: %+v", r.Routes)
	}
	if !routeMap["GET /:id"] {
		t.Errorf("expected GET /:id, got routes: %+v", r.Routes)
	}
}

func TestParse_Secrets(t *testing.T) {
	src := `const API_KEY = "sk-live-1234567890";
const JWT_SECRET = "mysupersecretkey";
const normalVar = "hello";
`
	r := Parse(src)
	if len(r.Secrets) < 2 {
		t.Fatalf("expected at least 2 secrets, got %d: %+v", len(r.Secrets), r.Secrets)
	}
	secretNames := map[string]bool{}
	for _, s := range r.Secrets {
		secretNames[s.Name] = true
	}
	if !secretNames["API_KEY"] {
		t.Error("expected secret API_KEY")
	}
	if !secretNames["JWT_SECRET"] {
		t.Error("expected secret JWT_SECRET")
	}
}

func TestParse_CommentsIgnored(t *testing.T) {
	src := `// import express from 'express';
/* app.get('/hidden', handler); */
const x = 1;
`
	r := Parse(src)
	for _, imp := range r.Imports {
		if imp.Source == "express" {
			t.Error("import inside comment should not be extracted")
		}
	}
	for _, rt := range r.Routes {
		if rt.Path == "/hidden" {
			t.Error("route inside comment should not be extracted")
		}
	}
}

func TestParse_StringsIgnored(t *testing.T) {
	// Patterns inside string values should not be extracted as top-level constructs
	src := `const msg = "import express from 'express'";
const msg2 = "app.get('/hidden', handler)";
`
	r := Parse(src)
	for _, imp := range r.Imports {
		if imp.Source == "express" {
			t.Error("import inside string should not be extracted")
		}
	}
	for _, rt := range r.Routes {
		if rt.Path == "/hidden" {
			t.Error("route inside string should not be extracted")
		}
	}
}

func TestParse_EmptyInput(t *testing.T) {
	r := Parse("")
	if r == nil {
		t.Fatal("Parse should return non-nil result for empty input")
	}
	if len(r.Imports) != 0 || len(r.Symbols) != 0 || len(r.Routes) != 0 {
		t.Error("expected no facts for empty input")
	}
}

func TestParse_SyntaxErrors(t *testing.T) {
	inputs := []string{
		"function {",
		"import from",
		"class { }}}}",
		"(((",
		"@@@",
		"const = ;",
		"export default;",
		string([]byte{0, 1, 2, 3}),
	}
	for _, src := range inputs {
		// Must not panic
		r := Parse(src)
		if r == nil {
			t.Errorf("Parse(%q) should return non-nil result", src)
		}
	}
}

func TestParse_SideEffectImport(t *testing.T) {
	src := `import './polyfills';
`
	r := Parse(src)
	if len(r.Imports) != 1 {
		t.Fatalf("expected 1 import, got %d", len(r.Imports))
	}
	if r.Imports[0].Source != "./polyfills" {
		t.Errorf("expected source './polyfills', got %q", r.Imports[0].Source)
	}
}

func TestParse_NamespaceImport(t *testing.T) {
	src := `import * as path from 'path';
`
	r := Parse(src)
	if len(r.Imports) != 1 {
		t.Fatalf("expected 1 import, got %d", len(r.Imports))
	}
	if r.Imports[0].Source != "path" {
		t.Errorf("expected source 'path', got %q", r.Imports[0].Source)
	}
}

func TestParse_AsyncFunction(t *testing.T) {
	src := `async function fetchData() { }
export async function processData() { }
`
	r := Parse(src)
	names := map[string]bool{}
	for _, s := range r.Symbols {
		if s.Kind == "function" {
			names[s.Name] = true
		}
	}
	if !names["fetchData"] {
		t.Error("expected async function fetchData")
	}
	if !names["processData"] {
		t.Error("expected exported async function processData")
	}
}

func TestParse_FastifyRoutes(t *testing.T) {
	src := `fastify.get('/health', handler);
fastify.post('/items', createItem);
`
	r := Parse(src)
	routeMap := map[string]bool{}
	for _, rt := range r.Routes {
		routeMap[rt.Method+" "+rt.Path] = true
	}
	if !routeMap["GET /health"] {
		t.Error("expected GET /health")
	}
	if !routeMap["POST /items"] {
		t.Error("expected POST /items")
	}
}

func TestParse_FastifyRegister(t *testing.T) {
	src := `fastify.register(authPlugin);
`
	r := Parse(src)
	if len(r.Middlewares) != 1 {
		t.Fatalf("expected 1 middleware, got %d", len(r.Middlewares))
	}
	if r.Middlewares[0].Name != "authPlugin" {
		t.Errorf("expected authPlugin, got %q", r.Middlewares[0].Name)
	}
}

func TestParse_FastifyAddHook(t *testing.T) {
	src := `fastify.addHook('onRequest', handler);
`
	r := Parse(src)
	if len(r.Middlewares) != 1 {
		t.Fatalf("expected 1 middleware, got %d", len(r.Middlewares))
	}
	if r.Middlewares[0].Name != "onRequest" {
		t.Errorf("expected onRequest, got %q", r.Middlewares[0].Name)
	}
	if r.Middlewares[0].Framework != "fastify-hook" {
		t.Errorf("expected fastify-hook framework, got %q", r.Middlewares[0].Framework)
	}
}

func TestParse_ExportDefaultFunction(t *testing.T) {
	src := `export default function handler() {}
`
	r := Parse(src)
	found := false
	for _, s := range r.Symbols {
		if s.Name == "handler" && s.Exported {
			found = true
		}
	}
	if !found {
		t.Errorf("expected exported default function handler, got: %+v", r.Symbols)
	}
}

func TestParse_ExportDefaultClass(t *testing.T) {
	src := `export default class MyClass {}
`
	r := Parse(src)
	found := false
	for _, s := range r.Symbols {
		if s.Name == "MyClass" && s.Exported && s.Kind == "class" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected exported default class MyClass, got: %+v", r.Symbols)
	}
}

func TestParse_InterfaceDecl(t *testing.T) {
	src := `export interface MyInterface {
  name: string;
}
`
	r := Parse(src)
	found := false
	for _, s := range r.Symbols {
		if s.Name == "MyInterface" && s.Kind == "interface" && s.Exported {
			found = true
		}
	}
	if !found {
		t.Errorf("expected exported interface MyInterface, got: %+v", r.Symbols)
	}
}

func TestParse_RouteObject(t *testing.T) {
	src := `fastify.route({ method: 'GET', url: '/status', handler: statusHandler });
server.route({ method: 'POST', path: '/login', handler: loginHandler });
`
	r := Parse(src)
	routeMap := map[string]bool{}
	for _, rt := range r.Routes {
		routeMap[rt.Method+" "+rt.Path] = true
	}
	if !routeMap["GET /status"] {
		t.Errorf("expected GET /status, got: %+v", r.Routes)
	}
	if !routeMap["POST /login"] {
		t.Errorf("expected POST /login, got: %+v", r.Routes)
	}
}

func TestParse_HapiExt(t *testing.T) {
	src := `server.ext('onPreHandler', authCheck);
`
	r := Parse(src)
	if len(r.Middlewares) < 1 {
		t.Fatal("expected at least 1 middleware for hapi ext")
	}
	found := false
	for _, mw := range r.Middlewares {
		if mw.Name == "onPreHandler" && mw.Framework == "hapi-ext" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected hapi-ext onPreHandler, got: %+v", r.Middlewares)
	}
}

func TestParse_ExpressRouteWithMiddleware(t *testing.T) {
	src := `app.get('/users', authMiddleware, handler);
`
	r := Parse(src)
	if len(r.Routes) != 1 {
		t.Fatalf("expected 1 route, got %d", len(r.Routes))
	}
	rt := r.Routes[0]
	if rt.Method != "GET" || rt.Path != "/users" {
		t.Errorf("unexpected route: %s %s", rt.Method, rt.Path)
	}
	if rt.Handler != "handler" {
		t.Errorf("expected handler 'handler', got %q", rt.Handler)
	}
	if len(rt.Middlewares) != 1 || rt.Middlewares[0] != "authMiddleware" {
		t.Errorf("expected middlewares [authMiddleware], got %v", rt.Middlewares)
	}
}

func TestParse_MultipleMiddleware(t *testing.T) {
	src := `app.get('/path', mw1, mw2, mw3, handler);
`
	r := Parse(src)
	if len(r.Routes) != 1 {
		t.Fatalf("expected 1 route, got %d", len(r.Routes))
	}
	rt := r.Routes[0]
	if rt.Handler != "handler" {
		t.Errorf("expected handler 'handler', got %q", rt.Handler)
	}
	if len(rt.Middlewares) != 3 {
		t.Fatalf("expected 3 middlewares, got %d: %v", len(rt.Middlewares), rt.Middlewares)
	}
	expected := []string{"mw1", "mw2", "mw3"}
	for i, name := range expected {
		if rt.Middlewares[i] != name {
			t.Errorf("middleware[%d] = %q, want %q", i, rt.Middlewares[i], name)
		}
	}
}

func TestParse_NestJSGuards(t *testing.T) {
	src := `@Controller('users')
export class UsersController {
  @UseGuards(AuthGuard)
  @Get('profile')
  getProfile() {}
}
`
	r := Parse(src)
	// Check that the route has guards attached
	var profileRoute *ASTRoute
	for i := range r.Routes {
		if r.Routes[i].Path == "/profile" && r.Routes[i].Method == "GET" {
			profileRoute = &r.Routes[i]
			break
		}
	}
	if profileRoute == nil {
		t.Fatalf("expected GET /profile route, got routes: %+v", r.Routes)
	}
	if len(profileRoute.Guards) != 1 || profileRoute.Guards[0] != "AuthGuard" {
		t.Errorf("expected guards [AuthGuard], got %v", profileRoute.Guards)
	}
	// Also check that AuthGuard appears as a middleware fact
	foundGuard := false
	for _, mw := range r.Middlewares {
		if mw.Name == "AuthGuard" && mw.Framework == "nestjs-guard" {
			foundGuard = true
		}
	}
	if !foundGuard {
		t.Errorf("expected AuthGuard in middlewares, got: %+v", r.Middlewares)
	}
}

func TestParse_MultipleConstructs(t *testing.T) {
	src := `import express from 'express';
const app = express();
export function handleRequest() {}
app.get('/api/users', handleRequest);
app.use(cors);
const API_KEY = "sk-live-abcdefghij";
`
	r := Parse(src)
	if len(r.Imports) < 1 {
		t.Error("expected at least 1 import")
	}
	if len(r.Symbols) < 2 {
		t.Errorf("expected at least 2 symbols, got %d", len(r.Symbols))
	}
	if len(r.Routes) < 1 {
		t.Error("expected at least 1 route")
	}
	if len(r.Middlewares) < 1 {
		t.Error("expected at least 1 middleware")
	}
	if len(r.Secrets) < 1 {
		t.Error("expected at least 1 secret")
	}
}
