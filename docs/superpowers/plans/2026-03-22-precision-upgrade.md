# Precision Upgrade Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Improve rule semantic precision across JS/TS and Python analyzers by enriching facts with caller context and route-to-middleware bindings, then tightening matchers to prefer structural evidence over name heuristics.

**Architecture:** Phase 1 enriches analyzers (CallerName for DataAccessFact, route-to-middleware binding for RouteFact). Phase 2 adds auth evidence scoring and tightens matchers. Phase 3 updates capability notes. All changes are same-file scoped for binding resolution.

**Tech Stack:** Go, custom JS/TS recursive descent parser, Python ast module subprocess

**Spec:** `docs/superpowers/specs/2026-03-22-precision-upgrade-design.md`

---

## File Structure

### New Files
- `internal/analyzers/jsts/spans.go` — FunctionSpan builder from ASTResult symbols
- `internal/analyzers/jsts/spans_test.go` — Tests for span building
- `internal/analyzers/jsts/binding.go` — Route-to-middleware binding resolution for Express/NestJS/Fastify
- `internal/analyzers/jsts/binding_test.go` — Tests for binding resolution
- `internal/rules/auth_evidence.go` — Auth evidence scoring helper
- `internal/rules/auth_evidence_test.go` — Tests for auth scoring

### Modified Files
- `internal/analyzers/jsts/parser.go` — Extract `app.use()` / `router.use()` calls as new AST constructs
- `internal/analyzers/jsts/bridge.go` — Wire binding resolution into fact conversion
- `internal/analyzers/js/analyzer.go` — Enrich DataAccessFact with CallerName/ImportsDirect
- `internal/analyzers/ts/analyzer.go` — Same enrichment as JS
- `internal/analyzers/python/ast_extract.py` — Improve caller/middleware extraction
- `internal/analyzers/python/analyzer.go` — Enrich DataAccessFact, project global middleware into routes
- `internal/rules/exists_matcher.go` — Use auth evidence scoring for findJWTMiddleware
- `internal/rules/relationship_matcher.go` — Use auth evidence scoring for route protection
- `internal/rules/pattern_matcher.go` — Use CallerName+ImportsDirect for DB access checks
- `internal/rules/capability.go` — Update framework-specific notes
- `internal/analyzers/js/analyzer_test.go` — Tests for enriched facts
- `internal/analyzers/python/analyzer_test.go` — Tests for enriched facts
- `internal/rules/exists_matcher_test.go` — Tests for tightened matchers
- `internal/rules/relationship_matcher_test.go` — Tests for tightened matchers
- `internal/rules/pattern_matcher_test.go` — Tests for tightened matchers

---

## Phase 1: Analyzer Enrichment

### Task 1: JS/TS Function Span Builder

Build a helper that creates function spans from ASTResult symbols for CallerName enrichment.

**Files:**
- Create: `internal/analyzers/jsts/spans.go`
- Create: `internal/analyzers/jsts/spans_test.go`

- [ ] **Step 1: Write failing tests for BuildFunctionSpans**

```go
// internal/analyzers/jsts/spans_test.go
package jsts

import "testing"

func TestBuildFunctionSpans_TopLevel(t *testing.T) {
	result := &ASTResult{
		Symbols: []ASTSymbol{
			{Name: "handleUsers", Kind: "function", Line: 5, EndLine: 20},
			{Name: "UserService", Kind: "class", Line: 25, EndLine: 50},
		},
	}
	spans := BuildFunctionSpans(result)
	// Class spans should be excluded
	if len(spans) != 1 {
		t.Fatalf("got %d spans, want 1", len(spans))
	}
	if spans[0].Name != "handleUsers" {
		t.Errorf("got name %q, want %q", spans[0].Name, "handleUsers")
	}
}

func TestBuildFunctionSpans_Methods(t *testing.T) {
	result := &ASTResult{
		Symbols: []ASTSymbol{
			{Name: "getUser", Kind: "method", Line: 10, EndLine: 15},
			{Name: "listUsers", Kind: "method", Line: 16, EndLine: 25},
		},
	}
	spans := BuildFunctionSpans(result)
	if len(spans) != 2 {
		t.Fatalf("got %d spans, want 2", len(spans))
	}
}

func TestFindEnclosingSpan_Narrowest(t *testing.T) {
	spans := []FunctionSpan{
		{Name: "outer", Kind: "function", StartLine: 1, EndLine: 50},
		{Name: "inner", Kind: "function", StartLine: 10, EndLine: 20},
	}
	name, kind := FindEnclosingSpan(spans, 15)
	if name != "inner" || kind != "function" {
		t.Errorf("got (%q, %q), want (inner, function)", name, kind)
	}
}

func TestFindEnclosingSpan_Outside(t *testing.T) {
	spans := []FunctionSpan{
		{Name: "handler", Kind: "function", StartLine: 10, EndLine: 20},
	}
	name, kind := FindEnclosingSpan(spans, 5)
	if name != "" || kind != "" {
		t.Errorf("got (%q, %q), want empty", name, kind)
	}
}

func TestBuildFunctionSpans_SkipsAnonymous(t *testing.T) {
	result := &ASTResult{
		Symbols: []ASTSymbol{
			{Name: "", Kind: "function", Line: 5, EndLine: 10},
			{Name: "named", Kind: "function", Line: 15, EndLine: 25},
		},
	}
	spans := BuildFunctionSpans(result)
	if len(spans) != 1 {
		t.Fatalf("got %d spans, want 1 (skip anonymous)", len(spans))
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /Users/sin-chengchen/products/verabase/code-verification-engine && go test ./internal/analyzers/jsts/ -run TestBuildFunctionSpans -v`
Expected: FAIL (undefined: BuildFunctionSpans)

- [ ] **Step 3: Implement FunctionSpan types and builder**

```go
// internal/analyzers/jsts/spans.go
package jsts

// FunctionSpan represents a named function/method scope for caller enrichment.
type FunctionSpan struct {
	Name      string
	Kind      string // "function" or "method"
	StartLine int
	EndLine   int
}

// BuildFunctionSpans extracts function/method spans from ASTResult symbols.
// Class spans are excluded (too broad). Anonymous functions (empty name) are skipped.
func BuildFunctionSpans(result *ASTResult) []FunctionSpan {
	var spans []FunctionSpan
	for _, sym := range result.Symbols {
		if sym.Name == "" {
			continue
		}
		if sym.Kind != "function" && sym.Kind != "method" {
			continue
		}
		if sym.EndLine <= sym.Line {
			continue
		}
		spans = append(spans, FunctionSpan{
			Name:      sym.Name,
			Kind:      sym.Kind,
			StartLine: sym.Line,
			EndLine:   sym.EndLine,
		})
	}
	return spans
}

// FindEnclosingSpan returns the narrowest function span containing the given line.
// Returns ("", "") if no span contains the line.
func FindEnclosingSpan(spans []FunctionSpan, line int) (name, kind string) {
	bestSize := int(^uint(0) >> 1) // max int
	for _, s := range spans {
		if line >= s.StartLine && line <= s.EndLine {
			size := s.EndLine - s.StartLine
			if size < bestSize {
				bestSize = size
				name = s.Name
				kind = s.Kind
			}
		}
	}
	return name, kind
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /Users/sin-chengchen/products/verabase/code-verification-engine && go test ./internal/analyzers/jsts/ -run TestBuildFunctionSpans -v && go test ./internal/analyzers/jsts/ -run TestFindEnclosingSpan -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/analyzers/jsts/spans.go internal/analyzers/jsts/spans_test.go
git commit -m "feat(jsts): add FunctionSpan builder for caller enrichment"
```

---

### Task 2: JS/TS DataAccessFact CallerName Enrichment

Enrich regex-detected DataAccessFact with CallerName/CallerKind from AST function spans, and ImportsDirect from import analysis.

**Files:**
- Modify: `internal/analyzers/js/analyzer.go`
- Modify: `internal/analyzers/ts/analyzer.go`
- Modify: `internal/analyzers/js/analyzer_test.go`

- [ ] **Step 1: Write failing test for JS CallerName enrichment**

Add test in `internal/analyzers/js/analyzer_test.go`:

```go
func TestDataAccessCallerEnrichment(t *testing.T) {
	dir := t.TempDir()
	// JS file with a handler function containing DB access
	src := `const { Sequelize } = require('sequelize');

function getUsers(req, res) {
  const users = Sequelize.findAll();
  res.json(users);
}

function helperNoDb() {
  console.log("no db here");
}
`
	writeFile(t, dir, "controller.js", src)
	analyzer := js.New()
	result, err := analyzer.Analyze(dir, []string{"controller.js"})
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, da := range result.DataAccess {
		if da.Operation != "" {
			found = true
			if da.CallerName != "getUsers" {
				t.Errorf("CallerName: got %q, want %q", da.CallerName, "getUsers")
			}
			if da.CallerKind != "function" {
				t.Errorf("CallerKind: got %q, want %q", da.CallerKind, "function")
			}
			if !da.ImportsDirect {
				t.Error("ImportsDirect: got false, want true (sequelize imported)")
			}
		}
	}
	if !found {
		t.Error("no DataAccessFact found")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/sin-chengchen/products/verabase/code-verification-engine && go test ./internal/analyzers/js/ -run TestDataAccessCallerEnrichment -v`
Expected: FAIL (CallerName is empty)

- [ ] **Step 3: Implement CallerName enrichment in JS analyzer**

In `internal/analyzers/js/analyzer.go`, after AST parsing and before/during DataAccessFact creation in the regex fallback section:

1. After `jsts.Parse()` and `jsts.ConvertToFacts()`, build function spans: `spans := jsts.BuildFunctionSpans(astResult)`
2. Build a set of known DB package import paths from the file's imports
3. After each regex-detected DataAccessFact is created, enrich it:
   - `callerName, callerKind := jsts.FindEnclosingSpan(spans, lineNumber)`
   - Set `da.CallerName = callerName`, `da.CallerKind = callerKind`
   - Check if any import matches the known JS DB packages list; if so, set `da.ImportsDirect = true`

Known JS/TS DB packages: `sequelize`, `typeorm`, `prisma`, `@prisma/client`, `mongoose`, `mongodb`, `knex`, `pg`, `mysql`, `mysql2`, `better-sqlite3`, `drizzle-orm`, `mikro-orm`

- [ ] **Step 4: Apply same enrichment to TS analyzer**

The TS analyzer in `internal/analyzers/ts/analyzer.go` has the same structure. Apply the identical enrichment logic.

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd /Users/sin-chengchen/products/verabase/code-verification-engine && go test ./internal/analyzers/js/ -run TestDataAccessCallerEnrichment -v`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add internal/analyzers/js/analyzer.go internal/analyzers/ts/analyzer.go internal/analyzers/js/analyzer_test.go
git commit -m "feat(js/ts): enrich DataAccessFact with CallerName and ImportsDirect"
```

---

### Task 3: JS/TS Route-to-Middleware Binding — Parser Extension

Extend the JSTS parser to extract `app.use()` / `router.use()` calls as new AST constructs.

**Files:**
- Modify: `internal/analyzers/jsts/parser.go`
- Create: `internal/analyzers/jsts/binding.go`
- Create: `internal/analyzers/jsts/binding_test.go`

- [ ] **Step 1: Add UseCall struct to ASTResult**

In `internal/analyzers/jsts/parser.go`, add:

```go
// ASTUseCall represents app.use() or router.use() middleware registration.
type ASTUseCall struct {
	Receiver    string   // "app", "router", variable name
	Path        string   // mount path if present (e.g., "/api")
	Middlewares []string // middleware names passed as arguments
	Line        int
}
```

Add `UseCalls []ASTUseCall` field to the `ASTResult` struct.

- [ ] **Step 2: Write failing tests for binding resolution**

```go
// internal/analyzers/jsts/binding_test.go
package jsts

import "testing"

func TestResolveBindings_GlobalUse(t *testing.T) {
	ast := &ASTResult{
		UseCalls: []ASTUseCall{
			{Receiver: "app", Middlewares: []string{"authMiddleware"}, Line: 5},
		},
		Routes: []ASTRoute{
			{Method: "GET", Path: "/users", Handler: "getUsers", Line: 10},
		},
	}
	routes := ResolveRouteBindings(ast)
	if len(routes) != 1 {
		t.Fatalf("got %d routes, want 1", len(routes))
	}
	if routes[0].Middlewares == nil {
		t.Fatal("Middlewares is nil, want non-nil")
	}
	if len(routes[0].Middlewares) != 1 || routes[0].Middlewares[0] != "authMiddleware" {
		t.Errorf("Middlewares: got %v, want [authMiddleware]", routes[0].Middlewares)
	}
}

func TestResolveBindings_OrderDependent(t *testing.T) {
	ast := &ASTResult{
		UseCalls: []ASTUseCall{
			{Receiver: "app", Middlewares: []string{"authMiddleware"}, Line: 15},
		},
		Routes: []ASTRoute{
			{Method: "GET", Path: "/before", Handler: "h1", Line: 5},
			{Method: "GET", Path: "/after", Handler: "h2", Line: 20},
		},
	}
	routes := ResolveRouteBindings(ast)
	// Route before use() should NOT inherit
	for _, r := range routes {
		if r.Path == "/before" && len(r.Middlewares) > 0 {
			t.Errorf("/before should not inherit authMiddleware, got %v", r.Middlewares)
		}
		if r.Path == "/after" {
			if len(r.Middlewares) != 1 || r.Middlewares[0] != "authMiddleware" {
				t.Errorf("/after should inherit authMiddleware, got %v", r.Middlewares)
			}
		}
	}
}

func TestResolveBindings_InlineMiddleware(t *testing.T) {
	ast := &ASTResult{
		Routes: []ASTRoute{
			{Method: "GET", Path: "/users", Handler: "getUsers", Middlewares: []string{"inlineAuth"}, Line: 10},
		},
	}
	routes := ResolveRouteBindings(ast)
	if len(routes[0].Middlewares) != 1 || routes[0].Middlewares[0] != "inlineAuth" {
		t.Errorf("got %v, want [inlineAuth]", routes[0].Middlewares)
	}
}

func TestResolveBindings_NoMiddleware(t *testing.T) {
	ast := &ASTResult{
		Routes: []ASTRoute{
			{Method: "GET", Path: "/users", Handler: "getUsers", Line: 10},
		},
	}
	routes := ResolveRouteBindings(ast)
	if routes[0].Middlewares == nil {
		t.Error("Middlewares should be empty slice, not nil")
	}
	if len(routes[0].Middlewares) != 0 {
		t.Errorf("Middlewares should be empty, got %v", routes[0].Middlewares)
	}
}

func TestResolveBindings_NestJSGuards(t *testing.T) {
	ast := &ASTResult{
		Routes: []ASTRoute{
			{Method: "GET", Path: "/users", Handler: "getUsers", Guards: []string{"AuthGuard"}, Line: 10},
		},
	}
	routes := ResolveRouteBindings(ast)
	if len(routes[0].Middlewares) != 1 || routes[0].Middlewares[0] != "AuthGuard" {
		t.Errorf("got %v, want [AuthGuard]", routes[0].Middlewares)
	}
}

func TestResolveBindings_MergedGlobalAndInline(t *testing.T) {
	ast := &ASTResult{
		UseCalls: []ASTUseCall{
			{Receiver: "app", Middlewares: []string{"globalAuth"}, Line: 1},
		},
		Routes: []ASTRoute{
			{Method: "GET", Path: "/users", Handler: "getUsers", Middlewares: []string{"inlineValidator"}, Line: 10},
		},
	}
	routes := ResolveRouteBindings(ast)
	if len(routes[0].Middlewares) != 2 {
		t.Fatalf("got %d middlewares, want 2", len(routes[0].Middlewares))
	}
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cd /Users/sin-chengchen/products/verabase/code-verification-engine && go test ./internal/analyzers/jsts/ -run TestResolveBindings -v`
Expected: FAIL (undefined: ResolveRouteBindings)

- [ ] **Step 4: Implement ResolveRouteBindings**

```go
// internal/analyzers/jsts/binding.go
package jsts

// ResolveRouteBindings resolves middleware bindings for routes within a single file.
// It projects global app.use() middleware into routes declared after them (by line number),
// merges inline route middleware and NestJS guards, and deduplicates.
func ResolveRouteBindings(ast *ASTResult) []ASTRoute {
	if len(ast.Routes) == 0 {
		return ast.Routes
	}

	// Collect global and scoped use() calls, sorted by line
	type useEntry struct {
		receiver    string
		middlewares []string
		line        int
	}
	var globalUses []useEntry
	scopedUses := map[string][]useEntry{} // receiver -> uses
	for _, u := range ast.UseCalls {
		if u.Receiver == "app" {
			globalUses = append(globalUses, useEntry{u.Receiver, u.Middlewares, u.Line})
		} else {
			scopedUses[u.Receiver] = append(scopedUses[u.Receiver], useEntry{u.Receiver, u.Middlewares, u.Line})
		}
	}

	resolved := make([]ASTRoute, len(ast.Routes))
	for i, route := range ast.Routes {
		resolved[i] = route

		var mws []string

		// Add global middleware declared before this route
		for _, u := range globalUses {
			if u.line < route.Line {
				mws = append(mws, u.middlewares...)
			}
		}

		// Add inline route middleware (already in route.Middlewares from parser)
		mws = append(mws, route.Middlewares...)

		// Add NestJS guards
		mws = append(mws, route.Guards...)

		// Deduplicate
		resolved[i].Middlewares = dedup(mws)
		// Ensure non-nil (empty slice means explicitly no middleware if nothing found)
		if resolved[i].Middlewares == nil {
			resolved[i].Middlewares = []string{}
		}
	}

	return resolved
}

func dedup(ss []string) []string {
	seen := make(map[string]bool, len(ss))
	var result []string
	for _, s := range ss {
		if !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}
	return result
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd /Users/sin-chengchen/products/verabase/code-verification-engine && go test ./internal/analyzers/jsts/ -run TestResolveBindings -v`
Expected: PASS

- [ ] **Step 6: Extend parser to extract UseCall AST constructs**

In `internal/analyzers/jsts/parser.go`:
- Add parsing for `app.use(...)` and `router.use(...)` patterns
- When parser encounters `IDENT.use(...)`, create `ASTUseCall` with receiver name, extract middleware argument names and optional path prefix

- [ ] **Step 7: Wire binding resolution into bridge.go**

In `internal/analyzers/jsts/bridge.go`:
- Before converting routes to facts, call `ResolveRouteBindings(result)` to get resolved routes
- Use resolved routes instead of raw `result.Routes` for fact conversion

- [ ] **Step 8: Run full JSTS test suite**

Run: `cd /Users/sin-chengchen/products/verabase/code-verification-engine && go test ./internal/analyzers/jsts/ -v`
Expected: PASS

- [ ] **Step 9: Commit**

```bash
git add internal/analyzers/jsts/parser.go internal/analyzers/jsts/binding.go internal/analyzers/jsts/binding_test.go internal/analyzers/jsts/bridge.go
git commit -m "feat(jsts): extract app.use() calls and resolve route-to-middleware bindings"
```

---

### Task 4: Python Route Binding Enrichment

Improve Python analyzer to project global middleware into route Middlewares and ensure CallerName enrichment for DataAccessFact.

**Files:**
- Modify: `internal/analyzers/python/ast_extract.py`
- Modify: `internal/analyzers/python/analyzer.go`
- Modify: `internal/analyzers/python/analyzer_test.go`

- [ ] **Step 1: Write failing test for Python route binding**

Add to `internal/analyzers/python/analyzer_test.go`:

```go
func TestPythonRouteBindingFastAPI(t *testing.T) {
	if !PythonASTAvailable() {
		t.Skip("python3 not available")
	}
	dir := t.TempDir()
	src := `from fastapi import FastAPI, Depends
from fastapi.security import OAuth2PasswordBearer

app = FastAPI()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def get_current_user(token: str = Depends(oauth2_scheme)):
    return {"user": "test"}

@app.get("/users")
def list_users(user = Depends(get_current_user)):
    return []

@app.get("/public")
def health():
    return {"status": "ok"}
`
	writeFile(t, dir, "main.py", src)
	analyzer := New()
	result, err := analyzer.Analyze(dir, []string{"main.py"})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range result.Routes {
		if r.Path == "/users" {
			if r.Middlewares == nil || len(r.Middlewares) == 0 {
				t.Error("/users route should have middleware from Depends(get_current_user)")
			}
		}
		if r.Path == "/public" {
			if r.Middlewares == nil {
				t.Error("/public route Middlewares should be empty slice, not nil")
			}
		}
	}
}
```

- [ ] **Step 2: Write failing test for Python DataAccess CallerName**

```go
func TestPythonDataAccessCallerName(t *testing.T) {
	if !PythonASTAvailable() {
		t.Skip("python3 not available")
	}
	dir := t.TempDir()
	src := `from sqlalchemy.orm import Session

def get_users(db: Session):
    return db.query(User).all()
`
	writeFile(t, dir, "service.py", src)
	analyzer := New()
	result, err := analyzer.Analyze(dir, []string{"service.py"})
	if err != nil {
		t.Fatal(err)
	}
	for _, da := range result.DataAccess {
		if da.CallerName != "get_users" {
			t.Errorf("CallerName: got %q, want %q", da.CallerName, "get_users")
		}
		if !da.ImportsDirect {
			t.Error("ImportsDirect: got false, want true")
		}
	}
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cd /Users/sin-chengchen/products/verabase/code-verification-engine && go test ./internal/analyzers/python/ -run TestPythonRouteBinding -v && go test ./internal/analyzers/python/ -run TestPythonDataAccessCallerName -v`
Expected: FAIL

- [ ] **Step 4: Improve ast_extract.py for route dependencies**

Ensure `_extract_routes_and_middleware` properly extracts `Depends()` arguments from:
- Path operation function parameter defaults: `def handler(user = Depends(get_current_user))`
- Route decorator keyword arguments

Ensure `_extract_data_access` properly sets `caller` and `caller_kind` for all detected DB operations.

- [ ] **Step 5: Improve Python analyzer.go for middleware projection**

In `convertASTResult()`:
1. Collect global middleware from `add_middleware()` calls and `before_request` decorators
2. For each route, merge global middleware + route-specific dependencies into `Middlewares`
3. Routes without any middleware get `Middlewares=[]string{}` (explicit empty)
4. Ensure CallerName and ImportsDirect are set on all DataAccessFact entries

- [ ] **Step 6: Add regex fallback CallerName enrichment**

In `analyzeFileRegex()`:
- Build function spans by scanning for `def ` and `async def ` lines
- After DataAccessFact detection, enrich with CallerName from enclosing def span
- Set ImportsDirect based on file-level DB package imports

- [ ] **Step 7: Run tests to verify they pass**

Run: `cd /Users/sin-chengchen/products/verabase/code-verification-engine && go test ./internal/analyzers/python/ -v`
Expected: PASS

- [ ] **Step 8: Commit**

```bash
git add internal/analyzers/python/ast_extract.py internal/analyzers/python/analyzer.go internal/analyzers/python/analyzer_test.go
git commit -m "feat(python): enrich routes with middleware binding and DataAccess with CallerName"
```

---

## Phase 2: Matcher Tightening

### Task 5: Auth Evidence Scoring Helper

Create the shared auth classification helper used by exists and relationship matchers.

**Files:**
- Create: `internal/rules/auth_evidence.go`
- Create: `internal/rules/auth_evidence_test.go`

- [ ] **Step 1: Write failing tests for auth classification**

```go
// internal/rules/auth_evidence_test.go
package rules

import "testing"

func TestClassifyAuth_Strong(t *testing.T) {
	// Binding + import = 5 -> strong
	ev := AuthEvidence{
		HasMiddlewareBinding: true,
		HasAuthImport:        true,
		HasAuthName:          true,
		MiddlewareName:       "jwtAuth",
	}
	if got := ClassifyAuth(ev); got != AuthStrong {
		t.Errorf("got %v, want AuthStrong", got)
	}
}

func TestClassifyAuth_StrongMinimal(t *testing.T) {
	// Binding(3) + import(2) = 5 -> strong
	ev := AuthEvidence{
		HasMiddlewareBinding: true,
		HasAuthImport:        true,
		MiddlewareName:       "customMiddleware",
	}
	if got := ClassifyAuth(ev); got != AuthStrong {
		t.Errorf("got %v, want AuthStrong", got)
	}
}

func TestClassifyAuth_WeakBindingNoImport(t *testing.T) {
	// Binding(3) + name(1) = 4 -> weak (no import)
	ev := AuthEvidence{
		HasMiddlewareBinding: true,
		HasAuthName:          true,
		MiddlewareName:       "authMiddleware",
	}
	if got := ClassifyAuth(ev); got != AuthWeak {
		t.Errorf("got %v, want AuthWeak", got)
	}
}

func TestClassifyAuth_WeakNameOnly(t *testing.T) {
	// Name(1) = 1 -> weak
	ev := AuthEvidence{
		HasAuthName:    true,
		MiddlewareName: "authCheck",
	}
	if got := ClassifyAuth(ev); got != AuthWeak {
		t.Errorf("got %v, want AuthWeak", got)
	}
}

func TestClassifyAuth_NotDetected_Contradictory(t *testing.T) {
	ev := AuthEvidence{
		HasMiddlewareBinding: true,
		HasContradictoryName: true,
		MiddlewareName:       "corsMiddleware",
	}
	if got := ClassifyAuth(ev); got != AuthNotDetected {
		t.Errorf("got %v, want AuthNotDetected", got)
	}
}

func TestClassifyAuth_NotDetected_NoSignals(t *testing.T) {
	ev := AuthEvidence{MiddlewareName: "unknownThing"}
	if got := ClassifyAuth(ev); got != AuthNotDetected {
		t.Errorf("got %v, want AuthNotDetected", got)
	}
}

func TestClassifyAuth_CompoundName_AuthOverrides(t *testing.T) {
	// "session_auth" has both contradictory (session) and auth tokens -> auth wins
	ev := AuthEvidence{
		HasMiddlewareBinding: true,
		HasAuthName:          true,
		HasContradictoryName: false, // should be false because auth overrides
		MiddlewareName:       "session_auth",
	}
	if got := ClassifyAuth(ev); got != AuthWeak {
		t.Errorf("got %v, want AuthWeak (auth overrides session)", got)
	}
}

func TestClassifyMiddlewareName(t *testing.T) {
	tests := []struct {
		name        string
		wantAuth    bool
		wantContra  bool
	}{
		{"jwtMiddleware", true, false},
		{"authGuard", true, false},
		{"corsHandler", false, true},
		{"helmetMiddleware", false, true},
		{"rateLimiter", false, true},
		{"sessionAuth", true, false},  // auth overrides session
		{"customThing", false, false},
		{"loginRequired", true, false},
		{"bodyParser", false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			auth, contra := ClassifyMiddlewareName(tt.name)
			if auth != tt.wantAuth {
				t.Errorf("auth: got %v, want %v", auth, tt.wantAuth)
			}
			if contra != tt.wantContra {
				t.Errorf("contra: got %v, want %v", contra, tt.wantContra)
			}
		})
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /Users/sin-chengchen/products/verabase/code-verification-engine && go test ./internal/rules/ -run TestClassifyAuth -v && go test ./internal/rules/ -run TestClassifyMiddlewareName -v`
Expected: FAIL (undefined)

- [ ] **Step 3: Implement auth evidence scoring**

```go
// internal/rules/auth_evidence.go
package rules

// AuthClassification represents the confidence level of auth evidence.
type AuthClassification int

const (
	AuthNotDetected AuthClassification = iota
	AuthWeak
	AuthStrong
)

// AuthEvidence holds signals for auth classification of a middleware/guard.
type AuthEvidence struct {
	HasMiddlewareBinding bool
	HasAuthImport        bool
	HasAuthName          bool
	HasContradictoryName bool
	MiddlewareName       string
}

var authTokens = map[string]bool{
	"auth": true, "jwt": true, "guard": true, "verify": true,
	"authenticate": true, "passport": true, "require": true,
	"login": true, "protect": true,
}

var contradictoryTokens = map[string]bool{
	"cors": true, "helmet": true, "log": true, "logger": true,
	"logging": true, "rate": true, "limit": true, "throttle": true,
	"metrics": true, "error": true, "compress": true, "compression": true,
	"static": true, "body": true, "parse": true, "json": true,
	"cookie": true, "csrf": true, "csp": true,
}

// "session" is contradictory ONLY if no auth token is present (handled in ClassifyMiddlewareName)
var sessionToken = "session"

// ClassifyMiddlewareName determines if a middleware name has auth tokens,
// contradictory tokens, or both. Auth tokens override contradictory when both present.
func ClassifyMiddlewareName(name string) (hasAuth, hasContradictory bool) {
	tokens := Tokenize(name)
	for _, tok := range tokens {
		if authTokens[tok] {
			hasAuth = true
		}
		if contradictoryTokens[tok] || tok == sessionToken {
			hasContradictory = true
		}
	}
	// Auth overrides contradictory
	if hasAuth {
		hasContradictory = false
	}
	return
}

// ClassifyAuth determines the auth classification of a middleware based on evidence signals.
func ClassifyAuth(ev AuthEvidence) AuthClassification {
	if ev.HasContradictoryName {
		return AuthNotDetected
	}

	score := 0
	if ev.HasMiddlewareBinding {
		score += 3
	}
	if ev.HasAuthImport {
		score += 2
	}
	if ev.HasAuthName {
		score += 1
	}

	if score >= 5 {
		return AuthStrong
	}
	if score >= 1 {
		return AuthWeak
	}
	return AuthNotDetected
}

// Known auth packages per language (for import matching).
var KnownAuthPackages = map[string][]string{
	"go": {
		"github.com/golang-jwt/jwt",
		"github.com/dgrijalva/jwt-go",
		"github.com/lestrrat-go/jwx",
	},
	"javascript": {
		"jsonwebtoken", "passport", "passport-jwt", "express-jwt",
		"@nestjs/jwt", "@nestjs/passport", "jose",
		"@auth0/nextjs-auth0", "next-auth",
	},
	"typescript": {
		"jsonwebtoken", "passport", "passport-jwt", "express-jwt",
		"@nestjs/jwt", "@nestjs/passport", "jose",
		"@auth0/nextjs-auth0", "next-auth",
	},
	"python": {
		"pyjwt", "python-jose", "fastapi.security",
		"flask-jwt-extended", "flask-login", "django.contrib.auth",
	},
}

// HasKnownAuthImport checks if any import in the given list matches a known auth package.
func HasKnownAuthImport(language string, importPaths []string) bool {
	packages, ok := KnownAuthPackages[language]
	if !ok {
		return false
	}
	for _, imp := range importPaths {
		for _, pkg := range packages {
			if imp == pkg || strings.HasPrefix(imp, pkg+"/") || strings.HasPrefix(imp, pkg+".") {
				return true
			}
		}
	}
	return false
}
```

Note: add `"strings"` to imports.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /Users/sin-chengchen/products/verabase/code-verification-engine && go test ./internal/rules/ -run TestClassifyAuth -v && go test ./internal/rules/ -run TestClassifyMiddlewareName -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/rules/auth_evidence.go internal/rules/auth_evidence_test.go
git commit -m "feat(rules): add auth evidence scoring helper for middleware classification"
```

---

### Task 6: Tighten exists_matcher — findJWTMiddleware

Update `findJWTMiddleware` to use auth evidence scoring instead of pure name matching.

**Files:**
- Modify: `internal/rules/exists_matcher.go`
- Modify: `internal/rules/exists_matcher_test.go` (if exists) or add tests

- [ ] **Step 1: Write failing test for improved JWT detection**

```go
func TestFindJWTMiddleware_StrongEvidence(t *testing.T) {
	fs := NewFactSet()
	fs.AddMiddleware(facts.MiddlewareFact{
		Language: facts.LangJavaScript,
		File:     "app.js",
		Name:     "authMiddleware",
	})
	fs.AddImport(facts.ImportFact{
		Language:   facts.LangJavaScript,
		File:       "app.js",
		ImportPath: "jsonwebtoken",
	})

	rule := Rule{Target: "auth.jwt_middleware"}
	evidence := findJWTMiddleware(rule, fs)
	if len(evidence) == 0 {
		t.Error("should find JWT middleware with auth name + JWT import")
	}
}

func TestFindJWTMiddleware_ContradictoryName(t *testing.T) {
	fs := NewFactSet()
	fs.AddMiddleware(facts.MiddlewareFact{
		Language: facts.LangJavaScript,
		File:     "app.js",
		Name:     "corsMiddleware",
	})
	fs.AddImport(facts.ImportFact{
		Language:   facts.LangJavaScript,
		File:       "app.js",
		ImportPath: "cors",
	})

	rule := Rule{Target: "auth.jwt_middleware"}
	evidence := findJWTMiddleware(rule, fs)
	if len(evidence) > 0 {
		t.Error("should NOT find JWT middleware for CORS middleware")
	}
}
```

- [ ] **Step 2: Run tests to verify current behavior**

Run: `cd /Users/sin-chengchen/products/verabase/code-verification-engine && go test ./internal/rules/ -run TestFindJWTMiddleware -v`

- [ ] **Step 3: Update findJWTMiddleware to use ClassifyAuth**

In `internal/rules/exists_matcher.go`, rewrite `findJWTMiddleware`:
1. For each MiddlewareFact, build AuthEvidence:
   - `HasAuthName, HasContradictoryName = ClassifyMiddlewareName(mw.Name)`
   - Collect import paths for the same file
   - `HasAuthImport = HasKnownAuthImport(languageString, filePaths)`
   - `HasMiddlewareBinding = false` (exists check, not route-bound)
2. Classify each middleware
3. Any AuthStrong → return evidence with `strong_inference`
4. Any AuthWeak → return evidence with `weak_inference`
5. None → fall through to imports+symbols fallback (also using ClassifyAuth)

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /Users/sin-chengchen/products/verabase/code-verification-engine && go test ./internal/rules/ -run TestFindJWTMiddleware -v`
Expected: PASS

- [ ] **Step 5: Run full rules test suite for regression**

Run: `cd /Users/sin-chengchen/products/verabase/code-verification-engine && go test ./internal/rules/ -v`
Expected: PASS (may need to update some existing tests if behavior changes)

- [ ] **Step 6: Commit**

```bash
git add internal/rules/exists_matcher.go internal/rules/exists_matcher_test.go
git commit -m "feat(rules): use auth evidence scoring in findJWTMiddleware"
```

---

### Task 7: Tighten relationship_matcher — matchProtectedRoutesUseAuth

Update `matchProtectedRoutesUseAuth` to use auth evidence scoring instead of name-token matching.

**Files:**
- Modify: `internal/rules/relationship_matcher.go`
- Modify: `internal/rules/relationship_matcher_test.go` (if exists) or add tests

- [ ] **Step 1: Write failing tests for improved route protection**

```go
func TestMatchProtectedRoutes_StrongAuth(t *testing.T) {
	fs := NewFactSet()
	fs.AddRoute(facts.RouteFact{
		Language:    facts.LangJavaScript,
		File:        "app.js",
		Method:      "GET",
		Path:        "/users",
		Handler:     "getUsers",
		Middlewares: []string{"authMiddleware"},
	})
	fs.AddImport(facts.ImportFact{
		Language:   facts.LangJavaScript,
		File:       "app.js",
		ImportPath: "jsonwebtoken",
	})

	rule := Rule{Target: "route.protected_uses_auth_middleware"}
	finding := matchProtectedRoutesUseAuth(rule, fs)
	if finding.Status != StatusPass {
		t.Errorf("status: got %v, want pass (strong auth: binding + import)", finding.Status)
	}
}

func TestMatchProtectedRoutes_WeakAuthOnly(t *testing.T) {
	fs := NewFactSet()
	fs.AddRoute(facts.RouteFact{
		Language:    facts.LangJavaScript,
		File:        "app.js",
		Method:      "GET",
		Path:        "/users",
		Handler:     "getUsers",
		Middlewares: []string{"authMiddleware"},
	})
	// No auth import

	rule := Rule{Target: "route.protected_uses_auth_middleware"}
	finding := matchProtectedRoutesUseAuth(rule, fs)
	// Weak auth only -> unknown (not enough for route protection)
	if finding.Status != StatusUnknown {
		t.Errorf("status: got %v, want unknown (weak auth only)", finding.Status)
	}
}

func TestMatchProtectedRoutes_ContradictoryMiddleware(t *testing.T) {
	fs := NewFactSet()
	fs.AddRoute(facts.RouteFact{
		Language:    facts.LangJavaScript,
		File:        "app.js",
		Method:      "GET",
		Path:        "/users",
		Handler:     "getUsers",
		Middlewares: []string{"corsMiddleware"},
	})

	rule := Rule{Target: "route.protected_uses_auth_middleware"}
	finding := matchProtectedRoutesUseAuth(rule, fs)
	if finding.Status != StatusFail {
		t.Errorf("status: got %v, want fail (CORS is not auth)", finding.Status)
	}
}
```

- [ ] **Step 2: Run tests to verify behavior before changes**

Run: `cd /Users/sin-chengchen/products/verabase/code-verification-engine && go test ./internal/rules/ -run TestMatchProtectedRoutes -v`

- [ ] **Step 3: Rewrite matchProtectedRoutesUseAuth to use ClassifyAuth**

Key changes:
1. For each route with `Middlewares != nil`, classify each middleware name:
   - Build `AuthEvidence` with `HasMiddlewareBinding=true`, check imports for auth packages, classify name
   - Route is protected if ANY middleware is `AuthStrong`
2. Aggregation per spec:
   - All routes AuthStrong → pass + strong_inference
   - All routes AuthWeak only → unknown
   - Any nil routes → unknown
   - Any explicitly unprotected → fail

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /Users/sin-chengchen/products/verabase/code-verification-engine && go test ./internal/rules/ -run TestMatchProtectedRoutes -v`
Expected: PASS

- [ ] **Step 5: Fix any regression in existing tests**

Run: `cd /Users/sin-chengchen/products/verabase/code-verification-engine && go test ./internal/rules/ -v`
Fix any failures from behavior changes.

- [ ] **Step 6: Commit**

```bash
git add internal/rules/relationship_matcher.go internal/rules/relationship_matcher_test.go
git commit -m "feat(rules): use auth evidence scoring in route protection matcher"
```

---

### Task 8: Tighten pattern_matcher — CallerName preference for DB access

Update `findDBAccessOutsideRepo` and related functions to prefer CallerName + ImportsDirect over file-path heuristics.

**Files:**
- Modify: `internal/rules/pattern_matcher.go`
- Modify: `internal/rules/pattern_matcher_test.go` (if exists)

- [ ] **Step 1: Write failing tests for CallerName-based detection**

```go
func TestFindDBAccess_CallerNameStrong(t *testing.T) {
	fs := NewFactSet()
	fs.AddRoute(facts.RouteFact{
		Language: facts.LangJavaScript,
		File:     "controller.js",
		Method:   "GET",
		Path:     "/users",
		Handler:  "getUsers",
	})
	fs.AddDataAccess(facts.DataAccessFact{
		Language:      facts.LangJavaScript,
		File:          "controller.js",
		Operation:     "findAll",
		Backend:       "sequelize",
		CallerName:    "getUsers",
		CallerKind:    "function",
		ImportsDirect: true,
	})

	rule := Rule{Target: "db.direct_access_from_controller"}
	evidence := findDBAccessOutsideRepo(rule, fs)
	if len(evidence) == 0 {
		t.Error("should flag direct DB access from route handler")
	}
}

func TestFindDBAccess_CallerNameDelegated(t *testing.T) {
	fs := NewFactSet()
	fs.AddRoute(facts.RouteFact{
		Language: facts.LangJavaScript,
		File:     "controller.js",
		Method:   "GET",
		Path:     "/users",
		Handler:  "getUsers",
	})
	fs.AddDataAccess(facts.DataAccessFact{
		Language:      facts.LangJavaScript,
		File:          "controller.js",
		Operation:     "findAll",
		Backend:       "sequelize",
		CallerName:    "getUsers",
		CallerKind:    "function",
		ImportsDirect: false, // delegated via service
	})

	rule := Rule{Target: "db.direct_access_from_controller"}
	evidence := findDBAccessOutsideRepo(rule, fs)
	if len(evidence) > 0 {
		t.Error("should NOT flag delegated DB access (ImportsDirect=false)")
	}
}

func TestFindDBAccess_NoCallerNameFallback(t *testing.T) {
	fs := NewFactSet()
	fs.AddDataAccess(facts.DataAccessFact{
		Language:  facts.LangJavaScript,
		File:      "controllers/user.js",
		Operation: "findAll",
		Backend:   "sequelize",
		// No CallerName -> file-path fallback
	})

	rule := Rule{Target: "db.direct_access_from_controller"}
	evidence := findDBAccessOutsideRepo(rule, fs)
	if len(evidence) == 0 {
		t.Error("should flag via file-path fallback when no CallerName")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /Users/sin-chengchen/products/verabase/code-verification-engine && go test ./internal/rules/ -run TestFindDBAccess -v`

- [ ] **Step 3: Update findDBAccessOutsideRepo**

Key changes:
1. Build route handler set: `map[fileHandler]bool` where `fileHandler = file + ":" + handler`
2. For each DataAccessFact:
   - If CallerName != "":
     - Check if `file:CallerName` matches any route handler (same-file matching)
     - If match + ImportsDirect → flag (strong_inference)
     - If match + !ImportsDirect → skip (delegated)
     - If no match → check file-path heuristic at weak_inference
   - If CallerName == "":
     - File-path fallback at weak_inference
3. Skip repo layer files and test files as before

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /Users/sin-chengchen/products/verabase/code-verification-engine && go test ./internal/rules/ -run TestFindDBAccess -v`
Expected: PASS

- [ ] **Step 5: Run full rules test suite**

Run: `cd /Users/sin-chengchen/products/verabase/code-verification-engine && go test ./internal/rules/ -v`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add internal/rules/pattern_matcher.go internal/rules/pattern_matcher_test.go
git commit -m "feat(rules): prefer CallerName+ImportsDirect over file-path heuristics in DB access matcher"
```

---

## Phase 3: Capability and Integration

### Task 9: Update Capability Notes

Update capability detail notes for improved frameworks.

**Files:**
- Modify: `internal/rules/capability.go`
- Modify: `internal/rules/capability_test.go`

- [ ] **Step 1: Read current capability.go**

Read `internal/rules/capability.go` to understand current CapabilityDetail entries for the target rules and frameworks.

- [ ] **Step 2: Update framework notes**

For JS/TS targets:
- `auth.jwt_middleware`: Add/update framework notes for Express/NestJS/Fastify: "binding+import scoring reduces false positives"
- `route.protected_uses_auth_middleware`: Notes: "same-file per-route binding extraction from use()/guards"
- `db.direct_access_from_controller`: Notes: "CallerName enrichment from AST function spans"

For Python targets:
- `auth.jwt_middleware`: FastAPI/Flask notes for dependency/decorator binding
- `route.protected_uses_auth_middleware`: FastAPI: "Depends propagation"; Flask: "decorator+before_request"
- `db.direct_access_from_controller`: Notes: "CallerName from AST/regex function spans"

Base levels remain `PartiallySup`. No trusted-core changes.

- [ ] **Step 3: Update capability tests**

Ensure capability tests validate the updated notes and unchanged levels.

- [ ] **Step 4: Run capability tests**

Run: `cd /Users/sin-chengchen/products/verabase/code-verification-engine && go test ./internal/rules/ -run TestCapability -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/rules/capability.go internal/rules/capability_test.go
git commit -m "feat(rules): update capability notes for improved framework precision"
```

---

### Task 10: Integration Tests and Full Verification

Add integration tests and run full test suite.

**Files:**
- Modify: various test files as needed

- [ ] **Step 1: Add integration test for JS/TS precision improvement**

Add a test that exercises the full analyzer → matcher path for a JS Express app with auth middleware:

```go
// In appropriate test file
func TestJSExpressAuthIntegration(t *testing.T) {
	dir := t.TempDir()
	src := `const express = require('express');
const jwt = require('jsonwebtoken');

const app = express();

function authMiddleware(req, res, next) {
  const token = req.headers.authorization;
  jwt.verify(token, 'secret', (err, decoded) => {
    if (err) return res.status(401).send('Unauthorized');
    req.user = decoded;
    next();
  });
}

app.use(authMiddleware);

app.get('/users', (req, res) => {
  res.json([]);
});

app.get('/health', (req, res) => {
  res.json({ status: 'ok' });
});
`
	writeFile(t, dir, "app.js", src)
	// Run JS analyzer
	analyzer := js.New()
	result, err := analyzer.Analyze(dir, []string{"app.js"})
	if err != nil {
		t.Fatal(err)
	}

	// Verify route binding enrichment
	for _, r := range result.Routes {
		if r.Middlewares == nil {
			t.Errorf("route %s Middlewares should not be nil", r.Path)
		}
		if r.Path == "/users" || r.Path == "/health" {
			if len(r.Middlewares) == 0 {
				t.Errorf("route %s should have inherited authMiddleware", r.Path)
			}
		}
	}
}
```

- [ ] **Step 2: Run integration tests**

Run: `cd /Users/sin-chengchen/products/verabase/code-verification-engine && go test ./internal/analyzers/js/ -run TestJSExpressAuthIntegration -v`
Expected: PASS

- [ ] **Step 3: Run full test suite**

Run: `cd /Users/sin-chengchen/products/verabase/code-verification-engine && go test ./... 2>&1 | tail -50`
Expected: All packages PASS

- [ ] **Step 4: Fix any regressions**

If any existing tests fail due to behavior changes, update them to reflect the new (correct) behavior. Document why.

- [ ] **Step 5: Final commit**

```bash
git add -A
git commit -m "feat: precision upgrade - integration tests and regression fixes"
```

---

## Verification Checklist

Before claiming completion:

- [ ] `go test ./...` passes with zero failures
- [ ] JS/TS DataAccessFact has CallerName/ImportsDirect enrichment
- [ ] JS/TS routes have middleware binding from app.use()/router.use()/guards
- [ ] Python routes have middleware binding from Depends/decorators/before_request
- [ ] Python DataAccessFact has CallerName enrichment
- [ ] Auth evidence scoring produces correct classification for strong/weak/not-detected
- [ ] findJWTMiddleware uses auth scoring instead of pure name matching
- [ ] matchProtectedRoutesUseAuth uses auth scoring with strict route-protection semantics
- [ ] findDBAccessOutsideRepo prefers CallerName+ImportsDirect over file-path heuristics
- [ ] Capability notes updated for improved frameworks
- [ ] No trusted-core changes
- [ ] No base capability level changes
- [ ] Go analyzer behavior unchanged (regression check)
