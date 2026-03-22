package python

// Task 4: Python Route Binding and CallerName Enrichment tests.
//
// Tests:
//  1. FastAPI route with Depends(get_current_user) → Middlewares includes dependency name
//  2. FastAPI route without dependencies → Middlewares = []string{} (not nil)
//  3. DataAccessFact inside a function → CallerName set (AST path)
//  4. DataAccessFact with sqlalchemy import → ImportsDirect = true (AST path)
//  5. Global middleware (add_middleware) projected into per-route Middlewares
//  6. Regex fallback: DataAccessFact inside a def → CallerName set
//  7. Regex fallback: sqlalchemy import → ImportsDirect = true

import (
	"testing"

	"github.com/verabase/code-verification-engine/internal/analyzers"
	"github.com/verabase/code-verification-engine/internal/typegraph"
)

// newTestResult creates an empty AnalysisResult suitable for unit tests.
func newTestResult() *analyzers.AnalysisResult {
	r := &analyzers.AnalysisResult{}
	r.TypeGraph = typegraph.New()
	return r
}

// TestFastAPIRouteWithDepends verifies that a FastAPI route using Depends()
// has the dependency name included in Middlewares.
func TestFastAPIRouteWithDepends(t *testing.T) {
	if !PythonASTAvailable() {
		t.Skip("python3 not available")
	}

	root, files := setupTempProject(t, map[string]string{
		"main.py": `from fastapi import FastAPI, Depends

app = FastAPI()

def get_current_user():
    pass

@app.get("/users")
async def list_users(user=Depends(get_current_user)):
    return []
`,
	})

	a := New()
	result, err := a.Analyze(root, files)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	found := false
	for _, rf := range result.Routes {
		if rf.Path == "/users" && rf.Method == "GET" {
			found = true
			hasDepends := false
			for _, mw := range rf.Middlewares {
				if mw == "get_current_user" {
					hasDepends = true
				}
			}
			if !hasDepends {
				t.Errorf("expected Middlewares to include 'get_current_user', got %v", rf.Middlewares)
			}
		}
	}
	if !found {
		t.Error("expected GET /users route")
	}
}

// TestFastAPIRouteWithoutDepsHasEmptyMiddlewares verifies that a route with no
// dependencies gets Middlewares = []string{} (not nil), so JSON serialises as [].
func TestFastAPIRouteWithoutDepsHasEmptyMiddlewares(t *testing.T) {
	if !PythonASTAvailable() {
		t.Skip("python3 not available")
	}

	root, files := setupTempProject(t, map[string]string{
		"main.py": `from fastapi import FastAPI

app = FastAPI()

@app.get("/health")
async def health():
    return {"status": "ok"}
`,
	})

	a := New()
	result, err := a.Analyze(root, files)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	found := false
	for _, rf := range result.Routes {
		if rf.Path == "/health" && rf.Method == "GET" {
			found = true
			if rf.Middlewares == nil {
				t.Error("expected Middlewares to be []string{} (not nil) for route without deps")
			}
		}
	}
	if !found {
		t.Error("expected GET /health route")
	}
}

// TestDataAccessCallerNameAST verifies that DataAccessFact inside a function
// has CallerName set (via AST path).
func TestDataAccessCallerNameAST(t *testing.T) {
	if !PythonASTAvailable() {
		t.Skip("python3 not available")
	}

	root, files := setupTempProject(t, map[string]string{
		"db.py": `from sqlalchemy.orm import Session

def get_user(db: Session, user_id: int):
    return db.query(Session).filter_by(id=user_id).first()
`,
	})

	a := New()
	result, err := a.Analyze(root, files)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	found := false
	for _, da := range result.DataAccess {
		if da.Backend == "sqlalchemy" {
			found = true
			if da.CallerName == "" {
				t.Errorf("expected CallerName to be set for DataAccessFact inside get_user, got empty")
			} else if da.CallerName != "get_user" {
				t.Errorf("expected CallerName = 'get_user', got %q", da.CallerName)
			}
		}
	}
	if !found {
		t.Error("expected at least one sqlalchemy DataAccessFact")
	}
}

// TestDataAccessImportsDirectAST verifies that DataAccessFact from a file with
// sqlalchemy import has ImportsDirect = true (via AST path).
func TestDataAccessImportsDirectAST(t *testing.T) {
	if !PythonASTAvailable() {
		t.Skip("python3 not available")
	}

	root, files := setupTempProject(t, map[string]string{
		"db.py": `from sqlalchemy.orm import Session

def get_user(db: Session, user_id: int):
    return db.query(Session).filter_by(id=user_id).first()
`,
	})

	a := New()
	result, err := a.Analyze(root, files)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	found := false
	for _, da := range result.DataAccess {
		if da.Backend == "sqlalchemy" {
			found = true
			if !da.ImportsDirect {
				t.Error("expected ImportsDirect = true for file that imports sqlalchemy")
			}
		}
	}
	if !found {
		t.Error("expected at least one sqlalchemy DataAccessFact")
	}
}

// TestGlobalMiddlewareProjectedIntoRoutes verifies that global add_middleware()
// calls are projected into each route's Middlewares list.
func TestGlobalMiddlewareProjectedIntoRoutes(t *testing.T) {
	if !PythonASTAvailable() {
		t.Skip("python3 not available")
	}

	root, files := setupTempProject(t, map[string]string{
		"main.py": `from fastapi import FastAPI
from starlette.middleware.cors import CORSMiddleware

app = FastAPI()
app.add_middleware(CORSMiddleware)

@app.get("/items")
async def list_items():
    return []
`,
	})

	a := New()
	result, err := a.Analyze(root, files)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	found := false
	for _, rf := range result.Routes {
		if rf.Path == "/items" && rf.Method == "GET" {
			found = true
			hasCORS := false
			for _, mw := range rf.Middlewares {
				if mw == "CORSMiddleware" {
					hasCORS = true
				}
			}
			if !hasCORS {
				t.Errorf("expected global CORSMiddleware to be projected into route Middlewares, got %v", rf.Middlewares)
			}
		}
	}
	if !found {
		t.Error("expected GET /items route")
	}
}

// TestRegexFallbackCallerNameEnrichment verifies the regex-fallback path sets
// CallerName on DataAccessFact when the data access is inside a def.
func TestRegexFallbackCallerNameEnrichment(t *testing.T) {
	a := New()
	lines := []string{
		"import sqlalchemy",
		"def fetch_data():",
		"    session = Session()",
	}
	fullSource := "import sqlalchemy\ndef fetch_data():\n    session = Session()\n"

	result := newTestResult()
	a.analyzeFileRegex("db.py", lines, fullSource, result)

	found := false
	for _, da := range result.DataAccess {
		if da.Backend == "sqlalchemy" {
			found = true
			if da.CallerName == "" {
				t.Errorf("expected CallerName to be set on regex-path DataAccessFact, got empty")
			} else if da.CallerName != "fetch_data" {
				t.Errorf("expected CallerName = 'fetch_data', got %q", da.CallerName)
			}
		}
	}
	if !found {
		t.Error("expected at least one sqlalchemy DataAccessFact via regex path")
	}
}

// TestFlaskBeforeRequestProjected verifies that @app.before_request is extracted
// as global middleware and projected into all routes.
func TestFlaskBeforeRequestProjected(t *testing.T) {
	if !PythonASTAvailable() {
		t.Skip("python3 not available")
	}

	root, files := setupTempProject(t, map[string]string{
		"app.py": `from flask import Flask

app = Flask(__name__)

@app.before_request
def check_auth():
    pass

@app.route("/users")
def list_users():
    return "users"

@app.route("/public")
def health():
    return "ok"
`,
	})

	a := New()
	result, err := a.Analyze(root, files)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	for _, rf := range result.Routes {
		hasCheckAuth := false
		for _, mw := range rf.Middlewares {
			if mw == "check_auth" {
				hasCheckAuth = true
			}
		}
		if !hasCheckAuth {
			t.Errorf("route %s should have check_auth from @app.before_request projected, got %v", rf.Path, rf.Middlewares)
		}
	}
}

// TestRegexFallbackImportsDirect verifies the regex-fallback path sets
// ImportsDirect = true when file imports a known DB package.
func TestRegexFallbackImportsDirect(t *testing.T) {
	a := New()
	lines := []string{
		"import sqlalchemy",
		"def fetch_data():",
		"    session = Session()",
	}
	fullSource := "import sqlalchemy\ndef fetch_data():\n    session = Session()\n"

	result := newTestResult()
	a.analyzeFileRegex("db.py", lines, fullSource, result)

	for _, da := range result.DataAccess {
		if da.Backend == "sqlalchemy" {
			if !da.ImportsDirect {
				t.Error("expected ImportsDirect = true on regex-path DataAccessFact for file importing sqlalchemy")
			}
		}
	}
}
