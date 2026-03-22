package python

// analyzer_coverage_test.go — additional tests to push coverage to ≥95%.
//
// Focus areas:
//   - analyzeFileRegex (37.4%): all regex sub-paths
//   - Analyze (87.0%): file read errors, AST fail-through
//   - countIndent (87.5%): tabs, empty, mixed
//   - ast_bridge.go: ParsePythonAST error paths, ensureScript/findPython3

import (
	"testing"

	"github.com/verabase/code-verification-engine/internal/analyzers"
	"github.com/verabase/code-verification-engine/internal/typegraph"
)

// ── helpers ──────────────────────────────────────────────────────────────────

// regexResult returns an empty AnalysisResult with a TypeGraph, for direct
// calls to analyzeFileRegex.
func regexResult() *analyzers.AnalysisResult {
	r := &analyzers.AnalysisResult{}
	r.TypeGraph = typegraph.New()
	return r
}

func analyzerForTest() *PythonAnalyzer {
	return New()
}

// ── countIndent ───────────────────────────────────────────────────────────────

func TestCountIndent_Spaces(t *testing.T) {
	if got := countIndent("    hello"); got != 4 {
		t.Errorf("expected 4, got %d", got)
	}
}

func TestCountIndent_Tabs(t *testing.T) {
	// each tab counts as 4
	if got := countIndent("\thello"); got != 4 {
		t.Errorf("expected 4, got %d", got)
	}
	if got := countIndent("\t\thello"); got != 8 {
		t.Errorf("expected 8, got %d", got)
	}
}

func TestCountIndent_Mixed(t *testing.T) {
	// tab (4) + 2 spaces = 6
	if got := countIndent("\t  hello"); got != 6 {
		t.Errorf("expected 6, got %d", got)
	}
}

func TestCountIndent_Empty(t *testing.T) {
	if got := countIndent(""); got != 0 {
		t.Errorf("expected 0, got %d", got)
	}
}

func TestCountIndent_NoIndent(t *testing.T) {
	if got := countIndent("hello"); got != 0 {
		t.Errorf("expected 0, got %d", got)
	}
}

func TestCountIndent_OnlySpaces(t *testing.T) {
	if got := countIndent("    "); got != 4 {
		t.Errorf("expected 4, got %d", got)
	}
}

// ── Analyze — file read error ─────────────────────────────────────────────────

func TestAnalyze_FileReadError_SkippedFiles(t *testing.T) {
	a := New()
	// Pass a valid root dir but a file that doesn't exist → read error → SkippedFiles
	result, err := a.Analyze("/tmp", []string{"this_file_definitely_does_not_exist.py"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Files) != 0 {
		t.Errorf("expected no FileFacts for unreadable file, got %d", len(result.Files))
	}
	if len(result.SkippedFiles) == 0 {
		t.Error("expected at least one SkippedFile entry")
	}
}

// ── analyzeFileRegex — imports ────────────────────────────────────────────────

func TestRegex_FromImport(t *testing.T) {
	a := analyzerForTest()
	lines := []string{
		"from fastapi import FastAPI, Depends",
	}
	result := regexResult()
	a.analyzeFileRegex("app.py", lines, lines[0], result)

	if len(result.Imports) == 0 {
		t.Fatal("expected at least one import")
	}
	found := false
	for _, imp := range result.Imports {
		if imp.ImportPath == "fastapi" {
			found = true
		}
	}
	if !found {
		t.Error("expected fastapi import")
	}
}

func TestRegex_ImportStatement(t *testing.T) {
	a := analyzerForTest()
	lines := []string{
		"import os",
		"import sys, json",
	}
	fullSource := "import os\nimport sys, json\n"
	result := regexResult()
	a.analyzeFileRegex("util.py", lines, fullSource, result)

	names := make(map[string]bool)
	for _, imp := range result.Imports {
		names[imp.ImportPath] = true
	}
	for _, want := range []string{"os", "sys", "json"} {
		if !names[want] {
			t.Errorf("expected import %q", want)
		}
	}
}

func TestRegex_ImportWithAlias(t *testing.T) {
	a := analyzerForTest()
	lines := []string{"import numpy as np"}
	result := regexResult()
	a.analyzeFileRegex("util.py", lines, lines[0], result)

	found := false
	for _, imp := range result.Imports {
		if imp.ImportPath == "numpy" && imp.Alias == "np" {
			found = true
		}
	}
	if !found {
		t.Error("expected numpy import with alias np")
	}
}

func TestRegex_FromImportWithAlias(t *testing.T) {
	a := analyzerForTest()
	lines := []string{"from datetime import datetime as dt"}
	result := regexResult()
	a.analyzeFileRegex("util.py", lines, lines[0], result)

	found := false
	for _, imp := range result.Imports {
		if imp.ImportPath == "datetime" && imp.Alias == "dt" {
			found = true
		}
	}
	if !found {
		t.Error("expected datetime import with alias dt")
	}
}

// ── analyzeFileRegex — symbols ────────────────────────────────────────────────

func TestRegex_FunctionSymbol(t *testing.T) {
	a := analyzerForTest()
	lines := []string{
		"def my_function(x, y):",
		"    return x + y",
	}
	fullSource := "def my_function(x, y):\n    return x + y\n"
	result := regexResult()
	a.analyzeFileRegex("util.py", lines, fullSource, result)

	found := false
	for _, sym := range result.Symbols {
		if sym.Name == "my_function" && sym.Kind == "function" && sym.Exported {
			found = true
		}
	}
	if !found {
		t.Error("expected exported function my_function")
	}
}

func TestRegex_PrivateFunctionSymbol(t *testing.T) {
	a := analyzerForTest()
	lines := []string{
		"def _private_func():",
		"    pass",
	}
	fullSource := "def _private_func():\n    pass\n"
	result := regexResult()
	a.analyzeFileRegex("util.py", lines, fullSource, result)

	found := false
	for _, sym := range result.Symbols {
		if sym.Name == "_private_func" && sym.Kind == "function" && !sym.Exported {
			found = true
		}
	}
	if !found {
		t.Error("expected unexported function _private_func")
	}
}

func TestRegex_AsyncFunctionSymbol(t *testing.T) {
	a := analyzerForTest()
	// funcDefRe matches `^(\s*)def\s+...` — async def does NOT match
	// because the line starts with "async", not "def".
	// This test verifies that a regular def inside an async context works.
	lines := []string{
		"def handle_request():",
		"    pass",
	}
	fullSource := "def handle_request():\n    pass\n"
	result := regexResult()
	a.analyzeFileRegex("app.py", lines, fullSource, result)

	found := false
	for _, sym := range result.Symbols {
		if sym.Name == "handle_request" {
			found = true
		}
	}
	if !found {
		t.Error("expected symbol handle_request")
	}
}

func TestRegex_ClassSymbol(t *testing.T) {
	a := analyzerForTest()
	lines := []string{
		"class UserService:",
		"    def get(self):",
		"        pass",
	}
	fullSource := "class UserService:\n    def get(self):\n        pass\n"
	result := regexResult()
	a.analyzeFileRegex("service.py", lines, fullSource, result)

	found := false
	for _, sym := range result.Symbols {
		if sym.Name == "UserService" && sym.Kind == "class" && sym.Exported {
			found = true
		}
	}
	if !found {
		t.Error("expected exported class UserService")
	}
}

func TestRegex_ClassWithBases(t *testing.T) {
	a := analyzerForTest()
	lines := []string{
		"class AdminService(BaseService):",
		"    pass",
	}
	fullSource := "class AdminService(BaseService):\n    pass\n"
	result := regexResult()
	a.analyzeFileRegex("service.py", lines, fullSource, result)

	found := false
	for _, sym := range result.Symbols {
		if sym.Name == "AdminService" && sym.Kind == "class" {
			found = true
		}
	}
	if !found {
		t.Error("expected class AdminService with base")
	}
}

// ── analyzeFileRegex — routes ─────────────────────────────────────────────────

func TestRegex_FastAPIGetRoute(t *testing.T) {
	a := analyzerForTest()
	lines := []string{
		`@app.get("/items")`,
		`def list_items():`,
		`    return []`,
	}
	fullSource := "@app.get(\"/items\")\ndef list_items():\n    return []\n"
	result := regexResult()
	a.analyzeFileRegex("main.py", lines, fullSource, result)

	found := false
	for _, rf := range result.Routes {
		if rf.Path == "/items" && rf.Method == "GET" && rf.Handler == "list_items" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected GET /items with handler list_items, routes: %+v", result.Routes)
	}
}

func TestRegex_FastAPIPostRoute(t *testing.T) {
	a := analyzerForTest()
	lines := []string{
		`@app.post("/users")`,
		`def create_user():`,
		`    pass`,
	}
	fullSource := "@app.post(\"/users\")\ndef create_user():\n    pass\n"
	result := regexResult()
	a.analyzeFileRegex("main.py", lines, fullSource, result)

	found := false
	for _, rf := range result.Routes {
		if rf.Path == "/users" && rf.Method == "POST" {
			found = true
		}
	}
	if !found {
		t.Error("expected POST /users route")
	}
}

func TestRegex_FastAPIPutDeletePatch(t *testing.T) {
	a := analyzerForTest()
	src := `@app.put("/items/{id}")
def update_item():
    pass

@app.delete("/items/{id}")
def delete_item():
    pass

@app.patch("/items/{id}")
def patch_item():
    pass
`
	lines := splitLines(src)
	result := regexResult()
	a.analyzeFileRegex("main.py", lines, src, result)

	methods := map[string]bool{}
	for _, rf := range result.Routes {
		methods[rf.Method] = true
	}
	for _, want := range []string{"PUT", "DELETE", "PATCH"} {
		if !methods[want] {
			t.Errorf("expected %s route", want)
		}
	}
}

func TestRegex_FlaskRouteHandlerDetection(t *testing.T) {
	a := analyzerForTest()
	lines := []string{
		`@app.route("/health")`,
		`def health_check():`,
		`    return "ok"`,
	}
	fullSource := "@app.route(\"/health\")\ndef health_check():\n    return \"ok\"\n"
	result := regexResult()
	a.analyzeFileRegex("app.py", lines, fullSource, result)

	found := false
	for _, rf := range result.Routes {
		if rf.Path == "/health" && rf.Handler == "health_check" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected Flask /health with handler health_check, routes: %+v", result.Routes)
	}
}

func TestRegex_FlaskRouteSkipsBlankLines(t *testing.T) {
	// handler detection skips blank lines between decorator and def
	a := analyzerForTest()
	lines := []string{
		`@app.route("/about")`,
		``,
		`def about():`,
		`    pass`,
	}
	fullSource := "@app.route(\"/about\")\n\ndef about():\n    pass\n"
	result := regexResult()
	a.analyzeFileRegex("app.py", lines, fullSource, result)

	found := false
	for _, rf := range result.Routes {
		if rf.Path == "/about" && rf.Handler == "about" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected Flask /about with handler about, routes: %+v", result.Routes)
	}
}

func TestRegex_DjangoPath(t *testing.T) {
	a := analyzerForTest()
	lines := []string{
		"    path('api/users/', views.user_list),",
	}
	fullSource := "    path('api/users/', views.user_list),\n"
	result := regexResult()
	a.analyzeFileRegex("urls.py", lines, fullSource, result)

	found := false
	for _, rf := range result.Routes {
		if rf.Path == "api/users/" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected Django path 'api/users/', routes: %+v", result.Routes)
	}
}

func TestRegex_DjangoUrl(t *testing.T) {
	a := analyzerForTest()
	lines := []string{
		`    url(r'^legacy/', views.legacy),`,
	}
	fullSource := `    url(r'^legacy/', views.legacy),` + "\n"
	result := regexResult()
	a.analyzeFileRegex("urls.py", lines, fullSource, result)

	found := false
	for _, rf := range result.Routes {
		if rf.Path == "^legacy/" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected Django url '^legacy/', routes: %+v", result.Routes)
	}
}

func TestRegex_DjangoRePath(t *testing.T) {
	a := analyzerForTest()
	lines := []string{
		`    re_path(r'^articles/$', views.articles),`,
	}
	fullSource := `    re_path(r'^articles/$', views.articles),` + "\n"
	result := regexResult()
	a.analyzeFileRegex("urls.py", lines, fullSource, result)

	found := false
	for _, rf := range result.Routes {
		if rf.Path == "^articles/$" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected Django re_path '^articles/$', routes: %+v", result.Routes)
	}
}

func TestRegex_StarletteRoute(t *testing.T) {
	a := analyzerForTest()
	lines := []string{
		`    Route("/items", endpoint=list_items),`,
	}
	fullSource := `    Route("/items", endpoint=list_items),` + "\n"
	result := regexResult()
	a.analyzeFileRegex("main.py", lines, fullSource, result)

	found := false
	for _, rf := range result.Routes {
		if rf.Path == "/items" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected Starlette Route /items, routes: %+v", result.Routes)
	}
}

// ── analyzeFileRegex — middleware ─────────────────────────────────────────────

func TestRegex_StarletteAddMiddleware(t *testing.T) {
	a := analyzerForTest()
	lines := []string{
		"app.add_middleware(CORSMiddleware)",
	}
	result := regexResult()
	a.analyzeFileRegex("main.py", lines, lines[0], result)

	found := false
	for _, mw := range result.Middlewares {
		if mw.Name == "CORSMiddleware" && mw.Kind == "starlette" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected starlette CORSMiddleware, got %+v", result.Middlewares)
	}
}

func TestRegex_DjangoMiddlewareInSettings(t *testing.T) {
	a := analyzerForTest()
	lines := []string{
		"MIDDLEWARE = [",
		"    'django.middleware.security.SecurityMiddleware',",
		"    'django.contrib.sessions.middleware.SessionMiddleware',",
		"]",
	}
	fullSource := "MIDDLEWARE = [\n    'django.middleware.security.SecurityMiddleware',\n    'django.contrib.sessions.middleware.SessionMiddleware',\n]\n"
	result := regexResult()
	a.analyzeFileRegex("settings.py", lines, fullSource, result)

	names := map[string]bool{}
	for _, mw := range result.Middlewares {
		names[mw.Name] = true
	}
	for _, want := range []string{
		"django.middleware.security.SecurityMiddleware",
		"django.contrib.sessions.middleware.SessionMiddleware",
	} {
		if !names[want] {
			t.Errorf("expected middleware %q", want)
		}
	}
}

func TestRegex_DjangoMiddlewareNotInNonSettings(t *testing.T) {
	// Django middleware pattern in a non-settings file should NOT emit middleware facts
	a := analyzerForTest()
	lines := []string{
		"    'django.middleware.security.SecurityMiddleware',",
	}
	result := regexResult()
	a.analyzeFileRegex("views.py", lines, lines[0], result)

	for _, mw := range result.Middlewares {
		if mw.Kind == "django" {
			t.Errorf("unexpected django middleware in non-settings file: %+v", mw)
		}
	}
}

func TestRegex_FastAPIDepends(t *testing.T) {
	a := analyzerForTest()
	lines := []string{
		"def endpoint(user=Depends(require_auth)):",
		"    pass",
	}
	fullSource := "def endpoint(user=Depends(require_auth)):\n    pass\n"
	result := regexResult()
	a.analyzeFileRegex("main.py", lines, fullSource, result)

	found := false
	for _, mw := range result.Middlewares {
		if mw.Name == "require_auth" && mw.Kind == "fastapi_depends" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected fastapi_depends require_auth, got %+v", result.Middlewares)
	}
}

// ── analyzeFileRegex — data access ────────────────────────────────────────────

func TestRegex_SQLAlchemyImportAndUsage(t *testing.T) {
	a := analyzerForTest()
	lines := []string{
		"from sqlalchemy.orm import Session",
		"def get_users(db: Session):",
		"    return db.query(Session).all()",
	}
	fullSource := "from sqlalchemy.orm import Session\ndef get_users(db: Session):\n    return db.query(Session).all()\n"
	result := regexResult()
	a.analyzeFileRegex("db.py", lines, fullSource, result)

	found := false
	for _, da := range result.DataAccess {
		if da.Backend == "sqlalchemy" && da.ImportsDirect {
			found = true
		}
	}
	if !found {
		t.Errorf("expected sqlalchemy data access with ImportsDirect=true, got %+v", result.DataAccess)
	}
}

func TestRegex_SQLAlchemyImport_NoSession_NoDataAccess(t *testing.T) {
	// importing sqlalchemy but never using Session → no DataAccessFact
	a := analyzerForTest()
	lines := []string{
		"from sqlalchemy.orm import Base",
		"class MyModel(Base):",
		"    pass",
	}
	fullSource := "from sqlalchemy.orm import Base\nclass MyModel(Base):\n    pass\n"
	result := regexResult()
	a.analyzeFileRegex("models.py", lines, fullSource, result)

	for _, da := range result.DataAccess {
		if da.Backend == "sqlalchemy" {
			t.Error("expected no sqlalchemy DataAccessFact when Session not used")
		}
	}
}

func TestRegex_Psycopg2Import(t *testing.T) {
	a := analyzerForTest()
	lines := []string{
		"import psycopg2",
		"conn = psycopg2.connect('dbname=test')",
	}
	fullSource := "import psycopg2\nconn = psycopg2.connect('dbname=test')\n"
	result := regexResult()
	a.analyzeFileRegex("db.py", lines, fullSource, result)

	found := false
	for _, da := range result.DataAccess {
		if da.Backend == "psycopg2" && da.ImportsDirect {
			found = true
		}
	}
	if !found {
		t.Errorf("expected psycopg2 data access with ImportsDirect=true, got %+v", result.DataAccess)
	}
}

func TestRegex_DjangoORM(t *testing.T) {
	a := analyzerForTest()
	lines := []string{
		"from django.db import models",
		"def get_all():",
		"    return User.objects.all()",
		"def create_one():",
		"    return User.objects.create(name='test')",
	}
	fullSource := "from django.db import models\ndef get_all():\n    return User.objects.all()\ndef create_one():\n    return User.objects.create(name='test')\n"
	result := regexResult()
	a.analyzeFileRegex("views.py", lines, fullSource, result)

	ops := map[string]bool{}
	for _, da := range result.DataAccess {
		if da.Backend == "django-orm" {
			ops[da.Operation] = true
		}
	}
	for _, want := range []string{"all", "create"} {
		if !ops[want] {
			t.Errorf("expected django-orm operation %q", want)
		}
	}
}

func TestRegex_TortoiseImport(t *testing.T) {
	a := analyzerForTest()
	lines := []string{
		"from tortoise import fields",
		"class User(Model):",
		"    name = fields.CharField()",
	}
	fullSource := "from tortoise import fields\nclass User(Model):\n    name = fields.CharField()\n"
	result := regexResult()
	a.analyzeFileRegex("models.py", lines, fullSource, result)

	found := false
	for _, da := range result.DataAccess {
		if da.Backend == "tortoise" && da.ImportsDirect {
			found = true
		}
	}
	if !found {
		t.Errorf("expected tortoise data access with ImportsDirect=true, got %+v", result.DataAccess)
	}
}

func TestRegex_ImportTortoiseDirect(t *testing.T) {
	// "import tortoise" (non-from style)
	a := analyzerForTest()
	lines := []string{
		"import tortoise",
	}
	result := regexResult()
	a.analyzeFileRegex("models.py", lines, lines[0], result)

	found := false
	for _, da := range result.DataAccess {
		if da.Backend == "tortoise" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected tortoise data access for 'import tortoise', got %+v", result.DataAccess)
	}
}

// ── analyzeFileRegex — CallerName enrichment ──────────────────────────────────

func TestRegex_CallerNameOnDjangoORM(t *testing.T) {
	a := analyzerForTest()
	lines := []string{
		"from django.db import models",
		"def list_active():",
		"    return User.objects.filter(active=True)",
	}
	fullSource := "from django.db import models\ndef list_active():\n    return User.objects.filter(active=True)\n"
	result := regexResult()
	a.analyzeFileRegex("views.py", lines, fullSource, result)

	for _, da := range result.DataAccess {
		if da.Backend == "django-orm" && da.Operation == "filter" {
			if da.CallerName != "list_active" {
				t.Errorf("expected CallerName=list_active, got %q", da.CallerName)
			}
		}
	}
}

func TestRegex_CallerNameOnSQLAlchemy(t *testing.T) {
	a := analyzerForTest()
	lines := []string{
		"import sqlalchemy",
		"def fetch_all(session):",
		"    return session.query(User).all()",
	}
	fullSource := "import sqlalchemy\ndef fetch_all(session):\n    return session.query(User).all()\n"
	result := regexResult()
	a.analyzeFileRegex("repo.py", lines, fullSource, result)

	for _, da := range result.DataAccess {
		if da.Backend == "sqlalchemy" {
			if da.CallerName != "fetch_all" {
				t.Errorf("expected CallerName=fetch_all, got %q", da.CallerName)
			}
		}
	}
}

// ── analyzeFileRegex — secrets ────────────────────────────────────────────────

func TestRegex_HardcodedPassword(t *testing.T) {
	a := analyzerForTest()
	lines := []string{
		`PASSWORD = "super-secret-123"`,
	}
	result := regexResult()
	a.analyzeFileRegex("config.py", lines, lines[0], result)

	found := false
	for _, s := range result.Secrets {
		if s.Value == "PASSWORD" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected secret PASSWORD, got %+v", result.Secrets)
	}
}

func TestRegex_HardcodedAPIKey(t *testing.T) {
	a := analyzerForTest()
	lines := []string{
		`API_KEY = "sk-abc123"`,
	}
	result := regexResult()
	a.analyzeFileRegex("config.py", lines, lines[0], result)

	found := false
	for _, s := range result.Secrets {
		if s.Value == "API_KEY" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected secret API_KEY, got %+v", result.Secrets)
	}
}

func TestRegex_HardcodedToken(t *testing.T) {
	a := analyzerForTest()
	lines := []string{
		`JWT_TOKEN = "eyJhbGciOiJIUzI1NiJ9"`,
	}
	result := regexResult()
	a.analyzeFileRegex("config.py", lines, lines[0], result)

	found := false
	for _, s := range result.Secrets {
		if s.Value == "JWT_TOKEN" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected secret JWT_TOKEN, got %+v", result.Secrets)
	}
}

func TestRegex_SecretEnvVarNotFlagged(t *testing.T) {
	// os.environ usage should NOT be flagged
	a := analyzerForTest()
	lines := []string{
		`SECRET_KEY = os.environ.get("SECRET_KEY", "fallback")`,
	}
	result := regexResult()
	a.analyzeFileRegex("config.py", lines, lines[0], result)

	for _, s := range result.Secrets {
		if s.Value == "SECRET_KEY" {
			t.Error("os.environ.get should not be flagged as a hardcoded secret")
		}
	}
}

func TestRegex_SecretDebugNotFlagged(t *testing.T) {
	// DEBUG variable should NOT be flagged
	a := analyzerForTest()
	lines := []string{
		`DEBUG = "true"`,
	}
	result := regexResult()
	a.analyzeFileRegex("config.py", lines, lines[0], result)

	for _, s := range result.Secrets {
		if s.Value == "DEBUG" {
			t.Error("DEBUG should not be flagged as a secret")
		}
	}
}

func TestRegex_SecretInCommentNotFlagged(t *testing.T) {
	// Secret pattern inside a comment must NOT be flagged (codeTrimmed guard)
	a := analyzerForTest()
	lines := []string{
		`# SECRET_KEY = "do-not-use"`,
		`x = 1`,
	}
	fullSource := "# SECRET_KEY = \"do-not-use\"\nx = 1\n"
	result := regexResult()
	a.analyzeFileRegex("config.py", lines, fullSource, result)

	for _, s := range result.Secrets {
		if s.Value == "SECRET_KEY" {
			t.Error("secret inside comment should not be flagged")
		}
	}
}

func TestRegex_DatabaseURLSecret(t *testing.T) {
	a := analyzerForTest()
	lines := []string{
		`DATABASE_URL = "postgresql://admin:pass@localhost/db"`,
	}
	result := regexResult()
	a.analyzeFileRegex("config.py", lines, lines[0], result)

	found := false
	for _, s := range result.Secrets {
		if s.Value == "DATABASE_URL" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected secret DATABASE_URL, got %+v", result.Secrets)
	}
}

// ── analyzeFileRegex — tests in test files ────────────────────────────────────

func TestRegex_TestFunctionInTestFile(t *testing.T) {
	a := analyzerForTest()
	lines := []string{
		"def test_create_user():",
		"    assert True",
	}
	fullSource := "def test_create_user():\n    assert True\n"
	result := regexResult()
	a.analyzeFileRegex("test_users.py", lines, fullSource, result)

	found := false
	for _, tf := range result.Tests {
		if tf.TestName == "test_create_user" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected test test_create_user, tests: %+v", result.Tests)
	}
}

func TestRegex_TestFunctionNotInNonTestFile(t *testing.T) {
	// test_ functions in non-test files should NOT become TestFacts
	a := analyzerForTest()
	lines := []string{
		"def test_helper():",
		"    pass",
	}
	fullSource := "def test_helper():\n    pass\n"
	result := regexResult()
	a.analyzeFileRegex("helpers.py", lines, fullSource, result)

	for _, tf := range result.Tests {
		if tf.TestName == "test_helper" {
			t.Error("test_ function in non-test file should not be a TestFact")
		}
	}
}

func TestRegex_TestClassMethods(t *testing.T) {
	a := analyzerForTest()
	src := `class TestOrders:
    def test_place_order(self):
        pass

    def test_cancel_order(self):
        pass
`
	lines := splitLines(src)
	result := regexResult()
	a.analyzeFileRegex("test_orders.py", lines, src, result)

	tests := map[string]bool{}
	for _, tf := range result.Tests {
		tests[tf.TestName] = true
	}
	for _, want := range []string{"test_place_order", "test_cancel_order"} {
		if !tests[want] {
			t.Errorf("expected test %q, tests: %+v", want, result.Tests)
		}
	}
}

func TestRegex_DjangoTestCaseInTestFile(t *testing.T) {
	a := analyzerForTest()
	src := `from django.test import TestCase

class TestUserModel(TestCase):
    def test_create(self):
        pass
`
	lines := splitLines(src)
	result := regexResult()
	a.analyzeFileRegex("test_models.py", lines, src, result)

	testNames := map[string]bool{}
	for _, tf := range result.Tests {
		testNames[tf.TestName] = true
	}
	// Django TestCase class itself should be recorded
	if !testNames["TestUserModel"] {
		t.Errorf("expected TestUserModel as test, tests: %+v", result.Tests)
	}
	if !testNames["test_create"] {
		t.Errorf("expected test_create, tests: %+v", result.Tests)
	}
}

// ── ast_bridge.go — ParsePythonAST error paths ────────────────────────────────

func TestParsePythonAST_NoPython3(t *testing.T) {
	// If python3 is available, skip this test (we can't simulate "no python3"
	// without modifying PATH in a race-safe way).
	if PythonASTAvailable() {
		t.Skip("python3 is available; cannot test the 'not found' path")
	}
	_, err := ParsePythonAST("import os")
	if err == nil {
		t.Error("expected error when python3 not found")
	}
}

func TestParsePythonAST_InvalidJSON_ViaInvalidSource(t *testing.T) {
	if !PythonASTAvailable() {
		t.Skip("python3 not available")
	}
	// The script handles syntax errors gracefully (returns {"error": "..."}),
	// so a syntax-broken file won't cause a JSON parse error.
	// We can still confirm the error field is set.
	source := `def broken(
`
	result, err := ParsePythonAST(source)
	if err != nil {
		// If the script returns non-JSON, err != nil is also acceptable
		t.Logf("ParsePythonAST returned error (acceptable): %v", err)
		return
	}
	if result.Error == nil || *result.Error == "" {
		t.Error("expected error field for broken Python source")
	}
}

func TestParsePythonAST_LargeValidSource(t *testing.T) {
	if !PythonASTAvailable() {
		t.Skip("python3 not available")
	}
	// Large-ish source to exercise the temp-file write + subprocess path fully
	src := `import os
import sys
from typing import List

def process(items: List[str]) -> List[str]:
    return [i.upper() for i in items]

class Processor:
    def __init__(self):
        self.data = []

    def run(self, items):
        return process(items)
`
	result, err := ParsePythonAST(src)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Error != nil && *result.Error != "" {
		t.Fatalf("AST error: %s", *result.Error)
	}
	if len(result.Symbols) == 0 {
		t.Error("expected at least one symbol")
	}
}

// ── Analyze — both paths (AST and regex) ─────────────────────────────────────

func TestAnalyze_RegexPath_AllFeatures(t *testing.T) {
	// Force the regex path by using analyzeFileRegex directly (avoids python3 dependency).
	a := analyzerForTest()
	src := `from sqlalchemy.orm import Session
import psycopg2
from fastapi import FastAPI, Depends
from tortoise import fields

app = FastAPI()

SECRET_KEY = "hardcoded-secret"

def auth_required():
    pass

@app.get("/users")
def list_users(auth=Depends(auth_required)):
    pass

@app.post("/users")
def create_user():
    pass

class UserRepo:
    def get(self, db: Session):
        return db.query(Session).first()

def test_list_users():
    assert True
`
	lines := splitLines(src)
	result := regexResult()
	a.analyzeFileRegex("test_app.py", lines, src, result)

	// Should have imports
	if len(result.Imports) == 0 {
		t.Error("expected imports")
	}
	// Should have symbols
	if len(result.Symbols) == 0 {
		t.Error("expected symbols")
	}
	// Should have routes
	if len(result.Routes) == 0 {
		t.Error("expected routes")
	}
	// Should have middleware (Depends)
	if len(result.Middlewares) == 0 {
		t.Error("expected middleware")
	}
	// Should have data access
	if len(result.DataAccess) == 0 {
		t.Error("expected data access facts")
	}
	// Should have secrets
	if len(result.Secrets) == 0 {
		t.Error("expected secrets")
	}
	// Should have tests
	if len(result.Tests) == 0 {
		t.Error("expected tests")
	}
}

func TestAnalyze_ASTFallbackToRegex(t *testing.T) {
	// Simulate the fall-through: if AST is available but produces an error,
	// Analyze should fall through to the regex path.
	// We test this indirectly by running Analyze on a project when python3 is available.
	root, files := setupTempProject(t, map[string]string{
		"service.py": `import sqlalchemy

class UserService:
    def get_user(self, session):
        return session.query(User).first()
`,
	})

	a := New()
	result, err := a.Analyze(root, files)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Files) == 0 {
		t.Error("expected at least one FileFact")
	}
}

// ── findPython3 and ensureScript ──────────────────────────────────────────────

func TestFindPython3_ReturnsString(t *testing.T) {
	// Just confirm it returns a string (empty or path) without panicking
	p := findPython3()
	t.Logf("findPython3 returned: %q", p)
}

func TestEnsureScript_CalledMultipleTimes(t *testing.T) {
	// ensureScript uses sync.Once, calling it multiple times is safe
	path1, err1 := ensureScript()
	path2, err2 := ensureScript()

	if err1 != nil || err2 != nil {
		t.Logf("ensureScript errors: %v / %v (acceptable if no write access)", err1, err2)
		return
	}
	if path1 != path2 {
		t.Errorf("ensureScript returned different paths: %q vs %q", path1, path2)
	}
	if path1 == "" {
		t.Error("expected non-empty script path")
	}
}

// ── edge cases for analyzeFileRegex ──────────────────────────────────────────

func TestRegex_EmptyFile(t *testing.T) {
	a := analyzerForTest()
	result := regexResult()
	a.analyzeFileRegex("empty.py", []string{}, "", result)
	// Should not panic, no facts expected
	if len(result.Imports) != 0 || len(result.Symbols) != 0 {
		t.Error("expected no facts for empty file")
	}
}

func TestRegex_OnlyComments(t *testing.T) {
	a := analyzerForTest()
	lines := []string{
		"# This is a comment",
		"# Another comment",
	}
	fullSource := "# This is a comment\n# Another comment\n"
	result := regexResult()
	a.analyzeFileRegex("comments.py", lines, fullSource, result)

	if len(result.Imports) != 0 || len(result.Symbols) != 0 {
		t.Error("expected no facts for comment-only file")
	}
}

func TestRegex_MultipleImportStyles(t *testing.T) {
	a := analyzerForTest()
	src := `import os, sys
from pathlib import Path, PurePath
import json as j
from collections import OrderedDict as OD
`
	lines := splitLines(src)
	result := regexResult()
	a.analyzeFileRegex("util.py", lines, src, result)

	names := map[string]bool{}
	for _, imp := range result.Imports {
		names[imp.ImportPath] = true
	}
	for _, want := range []string{"os", "sys", "pathlib", "collections"} {
		if !names[want] {
			t.Errorf("expected import %q, got %+v", want, result.Imports)
		}
	}
}

func TestRegex_FastAPIHandlerDetection_NoTrailingDef(t *testing.T) {
	// Route at end of file with no following def — handler should be empty string
	a := analyzerForTest()
	lines := []string{
		`@app.get("/ping")`,
	}
	fullSource := "@app.get(\"/ping\")\n"
	result := regexResult()
	a.analyzeFileRegex("main.py", lines, fullSource, result)

	found := false
	for _, rf := range result.Routes {
		if rf.Path == "/ping" && rf.Method == "GET" {
			found = true
			// handler may be empty string — that's fine
		}
	}
	if !found {
		t.Errorf("expected GET /ping route")
	}
}

func TestRegex_SQLAlchemyImportDirect(t *testing.T) {
	// "import sqlalchemy" (not from-style)
	a := analyzerForTest()
	lines := []string{
		"import sqlalchemy",
		"session = Session()",
	}
	fullSource := "import sqlalchemy\nsession = Session()\n"
	result := regexResult()
	a.analyzeFileRegex("db.py", lines, fullSource, result)

	found := false
	for _, da := range result.DataAccess {
		if da.Backend == "sqlalchemy" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected sqlalchemy DataAccessFact for 'import sqlalchemy', got %+v", result.DataAccess)
	}
}

func TestRegex_Psycopg2DirectImport(t *testing.T) {
	a := analyzerForTest()
	// The regex path detects psycopg2 via `import psycopg2` (importRe).
	lines := []string{
		"import psycopg2",
	}
	fullSource := "import psycopg2\n"
	result := regexResult()
	a.analyzeFileRegex("db.py", lines, fullSource, result)

	found := false
	for _, da := range result.DataAccess {
		if da.Backend == "psycopg2" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected psycopg2 DataAccessFact for 'import psycopg2', got %+v", result.DataAccess)
	}
}

// ── integration: Analyze with temp project ────────────────────────────────────

func TestAnalyze_RegexAndASTProvenance(t *testing.T) {
	root, files := setupTempProject(t, map[string]string{
		"app.py": `from flask import Flask

app = Flask(__name__)

@app.route("/hello")
def hello():
    return "Hello!"
`,
	})

	a := New()
	result, err := a.Analyze(root, files)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.Routes) == 0 {
		t.Error("expected at least one route")
	}
}

func TestAnalyze_MultipleFiles(t *testing.T) {
	root, files := setupTempProject(t, map[string]string{
		"app.py": `from flask import Flask
app = Flask(__name__)
SECRET_KEY = "abc123"
`,
		"test_app.py": `def test_something():
    assert True
`,
		"models.py": `from sqlalchemy.orm import Session
class User:
    pass
`,
	})

	a := New()
	result, err := a.Analyze(root, files)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.Files) != 3 {
		t.Errorf("expected 3 FileFacts, got %d", len(result.Files))
	}
}

// ── splitLines helper (used in tests above) ───────────────────────────────────

func splitLines(src string) []string {
	if src == "" {
		return nil
	}
	var lines []string
	start := 0
	for i, ch := range src {
		if ch == '\n' {
			lines = append(lines, src[start:i])
			start = i + 1
		}
	}
	if start < len(src) {
		lines = append(lines, src[start:])
	}
	return lines
}

// ── Additional coverage for Analyze error/fallback branches ───────────────────

func TestAnalyze_NonexistentFile(t *testing.T) {
	a := New()
	result, err := a.Analyze("/nonexistent/dir", []string{"nonexistent.py"})
	if err != nil {
		t.Fatalf("Analyze should not return error for unreadable files, got: %v", err)
	}
	if len(result.SkippedFiles) != 1 {
		t.Errorf("expected 1 skipped file, got %d", len(result.SkippedFiles))
	}
}

func TestAnalyze_ASTFallsBackToRegex(t *testing.T) {
	if !PythonASTAvailable() {
		t.Skip("python3 not available")
	}
	// File with syntax error → AST will fail → regex fallback
	root, files := setupTempProject(t, map[string]string{
		"broken.py": "def foo(\n    # incomplete\n    x = 1\n",
	})
	a := New()
	result, err := a.Analyze(root, files)
	if err != nil {
		t.Fatalf("Analyze should not error: %v", err)
	}
	// File should still be processed (via regex fallback)
	if len(result.Files) == 0 {
		t.Error("expected at least one FileFact from regex fallback")
	}
}

func TestAnalyze_EmptyFile(t *testing.T) {
	root, files := setupTempProject(t, map[string]string{
		"empty.py": "",
	})
	a := New()
	result, err := a.Analyze(root, files)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Files) == 0 {
		t.Error("expected FileFact even for empty file")
	}
}

func TestFindPython3_Runs(t *testing.T) {
	// Exercise findPython3 — it checks common paths and LookPath.
	p := findPython3()
	t.Logf("findPython3 returned: %q", p)
	// We can't assert a specific path, but it should not panic.
}

