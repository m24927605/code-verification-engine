package python

import (
	"testing"
)

func TestParsePythonAST_Imports(t *testing.T) {
	if !PythonASTAvailable() {
		t.Skip("python3 not available")
	}

	source := `import os
import sys
from flask import Flask, request
from sqlalchemy.orm import Session
`
	result, err := ParsePythonAST(source)
	if err != nil {
		t.Fatalf("ParsePythonAST failed: %v", err)
	}
	if result.Error != nil && *result.Error != "" {
		t.Fatalf("AST error: %s", *result.Error)
	}

	if len(result.Imports) < 4 {
		t.Fatalf("expected at least 4 imports, got %d", len(result.Imports))
	}

	foundOS := false
	foundFlask := false
	foundSQLAlchemy := false
	for _, imp := range result.Imports {
		if imp.Module == "os" {
			foundOS = true
		}
		if imp.Module == "flask" {
			foundFlask = true
			if len(imp.Names) < 2 {
				t.Errorf("expected flask import to have at least 2 names, got %v", imp.Names)
			}
		}
		if imp.Module == "sqlalchemy.orm" {
			foundSQLAlchemy = true
		}
	}
	if !foundOS {
		t.Error("expected import os")
	}
	if !foundFlask {
		t.Error("expected import flask")
	}
	if !foundSQLAlchemy {
		t.Error("expected import sqlalchemy.orm")
	}
}

func TestParsePythonAST_Symbols(t *testing.T) {
	if !PythonASTAvailable() {
		t.Skip("python3 not available")
	}

	source := `def get_users():
    return []

class UserService:
    def get(self, id):
        return id

    def create(self, data):
        return data

def _private_helper():
    pass
`
	result, err := ParsePythonAST(source)
	if err != nil {
		t.Fatalf("ParsePythonAST failed: %v", err)
	}

	foundFunc := false
	foundClass := false
	foundMethod := false
	foundPrivate := false
	for _, sym := range result.Symbols {
		if sym.Name == "get_users" && sym.Kind == "function" && sym.Exported {
			foundFunc = true
		}
		if sym.Name == "UserService" && sym.Kind == "class" && sym.Exported {
			foundClass = true
		}
		if sym.Name == "get" && sym.Kind == "method" {
			foundMethod = true
		}
		if sym.Name == "_private_helper" && sym.Kind == "function" && !sym.Exported {
			foundPrivate = true
		}
	}
	if !foundFunc {
		t.Error("expected function get_users")
	}
	if !foundClass {
		t.Error("expected class UserService")
	}
	if !foundMethod {
		t.Error("expected method get")
	}
	if !foundPrivate {
		t.Error("expected private function _private_helper")
	}
}

func TestParsePythonAST_Routes(t *testing.T) {
	if !PythonASTAvailable() {
		t.Skip("python3 not available")
	}

	source := `from fastapi import FastAPI

app = FastAPI()

@app.get("/health")
def health():
    return {"status": "ok"}

@app.post("/users")
def create_user():
    return {"id": "new"}
`
	result, err := ParsePythonAST(source)
	if err != nil {
		t.Fatalf("ParsePythonAST failed: %v", err)
	}

	foundHealth := false
	foundUsers := false
	for _, r := range result.Routes {
		if r.Path == "/health" && r.Method == "GET" && r.Handler == "health" {
			foundHealth = true
		}
		if r.Path == "/users" && r.Method == "POST" && r.Handler == "create_user" {
			foundUsers = true
		}
	}
	if !foundHealth {
		t.Error("expected GET /health route")
	}
	if !foundUsers {
		t.Error("expected POST /users route")
	}
}

func TestParsePythonAST_FlaskRoutes(t *testing.T) {
	if !PythonASTAvailable() {
		t.Skip("python3 not available")
	}

	source := `from flask import Flask

app = Flask(__name__)

@app.route("/users")
def get_users():
    return []
`
	result, err := ParsePythonAST(source)
	if err != nil {
		t.Fatalf("ParsePythonAST failed: %v", err)
	}

	foundUsers := false
	for _, r := range result.Routes {
		if r.Path == "/users" && r.Method == "ANY" && r.Handler == "get_users" {
			foundUsers = true
		}
	}
	if !foundUsers {
		t.Error("expected Flask route /users with handler get_users")
	}
}

func TestParsePythonAST_Middleware(t *testing.T) {
	if !PythonASTAvailable() {
		t.Skip("python3 not available")
	}

	source := `from fastapi import FastAPI, Depends

app = FastAPI()

def require_auth():
    pass

@app.get("/users")
def get_users(auth=Depends(require_auth)):
    return []

app.add_middleware(CORSMiddleware)
`
	result, err := ParsePythonAST(source)
	if err != nil {
		t.Fatalf("ParsePythonAST failed: %v", err)
	}

	foundDepends := false
	foundAddMiddleware := false
	for _, mw := range result.Middlewares {
		if mw.Name == "require_auth" && mw.Framework == "fastapi_depends" {
			foundDepends = true
		}
		if mw.Name == "CORSMiddleware" && mw.Framework == "starlette" {
			foundAddMiddleware = true
		}
	}
	if !foundDepends {
		t.Error("expected Depends(require_auth) middleware")
	}
	if !foundAddMiddleware {
		t.Error("expected add_middleware(CORSMiddleware)")
	}
}

func TestParsePythonAST_Secrets(t *testing.T) {
	if !PythonASTAvailable() {
		t.Skip("python3 not available")
	}

	source := `SECRET_KEY = "my-super-secret"
API_KEY = "sk-12345"
DATABASE_URL = "postgresql://admin:pass@localhost/db"
SAFE_KEY = os.environ.get("KEY", "")
DEBUG = True
`
	result, err := ParsePythonAST(source)
	if err != nil {
		t.Fatalf("ParsePythonAST failed: %v", err)
	}

	if len(result.Secrets) < 3 {
		t.Fatalf("expected at least 3 secrets, got %d", len(result.Secrets))
	}

	foundSecretKey := false
	foundAPIKey := false
	foundDBURL := false
	for _, s := range result.Secrets {
		if s.Name == "SECRET_KEY" {
			foundSecretKey = true
		}
		if s.Name == "API_KEY" {
			foundAPIKey = true
		}
		if s.Name == "DATABASE_URL" {
			foundDBURL = true
		}
	}
	if !foundSecretKey {
		t.Error("expected SECRET_KEY")
	}
	if !foundAPIKey {
		t.Error("expected API_KEY")
	}
	if !foundDBURL {
		t.Error("expected DATABASE_URL")
	}
}

func TestParsePythonAST_SyntaxError(t *testing.T) {
	if !PythonASTAvailable() {
		t.Skip("python3 not available")
	}

	source := `def broken(
    # missing closing paren
    x = 1
`
	result, err := ParsePythonAST(source)
	if err != nil {
		t.Fatalf("ParsePythonAST should not error on syntax errors: %v", err)
	}

	if result.Error == nil || *result.Error == "" {
		t.Error("expected a syntax error message in result")
	}
}

func TestParsePythonAST_EmptyInput(t *testing.T) {
	if !PythonASTAvailable() {
		t.Skip("python3 not available")
	}

	result, err := ParsePythonAST("")
	if err != nil {
		t.Fatalf("ParsePythonAST failed: %v", err)
	}

	if len(result.Imports) != 0 {
		t.Errorf("expected no imports, got %d", len(result.Imports))
	}
	if len(result.Symbols) != 0 {
		t.Errorf("expected no symbols, got %d", len(result.Symbols))
	}
}

func TestParsePythonAST_DataAccess(t *testing.T) {
	if !PythonASTAvailable() {
		t.Skip("python3 not available")
	}

	source := `from sqlalchemy.orm import Session

def get_users(session: Session):
    return session.query(User).all()
`
	result, err := ParsePythonAST(source)
	if err != nil {
		t.Fatalf("ParsePythonAST failed: %v", err)
	}

	foundSQLAlchemy := false
	for _, da := range result.DataAccess {
		if da.Backend == "sqlalchemy" {
			foundSQLAlchemy = true
		}
	}
	if !foundSQLAlchemy {
		t.Error("expected sqlalchemy data access")
	}
}

// ---------- False positive guard tests ----------

func TestParsePythonAST_ImportInsideTripleQuotedString(t *testing.T) {
	if !PythonASTAvailable() {
		t.Skip("python3 not available")
	}

	source := `"""
import os
from flask import Flask
"""

def real_func():
    pass
`
	result, err := ParsePythonAST(source)
	if err != nil {
		t.Fatalf("ParsePythonAST failed: %v", err)
	}

	// AST should NOT extract imports from inside triple-quoted strings
	if len(result.Imports) != 0 {
		t.Errorf("expected no imports (import is inside triple-quoted string), got %d: %+v", len(result.Imports), result.Imports)
	}
}

func TestParsePythonAST_RouteDecoratorInsideComment(t *testing.T) {
	if !PythonASTAvailable() {
		t.Skip("python3 not available")
	}

	// Comments are not parsed by ast, so route decorators in comments should be ignored
	source := `# @app.get("/health")
def not_a_route():
    pass
`
	result, err := ParsePythonAST(source)
	if err != nil {
		t.Fatalf("ParsePythonAST failed: %v", err)
	}

	if len(result.Routes) != 0 {
		t.Errorf("expected no routes (decorator is inside comment), got %d", len(result.Routes))
	}
}

func TestParsePythonAST_FunctionInsideString(t *testing.T) {
	if !PythonASTAvailable() {
		t.Skip("python3 not available")
	}

	source := `code_template = """
def generated_function():
    return 42
"""

def real_function():
    pass
`
	result, err := ParsePythonAST(source)
	if err != nil {
		t.Fatalf("ParsePythonAST failed: %v", err)
	}

	// Only real_function should be extracted
	funcCount := 0
	for _, sym := range result.Symbols {
		if sym.Kind == "function" {
			funcCount++
			if sym.Name != "real_function" {
				t.Errorf("unexpected function extracted: %s", sym.Name)
			}
		}
	}
	if funcCount != 1 {
		t.Errorf("expected exactly 1 function, got %d", funcCount)
	}
}

// ---------- Integration tests ----------

func TestAnalyzer_ASTProvenance(t *testing.T) {
	if !PythonASTAvailable() {
		t.Skip("python3 not available")
	}

	root, files := setupTempProject(t, map[string]string{
		"app.py": `from fastapi import FastAPI, Depends

app = FastAPI()

def require_auth():
    pass

@app.get("/health")
def health():
    return {"status": "ok"}

@app.post("/users")
def create_user(auth=Depends(require_auth)):
    return {"id": "new"}

SECRET_KEY = "hardcoded-secret"
`,
	})

	a := New()
	result, err := a.Analyze(root, files)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	// Check that imports have AST provenance
	for _, imp := range result.Imports {
		if imp.Provenance != "ast_derived" {
			t.Errorf("expected ast_derived provenance for import %s, got %q", imp.ImportPath, imp.Provenance)
		}
	}

	// Check that symbols have AST provenance
	for _, sym := range result.Symbols {
		if sym.Provenance != "ast_derived" {
			t.Errorf("expected ast_derived provenance for symbol %s, got %q", sym.Name, sym.Provenance)
		}
	}

	// Check that routes have AST provenance
	for _, r := range result.Routes {
		if r.Provenance != "ast_derived" {
			t.Errorf("expected ast_derived provenance for route %s, got %q", r.Path, r.Provenance)
		}
	}

	// Check that secrets have AST provenance
	for _, s := range result.Secrets {
		if s.Provenance != "ast_derived" {
			t.Errorf("expected ast_derived provenance for secret %s, got %q", s.Value, s.Provenance)
		}
	}

	// Check that middleware has AST provenance
	for _, mw := range result.Middlewares {
		if mw.Provenance != "ast_derived" {
			t.Errorf("expected ast_derived provenance for middleware %s, got %q", mw.Name, mw.Provenance)
		}
	}
}

func TestAnalyzer_ASTProducesCorrectFacts(t *testing.T) {
	if !PythonASTAvailable() {
		t.Skip("python3 not available")
	}

	root := fixtureRoot(t, "python-fastapi-clean")
	files := collectPythonFiles(t, root)

	a := New()
	result, err := a.Analyze(root, files)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	// Basic sanity checks — same as the original tests
	if len(result.Files) == 0 {
		t.Fatal("expected at least one FileFact")
	}
	if len(result.Imports) == 0 {
		t.Fatal("expected at least one ImportFact")
	}
	if len(result.Symbols) == 0 {
		t.Fatal("expected at least one SymbolFact")
	}

	// Check specific symbols
	foundVerifyToken := false
	foundUserService := false
	for _, sf := range result.Symbols {
		if sf.Name == "verify_token" {
			foundVerifyToken = true
		}
		if sf.Name == "UserService" {
			foundUserService = true
		}
	}
	if !foundVerifyToken {
		t.Error("expected to find function verify_token")
	}
	if !foundUserService {
		t.Error("expected to find class UserService")
	}

	// Check specific routes
	foundHealth := false
	for _, rf := range result.Routes {
		if rf.Path == "/health" && rf.Method == "GET" {
			foundHealth = true
		}
	}
	if !foundHealth {
		t.Error("expected to find GET /health route")
	}
}

func TestAnalyzer_ASTSecretDetection(t *testing.T) {
	if !PythonASTAvailable() {
		t.Skip("python3 not available")
	}

	root := fixtureRoot(t, "python-fastapi-hardcoded-secret")
	files := collectPythonFiles(t, root)

	a := New()
	result, err := a.Analyze(root, files)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	if len(result.Secrets) < 3 {
		t.Errorf("expected at least 3 secrets, got %d", len(result.Secrets))
	}

	// All secrets should have AST provenance
	for _, s := range result.Secrets {
		if s.Provenance != "ast_derived" {
			t.Errorf("expected ast_derived provenance for secret %s, got %q", s.Value, s.Provenance)
		}
	}
}

func TestAnalyzer_CleanAppNoSecretsAST(t *testing.T) {
	if !PythonASTAvailable() {
		t.Skip("python3 not available")
	}

	root := fixtureRoot(t, "python-fastapi-clean")
	files := collectPythonFiles(t, root)

	a := New()
	result, err := a.Analyze(root, files)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	for _, s := range result.Secrets {
		if s.File == "auth/jwt.py" {
			t.Error("auth/jwt.py uses os.environ.get, should NOT trigger secret detection via AST")
		}
	}
}

func TestPythonASTAvailable_Check(t *testing.T) {
	// This test just confirms the function runs without panic.
	// The result depends on the environment.
	available := PythonASTAvailable()
	t.Logf("PythonASTAvailable: %v", available)
}

func TestPythonAST_FastAPIDependencies(t *testing.T) {
	if !PythonASTAvailable() {
		t.Skip("python3 not available")
	}

	source := `from fastapi import FastAPI, Depends

app = FastAPI()

def auth_required():
    pass

def rate_limit():
    pass

@app.get("/users", dependencies=[Depends(auth_required)])
def get_users():
    return []

@app.post("/items")
def create_item(auth=Depends(rate_limit)):
    return {}
`
	result, err := ParsePythonAST(source)
	if err != nil {
		t.Fatalf("ParsePythonAST failed: %v", err)
	}

	// Check that routes have middleware bindings
	foundUsersRoute := false
	foundItemsRoute := false
	for _, r := range result.Routes {
		if r.Path == "/users" && r.Method == "GET" {
			foundUsersRoute = true
			if len(r.Middlewares) == 0 {
				t.Errorf("GET /users should have middlewares from dependencies=, got none")
			} else {
				foundAuth := false
				for _, mw := range r.Middlewares {
					if mw == "auth_required" {
						foundAuth = true
					}
				}
				if !foundAuth {
					t.Errorf("GET /users middlewares should contain 'auth_required', got %v", r.Middlewares)
				}
			}
		}
		if r.Path == "/items" && r.Method == "POST" {
			foundItemsRoute = true
			if len(r.Middlewares) == 0 {
				t.Errorf("POST /items should have middlewares from Depends() in params, got none")
			} else {
				foundRL := false
				for _, mw := range r.Middlewares {
					if mw == "rate_limit" {
						foundRL = true
					}
				}
				if !foundRL {
					t.Errorf("POST /items middlewares should contain 'rate_limit', got %v", r.Middlewares)
				}
			}
		}
	}
	if !foundUsersRoute {
		t.Error("expected GET /users route")
	}
	if !foundItemsRoute {
		t.Error("expected POST /items route")
	}
}

func TestPythonAST_FlaskLoginRequired(t *testing.T) {
	if !PythonASTAvailable() {
		t.Skip("python3 not available")
	}

	source := `from flask import Flask
from functools import wraps

app = Flask(__name__)

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        return f(*args, **kwargs)
    return decorated

@app.route("/dashboard")
@login_required
def dashboard():
    return "Dashboard"
`
	result, err := ParsePythonAST(source)
	if err != nil {
		t.Fatalf("ParsePythonAST failed: %v", err)
	}

	foundDashboard := false
	for _, r := range result.Routes {
		if r.Path == "/dashboard" {
			foundDashboard = true
			foundLoginReq := false
			for _, mw := range r.Middlewares {
				if mw == "login_required" {
					foundLoginReq = true
				}
			}
			if !foundLoginReq {
				t.Errorf("/dashboard route middlewares should contain 'login_required', got %v", r.Middlewares)
			}
		}
	}
	if !foundDashboard {
		t.Error("expected /dashboard route")
	}
}
