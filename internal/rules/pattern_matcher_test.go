package rules

import (
	"testing"

	"github.com/verabase/code-verification-engine/internal/facts"
)

// ---------------------------------------------------------------------------
// findDBAccessOutsideRepo
// ---------------------------------------------------------------------------

func TestFindDBAccessOutsideRepo_NonRepoFile(t *testing.T) {
	rule := Rule{
		ID: "ARCH-001", Languages: []string{"go"},
	}
	fs := &FactSet{
		Files: []facts.FileFact{
			fileFact("handlers/user.go", facts.LangGo),
		},
		DataAccess: []facts.DataAccessFact{
			dataAccess("db.Query", "handlers/user.go", facts.LangGo),
		},
	}

	ev := findDBAccessOutsideRepo(rule, fs)
	if len(ev) != 1 {
		t.Fatalf("expected 1 evidence, got %d", len(ev))
	}
	if ev[0].File != "handlers/user.go" {
		t.Errorf("file = %q, want handlers/user.go", ev[0].File)
	}
	if ev[0].Symbol != "db.Query" {
		t.Errorf("symbol = %q, want db.Query", ev[0].Symbol)
	}
}

func TestFindDBAccessOutsideRepo_RepoFile(t *testing.T) {
	rule := Rule{
		ID: "ARCH-001", Languages: []string{"go"},
	}
	fs := &FactSet{
		Files: []facts.FileFact{
			fileFact("repo/user.go", facts.LangGo),
		},
		DataAccess: []facts.DataAccessFact{
			dataAccess("db.Query", "repo/user.go", facts.LangGo),
		},
	}

	ev := findDBAccessOutsideRepo(rule, fs)
	if len(ev) != 0 {
		t.Errorf("expected 0 evidence for repo file, got %d", len(ev))
	}
}

func TestFindDBAccessOutsideRepo_TestFile(t *testing.T) {
	rule := Rule{
		ID: "ARCH-001", Languages: []string{"go"},
	}
	fs := &FactSet{
		Files: []facts.FileFact{
			fileFact("handlers/user_test.go", facts.LangGo),
		},
		DataAccess: []facts.DataAccessFact{
			dataAccess("db.Query", "handlers/user_test.go", facts.LangGo),
		},
	}

	ev := findDBAccessOutsideRepo(rule, fs)
	if len(ev) != 0 {
		t.Errorf("expected 0 evidence for test file, got %d", len(ev))
	}
}

func TestFindDBAccessOutsideRepo_RepositoryPath(t *testing.T) {
	rule := Rule{
		ID: "ARCH-001", Languages: []string{"go"},
	}
	fs := &FactSet{
		Files: []facts.FileFact{
			fileFact("internal/repository/user.go", facts.LangGo),
		},
		DataAccess: []facts.DataAccessFact{
			dataAccess("db.Exec", "internal/repository/user.go", facts.LangGo),
		},
	}

	ev := findDBAccessOutsideRepo(rule, fs)
	if len(ev) != 0 {
		t.Errorf("expected 0 evidence for repository path, got %d", len(ev))
	}
}

func TestFindDBAccessOutsideRepo_DALPath(t *testing.T) {
	rule := Rule{
		ID: "ARCH-001", Languages: []string{"go"},
	}
	fs := &FactSet{
		Files: []facts.FileFact{
			fileFact("dal/queries.go", facts.LangGo),
		},
		DataAccess: []facts.DataAccessFact{
			dataAccess("db.Exec", "dal/queries.go", facts.LangGo),
		},
	}

	ev := findDBAccessOutsideRepo(rule, fs)
	if len(ev) != 0 {
		t.Errorf("expected 0 evidence for dal path, got %d", len(ev))
	}
}

func TestFindDBAccessOutsideRepo_DataAccessPath(t *testing.T) {
	rule := Rule{
		ID: "ARCH-001", Languages: []string{"go"},
	}
	fs := &FactSet{
		Files: []facts.FileFact{
			fileFact("data-access/user.go", facts.LangGo),
		},
		DataAccess: []facts.DataAccessFact{
			dataAccess("db.Exec", "data-access/user.go", facts.LangGo),
		},
	}

	ev := findDBAccessOutsideRepo(rule, fs)
	if len(ev) != 0 {
		t.Errorf("expected 0 evidence for data-access path, got %d", len(ev))
	}
}

func TestFindDBAccessOutsideRepo_SymbolTokenRepository(t *testing.T) {
	rule := Rule{
		ID: "ARCH-001", Languages: []string{"go"},
	}
	fs := &FactSet{
		Files: []facts.FileFact{
			fileFact("pkg/store.go", facts.LangGo),
		},
		Symbols: []facts.SymbolFact{
			sym("UserRepository", "struct", "pkg/store.go", facts.LangGo, true, 1, 10),
		},
		DataAccess: []facts.DataAccessFact{
			dataAccess("db.Query", "pkg/store.go", facts.LangGo),
		},
	}

	ev := findDBAccessOutsideRepo(rule, fs)
	if len(ev) != 0 {
		t.Errorf("expected 0 evidence when symbol contains 'repository', got %d", len(ev))
	}
}

func TestFindDBAccessOutsideRepo_LanguageFilter(t *testing.T) {
	rule := Rule{
		ID: "ARCH-001", Languages: []string{"python"},
	}
	fs := &FactSet{
		Files: []facts.FileFact{
			fileFact("handlers/user.go", facts.LangGo),
		},
		DataAccess: []facts.DataAccessFact{
			dataAccess("db.Query", "handlers/user.go", facts.LangGo),
		},
	}

	ev := findDBAccessOutsideRepo(rule, fs)
	if len(ev) != 0 {
		t.Errorf("expected 0 evidence for language mismatch, got %d", len(ev))
	}
}

func TestFindDBAccessOutsideRepo_Empty(t *testing.T) {
	rule := Rule{
		ID: "ARCH-001", Languages: []string{"go"},
	}
	fs := &FactSet{}

	ev := findDBAccessOutsideRepo(rule, fs)
	if ev != nil {
		t.Errorf("expected nil for empty data access, got %v", ev)
	}
}

// ---------------------------------------------------------------------------
// findDBModelInRouteHandler
// ---------------------------------------------------------------------------

func TestFindDBModelInRouteHandler_Positive(t *testing.T) {
	// Now requires both model import AND data access in the handler
	rule := Rule{
		ID: "ARCH-002", Languages: []string{"go"},
	}
	fs := &FactSet{
		Files: []facts.FileFact{
			fileFact("model/user.go", facts.LangGo),
			fileFact("handler/user_handler.go", facts.LangGo),
		},
		Symbols: []facts.SymbolFact{
			sym("User", "struct", "model/user.go", facts.LangGo, true, 1, 10),
			sym("GetUser", "function", "handler/user_handler.go", facts.LangGo, true, 1, 20),
		},
		Imports: []facts.ImportFact{
			imp("./model/user", "", "handler/user_handler.go", facts.LangGo),
		},
		DataAccess: []facts.DataAccessFact{
			{
				Language:  facts.LangGo,
				File:      "handler/user_handler.go",
				Span:      facts.Span{Start: 15, End: 15},
				Operation: "db.Query",
				Backend:   "database/sql",
			},
		},
	}

	ev := findDBModelInRouteHandler(rule, fs)
	if len(ev) != 1 {
		t.Fatalf("expected 1 evidence, got %d", len(ev))
	}
	if ev[0].File != "handler/user_handler.go" {
		t.Errorf("file = %q, want handler/user_handler.go", ev[0].File)
	}
}

func TestFindDBModelInRouteHandler_NoFalsePositive_SymbolOnly(t *testing.T) {
	// A handler that references model symbols but does NOT have direct DB access
	// should NOT be flagged (this was the old false positive behavior)
	rule := Rule{
		ID: "ARCH-002", Languages: []string{"go"},
	}
	fs := &FactSet{
		Files: []facts.FileFact{
			fileFact("model/user.go", facts.LangGo),
			fileFact("handler/user_handler.go", facts.LangGo),
		},
		Symbols: []facts.SymbolFact{
			sym("User", "struct", "model/user.go", facts.LangGo, true, 1, 10),
			sym("GetUser", "function", "handler/user_handler.go", facts.LangGo, true, 1, 20),
		},
	}

	ev := findDBModelInRouteHandler(rule, fs)
	if len(ev) != 0 {
		t.Fatalf("expected 0 evidence (no DB access), got %d", len(ev))
	}
}

func TestFindDBModelInRouteHandler_NoModelFiles(t *testing.T) {
	rule := Rule{
		ID: "ARCH-002", Languages: []string{"go"},
	}
	fs := &FactSet{
		Files: []facts.FileFact{
			fileFact("handler/user_handler.go", facts.LangGo),
		},
		Symbols: []facts.SymbolFact{
			sym("GetUser", "function", "handler/user_handler.go", facts.LangGo, true, 1, 20),
		},
	}

	ev := findDBModelInRouteHandler(rule, fs)
	if ev != nil {
		t.Errorf("expected nil when no model files, got %v", ev)
	}
}

func TestFindDBModelInRouteHandler_NonHandlerFile(t *testing.T) {
	rule := Rule{
		ID: "ARCH-002", Languages: []string{"go"},
	}
	fs := &FactSet{
		Files: []facts.FileFact{
			fileFact("model/user.go", facts.LangGo),
			fileFact("service/user_service.go", facts.LangGo),
		},
		Symbols: []facts.SymbolFact{
			sym("User", "struct", "model/user.go", facts.LangGo, true, 1, 10),
			sym("CreateUser", "function", "service/user_service.go", facts.LangGo, true, 1, 20),
		},
	}

	ev := findDBModelInRouteHandler(rule, fs)
	if len(ev) != 0 {
		t.Errorf("expected 0 evidence for non-handler file, got %d", len(ev))
	}
}

func TestFindDBModelInRouteHandler_RouteFileCounts(t *testing.T) {
	// Route file with model import + data access should be flagged
	rule := Rule{
		ID: "ARCH-002", Languages: []string{"go"},
	}
	fs := &FactSet{
		Files: []facts.FileFact{
			fileFact("model/user.go", facts.LangGo),
			fileFact("api/v1/endpoints.go", facts.LangGo),
		},
		Symbols: []facts.SymbolFact{
			sym("User", "struct", "model/user.go", facts.LangGo, true, 1, 10),
			sym("ListUser", "function", "api/v1/endpoints.go", facts.LangGo, true, 1, 20),
		},
		Imports: []facts.ImportFact{
			imp("./model/user", "", "api/v1/endpoints.go", facts.LangGo),
		},
		Routes: []facts.RouteFact{
			route("GET", "/users", "ListUser", "api/v1/endpoints.go", facts.LangGo, nil),
		},
		DataAccess: []facts.DataAccessFact{
			{
				Language:  facts.LangGo,
				File:      "api/v1/endpoints.go",
				Span:      facts.Span{Start: 10, End: 10},
				Operation: "db.Query",
				Backend:   "database/sql",
			},
		},
	}

	ev := findDBModelInRouteHandler(rule, fs)
	if len(ev) != 1 {
		t.Fatalf("expected 1 evidence from route file, got %d", len(ev))
	}
}

func TestFindDBModelInRouteHandler_UnexportedModelSkipped(t *testing.T) {
	rule := Rule{
		ID: "ARCH-002", Languages: []string{"go"},
	}
	fs := &FactSet{
		Files: []facts.FileFact{
			fileFact("model/user.go", facts.LangGo),
			fileFact("handler/user_handler.go", facts.LangGo),
		},
		Symbols: []facts.SymbolFact{
			sym("user", "struct", "model/user.go", facts.LangGo, false, 1, 10),
			sym("Getuser", "function", "handler/user_handler.go", facts.LangGo, true, 1, 20),
		},
	}

	ev := findDBModelInRouteHandler(rule, fs)
	if len(ev) != 0 {
		t.Errorf("expected 0 evidence for unexported model, got %d", len(ev))
	}
}

func TestFindDBModelInRouteHandler_LanguageFilter(t *testing.T) {
	rule := Rule{
		ID: "ARCH-002", Languages: []string{"python"},
	}
	fs := &FactSet{
		Files: []facts.FileFact{
			fileFact("model/user.go", facts.LangGo),
			fileFact("handler/user_handler.go", facts.LangGo),
		},
		Symbols: []facts.SymbolFact{
			sym("User", "struct", "model/user.go", facts.LangGo, true, 1, 10),
			sym("GetUser", "function", "handler/user_handler.go", facts.LangGo, true, 1, 20),
		},
	}

	ev := findDBModelInRouteHandler(rule, fs)
	if len(ev) != 0 {
		t.Errorf("expected 0 evidence for language mismatch, got %d", len(ev))
	}
}

func TestFindDBModelInRouteHandler_TestFileSkipped(t *testing.T) {
	rule := Rule{
		ID: "ARCH-002", Languages: []string{"go"},
	}
	fs := &FactSet{
		Files: []facts.FileFact{
			fileFact("model/user.go", facts.LangGo),
			fileFact("handler/user_handler_test.go", facts.LangGo),
		},
		Symbols: []facts.SymbolFact{
			sym("User", "struct", "model/user.go", facts.LangGo, true, 1, 10),
			sym("GetUser", "function", "handler/user_handler_test.go", facts.LangGo, true, 1, 20),
		},
	}

	ev := findDBModelInRouteHandler(rule, fs)
	if len(ev) != 0 {
		t.Errorf("expected 0 evidence for test file, got %d", len(ev))
	}
}

// ---------------------------------------------------------------------------
// findSingletonMutableGlobal
// ---------------------------------------------------------------------------

func TestFindSingletonMutableGlobal_Positive(t *testing.T) {
	rule := Rule{
		ID: "ARCH-003", Languages: []string{"go"},
	}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("DBInstance", "variable", "pkg/globals.go", facts.LangGo, true, 1, 5),
		},
	}

	ev := findSingletonMutableGlobal(rule, fs)
	if len(ev) != 1 {
		t.Fatalf("expected 1 evidence, got %d", len(ev))
	}
	if ev[0].Symbol != "DBInstance" {
		t.Errorf("symbol = %q, want DBInstance", ev[0].Symbol)
	}
}

func TestFindSingletonMutableGlobal_ClientName(t *testing.T) {
	rule := Rule{
		ID: "ARCH-003", Languages: []string{"go"},
	}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("RedisClient", "var", "pkg/redis.go", facts.LangGo, true, 1, 5),
		},
	}

	ev := findSingletonMutableGlobal(rule, fs)
	if len(ev) != 1 {
		t.Fatalf("expected 1 evidence for client name, got %d", len(ev))
	}
}

func TestFindSingletonMutableGlobal_ConnectionPool(t *testing.T) {
	rule := Rule{
		ID: "ARCH-003", Languages: []string{"typescript"},
	}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("ConnectionPool", "let", "src/pool.ts", facts.LangTypeScript, true, 1, 5),
		},
	}

	ev := findSingletonMutableGlobal(rule, fs)
	if len(ev) != 1 {
		t.Fatalf("expected 1 evidence for connection pool, got %d", len(ev))
	}
}

func TestFindSingletonMutableGlobal_Negative_Function(t *testing.T) {
	rule := Rule{
		ID: "ARCH-003", Languages: []string{"go"},
	}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("GetInstance", "function", "pkg/globals.go", facts.LangGo, true, 1, 5),
		},
	}

	ev := findSingletonMutableGlobal(rule, fs)
	if len(ev) != 0 {
		t.Errorf("expected 0 evidence for function kind, got %d", len(ev))
	}
}

func TestFindSingletonMutableGlobal_Negative_Unexported(t *testing.T) {
	rule := Rule{
		ID: "ARCH-003", Languages: []string{"go"},
	}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("dbInstance", "variable", "pkg/globals.go", facts.LangGo, false, 1, 5),
		},
	}

	ev := findSingletonMutableGlobal(rule, fs)
	if len(ev) != 0 {
		t.Errorf("expected 0 evidence for unexported symbol, got %d", len(ev))
	}
}

func TestFindSingletonMutableGlobal_Negative_SafeName(t *testing.T) {
	rule := Rule{
		ID: "ARCH-003", Languages: []string{"go"},
	}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("MaxRetries", "variable", "pkg/config.go", facts.LangGo, true, 1, 5),
		},
	}

	ev := findSingletonMutableGlobal(rule, fs)
	if len(ev) != 0 {
		t.Errorf("expected 0 evidence for safe name, got %d", len(ev))
	}
}

func TestFindSingletonMutableGlobal_TestFileSkipped(t *testing.T) {
	rule := Rule{
		ID: "ARCH-003", Languages: []string{"go"},
	}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("DBInstance", "variable", "pkg/globals_test.go", facts.LangGo, true, 1, 5),
		},
	}

	ev := findSingletonMutableGlobal(rule, fs)
	if len(ev) != 0 {
		t.Errorf("expected 0 evidence for test file, got %d", len(ev))
	}
}

func TestFindSingletonMutableGlobal_LanguageFilter(t *testing.T) {
	rule := Rule{
		ID: "ARCH-003", Languages: []string{"python"},
	}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("GlobalSingleton", "variable", "pkg/globals.go", facts.LangGo, true, 1, 5),
		},
	}

	ev := findSingletonMutableGlobal(rule, fs)
	if len(ev) != 0 {
		t.Errorf("expected 0 evidence for language mismatch, got %d", len(ev))
	}
}

// ---------------------------------------------------------------------------
// isRepoLayerFile
// ---------------------------------------------------------------------------

func TestIsRepoLayerFile(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"repo/user.go", true},
		{"internal/repository/user.go", true},
		{"dal/queries.go", true},
		{"data-access/store.go", true},
		{"data_access/store.go", true},
		{"handler.go", false},
		{"service/user.go", false},
		{"controllers/api.go", false},
	}
	for _, tc := range tests {
		got := isRepoLayerFile(tc.path)
		if got != tc.want {
			t.Errorf("isRepoLayerFile(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}

// ---------------------------------------------------------------------------
// isModelFile
// ---------------------------------------------------------------------------

func TestIsModelFile(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"model/user.go", true},
		{"entity/order.go", true},
		{"schema/product.go", true},
		{"service.go", false},
		{"handler/api.go", false},
	}
	for _, tc := range tests {
		got := isModelFile(tc.path)
		if got != tc.want {
			t.Errorf("isModelFile(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}

// ---------------------------------------------------------------------------
// isHandlerFile
// ---------------------------------------------------------------------------

func TestIsHandlerFile(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"controller/user.go", true},
		{"handler/api.go", true},
		{"routes/v1.go", true},
		{"model.go", false},
		{"service/user.go", false},
	}
	for _, tc := range tests {
		got := isHandlerFile(tc.path)
		if got != tc.want {
			t.Errorf("isHandlerFile(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}

// ---------------------------------------------------------------------------
// isTestFilePath
// ---------------------------------------------------------------------------

func TestIsTestFilePath(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"foo_test.go", true},
		{"src/app.test.ts", true},
		{"src/app.spec.js", true},
		{"src/test/helper.go", true},
		{"src/tests/foo.go", true},
		{"foo.go", false},
		{"src/main.ts", false},
	}
	for _, tc := range tests {
		got := isTestFilePath(tc.path)
		if got != tc.want {
			t.Errorf("isTestFilePath(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}

// ---------------------------------------------------------------------------
// findDBAccessOutsideRepo — ImportsDirect tests
// ---------------------------------------------------------------------------

func TestRepoEncapsulation_DirectImport(t *testing.T) {
	rule := Rule{
		ID: "ARCH-001", Languages: []string{"go"},
	}
	fs := &FactSet{
		Files: []facts.FileFact{
			fileFact("service/user.go", facts.LangGo),
		},
		DataAccess: []facts.DataAccessFact{
			{
				Language:      facts.LangGo,
				File:          "service/user.go",
				Span:          facts.Span{Start: 10, End: 10},
				Operation:     "Query",
				Backend:       "database/sql",
				ImportsDirect: true,
			},
		},
	}

	ev := findDBAccessOutsideRepo(rule, fs)
	// service/user.go is NOT a handler/controller file, so without CallerName
	// it should NOT be flagged (service layer DB access is legitimate).
	if len(ev) != 0 {
		t.Fatalf("expected 0 evidence for service-layer file without caller context, got %d", len(ev))
	}
}

func TestRepoEncapsulation_DirectImport_ControllerFile(t *testing.T) {
	// File in a controller path WITH direct import should still be flagged
	rule := Rule{
		ID: "ARCH-001", Languages: []string{"go"},
	}
	fs := &FactSet{
		Files: []facts.FileFact{
			fileFact("controllers/user.go", facts.LangGo),
		},
		DataAccess: []facts.DataAccessFact{
			{
				Language:      facts.LangGo,
				File:          "controllers/user.go",
				Span:          facts.Span{Start: 10, End: 10},
				Operation:     "Query",
				Backend:       "database/sql",
				ImportsDirect: true,
			},
		},
	}

	ev := findDBAccessOutsideRepo(rule, fs)
	if len(ev) != 1 {
		t.Fatalf("expected 1 evidence for controller file with direct DB import, got %d", len(ev))
	}
}

func TestRepoEncapsulation_IndirectAccess(t *testing.T) {
	// File in repo layer should NOT be flagged even with direct import
	rule := Rule{
		ID: "ARCH-001", Languages: []string{"go"},
	}
	fs := &FactSet{
		Files: []facts.FileFact{
			fileFact("repository/user.go", facts.LangGo),
		},
		DataAccess: []facts.DataAccessFact{
			{
				Language:      facts.LangGo,
				File:          "repository/user.go",
				Span:          facts.Span{Start: 10, End: 10},
				Operation:     "Query",
				Backend:       "database/sql",
				ImportsDirect: true,
			},
		},
	}

	ev := findDBAccessOutsideRepo(rule, fs)
	if len(ev) != 0 {
		t.Errorf("expected 0 evidence for repo layer file, got %d", len(ev))
	}
}

// ---------------------------------------------------------------------------
// findSingletonMutableGlobal — IsMutable / const tests
// ---------------------------------------------------------------------------

func TestSingletonMutable_ConstNotFlagged(t *testing.T) {
	rule := Rule{
		ID: "ARCH-003", Languages: []string{"go"},
	}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			{
				Name:      "DBInstance",
				Kind:      "const",
				File:      "pkg/globals.go",
				Language:  facts.LangGo,
				Exported:  true,
				IsMutable: false,
				Span:      facts.Span{Start: 1, End: 5},
			},
		},
	}

	ev := findSingletonMutableGlobal(rule, fs)
	if len(ev) != 0 {
		t.Errorf("expected 0 evidence for const declaration, got %d", len(ev))
	}
}

func TestSingletonMutable_VarFlagged(t *testing.T) {
	rule := Rule{
		ID: "ARCH-003", Languages: []string{"go"},
	}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			{
				Name:      "DBInstance",
				Kind:      "var",
				File:      "pkg/globals.go",
				Language:  facts.LangGo,
				Exported:  true,
				IsMutable: true,
				Span:      facts.Span{Start: 1, End: 5},
			},
		},
	}

	ev := findSingletonMutableGlobal(rule, fs)
	if len(ev) != 1 {
		t.Fatalf("expected 1 evidence for var declaration, got %d", len(ev))
	}
	if ev[0].Symbol != "DBInstance" {
		t.Errorf("symbol = %q, want DBInstance", ev[0].Symbol)
	}
}

// ---------------------------------------------------------------------------
// Task 8: findDBAccessOutsideRepo — file-scoped CallerName handler matching
// ---------------------------------------------------------------------------

// TestDBAccessOutsideRepo_CallerMatchesHandler_DirectImport verifies that a DataAccessFact
// whose CallerName matches a route handler in the same file AND ImportsDirect=true
// is flagged as a violation.
func TestDBAccessOutsideRepo_CallerMatchesHandler_DirectImport(t *testing.T) {
	rule := Rule{
		ID: "ARCH-001", Languages: []string{"go"},
	}
	fs := &FactSet{
		Routes: []facts.RouteFact{
			route("GET", "/api/users", "GetUsers", "handlers/user.go", facts.LangGo, nil),
		},
		DataAccess: []facts.DataAccessFact{
			{
				Language:      facts.LangGo,
				File:          "handlers/user.go",
				Span:          facts.Span{Start: 15, End: 15},
				Operation:     "db.Query",
				Backend:       "database/sql",
				CallerName:    "GetUsers",
				ImportsDirect: true,
			},
		},
	}
	ev := findDBAccessOutsideRepo(rule, fs)
	if len(ev) != 1 {
		t.Fatalf("expected 1 evidence (caller=route handler + ImportsDirect=true), got %d", len(ev))
	}
	if ev[0].Symbol != "db.Query" {
		t.Errorf("symbol = %q, want db.Query", ev[0].Symbol)
	}
}

// TestDBAccessOutsideRepo_CallerMatchesHandler_NotDirect verifies that a DataAccessFact
// whose CallerName matches a route handler BUT ImportsDirect=false is skipped
// (delegated access — the actual DB call is elsewhere).
func TestDBAccessOutsideRepo_CallerMatchesHandler_NotDirect(t *testing.T) {
	rule := Rule{
		ID: "ARCH-001", Languages: []string{"go"},
	}
	fs := &FactSet{
		Routes: []facts.RouteFact{
			route("GET", "/api/users", "GetUsers", "handlers/user.go", facts.LangGo, nil),
		},
		DataAccess: []facts.DataAccessFact{
			{
				Language:      facts.LangGo,
				File:          "handlers/user.go",
				Span:          facts.Span{Start: 15, End: 15},
				Operation:     "repo.FindAll",
				Backend:       "internal/repo",
				CallerName:    "GetUsers",
				ImportsDirect: false, // delegated — handler calls repo, not DB directly
			},
		},
	}
	ev := findDBAccessOutsideRepo(rule, fs)
	if len(ev) != 0 {
		t.Errorf("expected 0 evidence (CallerName=handler but ImportsDirect=false → delegated), got %d", len(ev))
	}
}

// TestDBAccessOutsideRepo_CallerNoMatch_FallsBackToFileHeuristic verifies that when
// CallerName is set but does NOT match any route handler in the same file,
// the file-path heuristic is used (flagged if file path looks like a handler).
func TestDBAccessOutsideRepo_CallerNoMatch_HandlerFile(t *testing.T) {
	rule := Rule{
		ID: "ARCH-001", Languages: []string{"go"},
	}
	fs := &FactSet{
		Routes: []facts.RouteFact{
			route("GET", "/api/users", "GetUsers", "handlers/user.go", facts.LangGo, nil),
		},
		DataAccess: []facts.DataAccessFact{
			{
				Language:   facts.LangGo,
				File:       "handlers/helper.go", // same handler dir, different file → no route match
				Span:       facts.Span{Start: 5, End: 5},
				Operation:  "db.Exec",
				CallerName: "HelperFunc", // not a route handler
			},
		},
	}
	ev := findDBAccessOutsideRepo(rule, fs)
	// CallerName doesn't match a route handler in same file → file-path heuristic
	// "handlers/helper.go" matches isHandlerFile → flagged
	if len(ev) != 1 {
		t.Fatalf("expected 1 evidence (file-path fallback for non-handler caller in handler dir), got %d", len(ev))
	}
}

// TestDBAccessOutsideRepo_CallerMatchesHandler_DifferentFile verifies that a route handler
// in a DIFFERENT file does NOT match a DataAccessFact in another file
// (file-scoped matching prevents cross-file false positives).
func TestDBAccessOutsideRepo_CallerMatchesHandler_DifferentFile(t *testing.T) {
	rule := Rule{
		ID: "ARCH-001", Languages: []string{"go"},
	}
	fs := &FactSet{
		Routes: []facts.RouteFact{
			// GetUsers handler is in handlers/user.go
			route("GET", "/api/users", "GetUsers", "handlers/user.go", facts.LangGo, nil),
		},
		DataAccess: []facts.DataAccessFact{
			{
				Language:      facts.LangGo,
				File:          "service/user_service.go", // different file
				Span:          facts.Span{Start: 20, End: 20},
				Operation:     "db.Query",
				CallerName:    "GetUsers", // same name as route handler, but in different file
				ImportsDirect: true,
			},
		},
	}
	ev := findDBAccessOutsideRepo(rule, fs)
	// CallerName="GetUsers" but DataAccess is in service/user_service.go, not handlers/user.go
	// → route handler lookup uses "file:name" key, so no match
	// → falls back to file-path heuristic: service/user_service.go is not a handler file
	if len(ev) != 0 {
		t.Errorf("expected 0 evidence (route handler in different file, service dir is not handler dir), got %d", len(ev))
	}
}

// TestDBAccessOutsideRepo_NoCallerName_DirectImport verifies that a DataAccessFact
// without CallerName AND with ImportsDirect=true is flagged (no heuristic needed).
func TestDBAccessOutsideRepo_NoCallerName_DirectImport(t *testing.T) {
	rule := Rule{
		ID: "ARCH-001", Languages: []string{"go"},
	}
	fs := &FactSet{
		DataAccess: []facts.DataAccessFact{
			{
				Language:      facts.LangGo,
				File:          "cmd/main.go",
				Span:          facts.Span{Start: 10, End: 10},
				Operation:     "sql.Open",
				ImportsDirect: true,
				// CallerName is empty
			},
		},
	}
	ev := findDBAccessOutsideRepo(rule, fs)
	// cmd/main.go is NOT a handler/controller file, so without CallerName
	// the file-path heuristic should NOT flag it.
	if len(ev) != 0 {
		t.Fatalf("expected 0 evidence (cmd/main.go is not a handler file), got %d", len(ev))
	}
}
