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
	// GetUser does not contain "User" as substring... let's set up a matching name
	// Actually "GetUser" does contain "User" — so this should match.
	if len(ev) != 1 {
		t.Fatalf("expected 1 evidence, got %d", len(ev))
	}
	if ev[0].File != "handler/user_handler.go" {
		t.Errorf("file = %q, want handler/user_handler.go", ev[0].File)
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
		Routes: []facts.RouteFact{
			route("GET", "/users", "ListUser", "api/v1/endpoints.go", facts.LangGo, nil),
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
