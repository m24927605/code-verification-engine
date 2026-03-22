package rules

import (
	"testing"

	"github.com/verabase/code-verification-engine/internal/facts"
)

// ---------------------------------------------------------------------------
// findDirectDBAccessFromController — caller context tests
// ---------------------------------------------------------------------------

func TestDirectDBAccess_CallerIsHandler(t *testing.T) {
	rule := Rule{
		ID: "SEC-001", Target: "db.direct_access_from_controller", Languages: []string{"go"},
	}
	fs := &FactSet{
		Files: []facts.FileFact{
			fileFact("handler/user.go", facts.LangGo),
		},
		Symbols: []facts.SymbolFact{
			sym("GetUser", "function", "handler/user.go", facts.LangGo, true, 12, 20),
		},
		DataAccess: []facts.DataAccessFact{
			{
				Language:      facts.LangGo,
				File:          "handler/user.go",
				Span:          facts.Span{Start: 15, End: 15},
				Operation:     "QueryRow",
				Backend:       "database/sql",
				CallerName:    "GetUser",

				ImportsDirect: true,
			},
		},
	}

	ev := findDirectDBAccessFromController(rule, fs)
	if len(ev) != 1 {
		t.Fatalf("expected 1 evidence, got %d", len(ev))
	}
	if ev[0].Symbol != "QueryRow" {
		t.Errorf("symbol = %q, want QueryRow", ev[0].Symbol)
	}
}

func TestDirectDBAccess_CallerIsService(t *testing.T) {
	rule := Rule{
		ID: "SEC-001", Target: "db.direct_access_from_controller", Languages: []string{"go"},
	}
	fs := &FactSet{
		Files: []facts.FileFact{
			fileFact("service/user.go", facts.LangGo),
		},
		Symbols: []facts.SymbolFact{
			sym("CreateUser", "function", "service/user.go", facts.LangGo, true, 10, 30),
		},
		DataAccess: []facts.DataAccessFact{
			{
				Language:      facts.LangGo,
				File:          "service/user.go",
				Span:          facts.Span{Start: 20, End: 20},
				Operation:     "Exec",
				Backend:       "database/sql",
				CallerName:    "CreateUser",

				ImportsDirect: true,
			},
		},
	}

	ev := findDirectDBAccessFromController(rule, fs)
	if len(ev) != 0 {
		t.Errorf("expected 0 evidence for service caller, got %d", len(ev))
	}
}

func TestDirectDBAccess_FallbackToPath(t *testing.T) {
	rule := Rule{
		ID: "SEC-001", Target: "db.direct_access_from_controller", Languages: []string{"go"},
	}
	fs := &FactSet{
		Files: []facts.FileFact{
			fileFact("controller/api.go", facts.LangGo),
		},
		DataAccess: []facts.DataAccessFact{
			// No CallerName — falls back to file path heuristic
			dataAccess("db.Query", "controller/api.go", facts.LangGo),
		},
	}

	ev := findDirectDBAccessFromController(rule, fs)
	if len(ev) != 1 {
		t.Fatalf("expected 1 evidence via path fallback, got %d", len(ev))
	}
	if ev[0].File != "controller/api.go" {
		t.Errorf("file = %q, want controller/api.go", ev[0].File)
	}
}

func TestDirectDBAccess_CallerInRouteHandler(t *testing.T) {
	rule := Rule{
		ID: "SEC-001", Target: "db.direct_access_from_controller", Languages: []string{"go"},
	}
	fs := &FactSet{
		Files: []facts.FileFact{
			fileFact("api/endpoints.go", facts.LangGo),
		},
		Symbols: []facts.SymbolFact{
			sym("ListUsers", "function", "api/endpoints.go", facts.LangGo, true, 10, 30),
		},
		Routes: []facts.RouteFact{
			route("GET", "/users", "ListUsers", "api/endpoints.go", facts.LangGo, nil),
		},
		DataAccess: []facts.DataAccessFact{
			{
				Language:      facts.LangGo,
				File:          "api/endpoints.go",
				Span:          facts.Span{Start: 20, End: 20},
				Operation:     "Query",
				Backend:       "database/sql",
				CallerName:    "ListUsers",

				ImportsDirect: true,
			},
		},
	}

	ev := findDirectDBAccessFromController(rule, fs)
	if len(ev) != 1 {
		t.Fatalf("expected 1 evidence for route handler doing DB access, got %d", len(ev))
	}
}

func TestDirectDBAccess_CallerWithContext_NotController(t *testing.T) {
	// A file in handler/ directory but the caller function is a utility, not a handler.
	// Since the caller has context and the file IS a controller file, it still gets flagged.
	rule := Rule{
		ID: "SEC-001", Target: "db.direct_access_from_controller", Languages: []string{"go"},
	}
	fs := &FactSet{
		Files: []facts.FileFact{
			fileFact("internal/service/db.go", facts.LangGo),
		},
		Symbols: []facts.SymbolFact{
			sym("initDB", "function", "internal/service/db.go", facts.LangGo, false, 1, 10),
		},
		DataAccess: []facts.DataAccessFact{
			{
				Language:      facts.LangGo,
				File:          "internal/service/db.go",
				Span:          facts.Span{Start: 5, End: 5},
				Operation:     "Exec",
				Backend:       "database/sql",
				CallerName:    "initDB",

				ImportsDirect: true,
			},
		},
	}

	ev := findDirectDBAccessFromController(rule, fs)
	if len(ev) != 0 {
		t.Errorf("expected 0 evidence for non-controller caller in non-controller file, got %d", len(ev))
	}
}

// ---------------------------------------------------------------------------
// findDirectDBAccessFromController — original behavior preserved
// ---------------------------------------------------------------------------

func TestDirectDBAccess_FilePathHeuristic(t *testing.T) {
	rule := Rule{
		ID: "SEC-001", Target: "db.direct_access_from_controller", Languages: []string{"go"},
	}
	fs := &FactSet{
		Files: []facts.FileFact{
			fileFact("handlers/user.go", facts.LangGo),
		},
		Symbols: []facts.SymbolFact{
			sym("UserHandler", "struct", "handlers/user.go", facts.LangGo, true, 1, 5),
		},
		DataAccess: []facts.DataAccessFact{
			dataAccess("Query", "handlers/user.go", facts.LangGo),
		},
	}

	ev := findDirectDBAccessFromController(rule, fs)
	if len(ev) != 1 {
		t.Fatalf("expected 1 evidence, got %d", len(ev))
	}
}

func TestDirectDBAccess_SymbolNameMatch(t *testing.T) {
	rule := Rule{
		ID: "SEC-001", Target: "db.direct_access_from_controller", Languages: []string{"go"},
	}
	fs := &FactSet{
		Files: []facts.FileFact{
			fileFact("api/user.go", facts.LangGo),
		},
		Symbols: []facts.SymbolFact{
			sym("UserController", "struct", "api/user.go", facts.LangGo, true, 1, 5),
		},
		DataAccess: []facts.DataAccessFact{
			dataAccess("Query", "api/user.go", facts.LangGo),
		},
	}

	ev := findDirectDBAccessFromController(rule, fs)
	if len(ev) != 1 {
		t.Fatalf("expected 1 evidence via symbol name, got %d", len(ev))
	}
}

func TestDirectDBAccess_LanguageFilter(t *testing.T) {
	rule := Rule{
		ID: "SEC-001", Target: "db.direct_access_from_controller", Languages: []string{"python"},
	}
	fs := &FactSet{
		Files: []facts.FileFact{
			fileFact("handler/user.go", facts.LangGo),
		},
		DataAccess: []facts.DataAccessFact{
			dataAccess("Query", "handler/user.go", facts.LangGo),
		},
	}

	ev := findDirectDBAccessFromController(rule, fs)
	if len(ev) != 0 {
		t.Errorf("expected 0 evidence for language mismatch, got %d", len(ev))
	}
}
