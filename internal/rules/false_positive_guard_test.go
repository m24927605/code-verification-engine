package rules

import (
	"testing"

	"github.com/verabase/code-verification-engine/internal/facts"
)

// ---------------------------------------------------------------------------
// Guard 1: Auth binding false positive guard
// When AppBindings contain only non-auth middleware (e.g., logging),
// the auth matcher should NOT match.
// ---------------------------------------------------------------------------

func TestAuthBindingFalsePositive_NonAuthMiddleware(t *testing.T) {
	rule := Rule{
		ID:           "SEC-AUTH-001",
		Title:        "JWT authentication must exist",
		Category:     "security",
		Severity:     "high",
		Languages:    []string{"typescript"},
		Type:         "exists",
		Target:       "auth.jwt_middleware",
		Message:      "Test",
		MatcherClass: MatcherHeuristic,
	}

	fs := &FactSet{
		AppBindings: []facts.AppBindingFact{
			{
				Language: facts.LangTypeScript,
				File:     "src/app.module.ts",
				Span:     facts.Span{Start: 10, End: 12},
				Kind:     "middleware",
				Name:     "LoggingMiddleware",
				Scope:    "global",
			},
			{
				Language: facts.LangTypeScript,
				File:     "src/app.module.ts",
				Span:     facts.Span{Start: 13, End: 15},
				Kind:     "middleware",
				Name:     "CorsMiddleware",
				Scope:    "global",
			},
			{
				Language: facts.LangTypeScript,
				File:     "src/app.module.ts",
				Span:     facts.Span{Start: 16, End: 18},
				Kind:     "interceptor",
				Name:     "TransformInterceptor",
				Scope:    "global",
			},
		},
		Symbols: []facts.SymbolFact{
			{Name: "LoggingMiddleware", Kind: "class", File: "src/logging.middleware.ts", Language: facts.LangTypeScript, Span: facts.Span{Start: 1, End: 20}},
		},
	}

	ev := findAuthBindingEvidence(rule, fs)
	if len(ev) != 0 {
		t.Errorf("auth binding matcher should NOT match non-auth middleware, got %d evidence items: %+v", len(ev), ev)
	}
}

func TestAuthBindingFalsePositive_OnlyFilterKind(t *testing.T) {
	// AppBindings with Kind="filter" should not match auth detection
	rule := Rule{
		ID:        "SEC-AUTH-001",
		Languages: []string{"typescript"},
		Type:      "exists",
		Target:    "auth.jwt_middleware",
	}

	fs := &FactSet{
		AppBindings: []facts.AppBindingFact{
			{
				Language: facts.LangTypeScript,
				File:     "src/app.module.ts",
				Span:     facts.Span{Start: 10, End: 12},
				Kind:     "filter",
				Name:     "HttpExceptionFilter",
				Scope:    "global",
			},
		},
	}

	ev := findAuthBindingEvidence(rule, fs)
	if len(ev) != 0 {
		t.Errorf("filter-kind bindings should not produce auth evidence, got %d", len(ev))
	}
}

// ---------------------------------------------------------------------------
// Guard 2: Config env false positive guard
// When ConfigReads contain only file-based config (SourceKind="file"),
// env-based config matcher should NOT match via the ConfigReads path.
// ---------------------------------------------------------------------------

func TestConfigEnvFalsePositive_FileBasedConfig(t *testing.T) {
	rule := Rule{
		ID:           "SEC-SECRET-002",
		Title:        "Environment-based configuration must exist",
		Category:     "security",
		Severity:     "high",
		Languages:    []string{"typescript"},
		Type:         "exists",
		Target:       "config.env_based",
		Message:      "Test",
		MatcherClass: MatcherHeuristic,
	}

	fs := &FactSet{
		ConfigReads: []facts.ConfigReadFact{
			{
				Language:   facts.LangTypeScript,
				File:       "src/config/database.ts",
				Span:       facts.Span{Start: 5, End: 8},
				Key:        "database.host",
				SourceKind: "file",
			},
			{
				Language:   facts.LangTypeScript,
				File:       "src/config/app.ts",
				Span:       facts.Span{Start: 3, End: 6},
				Key:        "app.port",
				SourceKind: "file",
			},
		},
		// No imports that would match env packages
		Symbols: []facts.SymbolFact{
			{Name: "loadConfig", Kind: "function", File: "src/config/loader.ts", Language: facts.LangTypeScript, Span: facts.Span{Start: 1, End: 10}},
		},
	}

	result := findEnvBasedConfigResult(rule, fs)
	// With only file-based ConfigReads, the function should NOT take the env structural path.
	// It falls back to heuristic import matching, which should also find nothing.
	if len(result.Evidence) > 0 {
		// Check that the evidence is not from ConfigReads (file-based should not match env)
		for _, ev := range result.Evidence {
			if ev.Symbol == "config_read:database.host" || ev.Symbol == "config_read:app.port" {
				t.Errorf("file-based ConfigReads should NOT produce evidence for env-based config check, got: %+v", ev)
			}
		}
	}
}

func TestConfigEnvFalsePositive_MixedSourceKinds(t *testing.T) {
	// When ConfigReads contain both "file" and "env" SourceKinds,
	// only the "env" entries should produce evidence.
	rule := Rule{
		ID:        "SEC-SECRET-002",
		Languages: []string{"typescript"},
		Type:      "exists",
		Target:    "config.env_based",
	}

	fs := &FactSet{
		ConfigReads: []facts.ConfigReadFact{
			{
				Language:   facts.LangTypeScript,
				File:       "src/config/database.ts",
				Span:       facts.Span{Start: 5, End: 8},
				Key:        "database.host",
				SourceKind: "file",
			},
			{
				Language:   facts.LangTypeScript,
				File:       "src/config/secrets.ts",
				Span:       facts.Span{Start: 10, End: 12},
				Key:        "JWT_SECRET",
				SourceKind: "env",
			},
		},
	}

	ev := findEnvBasedConfig(rule, fs)
	if len(ev) == 0 {
		t.Fatal("expected evidence for env-sourced ConfigRead, got none")
	}
	// Should only contain the env-sourced entry
	for _, e := range ev {
		if e.Symbol == "config_read:database.host" {
			t.Errorf("file-based ConfigRead should not produce evidence, got: %+v", e)
		}
	}
}

// ---------------------------------------------------------------------------
// Guard 3: Architecture FileRole false positive guard
// When FileRoles mark a file as "service" (not controller),
// DB access in that file should NOT be flagged as controller-direct-access.
// ---------------------------------------------------------------------------

func TestArchFileRoleFalsePositive_ServiceFileNotController(t *testing.T) {
	rule := Rule{
		ID:           "ARCH-LAYER-001",
		Title:        "Controllers must not access database directly",
		Category:     "architecture",
		Severity:     "high",
		Languages:    []string{"typescript"},
		Type:         "not_exists",
		Target:       "db.direct_access_from_controller",
		Message:      "Test",
		MatcherClass: MatcherStructural,
	}

	fs := &FactSet{
		FileRoles: []facts.FileRoleFact{
			{Language: facts.LangTypeScript, File: "src/users/users.service.ts", Role: "service"},
		},
		DataAccess: []facts.DataAccessFact{
			{
				Language:  facts.LangTypeScript,
				File:      "src/users/users.service.ts",
				Span:      facts.Span{Start: 25, End: 28},
				Operation: "prisma.user.findMany",
				Backend:   "prisma",
			},
		},
		Files: []facts.FileFact{
			{File: "src/users/users.service.ts", Language: facts.LangTypeScript},
		},
		Symbols: []facts.SymbolFact{
			{Name: "UsersService", Kind: "class", File: "src/users/users.service.ts", Language: facts.LangTypeScript, Span: facts.Span{Start: 1, End: 50}},
		},
	}

	finding := matchNotExists(rule, fs, []string{"typescript"})
	// A service file with DB access should NOT produce a fail finding.
	// The file is marked as "service" by FileRoles, not "controller".
	// The path does not contain "controller", "handler", or "endpoint".
	if finding.Status == StatusFail {
		t.Errorf("DB access in a service file (FileRole=service) should NOT be flagged as controller-direct-access, got StatusFail with evidence: %+v", finding.Evidence)
	}
}

func TestArchFileRoleFalsePositive_ControllerFileShouldFlag(t *testing.T) {
	// Verify the positive case still works: controller file with DB access should fail
	rule := Rule{
		ID:           "ARCH-LAYER-001",
		Title:        "Controllers must not access database directly",
		Category:     "architecture",
		Severity:     "high",
		Languages:    []string{"typescript"},
		Type:         "not_exists",
		Target:       "db.direct_access_from_controller",
		Message:      "Test",
		MatcherClass: MatcherStructural,
	}

	fs := &FactSet{
		FileRoles: []facts.FileRoleFact{
			{Language: facts.LangTypeScript, File: "src/users/users.controller.ts", Role: "controller"},
		},
		DataAccess: []facts.DataAccessFact{
			{
				Language:  facts.LangTypeScript,
				File:      "src/users/users.controller.ts",
				Span:      facts.Span{Start: 25, End: 28},
				Operation: "prisma.user.findMany",
				Backend:   "prisma",
			},
		},
		Files: []facts.FileFact{
			{File: "src/users/users.controller.ts", Language: facts.LangTypeScript},
		},
		Symbols: []facts.SymbolFact{
			{Name: "UsersController", Kind: "class", File: "src/users/users.controller.ts", Language: facts.LangTypeScript, Span: facts.Span{Start: 1, End: 50}},
		},
	}

	finding := matchNotExists(rule, fs, []string{"typescript"})
	if finding.Status != StatusFail {
		t.Errorf("DB access in a controller file should be flagged, got Status=%q", finding.Status)
	}
}

func TestArchFileRoleFalsePositive_RepositoryFileNotController(t *testing.T) {
	// Files marked as "repository" should not be flagged even with DB access
	rule := Rule{
		ID:        "ARCH-LAYER-001",
		Languages: []string{"typescript"},
		Type:      "not_exists",
		Target:    "db.direct_access_from_controller",
	}

	fs := &FactSet{
		FileRoles: []facts.FileRoleFact{
			{Language: facts.LangTypeScript, File: "src/users/users.repository.ts", Role: "repository"},
		},
		DataAccess: []facts.DataAccessFact{
			{
				Language:  facts.LangTypeScript,
				File:      "src/users/users.repository.ts",
				Span:      facts.Span{Start: 10, End: 15},
				Operation: "prisma.user.findMany",
				Backend:   "prisma",
			},
		},
		Files: []facts.FileFact{
			{File: "src/users/users.repository.ts", Language: facts.LangTypeScript},
		},
		Symbols: []facts.SymbolFact{
			{Name: "UsersRepository", Kind: "class", File: "src/users/users.repository.ts", Language: facts.LangTypeScript, Span: facts.Span{Start: 1, End: 30}},
		},
	}

	finding := matchNotExists(rule, fs, []string{"typescript"})
	if finding.Status == StatusFail {
		t.Errorf("DB access in a repository file should NOT be flagged as controller-direct-access")
	}
}
