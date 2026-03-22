package rules

import (
	"testing"

	"github.com/verabase/code-verification-engine/internal/facts"
)

// ---------------------------------------------------------------------------
// 1. Auth with binding evidence produces structural-level finding
// ---------------------------------------------------------------------------

func TestAuthWithAppBindingEvidence(t *testing.T) {
	rule := Rule{
		ID:        "SEC-AUTH-001",
		Target:    "auth.jwt_middleware",
		Languages: []string{"typescript"},
		Type:      "exists",
	}
	fs := &FactSet{
		AppBindings: []facts.AppBindingFact{
			{
				Language: facts.LangTypeScript,
				File:     "src/app.module.ts",
				Span:     facts.Span{Start: 10, End: 12},
				Kind:     "guard",
				Name:     "JwtAuthGuard",
				Scope:    "global",
			},
		},
		// Provide minimal symbols to satisfy hasMinimalFacts
		Symbols: []facts.SymbolFact{
			sym("AppModule", "class", "src/app.module.ts", facts.LangTypeScript, true, 1, 20),
		},
	}

	finding := matchExists(rule, fs, []string{"typescript"})
	if finding.Status != StatusPass {
		t.Errorf("expected pass, got %s", finding.Status)
	}
	if finding.VerificationLevel != VerificationStrongInference {
		t.Errorf("expected strong_inference for binding evidence, got %s", finding.VerificationLevel)
	}
	if len(finding.Evidence) == 0 {
		t.Error("expected evidence from AppBindings")
	}
	// Evidence should reference the binding
	for _, ev := range finding.Evidence {
		if ev.File != "src/app.module.ts" {
			t.Errorf("expected evidence from app.module.ts, got %s", ev.File)
		}
	}
}

func TestAuthWithRouteBindingEvidence(t *testing.T) {
	rule := Rule{
		ID:        "SEC-AUTH-001",
		Target:    "auth.jwt_middleware",
		Languages: []string{"typescript"},
		Type:      "exists",
	}
	fs := &FactSet{
		RouteBindings: []facts.RouteBindingFact{
			{
				Language:    facts.LangTypeScript,
				File:        "src/users/users.controller.ts",
				Span:        facts.Span{Start: 5, End: 8},
				Handler:     "getProfile",
				Method:      "GET",
				Path:        "/users/profile",
				Middlewares: []string{"authMiddleware"},
			},
		},
		Symbols: []facts.SymbolFact{
			sym("UsersController", "class", "src/users/users.controller.ts", facts.LangTypeScript, true, 1, 30),
		},
	}

	finding := matchExists(rule, fs, []string{"typescript"})
	if finding.Status != StatusPass {
		t.Errorf("expected pass, got %s", finding.Status)
	}
	if finding.VerificationLevel != VerificationStrongInference {
		t.Errorf("expected strong_inference for route binding evidence, got %s", finding.VerificationLevel)
	}
}

func TestAuthWithRouteBindingGuardEvidence(t *testing.T) {
	rule := Rule{
		ID:        "SEC-AUTH-001",
		Target:    "auth.jwt_middleware",
		Languages: []string{"typescript"},
		Type:      "exists",
	}
	fs := &FactSet{
		RouteBindings: []facts.RouteBindingFact{
			{
				Language: facts.LangTypeScript,
				File:     "src/orders/orders.controller.ts",
				Span:     facts.Span{Start: 10, End: 15},
				Handler:  "createOrder",
				Method:   "POST",
				Path:     "/orders",
				Guards:   []string{"JwtAuthGuard"},
			},
		},
		Symbols: []facts.SymbolFact{
			sym("OrdersController", "class", "src/orders/orders.controller.ts", facts.LangTypeScript, true, 1, 40),
		},
	}

	finding := matchExists(rule, fs, []string{"typescript"})
	if finding.Status != StatusPass {
		t.Errorf("expected pass, got %s", finding.Status)
	}
	if finding.VerificationLevel != VerificationStrongInference {
		t.Errorf("expected strong_inference for guard binding evidence, got %s", finding.VerificationLevel)
	}
}

// ---------------------------------------------------------------------------
// 2. Auth without binding falls back to heuristic (current behavior)
// ---------------------------------------------------------------------------

func TestAuthWithoutBindingFallsBackToHeuristic(t *testing.T) {
	rule := Rule{
		ID:        "SEC-AUTH-001",
		Target:    "auth.jwt_middleware",
		Languages: []string{"typescript"},
		Type:      "exists",
	}
	fs := &FactSet{
		// No AppBindings, no RouteBindings
		Middlewares: []facts.MiddlewareFact{
			mw("JwtAuthGuard", "guard", "src/auth/jwt-auth.guard.ts", facts.LangTypeScript),
		},
		Imports: []facts.ImportFact{
			imp("@nestjs/jwt", "", "src/auth/jwt-auth.guard.ts", facts.LangTypeScript),
		},
		Symbols: []facts.SymbolFact{
			sym("JwtAuthGuard", "class", "src/auth/jwt-auth.guard.ts", facts.LangTypeScript, true, 1, 20),
		},
	}

	finding := matchExists(rule, fs, []string{"typescript"})
	if finding.Status != StatusPass {
		t.Errorf("expected pass via heuristic fallback, got %s", finding.Status)
	}
	// Without binding evidence, the heuristic produces weak_inference
	// (HasAuthImport +2, HasAuthName +1 = score 3 → AuthWeak → weak_inference).
	// This is the expected pre-Phase 4 behavior for exists-level auth checks.
	if finding.VerificationLevel != VerificationWeakInference {
		t.Errorf("expected weak_inference for heuristic auth (no binding), got %s", finding.VerificationLevel)
	}
}

func TestAuthNoEvidenceAtAll(t *testing.T) {
	rule := Rule{
		ID:        "SEC-AUTH-001",
		Target:    "auth.jwt_middleware",
		Languages: []string{"typescript"},
		Type:      "exists",
	}
	fs := &FactSet{
		// No auth-related facts at all
		Symbols: []facts.SymbolFact{
			sym("AppService", "class", "src/app.service.ts", facts.LangTypeScript, true, 1, 10),
		},
	}

	finding := matchExists(rule, fs, []string{"typescript"})
	if finding.Status != StatusFail {
		t.Errorf("expected fail when no auth evidence, got %s", finding.Status)
	}
}

// ---------------------------------------------------------------------------
// 3. Config with ConfigReads uses env source
// ---------------------------------------------------------------------------

func TestConfigWithConfigReadsEnvSource(t *testing.T) {
	rule := Rule{
		ID:        "SEC-SECRET-002",
		Target:    "config.env_based",
		Languages: []string{"typescript"},
		Type:      "exists",
	}
	fs := &FactSet{
		ConfigReads: []facts.ConfigReadFact{
			{
				Language:   facts.LangTypeScript,
				File:       "src/config/app.config.ts",
				Span:       facts.Span{Start: 5, End: 5},
				Key:        "DATABASE_URL",
				SourceKind: "env",
			},
			{
				Language:   facts.LangTypeScript,
				File:       "src/config/app.config.ts",
				Span:       facts.Span{Start: 6, End: 6},
				Key:        "JWT_SECRET",
				SourceKind: "env",
			},
		},
		Symbols: []facts.SymbolFact{
			sym("AppConfig", "class", "src/config/app.config.ts", facts.LangTypeScript, true, 1, 10),
		},
	}

	finding := matchExists(rule, fs, []string{"typescript"})
	if finding.Status != StatusPass {
		t.Errorf("expected pass, got %s", finding.Status)
	}
	if finding.VerificationLevel != VerificationStrongInference {
		t.Errorf("expected strong_inference for ConfigReads evidence, got %s", finding.VerificationLevel)
	}
	if len(finding.Evidence) == 0 {
		t.Error("expected evidence from ConfigReads")
	}
	// Evidence should reference config_read keys
	foundConfigRead := false
	for _, ev := range finding.Evidence {
		if ev.Symbol == "config_read:DATABASE_URL" || ev.Symbol == "config_read:JWT_SECRET" {
			foundConfigRead = true
		}
	}
	if !foundConfigRead {
		t.Error("expected evidence symbols to reference config_read keys")
	}
}

func TestConfigWithConfigReadsNonEnvIgnored(t *testing.T) {
	// ConfigReads with non-env source should not produce binding evidence,
	// and should fall back to import heuristic.
	rule := Rule{
		ID:        "SEC-SECRET-002",
		Target:    "config.env_based",
		Languages: []string{"typescript"},
		Type:      "exists",
	}
	fs := &FactSet{
		ConfigReads: []facts.ConfigReadFact{
			{
				Language:   facts.LangTypeScript,
				File:       "src/config/app.config.ts",
				Span:       facts.Span{Start: 5, End: 5},
				Key:        "app.port",
				SourceKind: "file", // not env
			},
		},
		Imports: []facts.ImportFact{
			imp("dotenv", "", "src/main.ts", facts.LangTypeScript),
		},
		Symbols: []facts.SymbolFact{
			sym("bootstrap", "function", "src/main.ts", facts.LangTypeScript, true, 1, 10),
		},
	}

	finding := matchExists(rule, fs, []string{"typescript"})
	if finding.Status != StatusPass {
		t.Errorf("expected pass via import fallback, got %s", finding.Status)
	}
	// Should use import heuristic path → verified level
	if finding.VerificationLevel != VerificationVerified {
		t.Errorf("expected verified for import-heuristic fallback, got %s", finding.VerificationLevel)
	}
}

// ---------------------------------------------------------------------------
// 4. Config without ConfigReads falls back to imports
// ---------------------------------------------------------------------------

func TestConfigWithoutConfigReadsFallsBackToImports(t *testing.T) {
	rule := Rule{
		ID:        "SEC-SECRET-002",
		Target:    "config.env_based",
		Languages: []string{"go"},
		Type:      "exists",
	}
	fs := &FactSet{
		// No ConfigReads
		Imports: []facts.ImportFact{
			imp("github.com/joho/godotenv", "", "main.go", facts.LangGo),
		},
		Symbols: []facts.SymbolFact{
			sym("main", "function", "main.go", facts.LangGo, true, 1, 10),
		},
	}

	finding := matchExists(rule, fs, []string{"go"})
	if finding.Status != StatusPass {
		t.Errorf("expected pass via import heuristic, got %s", finding.Status)
	}
	if finding.VerificationLevel != VerificationVerified {
		t.Errorf("expected verified for import-heuristic fallback, got %s", finding.VerificationLevel)
	}
	if len(finding.Evidence) == 0 {
		t.Error("expected evidence from import heuristic")
	}
}

// ---------------------------------------------------------------------------
// 5. Architecture with FileRoles uses role classification
// ---------------------------------------------------------------------------

func TestDirectDBAccessWithFileRoles(t *testing.T) {
	rule := Rule{
		ID:        "ARCH-LAYER-001",
		Target:    "db.direct_access_from_controller",
		Languages: []string{"typescript"},
		Type:      "not_exists",
	}
	fs := &FactSet{
		FileRoles: []facts.FileRoleFact{
			{
				Language: facts.LangTypeScript,
				File:     "src/users/users.controller.ts",
				Role:     "controller",
			},
			{
				Language: facts.LangTypeScript,
				File:     "src/users/users.service.ts",
				Role:     "service",
			},
		},
		DataAccess: []facts.DataAccessFact{
			{
				Language:  facts.LangTypeScript,
				File:      "src/users/users.controller.ts",
				Operation: "prisma.user.findMany",
				Backend:   "prisma",
				Span:      facts.Span{Start: 15, End: 15},
			},
		},
		Files: []facts.FileFact{
			fileFact("src/users/users.controller.ts", facts.LangTypeScript),
			fileFact("src/users/users.service.ts", facts.LangTypeScript),
		},
		Symbols: []facts.SymbolFact{
			sym("UsersController", "class", "src/users/users.controller.ts", facts.LangTypeScript, true, 1, 30),
		},
	}

	finding := matchNotExists(rule, fs, []string{"typescript"})
	if finding.Status != StatusFail {
		t.Errorf("expected fail (DB access in controller), got %s", finding.Status)
	}
	if len(finding.Evidence) == 0 {
		t.Error("expected evidence of DB access in controller file")
	}
}

func TestDirectDBAccessWithFileRoles_ServiceFileNotFlagged(t *testing.T) {
	// DB access in a service file (identified by FileRoles) should not be flagged.
	rule := Rule{
		ID:        "ARCH-LAYER-001",
		Target:    "db.direct_access_from_controller",
		Languages: []string{"typescript"},
		Type:      "not_exists",
	}
	fs := &FactSet{
		FileRoles: []facts.FileRoleFact{
			{
				Language: facts.LangTypeScript,
				File:     "src/users/users.service.ts",
				Role:     "service",
			},
		},
		DataAccess: []facts.DataAccessFact{
			{
				Language:  facts.LangTypeScript,
				File:      "src/users/users.service.ts",
				Operation: "prisma.user.findMany",
				Backend:   "prisma",
				Span:      facts.Span{Start: 15, End: 15},
			},
		},
		Files: []facts.FileFact{
			fileFact("src/users/users.service.ts", facts.LangTypeScript),
		},
		Symbols: []facts.SymbolFact{
			sym("UsersService", "class", "src/users/users.service.ts", facts.LangTypeScript, true, 1, 30),
		},
	}

	finding := matchNotExists(rule, fs, []string{"typescript"})
	if finding.Status != StatusPass {
		t.Errorf("expected pass (DB access in service, not controller), got %s", finding.Status)
	}
}

// ---------------------------------------------------------------------------
// 6. Architecture without FileRoles uses path heuristics (backward compat)
// ---------------------------------------------------------------------------

func TestDirectDBAccessWithoutFileRoles_PathHeuristic(t *testing.T) {
	rule := Rule{
		ID:        "ARCH-LAYER-001",
		Target:    "db.direct_access_from_controller",
		Languages: []string{"typescript"},
		Type:      "not_exists",
	}
	fs := &FactSet{
		// No FileRoles — should fall back to path heuristics
		DataAccess: []facts.DataAccessFact{
			{
				Language:  facts.LangTypeScript,
				File:      "src/users/users.controller.ts",
				Operation: "prisma.user.findMany",
				Backend:   "prisma",
				Span:      facts.Span{Start: 15, End: 15},
			},
		},
		Files: []facts.FileFact{
			fileFact("src/users/users.controller.ts", facts.LangTypeScript),
		},
		Symbols: []facts.SymbolFact{
			sym("UsersController", "class", "src/users/users.controller.ts", facts.LangTypeScript, true, 1, 30),
		},
	}

	finding := matchNotExists(rule, fs, []string{"typescript"})
	if finding.Status != StatusFail {
		t.Errorf("expected fail (DB access in controller by path heuristic), got %s", finding.Status)
	}
	if len(finding.Evidence) == 0 {
		t.Error("expected evidence of DB access in controller file via path heuristic")
	}
}

func TestDirectDBAccessWithoutFileRoles_NonControllerPath(t *testing.T) {
	// DB access in a file without controller in its path should not be flagged
	// when there are no FileRoles.
	rule := Rule{
		ID:        "ARCH-LAYER-001",
		Target:    "db.direct_access_from_controller",
		Languages: []string{"typescript"},
		Type:      "not_exists",
	}
	fs := &FactSet{
		DataAccess: []facts.DataAccessFact{
			{
				Language:  facts.LangTypeScript,
				File:      "src/users/users.service.ts",
				Operation: "prisma.user.findMany",
				Backend:   "prisma",
				Span:      facts.Span{Start: 15, End: 15},
			},
		},
		Files: []facts.FileFact{
			fileFact("src/users/users.service.ts", facts.LangTypeScript),
		},
		Symbols: []facts.SymbolFact{
			sym("UsersService", "class", "src/users/users.service.ts", facts.LangTypeScript, true, 1, 30),
		},
	}

	finding := matchNotExists(rule, fs, []string{"typescript"})
	if finding.Status != StatusPass {
		t.Errorf("expected pass (DB access in service file, not controller), got %s", finding.Status)
	}
}

// ---------------------------------------------------------------------------
// Helpers: fileRoleIs and findAuthBindingEvidence unit tests
// ---------------------------------------------------------------------------

func TestFileRoleIs(t *testing.T) {
	fs := &FactSet{
		FileRoles: []facts.FileRoleFact{
			{Language: facts.LangTypeScript, File: "src/users/users.controller.ts", Role: "controller"},
			{Language: facts.LangTypeScript, File: "src/users/users.service.ts", Role: "service"},
		},
	}

	if !fileRoleIs(fs, "src/users/users.controller.ts", "controller") {
		t.Error("expected fileRoleIs to return true for controller")
	}
	if !fileRoleIs(fs, "src/users/users.service.ts", "service") {
		t.Error("expected fileRoleIs to return true for service")
	}
	if fileRoleIs(fs, "src/users/users.controller.ts", "service") {
		t.Error("expected fileRoleIs to return false for wrong role")
	}
	if fileRoleIs(fs, "src/unknown/file.ts", "controller") {
		t.Error("expected fileRoleIs to return false for unknown file")
	}
}

func TestFileRoleIs_EmptyFileRoles(t *testing.T) {
	fs := &FactSet{}
	if fileRoleIs(fs, "src/users/users.controller.ts", "controller") {
		t.Error("expected fileRoleIs to return false when FileRoles is empty")
	}
}

func TestFindAuthBindingEvidence_NoBindings(t *testing.T) {
	rule := Rule{
		ID:        "SEC-AUTH-001",
		Languages: []string{"typescript"},
	}
	fs := &FactSet{}
	ev := findAuthBindingEvidence(rule, fs)
	if len(ev) != 0 {
		t.Errorf("expected no evidence without bindings, got %d", len(ev))
	}
}

func TestFindAuthBindingEvidence_NonAuthBinding(t *testing.T) {
	rule := Rule{
		ID:        "SEC-AUTH-001",
		Languages: []string{"typescript"},
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
		},
	}
	ev := findAuthBindingEvidence(rule, fs)
	if len(ev) != 0 {
		t.Errorf("expected no evidence for non-auth binding, got %d", len(ev))
	}
}

func TestFindAuthBindingEvidence_LanguageMismatch(t *testing.T) {
	rule := Rule{
		ID:        "SEC-AUTH-001",
		Languages: []string{"go"},
	}
	fs := &FactSet{
		AppBindings: []facts.AppBindingFact{
			{
				Language: facts.LangTypeScript,
				File:     "src/app.module.ts",
				Span:     facts.Span{Start: 10, End: 12},
				Kind:     "guard",
				Name:     "JwtAuthGuard",
				Scope:    "global",
			},
		},
	}
	ev := findAuthBindingEvidence(rule, fs)
	if len(ev) != 0 {
		t.Errorf("expected no evidence for language mismatch, got %d", len(ev))
	}
}
