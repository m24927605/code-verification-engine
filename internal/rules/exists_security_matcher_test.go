package rules

import (
	"testing"

	"github.com/verabase/code-verification-engine/internal/facts"
)

// ---------------------------------------------------------------------------
// findInputValidation
// ---------------------------------------------------------------------------

func TestFindInputValidation_ByImport(t *testing.T) {
	rule := Rule{ID: "T-001", Languages: []string{"go"}}
	fs := &FactSet{
		Imports: []facts.ImportFact{
			imp("github.com/go-playground/validator", "", "handler.go", facts.LangGo),
		},
	}
	ev := findInputValidation(rule, fs)
	if len(ev) == 0 {
		t.Error("expected evidence for validator import")
	}
}

func TestFindInputValidation_ByImport_Joi(t *testing.T) {
	// joi in a non-route file is weak evidence — should NOT pass
	rule := Rule{ID: "T-001", Languages: []string{"javascript"}}
	fs := &FactSet{
		Imports: []facts.ImportFact{
			imp("joi", "", "schema.js", facts.LangJavaScript),
		},
	}
	ev := findInputValidation(rule, fs)
	if len(ev) != 0 {
		t.Error("expected NO evidence for joi import in non-route file (config-only)")
	}
}

func TestFindInputValidation_ByImport_Joi_InController(t *testing.T) {
	// joi in a controller file IS strong evidence
	rule := Rule{ID: "T-001", Languages: []string{"javascript"}}
	fs := &FactSet{
		Imports: []facts.ImportFact{
			imp("joi", "", "user.controller.js", facts.LangJavaScript),
		},
	}
	ev := findInputValidation(rule, fs)
	if len(ev) == 0 {
		t.Error("expected evidence for joi import in controller file")
	}
}

func TestFindInputValidation_ByImport_Zod(t *testing.T) {
	// zod in a non-route file is weak evidence — should NOT pass
	rule := Rule{ID: "T-001", Languages: []string{"typescript"}}
	fs := &FactSet{
		Imports: []facts.ImportFact{
			imp("zod", "", "config.ts", facts.LangTypeScript),
		},
	}
	ev := findInputValidation(rule, fs)
	if len(ev) != 0 {
		t.Error("expected NO evidence for zod import in config file")
	}
}

func TestFindInputValidation_ByImport_Zod_InDTO(t *testing.T) {
	// zod in a DTO file IS strong evidence
	rule := Rule{ID: "T-001", Languages: []string{"typescript"}}
	fs := &FactSet{
		Imports: []facts.ImportFact{
			imp("zod", "", "create-user.dto.ts", facts.LangTypeScript),
		},
	}
	ev := findInputValidation(rule, fs)
	if len(ev) == 0 {
		t.Error("expected evidence for zod import in DTO file")
	}
}

func TestFindInputValidation_ByImport_Pydantic(t *testing.T) {
	rule := Rule{ID: "T-001", Languages: []string{"python"}}
	fs := &FactSet{
		Imports: []facts.ImportFact{
			imp("pydantic", "", "models.py", facts.LangPython),
		},
	}
	ev := findInputValidation(rule, fs)
	if len(ev) == 0 {
		t.Error("expected evidence for pydantic import")
	}
}

func TestFindInputValidation_BySymbol_Validate(t *testing.T) {
	rule := Rule{ID: "T-001", Languages: []string{"go"}}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("ValidateRequest", "function", "handler.go", facts.LangGo, true, 10, 20),
		},
	}
	ev := findInputValidation(rule, fs)
	if len(ev) == 0 {
		t.Error("expected evidence for validate symbol")
	}
}

func TestFindInputValidation_BySymbol_Sanitize(t *testing.T) {
	rule := Rule{ID: "T-001", Languages: []string{"go"}}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("SanitizeInput", "function", "handler.go", facts.LangGo, true, 10, 20),
		},
	}
	ev := findInputValidation(rule, fs)
	if len(ev) == 0 {
		t.Error("expected evidence for sanitize symbol")
	}
}

func TestFindInputValidation_BySymbol_Schema(t *testing.T) {
	// Schema symbol in a non-route file is NOT strong evidence for route-level validation
	rule := Rule{ID: "T-001", Languages: []string{"javascript"}}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("userSchema", "variable", "schema.js", facts.LangJavaScript, false, 1, 5),
		},
	}
	ev := findInputValidation(rule, fs)
	if len(ev) != 0 {
		t.Error("expected NO evidence for schema symbol in non-route file")
	}
}

func TestFindInputValidation_BySymbol_Schema_InController(t *testing.T) {
	// Schema symbol in a controller file IS strong evidence
	rule := Rule{ID: "T-001", Languages: []string{"javascript"}}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("validateRequest", "function", "user.controller.js", facts.LangJavaScript, false, 1, 5),
		},
	}
	ev := findInputValidation(rule, fs)
	if len(ev) == 0 {
		t.Error("expected evidence for validate symbol in controller file")
	}
}

func TestFindInputValidation_NoMatch(t *testing.T) {
	rule := Rule{ID: "T-001", Languages: []string{"go"}}
	fs := &FactSet{
		Imports: []facts.ImportFact{
			imp("fmt", "", "main.go", facts.LangGo),
		},
		Symbols: []facts.SymbolFact{
			sym("HandleRequest", "function", "handler.go", facts.LangGo, true, 1, 5),
		},
	}
	ev := findInputValidation(rule, fs)
	if len(ev) != 0 {
		t.Errorf("expected no evidence, got %d", len(ev))
	}
}

func TestFindInputValidation_WrongLanguage(t *testing.T) {
	rule := Rule{ID: "T-001", Languages: []string{"python"}}
	fs := &FactSet{
		Imports: []facts.ImportFact{
			imp("github.com/go-playground/validator", "", "handler.go", facts.LangGo),
		},
		Symbols: []facts.SymbolFact{
			sym("ValidateRequest", "function", "handler.go", facts.LangGo, true, 10, 20),
		},
	}
	ev := findInputValidation(rule, fs)
	if len(ev) != 0 {
		t.Errorf("expected no evidence for wrong language, got %d", len(ev))
	}
}

// ---------------------------------------------------------------------------
// findCORSConfiguration
// ---------------------------------------------------------------------------

func TestFindCORSConfiguration_ByImport(t *testing.T) {
	rule := Rule{ID: "T-002", Languages: []string{"go"}}
	fs := &FactSet{
		Imports: []facts.ImportFact{
			imp("github.com/rs/cors", "", "server.go", facts.LangGo),
		},
	}
	ev := findCORSConfiguration(rule, fs)
	if len(ev) == 0 {
		t.Error("expected evidence for cors import")
	}
}

func TestFindCORSConfiguration_ByImport_GinCors(t *testing.T) {
	rule := Rule{ID: "T-002", Languages: []string{"go"}}
	fs := &FactSet{
		Imports: []facts.ImportFact{
			imp("github.com/gin-contrib/cors", "", "server.go", facts.LangGo),
		},
	}
	ev := findCORSConfiguration(rule, fs)
	if len(ev) == 0 {
		t.Error("expected evidence for gin-contrib/cors import")
	}
}

func TestFindCORSConfiguration_ByImport_FastAPI(t *testing.T) {
	rule := Rule{ID: "T-002", Languages: []string{"python"}}
	fs := &FactSet{
		Imports: []facts.ImportFact{
			imp("fastapi.middleware.cors", "", "main.py", facts.LangPython),
		},
	}
	ev := findCORSConfiguration(rule, fs)
	if len(ev) == 0 {
		t.Error("expected evidence for fastapi cors import")
	}
}

func TestFindCORSConfiguration_ByMiddleware(t *testing.T) {
	rule := Rule{ID: "T-002", Languages: []string{"javascript"}}
	fs := &FactSet{
		Middlewares: []facts.MiddlewareFact{
			mw("corsMiddleware", "middleware", "app.js", facts.LangJavaScript),
		},
	}
	ev := findCORSConfiguration(rule, fs)
	if len(ev) == 0 {
		t.Error("expected evidence for cors middleware")
	}
}

func TestFindCORSConfiguration_NoMatch(t *testing.T) {
	rule := Rule{ID: "T-002", Languages: []string{"go"}}
	fs := &FactSet{
		Imports: []facts.ImportFact{
			imp("net/http", "", "server.go", facts.LangGo),
		},
	}
	ev := findCORSConfiguration(rule, fs)
	if len(ev) != 0 {
		t.Errorf("expected no evidence, got %d", len(ev))
	}
}

func TestFindCORSConfiguration_WrongLanguage(t *testing.T) {
	rule := Rule{ID: "T-002", Languages: []string{"typescript"}}
	fs := &FactSet{
		Imports: []facts.ImportFact{
			imp("github.com/rs/cors", "", "server.go", facts.LangGo),
		},
		Middlewares: []facts.MiddlewareFact{
			mw("corsMiddleware", "middleware", "app.go", facts.LangGo),
		},
	}
	ev := findCORSConfiguration(rule, fs)
	if len(ev) != 0 {
		t.Errorf("expected no evidence for wrong language, got %d", len(ev))
	}
}

// ---------------------------------------------------------------------------
// findSecurityHeaders
// ---------------------------------------------------------------------------

func TestFindSecurityHeaders_ByImport_Helmet(t *testing.T) {
	rule := Rule{ID: "T-003", Languages: []string{"javascript"}}
	fs := &FactSet{
		Imports: []facts.ImportFact{
			imp("helmet", "", "app.js", facts.LangJavaScript),
		},
	}
	ev := findSecurityHeaders(rule, fs)
	if len(ev) == 0 {
		t.Error("expected evidence for helmet import")
	}
}

func TestFindSecurityHeaders_ByImport_UnrolledSecure(t *testing.T) {
	rule := Rule{ID: "T-003", Languages: []string{"go"}}
	fs := &FactSet{
		Imports: []facts.ImportFact{
			imp("github.com/unrolled/secure", "", "middleware.go", facts.LangGo),
		},
	}
	ev := findSecurityHeaders(rule, fs)
	if len(ev) == 0 {
		t.Error("expected evidence for unrolled/secure import")
	}
}

func TestFindSecurityHeaders_ByImport_LastSegmentSecure(t *testing.T) {
	rule := Rule{ID: "T-003", Languages: []string{"go"}}
	fs := &FactSet{
		Imports: []facts.ImportFact{
			imp("github.com/foo/secure", "", "middleware.go", facts.LangGo),
		},
	}
	ev := findSecurityHeaders(rule, fs)
	if len(ev) == 0 {
		t.Error("expected evidence for import with last segment 'secure'")
	}
}

func TestFindSecurityHeaders_ByImport_NotPartialSecure(t *testing.T) {
	rule := Rule{ID: "T-003", Languages: []string{"go"}}
	fs := &FactSet{
		Imports: []facts.ImportFact{
			imp("github.com/foo/go-secure-api", "", "server.go", facts.LangGo),
		},
	}
	ev := findSecurityHeaders(rule, fs)
	if len(ev) != 0 {
		t.Errorf("expected no evidence for partial 'secure' in path, got %d", len(ev))
	}
}

func TestFindSecurityHeaders_ByMiddleware_Helmet(t *testing.T) {
	rule := Rule{ID: "T-003", Languages: []string{"javascript"}}
	fs := &FactSet{
		Middlewares: []facts.MiddlewareFact{
			mw("helmetMiddleware", "middleware", "app.js", facts.LangJavaScript),
		},
	}
	ev := findSecurityHeaders(rule, fs)
	if len(ev) == 0 {
		t.Error("expected evidence for helmet middleware")
	}
}

func TestFindSecurityHeaders_ByMiddleware_SecurityHeaders(t *testing.T) {
	rule := Rule{ID: "T-003", Languages: []string{"go"}}
	fs := &FactSet{
		Middlewares: []facts.MiddlewareFact{
			mw("securityHeaders", "middleware", "middleware.go", facts.LangGo),
		},
	}
	ev := findSecurityHeaders(rule, fs)
	if len(ev) == 0 {
		t.Error("expected evidence for security headers middleware")
	}
}

func TestFindSecurityHeaders_NoMatch(t *testing.T) {
	rule := Rule{ID: "T-003", Languages: []string{"go"}}
	fs := &FactSet{
		Imports: []facts.ImportFact{
			imp("net/http", "", "server.go", facts.LangGo),
		},
	}
	ev := findSecurityHeaders(rule, fs)
	if len(ev) != 0 {
		t.Errorf("expected no evidence, got %d", len(ev))
	}
}

func TestFindSecurityHeaders_WrongLanguage(t *testing.T) {
	rule := Rule{ID: "T-003", Languages: []string{"python"}}
	fs := &FactSet{
		Imports: []facts.ImportFact{
			imp("helmet", "", "app.js", facts.LangJavaScript),
		},
		Middlewares: []facts.MiddlewareFact{
			mw("helmetMiddleware", "middleware", "app.js", facts.LangJavaScript),
		},
	}
	ev := findSecurityHeaders(rule, fs)
	if len(ev) != 0 {
		t.Errorf("expected no evidence for wrong language, got %d", len(ev))
	}
}

// ---------------------------------------------------------------------------
// findEnvBasedConfig
// ---------------------------------------------------------------------------

func TestFindEnvBasedConfig_ByImport_Viper(t *testing.T) {
	rule := Rule{ID: "T-004", Languages: []string{"go"}}
	fs := &FactSet{
		Imports: []facts.ImportFact{
			imp("github.com/spf13/viper", "", "config.go", facts.LangGo),
		},
	}
	ev := findEnvBasedConfig(rule, fs)
	if len(ev) == 0 {
		t.Error("expected evidence for viper import")
	}
}

func TestFindEnvBasedConfig_ByImport_Dotenv(t *testing.T) {
	rule := Rule{ID: "T-004", Languages: []string{"javascript"}}
	fs := &FactSet{
		Imports: []facts.ImportFact{
			imp("dotenv", "", "config.js", facts.LangJavaScript),
		},
	}
	ev := findEnvBasedConfig(rule, fs)
	if len(ev) == 0 {
		t.Error("expected evidence for dotenv import")
	}
}

func TestFindEnvBasedConfig_ByImport_PythonDotenv(t *testing.T) {
	rule := Rule{ID: "T-004", Languages: []string{"python"}}
	fs := &FactSet{
		Imports: []facts.ImportFact{
			imp("python-dotenv", "", "config.py", facts.LangPython),
		},
	}
	ev := findEnvBasedConfig(rule, fs)
	if len(ev) == 0 {
		t.Error("expected evidence for python-dotenv import")
	}
}

func TestFindEnvBasedConfig_BySymbol_GetEnv(t *testing.T) {
	// NameMatchesToken splits camelCase: "Getenv" → ["getenv"] (single token)
	// "GetEnv" tokenizes to ["get", "env"] which won't match "getenv"
	// Use "Getenv" which matches os.Getenv pattern
	rule := Rule{ID: "T-004", Languages: []string{"go"}}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("Getenv", "function", "config.go", facts.LangGo, true, 5, 10),
		},
	}
	ev := findEnvBasedConfig(rule, fs)
	if len(ev) == 0 {
		t.Error("expected evidence for Getenv symbol")
	}
}

func TestFindEnvBasedConfig_BySymbol_LoadEnv(t *testing.T) {
	// NameMatchesToken: "Loadenv" → ["loadenv"] matches "loadenv"
	rule := Rule{ID: "T-004", Languages: []string{"go"}}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("Loadenv", "function", "config.go", facts.LangGo, true, 5, 10),
		},
	}
	ev := findEnvBasedConfig(rule, fs)
	if len(ev) == 0 {
		t.Error("expected evidence for Loadenv symbol")
	}
}

func TestFindEnvBasedConfig_BySymbol_ConfigEnv(t *testing.T) {
	rule := Rule{ID: "T-004", Languages: []string{"go"}}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("ConfigFromEnv", "function", "config.go", facts.LangGo, true, 5, 10),
		},
	}
	ev := findEnvBasedConfig(rule, fs)
	if len(ev) == 0 {
		t.Error("expected evidence for config+env symbol")
	}
}

func TestFindEnvBasedConfig_NoMatch(t *testing.T) {
	rule := Rule{ID: "T-004", Languages: []string{"go"}}
	fs := &FactSet{
		Imports: []facts.ImportFact{
			imp("net/http", "", "server.go", facts.LangGo),
		},
		Symbols: []facts.SymbolFact{
			sym("ReadConfig", "function", "config.go", facts.LangGo, true, 1, 5),
		},
	}
	ev := findEnvBasedConfig(rule, fs)
	if len(ev) != 0 {
		t.Errorf("expected no evidence, got %d", len(ev))
	}
}

func TestFindEnvBasedConfig_WrongLanguage(t *testing.T) {
	rule := Rule{ID: "T-004", Languages: []string{"python"}}
	fs := &FactSet{
		Imports: []facts.ImportFact{
			imp("github.com/spf13/viper", "", "config.go", facts.LangGo),
		},
	}
	ev := findEnvBasedConfig(rule, fs)
	if len(ev) != 0 {
		t.Errorf("expected no evidence for wrong language, got %d", len(ev))
	}
}

// ---------------------------------------------------------------------------
// findServiceLayer
// ---------------------------------------------------------------------------

func TestFindServiceLayer_Service(t *testing.T) {
	rule := Rule{ID: "T-005", Languages: []string{"go"}}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("UserService", "struct", "service.go", facts.LangGo, true, 1, 10),
		},
	}
	ev := findServiceLayer(rule, fs)
	if len(ev) == 0 {
		t.Error("expected evidence for service symbol")
	}
}

func TestFindServiceLayer_UseCase(t *testing.T) {
	// NameMatchesToken splits camelCase: "CreateUserUsecase" → [..., "usecase"]
	// "CreateUserUseCase" → ["create", "user", "use", "case"] won't match
	rule := Rule{ID: "T-005", Languages: []string{"go"}}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("CreateUserUsecase", "struct", "usecase.go", facts.LangGo, true, 1, 10),
		},
	}
	ev := findServiceLayer(rule, fs)
	if len(ev) == 0 {
		t.Error("expected evidence for usecase symbol")
	}
}

func TestFindServiceLayer_NoMatch(t *testing.T) {
	rule := Rule{ID: "T-005", Languages: []string{"go"}}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("UserHandler", "struct", "handler.go", facts.LangGo, true, 1, 10),
		},
	}
	ev := findServiceLayer(rule, fs)
	if len(ev) != 0 {
		t.Errorf("expected no evidence, got %d", len(ev))
	}
}

func TestFindServiceLayer_WrongLanguage(t *testing.T) {
	rule := Rule{ID: "T-005", Languages: []string{"python"}}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("UserService", "struct", "service.go", facts.LangGo, true, 1, 10),
		},
	}
	ev := findServiceLayer(rule, fs)
	if len(ev) != 0 {
		t.Errorf("expected no evidence for wrong language, got %d", len(ev))
	}
}

// ---------------------------------------------------------------------------
// findGlobalErrorHandler
// ---------------------------------------------------------------------------

func TestFindGlobalErrorHandler_ByMiddleware_Error(t *testing.T) {
	rule := Rule{ID: "T-006", Languages: []string{"javascript"}}
	fs := &FactSet{
		Middlewares: []facts.MiddlewareFact{
			mw("errorHandler", "middleware", "app.js", facts.LangJavaScript),
		},
	}
	ev := findGlobalErrorHandler(rule, fs)
	if len(ev) == 0 {
		t.Error("expected evidence for error middleware")
	}
}

func TestFindGlobalErrorHandler_ByMiddleware_Exception(t *testing.T) {
	rule := Rule{ID: "T-006", Languages: []string{"python"}}
	fs := &FactSet{
		Middlewares: []facts.MiddlewareFact{
			mw("exceptionCatcher", "middleware", "middleware.py", facts.LangPython),
		},
	}
	ev := findGlobalErrorHandler(rule, fs)
	if len(ev) == 0 {
		t.Error("expected evidence for exception middleware")
	}
}

func TestFindGlobalErrorHandler_ByMiddleware_Recovery(t *testing.T) {
	rule := Rule{ID: "T-006", Languages: []string{"go"}}
	fs := &FactSet{
		Middlewares: []facts.MiddlewareFact{
			mw("recoveryMiddleware", "middleware", "middleware.go", facts.LangGo),
		},
	}
	ev := findGlobalErrorHandler(rule, fs)
	if len(ev) == 0 {
		t.Error("expected evidence for recovery middleware")
	}
}

func TestFindGlobalErrorHandler_ByMiddleware_Catch(t *testing.T) {
	rule := Rule{ID: "T-006", Languages: []string{"javascript"}}
	fs := &FactSet{
		Middlewares: []facts.MiddlewareFact{
			mw("catchAll", "middleware", "app.js", facts.LangJavaScript),
		},
	}
	ev := findGlobalErrorHandler(rule, fs)
	if len(ev) == 0 {
		t.Error("expected evidence for catch middleware")
	}
}

func TestFindGlobalErrorHandler_BySymbol_ErrorHandler(t *testing.T) {
	// Class-only definitions without binding evidence should NOT pass
	rule := Rule{ID: "T-006", Languages: []string{"go"}}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("GlobalErrorHandler", "function", "errors.go", facts.LangGo, true, 1, 20),
		},
	}
	ev := findGlobalErrorHandler(rule, fs)
	if len(ev) != 0 {
		t.Error("expected NO evidence for error+handler symbol without binding evidence")
	}
}

func TestFindGlobalErrorHandler_BySymbol_WithBinding(t *testing.T) {
	// Class definition WITH binding evidence should pass
	rule := Rule{ID: "T-006", Languages: []string{"typescript"}}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("GlobalErrorHandler", "class", "errors.ts", facts.LangTypeScript, true, 1, 20),
			{Language: facts.LangTypeScript, File: "app.module.ts", Span: facts.Span{Start: 5, End: 5},
				Name: "NestJS:APP_PROVIDER", Kind: "provider_registration"},
		},
	}
	ev := findGlobalErrorHandler(rule, fs)
	if len(ev) == 0 {
		t.Error("expected evidence for error+handler symbol with binding evidence")
	}
}

func TestFindGlobalErrorHandler_BySymbol_ErrorMiddleware(t *testing.T) {
	// Class-only definitions without binding evidence should NOT pass
	rule := Rule{ID: "T-006", Languages: []string{"go"}}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("ErrorMiddleware", "function", "errors.go", facts.LangGo, true, 1, 20),
		},
	}
	ev := findGlobalErrorHandler(rule, fs)
	if len(ev) != 0 {
		t.Error("expected NO evidence for error+middleware symbol without binding")
	}
}

func TestFindGlobalErrorHandler_BySymbol_ExceptionHandler(t *testing.T) {
	// Class-only definitions without binding evidence should NOT pass
	rule := Rule{ID: "T-006", Languages: []string{"python"}}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("exception_handler", "function", "errors.py", facts.LangPython, false, 1, 10),
		},
	}
	ev := findGlobalErrorHandler(rule, fs)
	if len(ev) != 0 {
		t.Error("expected NO evidence for exception+handler symbol without binding")
	}
}

func TestFindGlobalErrorHandler_NoMatch(t *testing.T) {
	rule := Rule{ID: "T-006", Languages: []string{"go"}}
	fs := &FactSet{
		Middlewares: []facts.MiddlewareFact{
			mw("authMiddleware", "middleware", "auth.go", facts.LangGo),
		},
		Symbols: []facts.SymbolFact{
			sym("HandleRequest", "function", "handler.go", facts.LangGo, true, 1, 5),
		},
	}
	ev := findGlobalErrorHandler(rule, fs)
	if len(ev) != 0 {
		t.Errorf("expected no evidence, got %d", len(ev))
	}
}

func TestFindGlobalErrorHandler_WrongLanguage(t *testing.T) {
	rule := Rule{ID: "T-006", Languages: []string{"typescript"}}
	fs := &FactSet{
		Middlewares: []facts.MiddlewareFact{
			mw("errorHandler", "middleware", "app.go", facts.LangGo),
		},
		Symbols: []facts.SymbolFact{
			sym("GlobalErrorHandler", "function", "errors.go", facts.LangGo, true, 1, 20),
		},
	}
	ev := findGlobalErrorHandler(rule, fs)
	if len(ev) != 0 {
		t.Errorf("expected no evidence for wrong language, got %d", len(ev))
	}
}

// ---------------------------------------------------------------------------
// findPanicRecovery
// ---------------------------------------------------------------------------

func TestFindPanicRecovery_Recover(t *testing.T) {
	rule := Rule{ID: "T-007", Languages: []string{"go"}}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("RecoverFromPanic", "function", "recovery.go", facts.LangGo, true, 1, 10),
		},
	}
	ev := findPanicRecovery(rule, fs)
	if len(ev) == 0 {
		t.Error("expected evidence for recover symbol")
	}
}

func TestFindPanicRecovery_Recovery(t *testing.T) {
	rule := Rule{ID: "T-007", Languages: []string{"go"}}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("PanicRecovery", "function", "recovery.go", facts.LangGo, true, 1, 10),
		},
	}
	ev := findPanicRecovery(rule, fs)
	if len(ev) == 0 {
		t.Error("expected evidence for recovery symbol")
	}
}

func TestFindPanicRecovery_PanicHandler(t *testing.T) {
	rule := Rule{ID: "T-007", Languages: []string{"go"}}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("PanicHandler", "function", "recovery.go", facts.LangGo, true, 1, 10),
		},
	}
	ev := findPanicRecovery(rule, fs)
	if len(ev) == 0 {
		t.Error("expected evidence for panic+handler symbol")
	}
}

func TestFindPanicRecovery_NoMatch(t *testing.T) {
	rule := Rule{ID: "T-007", Languages: []string{"go"}}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("HandleRequest", "function", "handler.go", facts.LangGo, true, 1, 5),
		},
	}
	ev := findPanicRecovery(rule, fs)
	if len(ev) != 0 {
		t.Errorf("expected no evidence, got %d", len(ev))
	}
}

func TestFindPanicRecovery_WrongLanguage(t *testing.T) {
	rule := Rule{ID: "T-007", Languages: []string{"python"}}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("RecoverFromPanic", "function", "recovery.go", facts.LangGo, true, 1, 10),
		},
	}
	ev := findPanicRecovery(rule, fs)
	if len(ev) != 0 {
		t.Errorf("expected no evidence for wrong language, got %d", len(ev))
	}
}

// ---------------------------------------------------------------------------
// findStructuredLogging
// ---------------------------------------------------------------------------

func TestFindStructuredLogging_Zap(t *testing.T) {
	rule := Rule{ID: "T-008", Languages: []string{"go"}}
	fs := &FactSet{
		Imports: []facts.ImportFact{
			imp("go.uber.org/zap", "", "logger.go", facts.LangGo),
		},
	}
	ev := findStructuredLogging(rule, fs)
	if len(ev) == 0 {
		t.Error("expected evidence for zap import")
	}
}

func TestFindStructuredLogging_Winston(t *testing.T) {
	rule := Rule{ID: "T-008", Languages: []string{"javascript"}}
	fs := &FactSet{
		Imports: []facts.ImportFact{
			imp("winston", "", "logger.js", facts.LangJavaScript),
		},
	}
	ev := findStructuredLogging(rule, fs)
	if len(ev) == 0 {
		t.Error("expected evidence for winston import")
	}
}

func TestFindStructuredLogging_Logrus(t *testing.T) {
	rule := Rule{ID: "T-008", Languages: []string{"go"}}
	fs := &FactSet{
		Imports: []facts.ImportFact{
			imp("github.com/sirupsen/logrus", "", "logger.go", facts.LangGo),
		},
	}
	ev := findStructuredLogging(rule, fs)
	if len(ev) == 0 {
		t.Error("expected evidence for logrus import")
	}
}

func TestFindStructuredLogging_Structlog(t *testing.T) {
	rule := Rule{ID: "T-008", Languages: []string{"python"}}
	fs := &FactSet{
		Imports: []facts.ImportFact{
			imp("structlog", "", "logger.py", facts.LangPython),
		},
	}
	ev := findStructuredLogging(rule, fs)
	if len(ev) == 0 {
		t.Error("expected evidence for structlog import")
	}
}

func TestFindStructuredLogging_NoMatch(t *testing.T) {
	rule := Rule{ID: "T-008", Languages: []string{"go"}}
	fs := &FactSet{
		Imports: []facts.ImportFact{
			imp("fmt", "", "main.go", facts.LangGo),
		},
	}
	ev := findStructuredLogging(rule, fs)
	if len(ev) != 0 {
		t.Errorf("expected no evidence, got %d", len(ev))
	}
}

func TestFindStructuredLogging_WrongLanguage(t *testing.T) {
	rule := Rule{ID: "T-008", Languages: []string{"python"}}
	fs := &FactSet{
		Imports: []facts.ImportFact{
			imp("go.uber.org/zap", "", "logger.go", facts.LangGo),
		},
	}
	ev := findStructuredLogging(rule, fs)
	if len(ev) != 0 {
		t.Errorf("expected no evidence for wrong language, got %d", len(ev))
	}
}

// ---------------------------------------------------------------------------
// findRequestLogging
// ---------------------------------------------------------------------------

func TestFindRequestLogging_ByMiddleware_Logger(t *testing.T) {
	rule := Rule{ID: "T-009", Languages: []string{"go"}}
	fs := &FactSet{
		Middlewares: []facts.MiddlewareFact{
			mw("requestLogger", "middleware", "middleware.go", facts.LangGo),
		},
	}
	ev := findRequestLogging(rule, fs)
	if len(ev) == 0 {
		t.Error("expected evidence for logger middleware")
	}
}

func TestFindRequestLogging_ByMiddleware_Morgan(t *testing.T) {
	rule := Rule{ID: "T-009", Languages: []string{"javascript"}}
	fs := &FactSet{
		Middlewares: []facts.MiddlewareFact{
			mw("morganLogger", "middleware", "app.js", facts.LangJavaScript),
		},
	}
	ev := findRequestLogging(rule, fs)
	if len(ev) == 0 {
		t.Error("expected evidence for morgan middleware")
	}
}

func TestFindRequestLogging_ByMiddleware_Httplog(t *testing.T) {
	rule := Rule{ID: "T-009", Languages: []string{"go"}}
	fs := &FactSet{
		Middlewares: []facts.MiddlewareFact{
			mw("httplogMiddleware", "middleware", "middleware.go", facts.LangGo),
		},
	}
	ev := findRequestLogging(rule, fs)
	if len(ev) == 0 {
		t.Error("expected evidence for httplog middleware")
	}
}

func TestFindRequestLogging_ByImport_Morgan(t *testing.T) {
	rule := Rule{ID: "T-009", Languages: []string{"javascript"}}
	fs := &FactSet{
		Imports: []facts.ImportFact{
			imp("morgan", "", "app.js", facts.LangJavaScript),
		},
	}
	ev := findRequestLogging(rule, fs)
	if len(ev) == 0 {
		t.Error("expected evidence for morgan import")
	}
}

func TestFindRequestLogging_ByImport_ChiMiddleware(t *testing.T) {
	rule := Rule{ID: "T-009", Languages: []string{"go"}}
	fs := &FactSet{
		Imports: []facts.ImportFact{
			imp("github.com/go-chi/chi/middleware", "", "server.go", facts.LangGo),
		},
	}
	ev := findRequestLogging(rule, fs)
	if len(ev) == 0 {
		t.Error("expected evidence for chi/middleware import")
	}
}

func TestFindRequestLogging_NoMatch(t *testing.T) {
	rule := Rule{ID: "T-009", Languages: []string{"go"}}
	fs := &FactSet{
		Middlewares: []facts.MiddlewareFact{
			mw("authMiddleware", "middleware", "auth.go", facts.LangGo),
		},
		Imports: []facts.ImportFact{
			imp("net/http", "", "server.go", facts.LangGo),
		},
	}
	ev := findRequestLogging(rule, fs)
	if len(ev) != 0 {
		t.Errorf("expected no evidence, got %d", len(ev))
	}
}

func TestFindRequestLogging_WrongLanguage(t *testing.T) {
	rule := Rule{ID: "T-009", Languages: []string{"python"}}
	fs := &FactSet{
		Middlewares: []facts.MiddlewareFact{
			mw("requestLogger", "middleware", "middleware.go", facts.LangGo),
		},
		Imports: []facts.ImportFact{
			imp("morgan", "", "app.js", facts.LangJavaScript),
		},
	}
	ev := findRequestLogging(rule, fs)
	if len(ev) != 0 {
		t.Errorf("expected no evidence for wrong language, got %d", len(ev))
	}
}

// ---------------------------------------------------------------------------
// findHealthCheckRoute
// ---------------------------------------------------------------------------

func TestFindHealthCheckRoute_Health(t *testing.T) {
	rule := Rule{ID: "T-010", Languages: []string{"go"}}
	fs := &FactSet{
		Routes: []facts.RouteFact{
			route("GET", "/health", "healthHandler", "server.go", facts.LangGo, nil),
		},
	}
	ev := findHealthCheckRoute(rule, fs)
	if len(ev) == 0 {
		t.Error("expected evidence for /health route")
	}
}

func TestFindHealthCheckRoute_Healthz(t *testing.T) {
	rule := Rule{ID: "T-010", Languages: []string{"go"}}
	fs := &FactSet{
		Routes: []facts.RouteFact{
			route("GET", "/healthz", "healthHandler", "server.go", facts.LangGo, nil),
		},
	}
	ev := findHealthCheckRoute(rule, fs)
	if len(ev) == 0 {
		t.Error("expected evidence for /healthz route")
	}
}

func TestFindHealthCheckRoute_Ping(t *testing.T) {
	rule := Rule{ID: "T-010", Languages: []string{"javascript"}}
	fs := &FactSet{
		Routes: []facts.RouteFact{
			route("GET", "/ping", "pingHandler", "app.js", facts.LangJavaScript, nil),
		},
	}
	ev := findHealthCheckRoute(rule, fs)
	if len(ev) == 0 {
		t.Error("expected evidence for /ping route")
	}
}

func TestFindHealthCheckRoute_HealthLive(t *testing.T) {
	rule := Rule{ID: "T-010", Languages: []string{"go"}}
	fs := &FactSet{
		Routes: []facts.RouteFact{
			route("GET", "/health/live", "liveHandler", "server.go", facts.LangGo, nil),
		},
	}
	ev := findHealthCheckRoute(rule, fs)
	if len(ev) == 0 {
		t.Error("expected evidence for /health/live route")
	}
}

func TestFindHealthCheckRoute_HealthReady(t *testing.T) {
	rule := Rule{ID: "T-010", Languages: []string{"go"}}
	fs := &FactSet{
		Routes: []facts.RouteFact{
			route("GET", "/health/ready", "readyHandler", "server.go", facts.LangGo, nil),
		},
	}
	ev := findHealthCheckRoute(rule, fs)
	if len(ev) == 0 {
		t.Error("expected evidence for /health/ready route")
	}
}

func TestFindHealthCheckRoute_Readyz(t *testing.T) {
	rule := Rule{ID: "T-010", Languages: []string{"go"}}
	fs := &FactSet{
		Routes: []facts.RouteFact{
			route("GET", "/readyz", "readyHandler", "server.go", facts.LangGo, nil),
		},
	}
	ev := findHealthCheckRoute(rule, fs)
	if len(ev) == 0 {
		t.Error("expected evidence for /readyz route")
	}
}

func TestFindHealthCheckRoute_Livez(t *testing.T) {
	rule := Rule{ID: "T-010", Languages: []string{"go"}}
	fs := &FactSet{
		Routes: []facts.RouteFact{
			route("GET", "/livez", "liveHandler", "server.go", facts.LangGo, nil),
		},
	}
	ev := findHealthCheckRoute(rule, fs)
	if len(ev) == 0 {
		t.Error("expected evidence for /livez route")
	}
}

func TestFindHealthCheckRoute_NoMatch(t *testing.T) {
	rule := Rule{ID: "T-010", Languages: []string{"go"}}
	fs := &FactSet{
		Routes: []facts.RouteFact{
			route("GET", "/api/users", "usersHandler", "server.go", facts.LangGo, nil),
		},
	}
	ev := findHealthCheckRoute(rule, fs)
	if len(ev) != 0 {
		t.Errorf("expected no evidence, got %d", len(ev))
	}
}

func TestFindHealthCheckRoute_WrongLanguage(t *testing.T) {
	rule := Rule{ID: "T-010", Languages: []string{"python"}}
	fs := &FactSet{
		Routes: []facts.RouteFact{
			route("GET", "/health", "healthHandler", "server.go", facts.LangGo, nil),
		},
	}
	ev := findHealthCheckRoute(rule, fs)
	if len(ev) != 0 {
		t.Errorf("expected no evidence for wrong language, got %d", len(ev))
	}
}

// ---------------------------------------------------------------------------
// findGracefulShutdown
// ---------------------------------------------------------------------------

func TestFindGracefulShutdown_ByImport_OsSignal(t *testing.T) {
	rule := Rule{ID: "T-011", Languages: []string{"go"}}
	fs := &FactSet{
		Imports: []facts.ImportFact{
			imp("os/signal", "", "main.go", facts.LangGo),
		},
	}
	ev := findGracefulShutdown(rule, fs)
	if len(ev) == 0 {
		t.Error("expected evidence for os/signal import")
	}
}

func TestFindGracefulShutdown_ByImport_Syscall(t *testing.T) {
	rule := Rule{ID: "T-011", Languages: []string{"go"}}
	fs := &FactSet{
		Imports: []facts.ImportFact{
			imp("syscall", "", "main.go", facts.LangGo),
		},
	}
	ev := findGracefulShutdown(rule, fs)
	if len(ev) == 0 {
		t.Error("expected evidence for syscall import")
	}
}

func TestFindGracefulShutdown_ByImport_Graceful(t *testing.T) {
	rule := Rule{ID: "T-011", Languages: []string{"go"}}
	fs := &FactSet{
		Imports: []facts.ImportFact{
			imp("github.com/tylerb/graceful", "", "main.go", facts.LangGo),
		},
	}
	ev := findGracefulShutdown(rule, fs)
	if len(ev) == 0 {
		t.Error("expected evidence for graceful import")
	}
}

func TestFindGracefulShutdown_BySymbol_Shutdown(t *testing.T) {
	rule := Rule{ID: "T-011", Languages: []string{"go"}}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("GracefulShutdown", "function", "main.go", facts.LangGo, true, 50, 80),
		},
	}
	ev := findGracefulShutdown(rule, fs)
	if len(ev) == 0 {
		t.Error("expected evidence for shutdown symbol")
	}
}

func TestFindGracefulShutdown_BySymbol_Sigterm(t *testing.T) {
	rule := Rule{ID: "T-011", Languages: []string{"go"}}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("handleSigterm", "function", "main.go", facts.LangGo, false, 50, 80),
		},
	}
	ev := findGracefulShutdown(rule, fs)
	if len(ev) == 0 {
		t.Error("expected evidence for sigterm symbol")
	}
}

func TestFindGracefulShutdown_NoMatch(t *testing.T) {
	rule := Rule{ID: "T-011", Languages: []string{"go"}}
	fs := &FactSet{
		Imports: []facts.ImportFact{
			imp("fmt", "", "main.go", facts.LangGo),
		},
		Symbols: []facts.SymbolFact{
			sym("StartServer", "function", "main.go", facts.LangGo, true, 1, 5),
		},
	}
	ev := findGracefulShutdown(rule, fs)
	if len(ev) != 0 {
		t.Errorf("expected no evidence, got %d", len(ev))
	}
}

func TestFindGracefulShutdown_WrongLanguage(t *testing.T) {
	rule := Rule{ID: "T-011", Languages: []string{"javascript"}}
	fs := &FactSet{
		Imports: []facts.ImportFact{
			imp("os/signal", "", "main.go", facts.LangGo),
		},
		Symbols: []facts.SymbolFact{
			sym("GracefulShutdown", "function", "main.go", facts.LangGo, true, 50, 80),
		},
	}
	ev := findGracefulShutdown(rule, fs)
	if len(ev) != 0 {
		t.Errorf("expected no evidence for wrong language, got %d", len(ev))
	}
}

// ---------------------------------------------------------------------------
// findEnvFileCommitted
// ---------------------------------------------------------------------------

func TestFindEnvFileCommitted_DotEnv(t *testing.T) {
	rule := Rule{ID: "T-012", Languages: []string{"go"}}
	fs := &FactSet{
		Files: []facts.FileFact{
			fileFact(".env", facts.LangGo),
		},
	}
	ev := findEnvFileCommitted(rule, fs)
	if len(ev) == 0 {
		t.Error("expected evidence for .env file")
	}
}

func TestFindEnvFileCommitted_EnvLocal(t *testing.T) {
	rule := Rule{ID: "T-012", Languages: []string{"javascript"}}
	fs := &FactSet{
		Files: []facts.FileFact{
			fileFact(".env.local", facts.LangJavaScript),
		},
	}
	ev := findEnvFileCommitted(rule, fs)
	if len(ev) == 0 {
		t.Error("expected evidence for .env.local file")
	}
}

func TestFindEnvFileCommitted_EnvProduction(t *testing.T) {
	rule := Rule{ID: "T-012", Languages: []string{"javascript"}}
	fs := &FactSet{
		Files: []facts.FileFact{
			fileFact(".env.production", facts.LangJavaScript),
		},
	}
	ev := findEnvFileCommitted(rule, fs)
	if len(ev) == 0 {
		t.Error("expected evidence for .env.production file")
	}
}

func TestFindEnvFileCommitted_EnvDevelopment(t *testing.T) {
	rule := Rule{ID: "T-012", Languages: []string{"javascript"}}
	fs := &FactSet{
		Files: []facts.FileFact{
			fileFact(".env.development", facts.LangJavaScript),
		},
	}
	ev := findEnvFileCommitted(rule, fs)
	if len(ev) == 0 {
		t.Error("expected evidence for .env.development file")
	}
}

func TestFindEnvFileCommitted_ExcludesExample(t *testing.T) {
	rule := Rule{ID: "T-012", Languages: []string{"go"}}
	fs := &FactSet{
		Files: []facts.FileFact{
			fileFact(".env.example", facts.LangGo),
		},
	}
	ev := findEnvFileCommitted(rule, fs)
	if len(ev) != 0 {
		t.Errorf("expected no evidence for .env.example, got %d", len(ev))
	}
}

func TestFindEnvFileCommitted_ExcludesTemplate(t *testing.T) {
	rule := Rule{ID: "T-012", Languages: []string{"go"}}
	fs := &FactSet{
		Files: []facts.FileFact{
			fileFact(".env.template", facts.LangGo),
		},
	}
	ev := findEnvFileCommitted(rule, fs)
	if len(ev) != 0 {
		t.Errorf("expected no evidence for .env.template, got %d", len(ev))
	}
}

func TestFindEnvFileCommitted_ExcludesSample(t *testing.T) {
	rule := Rule{ID: "T-012", Languages: []string{"go"}}
	fs := &FactSet{
		Files: []facts.FileFact{
			fileFact(".env.sample", facts.LangGo),
		},
	}
	ev := findEnvFileCommitted(rule, fs)
	if len(ev) != 0 {
		t.Errorf("expected no evidence for .env.sample, got %d", len(ev))
	}
}

func TestFindEnvFileCommitted_NoMatch(t *testing.T) {
	rule := Rule{ID: "T-012", Languages: []string{"go"}}
	fs := &FactSet{
		Files: []facts.FileFact{
			fileFact("main.go", facts.LangGo),
			fileFact("config.yaml", facts.LangGo),
		},
	}
	ev := findEnvFileCommitted(rule, fs)
	if len(ev) != 0 {
		t.Errorf("expected no evidence, got %d", len(ev))
	}
}

// ---------------------------------------------------------------------------
// findDependencyInjection
// ---------------------------------------------------------------------------

func TestFindDependencyInjection_ByImport_Wire(t *testing.T) {
	rule := Rule{ID: "T-013", Languages: []string{"go"}}
	fs := &FactSet{
		Imports: []facts.ImportFact{
			imp("github.com/google/wire", "", "wire.go", facts.LangGo),
		},
	}
	ev := findDependencyInjection(rule, fs)
	if len(ev) == 0 {
		t.Error("expected evidence for wire import")
	}
}

func TestFindDependencyInjection_ByImport_Inversify(t *testing.T) {
	rule := Rule{ID: "T-013", Languages: []string{"typescript"}}
	fs := &FactSet{
		Imports: []facts.ImportFact{
			imp("inversify", "", "container.ts", facts.LangTypeScript),
		},
	}
	ev := findDependencyInjection(rule, fs)
	if len(ev) == 0 {
		t.Error("expected evidence for inversify import")
	}
}

func TestFindDependencyInjection_ByImport_Dig(t *testing.T) {
	rule := Rule{ID: "T-013", Languages: []string{"go"}}
	fs := &FactSet{
		Imports: []facts.ImportFact{
			imp("go.uber.org/dig", "", "container.go", facts.LangGo),
		},
	}
	ev := findDependencyInjection(rule, fs)
	if len(ev) == 0 {
		t.Error("expected evidence for dig import")
	}
}

func TestFindDependencyInjection_BySymbol_NewService(t *testing.T) {
	rule := Rule{ID: "T-013", Languages: []string{"go"}}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("NewUserService", "function", "service.go", facts.LangGo, true, 10, 20),
		},
	}
	ev := findDependencyInjection(rule, fs)
	if len(ev) == 0 {
		t.Error("expected evidence for NewService constructor")
	}
}

func TestFindDependencyInjection_BySymbol_NewHandler(t *testing.T) {
	rule := Rule{ID: "T-013", Languages: []string{"go"}}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("NewUserHandler", "function", "handler.go", facts.LangGo, true, 10, 20),
		},
	}
	ev := findDependencyInjection(rule, fs)
	if len(ev) == 0 {
		t.Error("expected evidence for NewHandler constructor")
	}
}

func TestFindDependencyInjection_BySymbol_NewController(t *testing.T) {
	rule := Rule{ID: "T-013", Languages: []string{"go"}}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("NewUserController", "function", "controller.go", facts.LangGo, true, 10, 20),
		},
	}
	ev := findDependencyInjection(rule, fs)
	if len(ev) == 0 {
		t.Error("expected evidence for NewController constructor")
	}
}

func TestFindDependencyInjection_BySymbol_NewRepository(t *testing.T) {
	rule := Rule{ID: "T-013", Languages: []string{"go"}}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("NewUserRepository", "function", "repo.go", facts.LangGo, true, 10, 20),
		},
	}
	ev := findDependencyInjection(rule, fs)
	if len(ev) == 0 {
		t.Error("expected evidence for NewRepository constructor")
	}
}

func TestFindDependencyInjection_BySymbol_NotNew(t *testing.T) {
	rule := Rule{ID: "T-013", Languages: []string{"go"}}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("GetUserService", "function", "service.go", facts.LangGo, true, 10, 20),
		},
	}
	ev := findDependencyInjection(rule, fs)
	if len(ev) != 0 {
		t.Errorf("expected no evidence for non-New prefix, got %d", len(ev))
	}
}

func TestFindDependencyInjection_NoMatch(t *testing.T) {
	rule := Rule{ID: "T-013", Languages: []string{"go"}}
	fs := &FactSet{
		Imports: []facts.ImportFact{
			imp("fmt", "", "main.go", facts.LangGo),
		},
		Symbols: []facts.SymbolFact{
			sym("HandleRequest", "function", "handler.go", facts.LangGo, true, 1, 5),
		},
	}
	ev := findDependencyInjection(rule, fs)
	if len(ev) != 0 {
		t.Errorf("expected no evidence, got %d", len(ev))
	}
}

func TestFindDependencyInjection_WrongLanguage(t *testing.T) {
	rule := Rule{ID: "T-013", Languages: []string{"python"}}
	fs := &FactSet{
		Imports: []facts.ImportFact{
			imp("github.com/google/wire", "", "wire.go", facts.LangGo),
		},
		Symbols: []facts.SymbolFact{
			sym("NewUserService", "function", "service.go", facts.LangGo, true, 10, 20),
		},
	}
	ev := findDependencyInjection(rule, fs)
	if len(ev) != 0 {
		t.Errorf("expected no evidence for wrong language, got %d", len(ev))
	}
}

// ---------------------------------------------------------------------------
// findSQLInjectionPattern
// ---------------------------------------------------------------------------

func TestFindSQLInjectionPattern_Raw(t *testing.T) {
	rule := Rule{ID: "T-014", Languages: []string{"go"}}
	fs := &FactSet{
		DataAccess: []facts.DataAccessFact{
			dataAccess("raw_query", "repo.go", facts.LangGo),
		},
	}
	ev := findSQLInjectionPattern(rule, fs)
	if len(ev) == 0 {
		t.Error("expected evidence for raw query")
	}
}

func TestFindSQLInjectionPattern_Exec(t *testing.T) {
	rule := Rule{ID: "T-014", Languages: []string{"go"}}
	fs := &FactSet{
		DataAccess: []facts.DataAccessFact{
			dataAccess("exec_sql", "repo.go", facts.LangGo),
		},
	}
	ev := findSQLInjectionPattern(rule, fs)
	if len(ev) == 0 {
		t.Error("expected evidence for exec operation")
	}
}

func TestFindSQLInjectionPattern_Query(t *testing.T) {
	rule := Rule{ID: "T-014", Languages: []string{"python"}}
	fs := &FactSet{
		DataAccess: []facts.DataAccessFact{
			dataAccess("query", "db.py", facts.LangPython),
		},
	}
	ev := findSQLInjectionPattern(rule, fs)
	if len(ev) == 0 {
		t.Error("expected evidence for query operation")
	}
}

func TestFindSQLInjectionPattern_NoMatch(t *testing.T) {
	rule := Rule{ID: "T-014", Languages: []string{"go"}}
	fs := &FactSet{
		DataAccess: []facts.DataAccessFact{
			dataAccess("find_all", "repo.go", facts.LangGo),
		},
	}
	ev := findSQLInjectionPattern(rule, fs)
	if len(ev) != 0 {
		t.Errorf("expected no evidence, got %d", len(ev))
	}
}

func TestFindSQLInjectionPattern_WrongLanguage(t *testing.T) {
	rule := Rule{ID: "T-014", Languages: []string{"python"}}
	fs := &FactSet{
		DataAccess: []facts.DataAccessFact{
			dataAccess("raw_query", "repo.go", facts.LangGo),
		},
	}
	ev := findSQLInjectionPattern(rule, fs)
	if len(ev) != 0 {
		t.Errorf("expected no evidence for wrong language, got %d", len(ev))
	}
}

// ---------------------------------------------------------------------------
// findSensitiveDataInLogs
// ---------------------------------------------------------------------------

func TestFindSensitiveDataInLogs_AlwaysNil(t *testing.T) {
	rule := Rule{ID: "T-015", Languages: []string{"go"}}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("LogPassword", "function", "logger.go", facts.LangGo, true, 1, 5),
		},
		Imports: []facts.ImportFact{
			imp("go.uber.org/zap", "", "logger.go", facts.LangGo),
		},
	}
	ev := findSensitiveDataInLogs(rule, fs)
	if ev != nil {
		t.Errorf("expected nil, got %v", ev)
	}
}

func TestFindSensitiveDataInLogs_EmptyFactSet(t *testing.T) {
	rule := Rule{ID: "T-015", Languages: []string{"go"}}
	fs := &FactSet{}
	ev := findSensitiveDataInLogs(rule, fs)
	if ev != nil {
		t.Errorf("expected nil, got %v", ev)
	}
}

// ---------------------------------------------------------------------------
// Integration tests via findExistsEvidence
// ---------------------------------------------------------------------------

func TestFindExistsEvidence_InputValidation(t *testing.T) {
	rule := Rule{ID: "T-100", Languages: []string{"go"}, Target: "security.input_validation"}
	fs := &FactSet{
		Imports: []facts.ImportFact{
			imp("github.com/go-playground/validator", "", "handler.go", facts.LangGo),
		},
	}
	ev := findExistsEvidence(rule, fs)
	if len(ev) == 0 {
		t.Error("expected evidence via findExistsEvidence for security.input_validation")
	}
}

func TestFindExistsEvidence_CORSConfiguration(t *testing.T) {
	rule := Rule{ID: "T-101", Languages: []string{"go"}, Target: "security.cors_configuration"}
	fs := &FactSet{
		Imports: []facts.ImportFact{
			imp("github.com/rs/cors", "", "server.go", facts.LangGo),
		},
	}
	ev := findExistsEvidence(rule, fs)
	if len(ev) == 0 {
		t.Error("expected evidence via findExistsEvidence for security.cors_configuration")
	}
}

func TestFindExistsEvidence_SecurityHeaders(t *testing.T) {
	rule := Rule{ID: "T-102", Languages: []string{"javascript"}, Target: "security.headers_middleware"}
	fs := &FactSet{
		Imports: []facts.ImportFact{
			imp("helmet", "", "app.js", facts.LangJavaScript),
		},
	}
	ev := findExistsEvidence(rule, fs)
	if len(ev) == 0 {
		t.Error("expected evidence via findExistsEvidence for security.headers_middleware")
	}
}

func TestFindExistsEvidence_EnvBasedConfig(t *testing.T) {
	rule := Rule{ID: "T-103", Languages: []string{"go"}, Target: "config.env_based"}
	fs := &FactSet{
		Imports: []facts.ImportFact{
			imp("github.com/spf13/viper", "", "config.go", facts.LangGo),
		},
	}
	ev := findExistsEvidence(rule, fs)
	if len(ev) == 0 {
		t.Error("expected evidence via findExistsEvidence for config.env_based")
	}
}

func TestFindExistsEvidence_ServiceLayer(t *testing.T) {
	rule := Rule{ID: "T-104", Languages: []string{"go"}, Target: "layer.service"}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("UserService", "struct", "service.go", facts.LangGo, true, 1, 10),
		},
	}
	ev := findExistsEvidence(rule, fs)
	if len(ev) == 0 {
		t.Error("expected evidence via findExistsEvidence for layer.service")
	}
}

func TestFindExistsEvidence_GlobalErrorHandler(t *testing.T) {
	rule := Rule{ID: "T-105", Languages: []string{"go"}, Target: "error.global_handler"}
	fs := &FactSet{
		Middlewares: []facts.MiddlewareFact{
			mw("errorHandler", "middleware", "middleware.go", facts.LangGo),
		},
	}
	ev := findExistsEvidence(rule, fs)
	if len(ev) == 0 {
		t.Error("expected evidence via findExistsEvidence for error.global_handler")
	}
}

func TestFindExistsEvidence_PanicRecovery(t *testing.T) {
	rule := Rule{ID: "T-106", Languages: []string{"go"}, Target: "error.panic_recovery"}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("RecoverFromPanic", "function", "recovery.go", facts.LangGo, true, 1, 10),
		},
	}
	ev := findExistsEvidence(rule, fs)
	if len(ev) == 0 {
		t.Error("expected evidence via findExistsEvidence for error.panic_recovery")
	}
}

func TestFindExistsEvidence_StructuredLogging(t *testing.T) {
	rule := Rule{ID: "T-107", Languages: []string{"go"}, Target: "logging.structured"}
	fs := &FactSet{
		Imports: []facts.ImportFact{
			imp("go.uber.org/zap", "", "logger.go", facts.LangGo),
		},
	}
	ev := findExistsEvidence(rule, fs)
	if len(ev) == 0 {
		t.Error("expected evidence via findExistsEvidence for logging.structured")
	}
}

func TestFindExistsEvidence_RequestLogging(t *testing.T) {
	rule := Rule{ID: "T-108", Languages: []string{"go"}, Target: "logging.request_logging"}
	fs := &FactSet{
		Middlewares: []facts.MiddlewareFact{
			mw("requestLogger", "middleware", "middleware.go", facts.LangGo),
		},
	}
	ev := findExistsEvidence(rule, fs)
	if len(ev) == 0 {
		t.Error("expected evidence via findExistsEvidence for logging.request_logging")
	}
}

func TestFindExistsEvidence_HealthCheckRoute(t *testing.T) {
	rule := Rule{ID: "T-109", Languages: []string{"go"}, Target: "route.health_check"}
	fs := &FactSet{
		Routes: []facts.RouteFact{
			route("GET", "/health", "healthHandler", "server.go", facts.LangGo, nil),
		},
	}
	ev := findExistsEvidence(rule, fs)
	if len(ev) == 0 {
		t.Error("expected evidence via findExistsEvidence for route.health_check")
	}
}

func TestFindExistsEvidence_GracefulShutdown(t *testing.T) {
	rule := Rule{ID: "T-110", Languages: []string{"go"}, Target: "lifecycle.graceful_shutdown"}
	fs := &FactSet{
		Imports: []facts.ImportFact{
			imp("os/signal", "", "main.go", facts.LangGo),
		},
	}
	ev := findExistsEvidence(rule, fs)
	if len(ev) == 0 {
		t.Error("expected evidence via findExistsEvidence for lifecycle.graceful_shutdown")
	}
}

func TestFindExistsEvidence_DependencyInjection(t *testing.T) {
	rule := Rule{ID: "T-111", Languages: []string{"go"}, Target: "architecture.dependency_injection"}
	fs := &FactSet{
		Imports: []facts.ImportFact{
			imp("github.com/google/wire", "", "wire.go", facts.LangGo),
		},
	}
	ev := findExistsEvidence(rule, fs)
	if len(ev) == 0 {
		t.Error("expected evidence via findExistsEvidence for architecture.dependency_injection")
	}
}

// ---------------------------------------------------------------------------
// findExistsEvidence — frontend targets
// ---------------------------------------------------------------------------

func TestFindExistsEvidence_FrontendAuthGuard(t *testing.T) {
	rule := Rule{ID: "T-200", Languages: []string{"javascript"}, Target: "frontend.auth_guard"}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("ProtectedRoute", "component", "routes.jsx", facts.LangJavaScript, true, 5, 20),
		},
	}
	ev := findExistsEvidence(rule, fs)
	if len(ev) == 0 {
		t.Error("expected evidence via findExistsEvidence for frontend.auth_guard")
	}
}

func TestFindExistsEvidence_FrontendAPIErrorHandling(t *testing.T) {
	rule := Rule{ID: "T-201", Languages: []string{"javascript"}, Target: "frontend.api_error_handling"}
	fs := &FactSet{
		Imports: []facts.ImportFact{
			imp("axios", "", "api.js", facts.LangJavaScript),
		},
	}
	ev := findExistsEvidence(rule, fs)
	if len(ev) == 0 {
		t.Error("expected evidence via findExistsEvidence for frontend.api_error_handling")
	}
}

func TestFindExistsEvidence_FrontendCSP(t *testing.T) {
	rule := Rule{ID: "T-202", Languages: []string{"javascript"}, Target: "frontend.csp_configured"}
	fs := &FactSet{
		Imports: []facts.ImportFact{
			imp("helmet", "", "server.js", facts.LangJavaScript),
		},
	}
	ev := findExistsEvidence(rule, fs)
	if len(ev) == 0 {
		t.Error("expected evidence via findExistsEvidence for frontend.csp_configured")
	}
}

func TestFindExistsEvidence_FrontendLockfile(t *testing.T) {
	rule := Rule{ID: "T-203", Languages: []string{"javascript"}, Target: "frontend.lockfile_exists"}
	fs := &FactSet{
		Files: []facts.FileFact{
			fileFact("package-lock.json", facts.LangJavaScript),
		},
	}
	ev := findExistsEvidence(rule, fs)
	if len(ev) == 0 {
		t.Error("expected evidence via findExistsEvidence for frontend.lockfile_exists")
	}
}

func TestFindExistsEvidence_FrontendFormValidation(t *testing.T) {
	rule := Rule{ID: "T-204", Languages: []string{"javascript"}, Target: "frontend.form_validation"}
	fs := &FactSet{
		Imports: []facts.ImportFact{
			imp("react-hook-form", "", "Form.jsx", facts.LangJavaScript),
		},
	}
	ev := findExistsEvidence(rule, fs)
	if len(ev) == 0 {
		t.Error("expected evidence via findExistsEvidence for frontend.form_validation")
	}
}

func TestFindExistsEvidence_UnknownTarget(t *testing.T) {
	rule := Rule{ID: "T-205", Languages: []string{"go"}, Target: "unknown.nonexistent"}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("main", "function", "main.go", facts.LangGo, false, 1, 5),
		},
	}
	ev := findExistsEvidence(rule, fs)
	if ev != nil {
		t.Errorf("expected nil for unknown target, got %v", ev)
	}
}

// ---------------------------------------------------------------------------
// findEnvBasedConfig — symbol branch coverage
// ---------------------------------------------------------------------------

func TestFindEnvBasedConfig_GetenvSymbol(t *testing.T) {
	rule := Rule{ID: "T-210", Languages: []string{"go"}}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("Getenv", "function", "config.go", facts.LangGo, true, 1, 5),
		},
	}
	ev := findEnvBasedConfig(rule, fs)
	if len(ev) == 0 {
		t.Error("expected evidence for getenv symbol")
	}
}

func TestFindEnvBasedConfig_LoadenvSymbol(t *testing.T) {
	rule := Rule{ID: "T-210b", Languages: []string{"go"}}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("Loadenv", "function", "config.go", facts.LangGo, true, 1, 5),
		},
	}
	ev := findEnvBasedConfig(rule, fs)
	if len(ev) == 0 {
		t.Error("expected evidence for loadenv symbol")
	}
}

func TestFindEnvBasedConfig_ConfigEnvSymbol(t *testing.T) {
	rule := Rule{ID: "T-211", Languages: []string{"go"}}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("ConfigEnv", "function", "config.go", facts.LangGo, true, 1, 5),
		},
	}
	ev := findEnvBasedConfig(rule, fs)
	if len(ev) == 0 {
		t.Error("expected evidence for config+env symbol")
	}
}

func TestFindEnvBasedConfig_SymbolWrongLanguage(t *testing.T) {
	rule := Rule{ID: "T-212", Languages: []string{"go"}}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("GetEnvVar", "function", "config.py", facts.LangPython, true, 1, 5),
		},
	}
	ev := findEnvBasedConfig(rule, fs)
	if len(ev) != 0 {
		t.Errorf("expected no evidence for wrong language, got %d", len(ev))
	}
}

// ---------------------------------------------------------------------------
// findEnvFileCommitted — additional edge cases
// ---------------------------------------------------------------------------

func TestFindEnvFileCommitted_EnvExample_Excluded(t *testing.T) {
	rule := Rule{ID: "T-221", Languages: []string{"javascript"}}
	fs := &FactSet{
		Files: []facts.FileFact{
			fileFact(".env.example", facts.LangJavaScript),
		},
	}
	ev := findEnvFileCommitted(rule, fs)
	if len(ev) != 0 {
		t.Errorf("expected no evidence for .env.example, got %d", len(ev))
	}
}

func TestFindEnvFileCommitted_EnvTemplate_Excluded(t *testing.T) {
	rule := Rule{ID: "T-222", Languages: []string{"javascript"}}
	fs := &FactSet{
		Files: []facts.FileFact{
			fileFact(".env.template", facts.LangJavaScript),
		},
	}
	ev := findEnvFileCommitted(rule, fs)
	if len(ev) != 0 {
		t.Errorf("expected no evidence for .env.template, got %d", len(ev))
	}
}

func TestFindEnvFileCommitted_EnvSample_Excluded(t *testing.T) {
	rule := Rule{ID: "T-223", Languages: []string{"javascript"}}
	fs := &FactSet{
		Files: []facts.FileFact{
			fileFact(".env.sample", facts.LangJavaScript),
		},
	}
	ev := findEnvFileCommitted(rule, fs)
	if len(ev) != 0 {
		t.Errorf("expected no evidence for .env.sample, got %d", len(ev))
	}
}

func TestFindEnvFileCommitted_NotEnvFile(t *testing.T) {
	rule := Rule{ID: "T-226", Languages: []string{"javascript"}}
	fs := &FactSet{
		Files: []facts.FileFact{
			fileFact("config.json", facts.LangJavaScript),
		},
	}
	ev := findEnvFileCommitted(rule, fs)
	if len(ev) != 0 {
		t.Errorf("expected no evidence for config.json, got %d", len(ev))
	}
}

func TestFindEnvFileCommitted_EnvDevelopment_Flagged(t *testing.T) {
	rule := Rule{ID: "T-227", Languages: []string{"javascript"}}
	fs := &FactSet{
		Files: []facts.FileFact{
			fileFact(".env.development", facts.LangJavaScript),
		},
	}
	ev := findEnvFileCommitted(rule, fs)
	if len(ev) == 0 {
		t.Error("expected evidence for .env.development")
	}
}
