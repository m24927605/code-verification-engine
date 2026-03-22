package rules

import (
	"path/filepath"
	"strings"

	"github.com/verabase/code-verification-engine/internal/scope"
)

// Additional exists matchers for security, architecture, quality targets.

func init() {
	// Register new matchers in the exists dispatch
}

// findInputValidation looks for route-level input validation, not just config/schema validation.
// Must NOT pass merely because of config-only schema libraries (zod for config, etc.).
// Requires evidence of request-level validation:
//   - ValidationPipe (NestJS global or route-level)
//   - class-validator decorators / class-transformer usage in DTOs
//   - express-validator middleware
//   - Route-level pipe decorators
//   - schema.parse/safeParse applied to request body/query/params
func findInputValidation(rule Rule, fs *FactSet) []Evidence {
	// Strong validation evidence: packages specifically for request input validation
	requestValidationPackages := []string{
		"class-validator", "express-validator",
		"pydantic", "marshmallow", "cerberus", "wtforms",
		"ozzo-validation", "go-playground/validator",
	}

	// Weak validation evidence: packages that CAN be used for input validation
	// but are often used for config validation only (zod, yup, joi)
	weakValidationPackages := []string{
		"validator", "joi", "zod", "yup",
	}

	var strongEvidence []Evidence
	var weakEvidence []Evidence

	// Check for strong validation packages
	for _, imp := range fs.Imports {
		if !languageMatch(string(imp.Language), rule.Languages) {
			continue
		}
		if scope.IsTestOrFixturePath(imp.File) {
			continue
		}
		for _, pkg := range requestValidationPackages {
			if strings.Contains(imp.ImportPath, pkg) {
				strongEvidence = append(strongEvidence, Evidence{
					File:      imp.File,
					LineStart: imp.Span.Start,
					LineEnd:   imp.Span.End,
					Symbol:    imp.ImportPath,
				})
			}
		}
		for _, pkg := range weakValidationPackages {
			if strings.Contains(imp.ImportPath, pkg) {
				// Only count weak packages if they're in route/controller/handler/middleware files
				fileLower := strings.ToLower(imp.File)
				isRouteFile := strings.Contains(fileLower, "controller") ||
					strings.Contains(fileLower, "handler") || strings.Contains(fileLower, "route") ||
					strings.Contains(fileLower, "middleware") || strings.Contains(fileLower, "pipe") ||
					strings.Contains(fileLower, "dto") || strings.Contains(fileLower, "guard")
				if isRouteFile {
					strongEvidence = append(strongEvidence, Evidence{
						File:      imp.File,
						LineStart: imp.Span.Start,
						LineEnd:   imp.Span.End,
						Symbol:    imp.ImportPath,
					})
				} else {
					weakEvidence = append(weakEvidence, Evidence{
						File:      imp.File,
						LineStart: imp.Span.Start,
						LineEnd:   imp.Span.End,
						Symbol:    imp.ImportPath,
					})
				}
			}
		}
	}

	// Check for NestJS ValidationPipe or other validation-specific symbols
	for _, sym := range fs.Symbols {
		if !languageMatch(string(sym.Language), rule.Languages) {
			continue
		}
		if scope.IsTestOrFixturePath(sym.File) {
			continue
		}
		lower := strings.ToLower(sym.Name)
		// NestJS ValidationPipe is strong evidence
		if strings.Contains(lower, "validationpipe") || strings.Contains(lower, "nestjs:validationpipe") {
			strongEvidence = append(strongEvidence, Evidence{
				File:      sym.File,
				LineStart: sym.Span.Start,
				LineEnd:   sym.Span.End,
				Symbol:    sym.Name,
			})
			continue
		}
		// Route-level validation symbols
		if NameMatchesToken(sym.Name, "validate") || NameMatchesToken(sym.Name, "sanitize") {
			fileLower := strings.ToLower(sym.File)
			// Only count if in route/controller/handler/middleware context
			isRouteContext := strings.Contains(fileLower, "controller") ||
				strings.Contains(fileLower, "handler") || strings.Contains(fileLower, "route") ||
				strings.Contains(fileLower, "middleware") || strings.Contains(fileLower, "pipe") ||
				strings.Contains(fileLower, "dto")
			if isRouteContext {
				strongEvidence = append(strongEvidence, Evidence{
					File:      sym.File,
					LineStart: sym.Span.Start,
					LineEnd:   sym.Span.End,
					Symbol:    sym.Name,
				})
			}
		}
	}

	// Check for global NestJS provider registration of validation
	for _, sym := range fs.Symbols {
		if !languageMatch(string(sym.Language), rule.Languages) {
			continue
		}
		if sym.Kind == "provider_registration" || sym.Kind == "global_registration" {
			strongEvidence = append(strongEvidence, Evidence{
				File:      sym.File,
				LineStart: sym.Span.Start,
				LineEnd:   sym.Span.End,
				Symbol:    sym.Name,
			})
		}
	}

	// Only return strong evidence. Weak evidence alone is insufficient.
	if len(strongEvidence) > 0 {
		return strongEvidence
	}
	// If only weak evidence exists, don't pass — return nil to indicate unknown/fail
	return nil
}

// findCORSConfiguration detects CORS configuration and distinguishes between:
//   - Explicitly configured and constrained → pass
//   - Explicitly configured but dangerously permissive (origin: true, origin: '*') → fail (via findCORSPermissive)
//   - No evidence of configuration → fail
//
// This function is called by the "exists" matcher, so returning evidence = pass.
// For SEC-CORS-001, the permissive detection is handled as a separate evidence enrichment.
func findCORSConfiguration(rule Rule, fs *FactSet) []Evidence {
	corsPackages := []string{"cors", "fastapi.middleware.cors", "rs/cors", "gin-contrib/cors"}
	var evidence []Evidence
	hasPermissive := false

	for _, imp := range fs.Imports {
		if !languageMatch(string(imp.Language), rule.Languages) {
			continue
		}
		for _, pkg := range corsPackages {
			if strings.Contains(imp.ImportPath, pkg) {
				evidence = append(evidence, Evidence{
					File:      imp.File,
					LineStart: imp.Span.Start,
					LineEnd:   imp.Span.End,
					Symbol:    imp.ImportPath,
				})
			}
		}
	}
	for _, mw := range fs.Middlewares {
		if !languageMatch(string(mw.Language), rule.Languages) {
			continue
		}
		lower := strings.ToLower(mw.Name)
		if NameMatchesToken(mw.Name, "cors") || strings.HasPrefix(lower, "enablecors") {
			// Detect if the CORS config is dangerously permissive
			if strings.Contains(lower, "permissive") {
				hasPermissive = true
			}
			evidence = append(evidence, Evidence{
				File:      mw.File,
				LineStart: mw.Span.Start,
				LineEnd:   mw.Span.End,
				Symbol:    mw.Name,
			})
		}
	}

	// If we found CORS config but it's permissive, annotate the evidence
	if hasPermissive && len(evidence) > 0 {
		for i := range evidence {
			if strings.Contains(strings.ToLower(evidence[i].Symbol), "permissive") {
				evidence[i].Symbol = evidence[i].Symbol + " [WARNING: dangerously permissive - origin:true or origin:*]"
			}
		}
	}

	return evidence
}

// findCORSPermissive checks if CORS is configured but dangerously permissive.
// Returns evidence of permissive CORS configuration (origin: true, origin: '*').
func findCORSPermissive(rule Rule, fs *FactSet) []Evidence {
	var evidence []Evidence
	for _, mw := range fs.Middlewares {
		if !languageMatch(string(mw.Language), rule.Languages) {
			continue
		}
		lower := strings.ToLower(mw.Name)
		if strings.Contains(lower, "enablecors:permissive") {
			evidence = append(evidence, Evidence{
				File:      mw.File,
				LineStart: mw.Span.Start,
				LineEnd:   mw.Span.End,
				Symbol:    "CORS configured with permissive origin (origin: true or origin: '*')",
			})
		}
	}
	return evidence
}

func findSecurityHeaders(rule Rule, fs *FactSet) []Evidence {
	// Match specific security header packages only.
	// "secure" alone is too broad (matches project names like "go-secure-api").
	headerPackages := []string{
		"helmet",                   // Node.js
		"securityheaders",          // generic
		"nosurf",                   // Go CSRF
		"unrolled/secure",          // Go secure middleware
		"gorilla/securecookie",     // Go
		"secure-middleware",        // generic
		"fastapi-security",         // Python
		"django-secure",            // Python
	}
	var evidence []Evidence
	for _, imp := range fs.Imports {
		if !languageMatch(string(imp.Language), rule.Languages) {
			continue
		}
		if scope.IsTestOrFixturePath(imp.File) {
			continue
		}
		lowerPath := strings.ToLower(imp.ImportPath)
		for _, pkg := range headerPackages {
			if strings.Contains(lowerPath, pkg) {
				evidence = append(evidence, Evidence{
					File:      imp.File,
					LineStart: imp.Span.Start,
					LineEnd:   imp.Span.End,
					Symbol:    imp.ImportPath,
				})
			}
		}
		// Match packages whose final segment is exactly "secure" (e.g., "github.com/foo/secure")
		// but not partial matches like "go-secure-api"
		parts := strings.Split(lowerPath, "/")
		lastPart := parts[len(parts)-1]
		if lastPart == "secure" {
			evidence = append(evidence, Evidence{
				File:      imp.File,
				LineStart: imp.Span.Start,
				LineEnd:   imp.Span.End,
				Symbol:    imp.ImportPath,
			})
		}
	}
	for _, mw := range fs.Middlewares {
		if !languageMatch(string(mw.Language), rule.Languages) {
			continue
		}
		if NameMatchesToken(mw.Name, "helmet") || NameMatchesToken(mw.Name, "secure") ||
			NameMatchesToken(mw.Name, "security") || NameMatchesToken(mw.Name, "header") {
			evidence = append(evidence, Evidence{
				File:      mw.File,
				LineStart: mw.Span.Start,
				LineEnd:   mw.Span.End,
				Symbol:    mw.Name,
			})
		}
	}
	return evidence
}

func findEnvBasedConfig(rule Rule, fs *FactSet) []Evidence {
	// Phase 4: If ConfigReads has entries with SourceKind="env", use them as strong evidence.
	if len(fs.ConfigReads) > 0 {
		var bindingEvidence []Evidence
		for _, cr := range fs.ConfigReads {
			if !languageMatch(string(cr.Language), rule.Languages) {
				continue
			}
			if cr.SourceKind == "env" {
				bindingEvidence = append(bindingEvidence, Evidence{
					File:      cr.File,
					LineStart: cr.Span.Start,
					LineEnd:   cr.Span.End,
					Symbol:    "config_read:" + cr.Key,
				})
			}
		}
		if len(bindingEvidence) > 0 {
			return bindingEvidence
		}
	}

	// Fallback: heuristic import-based detection (pre-Phase 4 behavior).
	envPackages := []string{
		"dotenv", "env", "godotenv", "viper", "envconfig", "cleanenv",
		"python-dotenv", "decouple", "environ",
	}
	var evidence []Evidence
	for _, imp := range fs.Imports {
		if !languageMatch(string(imp.Language), rule.Languages) {
			continue
		}
		for _, pkg := range envPackages {
			if strings.Contains(imp.ImportPath, pkg) {
				evidence = append(evidence, Evidence{
					File:      imp.File,
					LineStart: imp.Span.Start,
					LineEnd:   imp.Span.End,
					Symbol:    imp.ImportPath,
				})
			}
		}
	}
	for _, sym := range fs.Symbols {
		if !languageMatch(string(sym.Language), rule.Languages) {
			continue
		}
		if NameMatchesToken(sym.Name, "getenv") || NameMatchesToken(sym.Name, "loadenv") ||
			NameMatchesToken(sym.Name, "config") && NameMatchesToken(sym.Name, "env") {
			evidence = append(evidence, Evidence{
				File:      sym.File,
				LineStart: sym.Span.Start,
				LineEnd:   sym.Span.End,
				Symbol:    sym.Name,
			})
		}
	}
	return evidence
}

func findServiceLayer(rule Rule, fs *FactSet) []Evidence {
	var evidence []Evidence
	for _, sym := range fs.Symbols {
		if !languageMatch(string(sym.Language), rule.Languages) {
			continue
		}
		if NameMatchesToken(sym.Name, "service") || NameMatchesToken(sym.Name, "usecase") {
			evidence = append(evidence, Evidence{
				File:      sym.File,
				LineStart: sym.Span.Start,
				LineEnd:   sym.Span.End,
				Symbol:    sym.Name,
			})
		}
	}
	return evidence
}

// findGlobalErrorHandler looks for error handlers that are actually registered globally.
// For NestJS: APP_FILTER or useGlobalFilters is required for class-based exception filters.
// For Express: app.use(errorHandler) or middleware registration is sufficient.
func findGlobalErrorHandler(rule Rule, fs *FactSet) []Evidence {
	var middlewareEvidence []Evidence
	for _, mw := range fs.Middlewares {
		if !languageMatch(string(mw.Language), rule.Languages) {
			continue
		}
		if scope.IsTestOrFixturePath(mw.File) {
			continue
		}
		if NameMatchesToken(mw.Name, "error") || NameMatchesToken(mw.Name, "exception") ||
			NameMatchesToken(mw.Name, "recovery") || NameMatchesToken(mw.Name, "catch") {
			middlewareEvidence = append(middlewareEvidence, Evidence{
				File:      mw.File,
				LineStart: mw.Span.Start,
				LineEnd:   mw.Span.End,
				Symbol:    mw.Name,
			})
		}
	}

	// Middleware-level evidence (Express app.use, etc.) is direct binding evidence
	if len(middlewareEvidence) > 0 {
		return middlewareEvidence
	}

	// Check for class-based error handlers
	var classEvidence []Evidence
	for _, sym := range fs.Symbols {
		if !languageMatch(string(sym.Language), rule.Languages) {
			continue
		}
		if scope.IsTestOrFixturePath(sym.File) {
			continue
		}
		if (NameMatchesToken(sym.Name, "error") && NameMatchesToken(sym.Name, "handler")) ||
			(NameMatchesToken(sym.Name, "error") && NameMatchesToken(sym.Name, "middleware")) ||
			(NameMatchesToken(sym.Name, "exception") && NameMatchesToken(sym.Name, "handler")) ||
			(NameMatchesToken(sym.Name, "exception") && NameMatchesToken(sym.Name, "filter")) {
			classEvidence = append(classEvidence, Evidence{
				File:      sym.File,
				LineStart: sym.Span.Start,
				LineEnd:   sym.Span.End,
				Symbol:    sym.Name,
			})
		}
	}

	// For class-based filters: require actual binding evidence
	if len(classEvidence) > 0 {
		if hasRuntimeBindingEvidence(fs, rule.Languages) {
			return classEvidence
		}
		// No binding evidence — class exists but isn't registered globally
		// Return nil (unknown/fail) instead of claiming it's in use
		return nil
	}

	return nil
}

func findPanicRecovery(rule Rule, fs *FactSet) []Evidence {
	var evidence []Evidence
	for _, sym := range fs.Symbols {
		if !languageMatch(string(sym.Language), rule.Languages) {
			continue
		}
		if NameMatchesToken(sym.Name, "recover") || NameMatchesToken(sym.Name, "recovery") ||
			NameMatchesToken(sym.Name, "panic") && NameMatchesToken(sym.Name, "handler") {
			evidence = append(evidence, Evidence{
				File:      sym.File,
				LineStart: sym.Span.Start,
				LineEnd:   sym.Span.End,
				Symbol:    sym.Name,
			})
		}
	}
	return evidence
}

func findStructuredLogging(rule Rule, fs *FactSet) []Evidence {
	logPackages := []string{
		"zap", "zerolog", "logrus", "slog", "winston", "pino", "bunyan",
		"structlog", "loguru", "logging",
	}
	var evidence []Evidence
	for _, imp := range fs.Imports {
		if !languageMatch(string(imp.Language), rule.Languages) {
			continue
		}
		if scope.IsTestOrFixturePath(imp.File) {
			continue
		}
		for _, pkg := range logPackages {
			if strings.Contains(imp.ImportPath, pkg) {
				evidence = append(evidence, Evidence{
					File:      imp.File,
					LineStart: imp.Span.Start,
					LineEnd:   imp.Span.End,
					Symbol:    imp.ImportPath,
				})
			}
		}
	}
	return evidence
}

// findRequestLogging looks for request logging middleware that is actually bound.
// Class definitions without binding evidence are not sufficient for NestJS interceptors.
func findRequestLogging(rule Rule, fs *FactSet) []Evidence {
	var evidence []Evidence
	for _, mw := range fs.Middlewares {
		if !languageMatch(string(mw.Language), rule.Languages) {
			continue
		}
		if scope.IsTestOrFixturePath(mw.File) {
			continue
		}
		if NameMatchesToken(mw.Name, "log") || NameMatchesToken(mw.Name, "logger") ||
			NameMatchesToken(mw.Name, "request") && NameMatchesToken(mw.Name, "log") ||
			NameMatchesToken(mw.Name, "morgan") || NameMatchesToken(mw.Name, "httplog") {
			evidence = append(evidence, Evidence{
				File:      mw.File,
				LineStart: mw.Span.Start,
				LineEnd:   mw.Span.End,
				Symbol:    mw.Name,
			})
		}
	}
	logMiddlewarePackages := []string{"morgan", "httplog", "gin-logger", "chi/middleware"}
	for _, imp := range fs.Imports {
		if !languageMatch(string(imp.Language), rule.Languages) {
			continue
		}
		if scope.IsTestOrFixturePath(imp.File) {
			continue
		}
		for _, pkg := range logMiddlewarePackages {
			if strings.Contains(imp.ImportPath, pkg) {
				evidence = append(evidence, Evidence{
					File:      imp.File,
					LineStart: imp.Span.Start,
					LineEnd:   imp.Span.End,
					Symbol:    imp.ImportPath,
				})
			}
		}
	}

	// For NestJS interceptor-based logging: require binding evidence
	if len(evidence) == 0 {
		var classEvidence []Evidence
		for _, sym := range fs.Symbols {
			if !languageMatch(string(sym.Language), rule.Languages) {
				continue
			}
			lower := strings.ToLower(sym.Name)
			if (strings.Contains(lower, "log") || strings.Contains(lower, "metrics")) &&
				strings.Contains(lower, "interceptor") &&
				(sym.Kind == "class" || sym.Kind == "function") {
				classEvidence = append(classEvidence, Evidence{
					File:      sym.File,
					LineStart: sym.Span.Start,
					LineEnd:   sym.Span.End,
					Symbol:    sym.Name,
				})
			}
		}
		if len(classEvidence) > 0 && hasRuntimeBindingEvidence(fs, rule.Languages) {
			return classEvidence
		}
	}

	return evidence
}

func findHealthCheckRoute(rule Rule, fs *FactSet) []Evidence {
	var evidence []Evidence
	for _, route := range fs.Routes {
		if !languageMatch(string(route.Language), rule.Languages) {
			continue
		}
		lower := strings.ToLower(route.Path)
		if lower == "/health" || lower == "/healthz" || lower == "/health/live" ||
			lower == "/health/ready" || lower == "/ping" || lower == "/readyz" || lower == "/livez" {
			evidence = append(evidence, Evidence{
				File:      route.File,
				LineStart: route.Span.Start,
				LineEnd:   route.Span.End,
				Symbol:    route.Handler,
			})
		}
	}
	return evidence
}

// findGracefulShutdown detects graceful shutdown handling.
// Important: does not pass the entire backend/server rule merely because one process type
// (e.g., a worker) handles signals. Differentiates between:
//   - API server entrypoint (main.ts, server.ts, app.ts, index.ts)
//   - Worker processes (worker.ts, consumer.ts, processor.ts)
//   - Other entrypoints
//
// For the rule to pass, the API server entrypoint should have shutdown handling,
// not just a worker process.
func findGracefulShutdown(rule Rule, fs *FactSet) []Evidence {
	shutdownPackages := []string{"os/signal", "signal", "syscall", "graceful"}

	// Classify evidence by file context
	type shutdownEvidence struct {
		ev     Evidence
		isMain bool // true if in main/server/app entrypoint
	}
	var allEvidence []shutdownEvidence

	classifyFile := func(file string) bool {
		lower := strings.ToLower(file)
		base := strings.ToLower(filepath.Base(file))
		// Main server entrypoints
		return base == "main.ts" || base == "main.js" || base == "main.go" || base == "main.py" ||
			base == "server.ts" || base == "server.js" || base == "server.go" ||
			base == "app.ts" || base == "app.js" || base == "app.go" ||
			base == "index.ts" || base == "index.js" ||
			strings.Contains(lower, "bootstrap")
	}

	for _, imp := range fs.Imports {
		if !languageMatch(string(imp.Language), rule.Languages) {
			continue
		}
		for _, pkg := range shutdownPackages {
			if strings.Contains(imp.ImportPath, pkg) {
				allEvidence = append(allEvidence, shutdownEvidence{
					ev: Evidence{
						File:      imp.File,
						LineStart: imp.Span.Start,
						LineEnd:   imp.Span.End,
						Symbol:    imp.ImportPath,
					},
					isMain: classifyFile(imp.File),
				})
			}
		}
	}
	for _, sym := range fs.Symbols {
		if !languageMatch(string(sym.Language), rule.Languages) {
			continue
		}
		if NameMatchesToken(sym.Name, "graceful") || NameMatchesToken(sym.Name, "shutdown") ||
			NameMatchesToken(sym.Name, "sigterm") || NameMatchesToken(sym.Name, "sigint") {
			allEvidence = append(allEvidence, shutdownEvidence{
				ev: Evidence{
					File:      sym.File,
					LineStart: sym.Span.Start,
					LineEnd:   sym.Span.End,
					Symbol:    sym.Name,
				},
				isMain: classifyFile(sym.File),
			})
		}
	}

	// Prioritize main/server evidence. If only worker evidence exists,
	// still return it but annotate that it's worker-only.
	var mainEvidence []Evidence
	var workerEvidence []Evidence
	for _, e := range allEvidence {
		if e.isMain {
			mainEvidence = append(mainEvidence, e.ev)
		} else {
			workerEvidence = append(workerEvidence, e.ev)
		}
	}

	if len(mainEvidence) > 0 {
		return mainEvidence
	}

	// Only worker evidence — annotate as worker-only
	if len(workerEvidence) > 0 {
		for i := range workerEvidence {
			workerEvidence[i].Symbol = workerEvidence[i].Symbol + " [worker-only, not API server entrypoint]"
		}
		return workerEvidence
	}

	return nil
}

func findEnvFileCommitted(rule Rule, fs *FactSet) []Evidence {
	var evidence []Evidence
	for _, f := range fs.Files {
		lower := strings.ToLower(f.File)
		if strings.HasSuffix(lower, ".env") || strings.Contains(lower, ".env.local") ||
			strings.Contains(lower, ".env.production") || strings.Contains(lower, ".env.development") {
			// Skip .env.example and .env.template
			if strings.Contains(lower, "example") || strings.Contains(lower, "template") || strings.Contains(lower, "sample") {
				continue
			}
			evidence = append(evidence, Evidence{
				File:      f.File,
				LineStart: 1,
				LineEnd:   1,
				Symbol:    f.File,
			})
		}
	}
	return evidence
}

func findDependencyInjection(rule Rule, fs *FactSet) []Evidence {
	diPackages := []string{
		"wire", "dig", "fx", "inject", "inversify", "tsyringe", "typedi",
		"injector", "dependency-injector",
	}
	var evidence []Evidence
	for _, imp := range fs.Imports {
		if !languageMatch(string(imp.Language), rule.Languages) {
			continue
		}
		for _, pkg := range diPackages {
			if strings.Contains(imp.ImportPath, pkg) {
				evidence = append(evidence, Evidence{
					File:      imp.File,
					LineStart: imp.Span.Start,
					LineEnd:   imp.Span.End,
					Symbol:    imp.ImportPath,
				})
			}
		}
	}
	// Also check constructor injection patterns
	for _, sym := range fs.Symbols {
		if !languageMatch(string(sym.Language), rule.Languages) {
			continue
		}
		if strings.HasPrefix(sym.Name, "New") && (NameMatchesToken(sym.Name, "service") ||
			NameMatchesToken(sym.Name, "handler") || NameMatchesToken(sym.Name, "controller") ||
			NameMatchesToken(sym.Name, "repository")) {
			evidence = append(evidence, Evidence{
				File:      sym.File,
				LineStart: sym.Span.Start,
				LineEnd:   sym.Span.End,
				Symbol:    sym.Name,
			})
		}
	}
	return evidence
}

func findSQLInjectionPattern(rule Rule, fs *FactSet) []Evidence {
	var evidence []Evidence
	for _, da := range fs.DataAccess {
		if !languageMatch(string(da.Language), rule.Languages) {
			continue
		}
		if strings.Contains(da.Operation, "raw") || strings.Contains(da.Operation, "exec") ||
			strings.Contains(da.Operation, "query") {
			// Check if this is a raw query pattern (heuristic)
			evidence = append(evidence, Evidence{
				File:      da.File,
				LineStart: da.Span.Start,
				LineEnd:   da.Span.End,
				Symbol:    da.Operation,
			})
		}
	}
	return evidence
}

func findSensitiveDataInLogs(rule Rule, fs *FactSet) []Evidence {
	// This is a heuristic check — look for log calls near password/token variables
	// In v1, this returns unknown for most cases since precise detection requires data flow analysis
	return nil
}

// findAuthBindingEvidence checks AppBindings and RouteBindings for auth-related
// middleware/guard registrations. Returns structural-level evidence when found.
// This provides stronger evidence than symbol/import name heuristics because it
// proves the auth mechanism is actually bound (registered) in the application.
func findAuthBindingEvidence(rule Rule, fs *FactSet) []Evidence {
	var evidence []Evidence

	// Check AppBindings for auth-related middleware/guard registrations
	for _, ab := range fs.AppBindings {
		if !languageMatch(string(ab.Language), rule.Languages) {
			continue
		}
		if ab.Kind != "middleware" && ab.Kind != "guard" {
			continue
		}
		nameLower := strings.ToLower(ab.Name)
		if strings.Contains(nameLower, "auth") || strings.Contains(nameLower, "jwt") ||
			strings.Contains(nameLower, "passport") || strings.Contains(nameLower, "guard") ||
			strings.Contains(nameLower, "protect") || strings.Contains(nameLower, "login") {
			evidence = append(evidence, Evidence{
				File:      ab.File,
				LineStart: ab.Span.Start,
				LineEnd:   ab.Span.End,
				Symbol:    "binding:" + ab.Kind + ":" + ab.Name,
			})
		}
	}

	// Check RouteBindings for handlers with auth middleware/guard chains
	for _, rb := range fs.RouteBindings {
		if !languageMatch(string(rb.Language), rule.Languages) {
			continue
		}
		for _, mwName := range rb.Middlewares {
			mwLower := strings.ToLower(mwName)
			if strings.Contains(mwLower, "auth") || strings.Contains(mwLower, "jwt") ||
				strings.Contains(mwLower, "passport") || strings.Contains(mwLower, "protect") {
				evidence = append(evidence, Evidence{
					File:      rb.File,
					LineStart: rb.Span.Start,
					LineEnd:   rb.Span.End,
					Symbol:    "route_binding:" + rb.Handler + ":" + mwName,
				})
			}
		}
		for _, guardName := range rb.Guards {
			gLower := strings.ToLower(guardName)
			if strings.Contains(gLower, "auth") || strings.Contains(gLower, "jwt") ||
				strings.Contains(gLower, "passport") || strings.Contains(gLower, "guard") {
				evidence = append(evidence, Evidence{
					File:      rb.File,
					LineStart: rb.Span.Start,
					LineEnd:   rb.Span.End,
					Symbol:    "route_binding:" + rb.Handler + ":" + guardName,
				})
			}
		}
	}

	return evidence
}

// fileRoleIs checks if a file has a specific architectural role according to FileRoleFacts.
// Returns true if any FileRoleFact matches the given file and role.
func fileRoleIs(fs *FactSet, file string, role string) bool {
	for _, fr := range fs.FileRoles {
		if fr.File == file && fr.Role == role {
			return true
		}
	}
	return false
}
