package rules

import "strings"

// Additional exists matchers for security, architecture, quality targets.

func init() {
	// Register new matchers in the exists dispatch
}

func findInputValidation(rule Rule, fs *FactSet) []Evidence {
	validationPackages := []string{
		"validator", "joi", "zod", "yup", "class-validator", "express-validator",
		"pydantic", "marshmallow", "cerberus", "wtforms",
		"ozzo-validation", "go-playground/validator",
	}
	var evidence []Evidence
	for _, imp := range fs.Imports {
		if !languageMatch(string(imp.Language), rule.Languages) {
			continue
		}
		for _, pkg := range validationPackages {
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
	// Also check for validation-related symbols
	for _, sym := range fs.Symbols {
		if !languageMatch(string(sym.Language), rule.Languages) {
			continue
		}
		if NameMatchesToken(sym.Name, "validate") || NameMatchesToken(sym.Name, "sanitize") ||
			NameMatchesToken(sym.Name, "schema") {
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

func findCORSConfiguration(rule Rule, fs *FactSet) []Evidence {
	corsPackages := []string{"cors", "fastapi.middleware.cors", "rs/cors", "gin-contrib/cors"}
	var evidence []Evidence
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
		if NameMatchesToken(mw.Name, "cors") {
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

func findGlobalErrorHandler(rule Rule, fs *FactSet) []Evidence {
	var evidence []Evidence
	for _, mw := range fs.Middlewares {
		if !languageMatch(string(mw.Language), rule.Languages) {
			continue
		}
		if NameMatchesToken(mw.Name, "error") || NameMatchesToken(mw.Name, "exception") ||
			NameMatchesToken(mw.Name, "recovery") || NameMatchesToken(mw.Name, "catch") {
			evidence = append(evidence, Evidence{
				File:      mw.File,
				LineStart: mw.Span.Start,
				LineEnd:   mw.Span.End,
				Symbol:    mw.Name,
			})
		}
	}
	for _, sym := range fs.Symbols {
		if !languageMatch(string(sym.Language), rule.Languages) {
			continue
		}
		if (NameMatchesToken(sym.Name, "error") && NameMatchesToken(sym.Name, "handler")) ||
			(NameMatchesToken(sym.Name, "error") && NameMatchesToken(sym.Name, "middleware")) ||
			(NameMatchesToken(sym.Name, "exception") && NameMatchesToken(sym.Name, "handler")) {
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

func findRequestLogging(rule Rule, fs *FactSet) []Evidence {
	var evidence []Evidence
	for _, mw := range fs.Middlewares {
		if !languageMatch(string(mw.Language), rule.Languages) {
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

func findGracefulShutdown(rule Rule, fs *FactSet) []Evidence {
	shutdownPackages := []string{"os/signal", "signal", "syscall", "graceful"}
	var evidence []Evidence
	for _, imp := range fs.Imports {
		if !languageMatch(string(imp.Language), rule.Languages) {
			continue
		}
		for _, pkg := range shutdownPackages {
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
		if NameMatchesToken(sym.Name, "graceful") || NameMatchesToken(sym.Name, "shutdown") ||
			NameMatchesToken(sym.Name, "sigterm") || NameMatchesToken(sym.Name, "sigint") {
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
