package rules

import (
	"strings"

	"github.com/verabase/code-verification-engine/internal/scope"
)

// findDBAccessOutsideRepo finds DataAccessFact entries in files that are NOT
// in the repository/data-access layer and are NOT test files.
//
// When CallerName is available, file-scoped handler matching is used for precision:
//   - If CallerName matches a route handler in the SAME FILE and ImportsDirect=true
//     → flagged at strong_inference (caller is a route handler doing direct DB access)
//   - If CallerName matches a route handler in the SAME FILE and ImportsDirect=false
//     → skipped (delegated access; the actual DB call is in the repo layer)
//   - If CallerName does NOT match any route handler in the same file
//     → fall back to file-path heuristic at weak_inference
//
// When CallerName is absent → fall back to file-path heuristic at weak_inference.
//
// Note: this function returns plain []Evidence for compatibility with matchNotExists.
// The caller (matchNotExists) uses VerificationVerified for fail findings; this is
// intentional because when we DO find evidence, we found a concrete occurrence.
// However the evidence quality varies; see inline comments.
func findDBAccessOutsideRepo(rule Rule, fs *FactSet) []Evidence {
	if len(fs.DataAccess) == 0 {
		return nil
	}

	repoFiles := make(map[string]bool)

	// Identify repository files by path
	for _, f := range fs.Files {
		if isRepoLayerFile(f.File) {
			repoFiles[f.File] = true
		}
	}

	// Identify repository files by symbol name
	for _, sym := range fs.Symbols {
		if NameMatchesToken(sym.Name, "repository") || NameMatchesToken(sym.Name, "repo") {
			repoFiles[sym.File] = true
		}
	}

	// Build file-scoped route handler set: map[file]→set of handler names.
	// Using "file:handler" composite keys for O(1) lookup.
	routeHandlerKeys := make(map[string]bool) // "file:handlerName" → true
	for _, r := range fs.Routes {
		if r.Handler != "" {
			routeHandlerKeys[r.File+":"+r.Handler] = true
		}
	}

	var evidence []Evidence
	for _, da := range fs.DataAccess {
		if !languageMatch(string(da.Language), rule.Languages) {
			continue
		}
		if repoFiles[da.File] {
			continue
		}
		if scope.IsTestOrFixturePath(da.File) {
			continue
		}

		if da.CallerName != "" {
			// Precise path: caller identity is known.
			isRouteHandler := routeHandlerKeys[da.File+":"+da.CallerName]
			if isRouteHandler {
				if da.ImportsDirect {
					// Route handler directly imports a DB lib → strong evidence of violation.
					evidence = append(evidence, Evidence{
						File:      da.File,
						LineStart: da.Span.Start,
						LineEnd:   da.Span.End,
						Symbol:    da.Operation,
					})
				}
				// else: ImportsDirect=false → delegated access; skip.
			} else {
				// Caller is not a route handler in the same file.
				// Fall back to file-path heuristic (weak signal).
				if isHandlerFile(da.File) {
					evidence = append(evidence, Evidence{
						File:      da.File,
						LineStart: da.Span.Start,
						LineEnd:   da.Span.End,
						Symbol:    da.Operation,
					})
				}
			}
		} else {
			// No caller context: fall back to file-path heuristic.
			// Only flag if the file is in a handler/controller path.
			if isHandlerFile(da.File) {
				evidence = append(evidence, Evidence{
					File:      da.File,
					LineStart: da.Span.Start,
					LineEnd:   da.Span.End,
					Symbol:    da.Operation,
				})
			}
		}
	}
	return evidence
}

// findDBModelInRouteHandler finds handler/controller files that directly
// return raw DB models/entities without DTO transformation.
//
// To reduce false positives, we require stronger evidence than just symbol name overlap:
//   - The controller must directly import a model/entity/schema file
//   - The import must be of the actual ORM entity type, not a DTO/response type
//   - Controllers that reference model-like symbols but perform DTO transformation
//     (e.g., mapping fields, using toJSON, using response types) should NOT be flagged
func findDBModelInRouteHandler(rule Rule, fs *FactSet) []Evidence {
	// Build set of model files
	modelFiles := make(map[string]bool)
	for _, f := range fs.Files {
		if isModelFile(f.File) {
			modelFiles[f.File] = true
		}
	}
	if len(modelFiles) == 0 {
		return nil
	}

	// Build set of handler/controller files
	handlerFiles := make(map[string]bool)
	for _, f := range fs.Files {
		if isHandlerFile(f.File) {
			handlerFiles[f.File] = true
		}
	}
	for _, r := range fs.Routes {
		handlerFiles[r.File] = true
	}

	// Build a set of handler files that directly import model/entity files
	handlerImportsModel := make(map[string]bool)
	for _, imp := range fs.Imports {
		if !handlerFiles[imp.File] {
			continue
		}
		impLower := strings.ToLower(imp.ImportPath)
		// Check if import references a model/entity/schema module
		if strings.Contains(impLower, "entity") || strings.Contains(impLower, "model") ||
			strings.Contains(impLower, "schema") {
			// Exclude imports that suggest DTO/response types
			if !strings.Contains(impLower, "dto") && !strings.Contains(impLower, "response") &&
				!strings.Contains(impLower, "request") && !strings.Contains(impLower, "view") {
				handlerImportsModel[imp.File] = true
			}
		}
	}

	// Also check if controllers have DataAccess facts (strong evidence of direct DB access)
	handlerHasDataAccess := make(map[string]bool)
	for _, da := range fs.DataAccess {
		if handlerFiles[da.File] && !scope.IsTestOrFixturePath(da.File) {
			handlerHasDataAccess[da.File] = true
		}
	}

	// Only flag controllers that both import model files AND have direct data access
	var evidence []Evidence
	for _, da := range fs.DataAccess {
		if !languageMatch(string(da.Language), rule.Languages) {
			continue
		}
		if !handlerFiles[da.File] {
			continue
		}
		if scope.IsTestOrFixturePath(da.File) {
			continue
		}
		// Require the handler to import model/entity files directly
		if handlerImportsModel[da.File] {
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

// findSingletonMutableGlobal finds mutable global/singleton variables.
// Excludes:
//   - immutable exported constants (const/readonly)
//   - DI tokens (Symbol(), InjectionToken, etc.)
//   - schema/table declarations (schema, table, pgTable, defineTable)
//   - enum-like exports
//   - type/interface declarations
//   - metadata/decorator exports
func findSingletonMutableGlobal(rule Rule, fs *FactSet) []Evidence {
	mutableKinds := map[string]bool{
		"variable": true,
		"var":      true,
		"let":      true,
	}

	// Immutable kinds are never flagged regardless of name.
	immutableKinds := map[string]bool{
		"const":    true,
		"readonly": true,
	}

	// Non-mutable declaration kinds — these can never be runtime mutable state
	nonMutableKinds := map[string]bool{
		"type":      true,
		"interface": true,
		"enum":      true,
		"class":     true, // classes themselves aren't mutable state; instances are
	}

	suspectNames := []string{
		"instance", "singleton", "global", "db", "client",
		"conn", "connection", "pool",
	}

	// Names that indicate DI tokens, schemas, or other non-mutable patterns
	excludePatterns := []string{
		"token", "injection", "provider", // DI tokens
		"schema", "table", "column", "migration", // DB schema declarations
		"enum", "type", "interface", // Type-level declarations
		"decorator", "metadata", "reflect", // Metadata
		"config", "options", "settings", // Configuration objects (usually immutable)
		"symbol", // Symbol() tokens
	}

	var evidence []Evidence
	for _, sym := range fs.Symbols {
		if !languageMatch(string(sym.Language), rule.Languages) {
			continue
		}
		if scope.IsTestOrFixturePath(sym.File) {
			continue
		}
		// Skip immutable declarations (const/readonly) — they cannot be reassigned.
		if immutableKinds[strings.ToLower(sym.Kind)] {
			continue
		}
		// Skip type-level declarations
		if nonMutableKinds[strings.ToLower(sym.Kind)] {
			continue
		}
		// If IsMutable is explicitly false and the kind is known, skip.
		if !sym.IsMutable && !mutableKinds[strings.ToLower(sym.Kind)] {
			continue
		}
		if !sym.Exported {
			continue
		}

		nameLower := strings.ToLower(sym.Name)

		// Check exclusion patterns first — if the name suggests a non-mutable pattern, skip
		excluded := false
		for _, pattern := range excludePatterns {
			if strings.Contains(nameLower, pattern) {
				excluded = true
				break
			}
		}
		if excluded {
			continue
		}

		// Check file path exclusion: files that are clearly schema/migration/config files
		fileLower := strings.ToLower(sym.File)
		if strings.Contains(fileLower, "schema") || strings.Contains(fileLower, "migration") ||
			strings.Contains(fileLower, "config") || strings.Contains(fileLower, "constant") ||
			strings.Contains(fileLower, "enum") || strings.Contains(fileLower, "type") {
			continue
		}

		for _, suspect := range suspectNames {
			if strings.Contains(nameLower, suspect) {
				evidence = append(evidence, Evidence{
					File:      sym.File,
					LineStart: sym.Span.Start,
					LineEnd:   sym.Span.End,
					Symbol:    sym.Name,
				})
				break
			}
		}
	}
	return evidence
}

// isRepoLayerFile returns true if the file path suggests a repository/data-access layer.
func isRepoLayerFile(path string) bool {
	lower := strings.ToLower(path)
	return strings.Contains(lower, "repo") ||
		strings.Contains(lower, "repository") ||
		strings.Contains(lower, "dal") ||
		strings.Contains(lower, "data-access") ||
		strings.Contains(lower, "data_access")
}

// isModelFile returns true if the file path suggests a DB model/entity file.
func isModelFile(path string) bool {
	lower := strings.ToLower(path)
	return strings.Contains(lower, "model") ||
		strings.Contains(lower, "entity") ||
		strings.Contains(lower, "schema")
}

// isHandlerFile returns true if the file path suggests a handler/controller file.
func isHandlerFile(path string) bool {
	lower := strings.ToLower(path)
	return strings.Contains(lower, "controller") ||
		strings.Contains(lower, "handler") ||
		strings.Contains(lower, "route")
}

// isTestFilePath returns true if the file path suggests a test file.
// Deprecated: use scope.IsTestOrFixturePath for broader coverage.
func isTestFilePath(path string) bool {
	return scope.IsTestOrFixturePath(path)
}
