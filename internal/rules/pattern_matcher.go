package rules

import "strings"

// findDBAccessOutsideRepo finds DataAccessFact entries in files that are NOT
// in the repository/data-access layer and are NOT test files.
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

	var evidence []Evidence
	for _, da := range fs.DataAccess {
		if !languageMatch(string(da.Language), rule.Languages) {
			continue
		}
		if repoFiles[da.File] {
			continue
		}
		if isTestFilePath(da.File) {
			continue
		}
		evidence = append(evidence, Evidence{
			File:      da.File,
			LineStart: da.Span.Start,
			LineEnd:   da.Span.End,
			Symbol:    da.Operation,
		})
	}
	return evidence
}

// findDBModelInRouteHandler finds handler/controller files that directly
// reference DB model types without a DTO/response layer in between.
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

	// Build set of model symbol names from model files
	modelSymbols := make(map[string]bool)
	for _, sym := range fs.Symbols {
		if modelFiles[sym.File] && sym.Exported {
			modelSymbols[sym.Name] = true
		}
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

	// Find symbols in handler files that reference model type names
	var evidence []Evidence
	for _, sym := range fs.Symbols {
		if !languageMatch(string(sym.Language), rule.Languages) {
			continue
		}
		if !handlerFiles[sym.File] {
			continue
		}
		if isTestFilePath(sym.File) {
			continue
		}
		// Check if the symbol name contains a model type name (heuristic)
		for modelName := range modelSymbols {
			if strings.Contains(sym.Name, modelName) {
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

// findSingletonMutableGlobal finds mutable global/singleton variables.
func findSingletonMutableGlobal(rule Rule, fs *FactSet) []Evidence {
	mutableKinds := map[string]bool{
		"variable": true,
		"var":      true,
		"let":      true,
	}

	suspectNames := []string{
		"instance", "singleton", "global", "db", "client",
		"conn", "connection", "pool",
	}

	var evidence []Evidence
	for _, sym := range fs.Symbols {
		if !languageMatch(string(sym.Language), rule.Languages) {
			continue
		}
		if isTestFilePath(sym.File) {
			continue
		}
		if !mutableKinds[strings.ToLower(sym.Kind)] {
			continue
		}
		if !sym.Exported {
			continue
		}

		nameLower := strings.ToLower(sym.Name)
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
func isTestFilePath(path string) bool {
	lower := strings.ToLower(path)
	return strings.Contains(lower, "_test.") ||
		strings.Contains(lower, ".test.") ||
		strings.Contains(lower, ".spec.") ||
		strings.Contains(lower, "/test/") ||
		strings.Contains(lower, "/tests/")
}
