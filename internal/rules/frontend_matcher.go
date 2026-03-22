package rules

import "strings"

// Frontend security and quality matchers.

// findDangerousHTML looks for dangerouslySetInnerHTML, v-html, [innerHTML], bypassSecurityTrustHtml usage.
func findDangerousHTML(rule Rule, fs *FactSet) []Evidence {
	dangerousPatterns := []string{
		"dangerouslysetinnerhtml", "v-html", "[innerhtml]", "bypasssecuritytrusthtml",
	}
	var evidence []Evidence
	for _, sym := range fs.Symbols {
		if !languageMatch(string(sym.Language), rule.Languages) {
			continue
		}
		lower := strings.ToLower(sym.Name)
		for _, pattern := range dangerousPatterns {
			if strings.Contains(lower, pattern) {
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
	for _, imp := range fs.Imports {
		if !languageMatch(string(imp.Language), rule.Languages) {
			continue
		}
		lower := strings.ToLower(imp.ImportPath)
		if strings.Contains(lower, "dompurify") || strings.Contains(lower, "sanitize-html") {
			// These are sanitizers — presence alongside dangerous HTML is not necessarily bad,
			// but we still flag the dangerous patterns found above.
			continue
		}
	}
	return evidence
}

// findInnerHTMLUsage looks for direct innerHTML assignments.
func findInnerHTMLUsage(rule Rule, fs *FactSet) []Evidence {
	var evidence []Evidence
	for _, sym := range fs.Symbols {
		if !languageMatch(string(sym.Language), rule.Languages) {
			continue
		}
		lower := strings.ToLower(sym.Name)
		if strings.Contains(lower, "innerhtml") {
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

// findTokenInLocalStorage detects auth token storage in localStorage/sessionStorage.
// Detection strategies:
//  1. Direct call expressions: localStorage.setItem(...) / sessionStorage.setItem(...)
//     emitted by the analyzer as SymbolFacts with kind "call_expression"
//  2. Token storage wrapper functions: functions in auth-related files whose names
//     suggest token persistence (setToken, storeToken, saveToken, persistToken)
//  3. Symbol name heuristic (legacy): symbols containing both "localstorage" and a token keyword
//  4. Auth-file context: localStorage/sessionStorage calls in files whose path contains "auth"
func findTokenInLocalStorage(rule Rule, fs *FactSet) []Evidence {
	tokenKeywords := []string{"token", "jwt", "auth", "session", "credential", "access_token", "refresh_token"}

	// Build set of files that contain localStorage/sessionStorage call expressions
	storageCallFiles := make(map[string]bool)
	var evidence []Evidence

	for _, sym := range fs.Symbols {
		if !languageMatch(string(sym.Language), rule.Languages) {
			continue
		}
		lower := strings.ToLower(sym.Name)

		// Strategy 1: Direct call expressions emitted by analyzer (e.g., "localStorage.setItem")
		if sym.Kind == "call_expression" &&
			(strings.HasPrefix(lower, "localstorage.") || strings.HasPrefix(lower, "sessionstorage.")) {
			storageCallFiles[sym.File] = true
			// Check if this call is in a file with auth/token context
			fileLower := strings.ToLower(sym.File)
			for _, kw := range tokenKeywords {
				if strings.Contains(fileLower, kw) {
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

		// Strategy 3: Legacy symbol name heuristic
		if strings.Contains(lower, "localstorage") &&
			(strings.Contains(lower, "token") || strings.Contains(lower, "jwt") ||
				strings.Contains(lower, "auth") || strings.Contains(lower, "session")) {
			evidence = append(evidence, Evidence{
				File:      sym.File,
				LineStart: sym.Span.Start,
				LineEnd:   sym.Span.End,
				Symbol:    sym.Name,
			})
		}
	}

	// Strategy 2: Token storage wrapper functions in files that have localStorage calls
	for _, sym := range fs.Symbols {
		if !languageMatch(string(sym.Language), rule.Languages) {
			continue
		}
		if sym.Kind != "function" {
			continue
		}
		if !storageCallFiles[sym.File] {
			continue
		}
		lower := strings.ToLower(sym.Name)
		// Functions that set/store/save/persist tokens
		isStorageFunc := (strings.Contains(lower, "set") || strings.Contains(lower, "store") ||
			strings.Contains(lower, "save") || strings.Contains(lower, "persist"))
		hasTokenRef := false
		for _, kw := range tokenKeywords {
			if strings.Contains(lower, kw) {
				hasTokenRef = true
				break
			}
		}
		if isStorageFunc && hasTokenRef {
			evidence = append(evidence, Evidence{
				File:      sym.File,
				LineStart: sym.Span.Start,
				LineEnd:   sym.Span.End,
				Symbol:    sym.Name,
			})
		}
	}

	// Strategy 4: Check for constant definitions with token-like key names in files with localStorage calls
	for _, sym := range fs.Symbols {
		if !languageMatch(string(sym.Language), rule.Languages) {
			continue
		}
		if !storageCallFiles[sym.File] {
			continue
		}
		if sym.Kind != "variable" && sym.Kind != "const" {
			continue
		}
		lower := strings.ToLower(sym.Name)
		// Constants like TOKEN_KEY, AUTH_TOKEN, SESSION_KEY
		for _, kw := range tokenKeywords {
			if strings.Contains(lower, kw) && (strings.Contains(lower, "key") || strings.Contains(lower, "name") || strings.Contains(lower, "storage")) {
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

// findEnvExposesSecret looks for public env vars (NEXT_PUBLIC_, VITE_, REACT_APP_) containing secret/key/password/token.
func findEnvExposesSecret(rule Rule, fs *FactSet) []Evidence {
	publicPrefixes := []string{"next_public_", "vite_", "react_app_"}
	sensitiveKeywords := []string{"secret", "key", "password", "token", "credential", "private"}
	var evidence []Evidence
	for _, sym := range fs.Symbols {
		if !languageMatch(string(sym.Language), rule.Languages) {
			continue
		}
		lower := strings.ToLower(sym.Name)
		hasPublicPrefix := false
		for _, prefix := range publicPrefixes {
			if strings.Contains(lower, prefix) {
				hasPublicPrefix = true
				break
			}
		}
		if !hasPublicPrefix {
			continue
		}
		for _, kw := range sensitiveKeywords {
			if strings.Contains(lower, kw) {
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
	for _, f := range fs.Files {
		lower := strings.ToLower(f.File)
		if !strings.Contains(lower, ".env") {
			continue
		}
		// File-level check: env files with public prefixes exposing secrets
		// This is a heuristic — full detection requires reading file contents
	}
	return evidence
}

// findAuthGuard looks for route protection patterns like ProtectedRoute, AuthGuard, requireAuth.
func findAuthGuard(rule Rule, fs *FactSet) []Evidence {
	guardPatterns := []string{
		"protectedroute", "authguard", "requireauth", "canactivate",
		"privateroute", "authmiddleware", "routeguard", "withauth",
		"useauth", "isauthenticated",
	}
	var evidence []Evidence
	for _, sym := range fs.Symbols {
		if !languageMatch(string(sym.Language), rule.Languages) {
			continue
		}
		lower := strings.ToLower(sym.Name)
		for _, pattern := range guardPatterns {
			if strings.Contains(lower, pattern) {
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
	// Also check imports for auth middleware packages
	authPackages := []string{"@auth0", "next-auth", "passport", "auth-guard", "vue-router/guard"}
	for _, imp := range fs.Imports {
		if !languageMatch(string(imp.Language), rule.Languages) {
			continue
		}
		for _, pkg := range authPackages {
			if strings.Contains(strings.ToLower(imp.ImportPath), pkg) {
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

// findAPIErrorHandling looks for global error handling patterns like interceptors and error boundaries.
func findAPIErrorHandling(rule Rule, fs *FactSet) []Evidence {
	errorHandlingPackages := []string{
		"axios", "react-error-boundary", "error-boundary",
		"@angular/common/http", "vue-axios",
	}
	var evidence []Evidence
	for _, imp := range fs.Imports {
		if !languageMatch(string(imp.Language), rule.Languages) {
			continue
		}
		for _, pkg := range errorHandlingPackages {
			if strings.Contains(strings.ToLower(imp.ImportPath), pkg) {
				evidence = append(evidence, Evidence{
					File:      imp.File,
					LineStart: imp.Span.Start,
					LineEnd:   imp.Span.End,
					Symbol:    imp.ImportPath,
				})
			}
		}
	}
	// Check for error handling symbols
	for _, sym := range fs.Symbols {
		if !languageMatch(string(sym.Language), rule.Languages) {
			continue
		}
		lower := strings.ToLower(sym.Name)
		if strings.Contains(lower, "errorboundary") || strings.Contains(lower, "interceptor") ||
			strings.Contains(lower, "globalerrorhandler") ||
			(strings.Contains(lower, "error") && strings.Contains(lower, "handler")) {
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

// findCSPConfigured looks for Content-Security-Policy configuration or helmet CSP usage.
func findCSPConfigured(rule Rule, fs *FactSet) []Evidence {
	cspPackages := []string{"helmet", "csp", "content-security-policy"}
	var evidence []Evidence
	for _, imp := range fs.Imports {
		if !languageMatch(string(imp.Language), rule.Languages) {
			continue
		}
		for _, pkg := range cspPackages {
			if strings.Contains(strings.ToLower(imp.ImportPath), pkg) {
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
		lower := strings.ToLower(sym.Name)
		if strings.Contains(lower, "contentsecuritypolicy") || strings.Contains(lower, "csp") {
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

// findLockfileExists looks for package lock files (package-lock.json, yarn.lock, pnpm-lock.yaml).
func findLockfileExists(rule Rule, fs *FactSet) []Evidence {
	lockfiles := []string{"package-lock.json", "yarn.lock", "pnpm-lock.yaml"}
	var evidence []Evidence
	for _, f := range fs.Files {
		lower := strings.ToLower(f.File)
		for _, lockfile := range lockfiles {
			if strings.HasSuffix(lower, lockfile) {
				evidence = append(evidence, Evidence{
					File:      f.File,
					LineStart: 1,
					LineEnd:   1,
					Symbol:    f.File,
				})
				break
			}
		}
	}
	return evidence
}

// findConsoleLogInProduction checks for console.log usage in production code.
// Precise detection is difficult without build configuration analysis — returns nil (unknown).
func findConsoleLogInProduction(_ Rule, _ *FactSet) []Evidence {
	return nil
}

// findFormValidation looks for form validation library imports.
func findFormValidation(rule Rule, fs *FactSet) []Evidence {
	validationPackages := []string{
		"react-hook-form", "formik", "vee-validate", "@angular/forms",
		"yup", "zod", "joi", "vuelidate", "final-form",
	}
	var evidence []Evidence
	for _, imp := range fs.Imports {
		if !languageMatch(string(imp.Language), rule.Languages) {
			continue
		}
		for _, pkg := range validationPackages {
			if strings.Contains(strings.ToLower(imp.ImportPath), pkg) {
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
		lower := strings.ToLower(sym.Name)
		if strings.Contains(lower, "useform") || strings.Contains(lower, "formvalidation") ||
			strings.Contains(lower, "validateform") {
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
