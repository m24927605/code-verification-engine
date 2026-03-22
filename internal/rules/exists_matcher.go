package rules

import (
	"strings"

	"github.com/verabase/code-verification-engine/internal/scope"
)

// evidenceResult bundles evidence with the verification level appropriate for that evidence.
// This allows sub-finders to signal whether evidence is "verified" or merely "strong_inference".
type evidenceResult struct {
	Evidence          []Evidence
	VerificationLevel VerificationLevel
}

// matchExists checks whether a required capability or structure exists.
func matchExists(rule Rule, fs *FactSet, repoLanguages []string) Finding {
	finding := Finding{
		RuleID:  rule.ID,
		Message: rule.Message,
	}

	required := RequiredFactTypes(rule.Target)
	if !hasMinimalFacts(fs, required) {
		finding.Status = StatusUnknown
		finding.Confidence = ConfidenceLow
		finding.VerificationLevel = VerificationWeakInference
		finding.UnknownReasons = []string{UnknownInsufficientEvidence, "target: " + rule.Target}
		return finding
	}

	result := findExistsEvidenceResult(rule, fs)
	if len(result.Evidence) > 0 {
		finding.Status = StatusPass
		finding.Confidence = ConfidenceHigh
		finding.VerificationLevel = result.VerificationLevel
		finding.Evidence = result.Evidence
	} else {
		// Absence of evidence is not verified evidence of absence.
		// We thoroughly searched the codebase and found nothing, which is
		// strong inference but not direct evidence we can point to.
		finding.Status = StatusFail
		finding.Confidence = ConfidenceMedium
		finding.VerificationLevel = VerificationStrongInference
	}
	return finding
}

// findExistsEvidenceResult returns an evidenceResult that includes both evidence
// and the appropriate verification level. For targets that benefit from auth scoring
// (e.g. auth.jwt_middleware), the level is determined by evidence strength.
func findExistsEvidenceResult(rule Rule, fs *FactSet) evidenceResult {
	switch rule.Target {
	case "auth.jwt_middleware":
		return findJWTMiddlewareResult(rule, fs)
	case "security.cors_configuration":
		return findCORSEvidenceResult(rule, fs)
	case "config.env_based":
		return findEnvBasedConfigResult(rule, fs)
	default:
		ev := findExistsEvidence(rule, fs)
		return evidenceResult{Evidence: ev, VerificationLevel: VerificationVerified}
	}
}

// findEnvBasedConfigResult wraps findEnvBasedConfig with appropriate verification level.
// Phase 4: When ConfigReads with SourceKind="env" are present, the evidence is structural
// (binding-level). Otherwise, it falls back to heuristic import matching.
func findEnvBasedConfigResult(rule Rule, fs *FactSet) evidenceResult {
	// Check if ConfigReads has env entries — if so, evidence is structural-level.
	if len(fs.ConfigReads) > 0 {
		for _, cr := range fs.ConfigReads {
			if languageMatch(string(cr.Language), rule.Languages) && cr.SourceKind == "env" {
				// At least one ConfigRead with env source exists — use structural path.
				ev := findEnvBasedConfig(rule, fs)
				if len(ev) > 0 {
					return evidenceResult{Evidence: ev, VerificationLevel: VerificationStrongInference}
				}
				break
			}
		}
	}

	// Fallback: heuristic import-based detection.
	ev := findEnvBasedConfig(rule, fs)
	return evidenceResult{Evidence: ev, VerificationLevel: VerificationVerified}
}

// findCORSEvidenceResult handles SEC-CORS-001 with semantic distinction between:
//   - pass: configured and constrained
//   - fail with evidence: configured but dangerously permissive
//   - fail without evidence: no configuration found
func findCORSEvidenceResult(rule Rule, fs *FactSet) evidenceResult {
	corsEvidence := findCORSConfiguration(rule, fs)
	permissiveEvidence := findCORSPermissive(rule, fs)

	if len(permissiveEvidence) > 0 {
		// CORS is configured but dangerously permissive — return as evidence
		// The exists matcher will report "pass" because evidence was found,
		// but we annotate the evidence to indicate the permissive configuration
		return evidenceResult{Evidence: permissiveEvidence, VerificationLevel: VerificationStrongInference}
	}

	if len(corsEvidence) > 0 {
		return evidenceResult{Evidence: corsEvidence, VerificationLevel: VerificationVerified}
	}

	return evidenceResult{}
}

func findExistsEvidence(rule Rule, fs *FactSet) []Evidence {
	switch rule.Target {
	case "auth.api_key_validation":
		return findAPIKeyValidation(rule, fs)
	case "rate_limit.middleware":
		return findRateLimitMiddleware(rule, fs)
	case "layer.repository":
		return findRepositoryLayer(rule, fs)
	case "layer.service":
		return findServiceLayer(rule, fs)
	case "config.env_based":
		return findEnvBasedConfig(rule, fs)
	case "security.input_validation":
		return findInputValidation(rule, fs)
	case "security.cors_configuration":
		return findCORSConfiguration(rule, fs)
	case "security.headers_middleware":
		return findSecurityHeaders(rule, fs)
	case "error.global_handler":
		return findGlobalErrorHandler(rule, fs)
	case "error.panic_recovery":
		return findPanicRecovery(rule, fs)
	case "logging.structured":
		return findStructuredLogging(rule, fs)
	case "logging.request_logging":
		return findRequestLogging(rule, fs)
	case "route.health_check":
		return findHealthCheckRoute(rule, fs)
	case "lifecycle.graceful_shutdown":
		return findGracefulShutdown(rule, fs)
	case "architecture.dependency_injection":
		return findDependencyInjection(rule, fs)
	case "frontend.auth_guard":
		return findAuthGuard(rule, fs)
	case "frontend.api_error_handling":
		return findAPIErrorHandling(rule, fs)
	case "frontend.csp_configured":
		return findCSPConfigured(rule, fs)
	case "frontend.lockfile_exists":
		return findLockfileExists(rule, fs)
	case "frontend.form_validation":
		return findFormValidation(rule, fs)
	case "gof.singleton", "gof.factory_method", "gof.abstract_factory", "gof.builder", "gof.prototype",
		"gof.adapter", "gof.bridge", "gof.composite", "gof.decorator", "gof.facade", "gof.flyweight", "gof.proxy",
		"gof.chain_of_responsibility", "gof.command", "gof.interpreter", "gof.iterator", "gof.mediator",
		"gof.memento", "gof.observer", "gof.state", "gof.strategy", "gof.template_method", "gof.visitor":
		return findGoFEvidence(rule, fs)
	default:
		return nil
	}
}

// findJWTMiddlewareResult uses auth evidence scoring to classify each MiddlewareFact
// and returns the best evidence found along with the appropriate verification level.
//
// Scoring (via ClassifyAuth):
//
//	AuthStrong (score>=5) → VerificationStrongInference (advisory trust — binding not checked here)
//	AuthWeak   (score>=1) → VerificationWeakInference
//	AuthNotDetected       → skipped
//
// Per spec: jwt_middleware existence check is an exists rule and therefore NEVER produces
// VerificationVerified — only strong_inference at most, because we cannot prove route binding
// from an exists check alone.
func findJWTMiddlewareResult(rule Rule, fs *FactSet) evidenceResult {
	// Phase 4: Check for binding-level evidence first (AppBindings/RouteBindings).
	// Binding evidence is stronger than heuristic because it proves the auth mechanism
	// is actually registered in the application, not just defined.
	bindingEvidence := findAuthBindingEvidence(rule, fs)
	if len(bindingEvidence) > 0 {
		return evidenceResult{Evidence: bindingEvidence, VerificationLevel: VerificationStrongInference}
	}

	// Fallback: heuristic matching via middleware names and imports (pre-Phase 4 behavior).
	// Build file→import-paths index for language-aware auth import detection.
	fileImports := make(map[string][]string)
	for _, imp := range fs.Imports {
		if !languageMatch(string(imp.Language), rule.Languages) {
			continue
		}
		fileImports[imp.File] = append(fileImports[imp.File], imp.ImportPath)
	}

	bestClass := AuthNotDetected
	var strongEvidence []Evidence
	var weakEvidence []Evidence

	for _, mw := range fs.Middlewares {
		if !languageMatch(string(mw.Language), rule.Languages) {
			continue
		}
		if !WhereMatchesSymbol(rule.Where, mw.Name, mw.File) {
			continue
		}

		hasAuth, hasContra := ClassifyMiddlewareName(mw.Name)
		hasImport := HasKnownAuthImport(string(mw.Language), fileImports[mw.File])

		ev := AuthEvidence{
			HasMiddlewareBinding: false, // exists check, not route-bound
			HasAuthImport:        hasImport,
			HasAuthName:          hasAuth,
			HasContradictoryName: hasContra,
			MiddlewareName:       mw.Name,
		}
		class := ClassifyAuth(ev)

		entry := Evidence{
			File:      mw.File,
			LineStart: mw.Span.Start,
			LineEnd:   mw.Span.End,
			Symbol:    mw.Name,
		}

		switch class {
		case AuthStrong:
			if bestClass < AuthStrong {
				bestClass = AuthStrong
			}
			strongEvidence = append(strongEvidence, entry)
		case AuthWeak:
			if bestClass < AuthWeak {
				bestClass = AuthWeak
			}
			weakEvidence = append(weakEvidence, entry)
		}
	}

	if bestClass == AuthStrong {
		return evidenceResult{Evidence: strongEvidence, VerificationLevel: VerificationStrongInference}
	}
	if bestClass == AuthWeak {
		return evidenceResult{Evidence: weakEvidence, VerificationLevel: VerificationWeakInference}
	}

	// Fallback: check JWT imports + matching symbols (symbol-level weak inference).
	fallback := findJWTByImportsAndSymbols(rule, fs)
	if len(fallback) > 0 {
		return evidenceResult{Evidence: fallback, VerificationLevel: VerificationWeakInference}
	}
	return evidenceResult{}
}

func findJWTByImportsAndSymbols(rule Rule, fs *FactSet) []Evidence {
	var evidence []Evidence
	jwtImportFiles := make(map[string]bool)
	for _, imp := range fs.Imports {
		if !languageMatch(string(imp.Language), rule.Languages) {
			continue
		}
		if strings.Contains(imp.ImportPath, "jwt") || strings.Contains(imp.ImportPath, "jsonwebtoken") {
			jwtImportFiles[imp.File] = true
		}
	}
	if len(jwtImportFiles) == 0 {
		return nil
	}
	for _, sym := range fs.Symbols {
		if !languageMatch(string(sym.Language), rule.Languages) {
			continue
		}
		if !jwtImportFiles[sym.File] {
			continue
		}
		if !WhereMatchesSymbol(rule.Where, sym.Name, sym.File) {
			continue
		}
		if NameMatchesToken(sym.Name, "verify") || NameMatchesToken(sym.Name, "validate") ||
			NameMatchesToken(sym.Name, "middleware") || NameMatchesToken(sym.Name, "auth") ||
			NameMatchesToken(sym.Name, "token") {
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

func findAPIKeyValidation(rule Rule, fs *FactSet) []Evidence {
	var evidence []Evidence
	for _, sym := range fs.Symbols {
		if !languageMatch(string(sym.Language), rule.Languages) {
			continue
		}
		if !WhereMatchesSymbol(rule.Where, sym.Name, sym.File) {
			continue
		}
		if (NameMatchesToken(sym.Name, "api") && NameMatchesToken(sym.Name, "key")) ||
			(NameMatchesToken(sym.Name, "api") && NameMatchesToken(sym.Name, "validate")) {
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

// findRateLimitMiddleware looks for rate limiting that is actually bound/registered,
// not just a class definition without runtime binding.
func findRateLimitMiddleware(rule Rule, fs *FactSet) []Evidence {
	var evidence []Evidence
	for _, mw := range fs.Middlewares {
		if !languageMatch(string(mw.Language), rule.Languages) {
			continue
		}
		if scope.IsTestOrFixturePath(mw.File) {
			continue
		}
		if !WhereMatchesSymbol(rule.Where, mw.Name, mw.File) {
			continue
		}
		if NameMatchesToken(mw.Name, "rate") || NameMatchesToken(mw.Name, "limit") ||
			NameMatchesToken(mw.Name, "throttle") {
			evidence = append(evidence, Evidence{
				File:      mw.File,
				LineStart: mw.Span.Start,
				LineEnd:   mw.Span.End,
				Symbol:    mw.Name,
			})
		}
	}

	// Also check for class definitions + binding evidence
	if len(evidence) == 0 {
		// Look for rate-limit class definitions
		var classEvidence []Evidence
		for _, sym := range fs.Symbols {
			if !languageMatch(string(sym.Language), rule.Languages) {
				continue
			}
			if scope.IsTestOrFixturePath(sym.File) {
				continue
			}
			lower := strings.ToLower(sym.Name)
			if (strings.Contains(lower, "ratelimit") || strings.Contains(lower, "rate_limit") ||
				strings.Contains(lower, "throttle")) &&
				(sym.Kind == "class" || sym.Kind == "function") {
				classEvidence = append(classEvidence, Evidence{
					File:      sym.File,
					LineStart: sym.Span.Start,
					LineEnd:   sym.Span.End,
					Symbol:    sym.Name,
				})
			}
		}
		// Only return class evidence if there's also binding evidence
		if len(classEvidence) > 0 && hasRuntimeBindingEvidence(fs, rule.Languages) {
			return classEvidence
		}
	}

	return evidence
}

// hasRuntimeBindingEvidence checks if there are NestJS global registration patterns
// (APP_INTERCEPTOR, APP_FILTER, useGlobalInterceptors, consumer.apply, etc.)
func hasRuntimeBindingEvidence(fs *FactSet, languages []string) bool {
	for _, sym := range fs.Symbols {
		if !languageMatch(string(sym.Language), languages) {
			continue
		}
		switch sym.Kind {
		case "provider_registration", "global_registration", "middleware_registration":
			return true
		}
	}
	return false
}

func findRepositoryLayer(rule Rule, fs *FactSet) []Evidence {
	var evidence []Evidence
	for _, sym := range fs.Symbols {
		if !languageMatch(string(sym.Language), rule.Languages) {
			continue
		}
		if !WhereMatchesSymbol(rule.Where, sym.Name, sym.File) {
			continue
		}
		if NameMatchesToken(sym.Name, "repository") || NameMatchesToken(sym.Name, "repo") {
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
