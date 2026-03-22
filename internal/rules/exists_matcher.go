package rules

import "strings"

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

	evidence := findExistsEvidence(rule, fs)
	if len(evidence) > 0 {
		finding.Status = StatusPass
		finding.Confidence = ConfidenceHigh
		finding.VerificationLevel = VerificationVerified
		finding.Evidence = evidence
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

func findExistsEvidence(rule Rule, fs *FactSet) []Evidence {
	switch rule.Target {
	case "auth.jwt_middleware":
		return findJWTMiddleware(rule, fs)
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

func findJWTMiddleware(rule Rule, fs *FactSet) []Evidence {
	var evidence []Evidence
	for _, mw := range fs.Middlewares {
		if !languageMatch(string(mw.Language), rule.Languages) {
			continue
		}
		if !WhereMatchesSymbol(rule.Where, mw.Name, mw.File) {
			continue
		}
		if NameMatchesToken(mw.Name, "jwt") || NameMatchesToken(mw.Name, "auth") {
			evidence = append(evidence, Evidence{
				File:      mw.File,
				LineStart: mw.Span.Start,
				LineEnd:   mw.Span.End,
				Symbol:    mw.Name,
			})
		}
	}
	if len(evidence) == 0 {
		evidence = findJWTByImportsAndSymbols(rule, fs)
	}
	return evidence
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

func findRateLimitMiddleware(rule Rule, fs *FactSet) []Evidence {
	var evidence []Evidence
	for _, mw := range fs.Middlewares {
		if !languageMatch(string(mw.Language), rule.Languages) {
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
	return evidence
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
