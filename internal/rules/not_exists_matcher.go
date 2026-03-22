package rules

import "strings"

// matchNotExists checks that an undesirable pattern is absent.
// Safety: pass means "not detected within scope", not "proven absent everywhere".
func matchNotExists(rule Rule, fs *FactSet, repoLanguages []string) Finding {
	finding := Finding{
		RuleID:  rule.ID,
		Message: rule.Message,
	}

	if !hasMinimalFactsForNotExists(fs, rule.Target) {
		finding.Status = StatusUnknown
		finding.Confidence = ConfidenceLow
		finding.VerificationLevel = VerificationWeakInference
		finding.UnknownReasons = []string{UnknownInsufficientEvidence, "target: " + rule.Target}
		return finding
	}

	evidence := findNotExistsEvidence(rule, fs)
	if len(evidence) > 0 {
		finding.Status = StatusFail
		finding.Confidence = ConfidenceHigh
		finding.VerificationLevel = VerificationVerified
		finding.Evidence = evidence
	} else {
		finding.Status = StatusPass
		finding.Confidence = ConfidenceHigh
		finding.VerificationLevel = VerificationVerified
	}
	return finding
}

func findNotExistsEvidence(rule Rule, fs *FactSet) []Evidence {
	switch rule.Target {
	case "db.direct_access_from_controller":
		return findDirectDBAccessFromController(rule, fs)
	case "secret.hardcoded_credential":
		return findHardcodedCredentials(rule, fs)
	case "secret.env_file_committed":
		return findEnvFileCommitted(rule, fs)
	case "security.sql_injection_pattern":
		return findSQLInjectionPattern(rule, fs)
	case "security.sensitive_data_in_logs":
		return findSensitiveDataInLogs(rule, fs)
	case "frontend.xss_dangerous_html":
		return findDangerousHTML(rule, fs)
	case "frontend.xss_innerhtml":
		return findInnerHTMLUsage(rule, fs)
	case "frontend.token_in_localstorage":
		return findTokenInLocalStorage(rule, fs)
	case "frontend.env_exposes_secret":
		return findEnvExposesSecret(rule, fs)
	case "frontend.console_log_in_production":
		return findConsoleLogInProduction(rule, fs)
	case "pattern.repository_encapsulation":
		return findDBAccessOutsideRepo(rule, fs)
	case "pattern.dto_separation":
		return findDBModelInRouteHandler(rule, fs)
	case "pattern.singleton_mutable_global":
		return findSingletonMutableGlobal(rule, fs)
	default:
		return nil
	}
}

func findDirectDBAccessFromController(rule Rule, fs *FactSet) []Evidence {
	var evidence []Evidence
	controllerFiles := make(map[string]bool)
	for _, f := range fs.Files {
		if !languageMatch(string(f.Language), rule.Languages) {
			continue
		}
		if isControllerFile(f.File) {
			controllerFiles[f.File] = true
		}
	}
	for _, sym := range fs.Symbols {
		if !languageMatch(string(sym.Language), rule.Languages) {
			continue
		}
		if NameMatchesToken(sym.Name, "controller") || NameMatchesToken(sym.Name, "handler") {
			controllerFiles[sym.File] = true
		}
	}

	for _, da := range fs.DataAccess {
		if !languageMatch(string(da.Language), rule.Languages) {
			continue
		}
		if controllerFiles[da.File] {
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

func findHardcodedCredentials(rule Rule, fs *FactSet) []Evidence {
	var evidence []Evidence
	for _, s := range fs.Secrets {
		if !languageMatch(string(s.Language), rule.Languages) {
			continue
		}
		evidence = append(evidence, Evidence{
			File:      s.File,
			LineStart: s.Span.Start,
			LineEnd:   s.Span.End,
			Symbol:    s.Kind,
		})
	}
	return evidence
}

func isControllerFile(path string) bool {
	lower := strings.ToLower(path)
	return strings.Contains(lower, "controller") || strings.Contains(lower, "handler") || strings.Contains(lower, "endpoint")
}

func hasMinimalFactsForNotExists(fs *FactSet, target string) bool {
	if fs == nil {
		return false
	}
	switch target {
	case "db.direct_access_from_controller":
		return len(fs.Symbols) > 0 || len(fs.Files) > 0
	case "secret.hardcoded_credential":
		return len(fs.Files) > 0 || len(fs.Symbols) > 0 || len(fs.Secrets) > 0
	case "frontend.env_exposes_secret":
		return len(fs.Files) > 0 || len(fs.Symbols) > 0
	case "frontend.xss_dangerous_html":
		return len(fs.Symbols) > 0 || len(fs.Imports) > 0
	case "frontend.xss_innerhtml":
		return len(fs.Symbols) > 0
	case "frontend.token_in_localstorage":
		return len(fs.Symbols) > 0
	case "frontend.console_log_in_production":
		return len(fs.Symbols) > 0
	case "pattern.repository_encapsulation":
		return len(fs.DataAccess) > 0
	case "pattern.dto_separation":
		return len(fs.Symbols) > 0 && len(fs.Routes) > 0
	case "pattern.singleton_mutable_global":
		return len(fs.Symbols) > 0
	default:
		return len(fs.Symbols) > 0
	}
}
