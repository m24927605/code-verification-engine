package rules

import (
	"strings"

	"github.com/verabase/code-verification-engine/internal/facts"
	"github.com/verabase/code-verification-engine/internal/scope"
)

// testScopeDowngradeRules lists rules where test-only evidence should NOT
// produce a machine_trusted fail. Instead, the finding is downgraded to
// advisory confidence so operators are not misled by test-fixture noise.
var testScopeDowngradeRules = map[string]bool{
	"SEC-SECRET-001": true,
	"SEC-INPUT-001":  true,
	"SEC-HELMET-001": true,
	"SEC-RATE-001":   true,
	"FE-TOKEN-001":   true,
}

// allEvidenceFromTestScope returns true if every evidence item is from
// test or fixture scope (not production code).
func allEvidenceFromTestScope(evidence []Evidence) bool {
	if len(evidence) == 0 {
		return false
	}
	for _, ev := range evidence {
		if scope.IsProductionPath(ev.File) {
			return false
		}
	}
	return true
}

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

		// Test-only evidence downgrade: if ALL evidence is from test/fixture scope,
		// downgrade confidence. The trust class will be normalized later, but we
		// signal that this finding is test-scope-only via a lower verification level
		// and an annotation in UnknownReasons.
		if testScopeDowngradeRules[rule.ID] && allEvidenceFromTestScope(evidence) {
			finding.Confidence = ConfidenceLow
			finding.VerificationLevel = VerificationWeakInference
			finding.UnknownReasons = append(finding.UnknownReasons, "test_scope_only_evidence")
		}
	} else {
		// Pass means "not detected within scan scope", not "proven absent everywhere".
		// Absence of evidence is not evidence of absence — strong_inference, not verified.
		finding.Status = StatusPass

		// Coverage-aware pass trust gate: downgrade pass confidence when
		// the search space is not exhaustively covered.
		// Use repo-language intersection, not all rule languages — a Go-only repo
		// should not require JS/TS/Python analyzers to achieve full coverage.
		coverage := analyzerCoverageForRule(fs, rule.Languages, repoLanguages)
		switch coverage {
		case analyzerCoverageOK:
			finding.Confidence = ConfidenceMedium
			finding.VerificationLevel = VerificationStrongInference
		case analyzerCoveragePartial:
			finding.Confidence = ConfidenceLow
			finding.VerificationLevel = VerificationWeakInference
		case analyzerCoverageMissing:
			finding.Confidence = ConfidenceLow
			finding.VerificationLevel = VerificationWeakInference
			finding.UnknownReasons = append(finding.UnknownReasons, UnknownAnalyzerIncomplete)
		}
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
	case "config.secret_key_not_literal":
		return findSecretKeyNotLiteralEvidence(rule, fs)
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

	// Build a set of controller/handler files.
	// Phase 4: prefer FileRoles when available, fall back to path heuristic.
	controllerFiles := make(map[string]bool)
	hasFileRoles := len(fs.FileRoles) > 0

	if hasFileRoles {
		// Use FileRoles for controller/handler classification (stronger evidence).
		for _, fr := range fs.FileRoles {
			if fr.Role == "controller" || fr.Role == "handler" {
				controllerFiles[fr.File] = true
			}
		}
	}

	// Also apply path heuristic (always, for backward compat and to catch unlabeled files).
	for _, f := range fs.Files {
		if !languageMatch(string(f.Language), rule.Languages) {
			continue
		}
		if isControllerFile(f.File) {
			controllerFiles[f.File] = true
		}
	}

	// Build a set of controller/handler symbols (file:name key)
	controllerSymbols := make(map[string]bool)
	for _, sym := range fs.Symbols {
		if !languageMatch(string(sym.Language), rule.Languages) {
			continue
		}
		if NameMatchesToken(sym.Name, "controller") || NameMatchesToken(sym.Name, "handler") {
			controllerFiles[sym.File] = true
			controllerSymbols[sym.File+":"+sym.Name] = true
		}
	}

	// Cross-reference with route handlers: any function that serves as a route handler
	// is a controller symbol. We bind handler names to their route FILE to avoid
	// name collisions — a service-layer function with the same name as a handler
	// in a different file should NOT be treated as a controller symbol.
	routeHandlerFiles := make(map[string]bool)
	routeHandlerKeys := make(map[string]bool) // file:handler keys
	for _, r := range fs.Routes {
		if r.Handler != "" {
			routeHandlerFiles[r.File] = true
			routeHandlerKeys[r.File+":"+r.Handler] = true
		}
	}

	// Mark symbols as controller symbols only if they are in the SAME FILE
	// as their route registration. This prevents false positives from
	// different-layer functions that happen to share the same name.
	for _, sym := range fs.Symbols {
		if routeHandlerKeys[sym.File+":"+sym.Name] {
			controllerSymbols[sym.File+":"+sym.Name] = true
		}
	}

	// Build a set of service-delegation patterns to exclude.
	// Operations like "this.service.create" or "this.repository.find" are
	// service delegation, not direct DB access.
	isServiceDelegation := func(op string) bool {
		opLower := strings.ToLower(op)
		// this.xxxService.method() or this.xxxRepo.method() — service delegation
		if strings.HasPrefix(opLower, "this.") {
			rest := opLower[5:]
			if strings.Contains(rest, "service.") || strings.Contains(rest, "repo.") ||
				strings.Contains(rest, "repository.") {
				return true
			}
		}
		return false
	}

	// Identify which backends represent direct DB access
	isDirectDBBackend := func(backend, op string) bool {
		if backend != "" {
			// Any known DB backend is direct access
			return true
		}
		// No backend specified — check operation for DB indicators
		opLower := strings.ToLower(op)
		return strings.Contains(opLower, "query") || strings.Contains(opLower, "sql") ||
			strings.Contains(opLower, "drizzle") || strings.Contains(opLower, "pool") ||
			strings.Contains(opLower, "exec") || strings.Contains(opLower, "findmany") ||
			strings.Contains(opLower, "findunique") || strings.Contains(opLower, "findone")
	}

	for _, da := range fs.DataAccess {
		if !languageMatch(string(da.Language), rule.Languages) {
			continue
		}

		// Skip test/fixture files — direct DB access in tests is expected
		if scope.IsTestOrFixturePath(da.File) {
			continue
		}

		// Skip service delegation patterns
		if isServiceDelegation(da.Operation) {
			continue
		}

		// Only flag if it's a direct DB backend operation
		if !isDirectDBBackend(da.Backend, da.Operation) {
			continue
		}

		// Primary: check if the CALLER is a controller/handler symbol
		if da.CallerName != "" {
			key := da.File + ":" + da.CallerName
			if controllerSymbols[key] || controllerFiles[da.File] || routeHandlerFiles[da.File] {
				evidence = append(evidence, Evidence{
					File:      da.File,
					LineStart: da.Span.Start,
					LineEnd:   da.Span.End,
					Symbol:    da.Operation,
				})
			}
			continue // have caller context, use it precisely
		}

		// Fallback: file-path heuristic (when no caller context available)
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

// secretPriority classifies a secret finding for evidence ranking.
// Higher priority = more important to surface first.
type secretPriority int

const (
	secretPriorityTestFixture        secretPriority = 0 // test-only literal
	secretPriorityHarmlessLabel      secretPriority = 1 // token key name, storage key
	secretPriorityProductionFallback secretPriority = 3 // fallback/default prod secret
	secretPriorityRealCredential     secretPriority = 4 // likely real embedded credential
)

func classifySecretPriority(s facts.SecretFact) (secretPriority, string) {
	fileLower := strings.ToLower(s.File)
	valueLower := strings.ToLower(s.Value)

	// Test fixtures: secrets in test files
	if scope.IsTestOrFixturePath(s.File) || strings.Contains(fileLower, "sample") {
		return secretPriorityTestFixture, "test_fixture"
	}

	// Harmless labels: token key names, storage key identifiers
	// These are identifiers like TOKEN_KEY = 'my_auth_token' — the value is a label, not a secret
	if len(s.Value) > 0 && len(s.Value) < 30 && !strings.ContainsAny(s.Value, "=+/") {
		// Short, no base64 chars — likely a label not a real secret
		if strings.Contains(valueLower, "key") || strings.Contains(valueLower, "name") ||
			strings.Contains(valueLower, "prefix") || strings.Contains(valueLower, "header") {
			return secretPriorityHarmlessLabel, "storage_key_label"
		}
	}

	// Production fallback secrets: secrets in main.ts, module files, strategy files
	// with fallback/default patterns
	if strings.Contains(fileLower, "main.") || strings.Contains(fileLower, "module.") ||
		strings.Contains(fileLower, "strategy.") || strings.Contains(fileLower, "config.") ||
		strings.Contains(fileLower, "bootstrap") {
		return secretPriorityProductionFallback, "production_fallback"
	}

	// Default value patterns that suggest fallback secrets
	if strings.Contains(valueLower, "default") || strings.Contains(valueLower, "fallback") ||
		strings.Contains(valueLower, "change") || strings.Contains(valueLower, "replace") {
		return secretPriorityProductionFallback, "production_fallback"
	}

	// Otherwise: likely real embedded credential
	return secretPriorityRealCredential, "embedded_credential"
}

func findHardcodedCredentials(rule Rule, fs *FactSet) []Evidence {
	type rankedEvidence struct {
		ev       Evidence
		priority secretPriority
	}
	var ranked []rankedEvidence

	for _, s := range fs.Secrets {
		if !languageMatch(string(s.Language), rule.Languages) {
			continue
		}
		priority, classification := classifySecretPriority(s)
		ranked = append(ranked, rankedEvidence{
			ev: Evidence{
				File:      s.File,
				LineStart: s.Span.Start,
				LineEnd:   s.Span.End,
				Symbol:    s.Kind + ":" + classification,
			},
			priority: priority,
		})
	}

	// Sort by priority descending (most important first)
	for i := 0; i < len(ranked); i++ {
		for j := i + 1; j < len(ranked); j++ {
			if ranked[j].priority > ranked[i].priority {
				ranked[i], ranked[j] = ranked[j], ranked[i]
			}
		}
	}

	evidence := make([]Evidence, len(ranked))
	for i, r := range ranked {
		evidence[i] = r.ev
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
	case "config.secret_key_not_literal":
		return len(fs.ConfigReads) > 0
	default:
		return len(fs.Symbols) > 0
	}
}

// analyzerCoverage represents the aggregate coverage level of analyzers
// for a rule's required languages.
type analyzerCoverage int

const (
	analyzerCoverageOK      analyzerCoverage = iota // all relevant analyzers succeeded
	analyzerCoveragePartial                         // at least one analyzer ran partially
	analyzerCoverageMissing                         // at least one analyzer is missing or errored
)

// analyzerCoverageForRule checks the FactSet's AnalyzerStatus map against
// the intersection of the rule's required languages and the repo's actual
// languages, returning the worst-case coverage level.
//
// Only languages actually present in the repo are checked — a Go-only repo
// should not require JS/TS/Python analyzers to achieve "full coverage" for
// rules declared against allLanguages.
//
// When AnalyzerStatus is nil (pre-Phase-5 callers), we treat it as OK to
// preserve backward compatibility — the existing pass semantics are unchanged.
func analyzerCoverageForRule(fs *FactSet, ruleLanguages, repoLanguages []string) analyzerCoverage {
	if fs == nil || fs.AnalyzerStatus == nil {
		return analyzerCoverageOK
	}

	// Intersect rule languages with repo languages
	relevant := intersectLanguages(ruleLanguages, repoLanguages)
	if len(relevant) == 0 {
		// Rule doesn't apply to any repo language — shouldn't reach here,
		// but treat as OK to be safe.
		return analyzerCoverageOK
	}

	worst := analyzerCoverageOK
	for _, lang := range relevant {
		status, exists := fs.AnalyzerStatus[lang]
		if !exists || status == "error" {
			return analyzerCoverageMissing
		}
		if status == "partial" && worst < analyzerCoveragePartial {
			worst = analyzerCoveragePartial
		}
	}
	return worst
}
