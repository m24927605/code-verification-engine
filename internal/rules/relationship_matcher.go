package rules

import "strings"

// matchRelationship checks whether a required relationship exists between code elements.
func matchRelationship(rule Rule, fs *FactSet, repoLanguages []string) Finding {
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

	switch rule.Target {
	case "route.protected_uses_auth_middleware":
		return matchProtectedRoutesUseAuth(rule, fs)
	case "route.public_without_auth":
		return matchPublicRoutesWithoutAuth(rule, fs)
	default:
		finding.Status = StatusUnknown
		finding.Confidence = ConfidenceLow
		finding.VerificationLevel = VerificationWeakInference
		finding.UnknownReasons = []string{UnknownUnsupportedPattern, "target: " + rule.Target}
		return finding
	}
}

// matchProtectedRoutesUseAuth checks route-to-middleware binding.
//
// This matcher can only produce verified results when routes carry explicit
// middleware bindings (route.Middlewares). Without that data it returns unknown,
// because directory/filename heuristics produce unacceptable false positive rates
// for a verification engine.
func matchProtectedRoutesUseAuth(rule Rule, fs *FactSet) Finding {
	finding := Finding{
		RuleID:  rule.ID,
		Message: rule.Message,
	}

	// Check if any routes have explicit middleware bindings
	hasBindingData := false
	for _, route := range fs.Routes {
		if len(route.Middlewares) > 0 {
			hasBindingData = true
			break
		}
	}

	if !hasBindingData {
		// Without per-route middleware binding data, we cannot reliably
		// determine which routes are protected. Return unknown rather than
		// guessing based on file proximity.
		//
		// We CAN still report whether auth middleware exists at all —
		// that's covered by the separate SEC-AUTH-001 (auth.jwt_middleware) rule.
		finding.Status = StatusUnknown
		finding.Confidence = ConfidenceLow
		finding.VerificationLevel = VerificationWeakInference
		finding.UnknownReasons = []string{
			UnknownMissingBindingData,
			"per-route middleware data not available from current analyzers",
		}
		return finding
	}

	// When binding data IS available (e.g., NestJS @UseGuards, Express inline middleware),
	// check each non-public route for auth middleware.
	authMiddlewares := make(map[string]bool)
	for _, mw := range fs.Middlewares {
		if !languageMatch(string(mw.Language), rule.Languages) {
			continue
		}
		if NameMatchesToken(mw.Name, "auth") || NameMatchesToken(mw.Name, "jwt") ||
			NameMatchesToken(mw.Name, "authenticate") {
			authMiddlewares[mw.Name] = true
		}
	}

	var unprotected []Evidence
	for _, route := range fs.Routes {
		if !languageMatch(string(route.Language), rule.Languages) {
			continue
		}
		if isPublicRoute(route.Path) {
			continue
		}
		hasAuth := false
		for _, mwName := range route.Middlewares {
			if authMiddlewares[mwName] || NameMatchesToken(mwName, "auth") || NameMatchesToken(mwName, "jwt") {
				hasAuth = true
				break
			}
		}
		if !hasAuth {
			unprotected = append(unprotected, Evidence{
				File:      route.File,
				LineStart: route.Span.Start,
				LineEnd:   route.Span.End,
				Symbol:    route.Handler,
			})
		}
	}

	if len(unprotected) > 0 {
		finding.Status = StatusFail
		finding.Confidence = ConfidenceHigh
		finding.VerificationLevel = VerificationVerified
		finding.Evidence = unprotected
	} else {
		finding.Status = StatusPass
		finding.Confidence = ConfidenceHigh
		finding.VerificationLevel = VerificationVerified
	}
	return finding
}

func matchPublicRoutesWithoutAuth(rule Rule, fs *FactSet) Finding {
	finding := Finding{
		RuleID:  rule.ID,
		Message: rule.Message,
	}

	var publicRoutes []Evidence
	for _, route := range fs.Routes {
		if !languageMatch(string(route.Language), rule.Languages) {
			continue
		}
		if isPublicRoute(route.Path) {
			publicRoutes = append(publicRoutes, Evidence{
				File:      route.File,
				LineStart: route.Span.Start,
				LineEnd:   route.Span.End,
				Symbol:    route.Handler,
			})
		}
	}

	if len(publicRoutes) > 0 {
		finding.Status = StatusPass
		finding.Confidence = ConfidenceHigh
		finding.VerificationLevel = VerificationVerified
		finding.Evidence = publicRoutes
	} else {
		// No public routes detected — this isn't necessarily bad,
		// but we can't confirm intentionality either
		finding.Status = StatusUnknown
		finding.Confidence = ConfidenceLow
		finding.VerificationLevel = VerificationWeakInference
		finding.UnknownReasons = []string{UnknownInsufficientEvidence, "no public routes detected in scanned code"}
	}
	return finding
}

func isPublicRoute(path string) bool {
	lower := strings.ToLower(path)
	publicPrefixes := []string{"/health", "/ping", "/public", "/login", "/register", "/signup", "/auth/callback"}
	for _, prefix := range publicPrefixes {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	return false
}
