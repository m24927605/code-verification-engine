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

// matchProtectedRoutesUseAuth checks route-to-middleware binding using auth evidence scoring.
//
// Per spec: route protection NEVER produces VerificationVerified — only strong_inference at most
// (advisory trust class). This is because middleware binding is a structural signal, not runtime proof.
//
// A route is "protected" only if ANY bound middleware classifies as AuthStrong via ClassifyAuth.
// AuthWeak-only routes are treated as insufficiently protected → unknown.
//
// Outcome logic for routes WITH binding data:
//   - Any route has a middleware with AuthStrong → pass outcome for that route
//   - Any route with binding has NO AuthStrong middleware → unprotected (fail evidence)
//   - Any route with binding has only AuthWeak middlewares → weak_only (insufficient)
//
// Final aggregation:
//   - Any unprotected routes → StatusFail + strong_inference
//   - All binding routes have AuthStrong → StatusPass + strong_inference (or medium if some nil)
//   - All binding routes are weak_only and no fail → StatusUnknown (insufficient)
//   - No routes with binding → StatusUnknown
func matchProtectedRoutesUseAuth(rule Rule, fs *FactSet) Finding {
	finding := Finding{
		RuleID:  rule.ID,
		Message: rule.Message,
	}

	// Build file→import-paths index for auth import detection.
	fileImports := make(map[string][]string)
	for _, imp := range fs.Imports {
		if !languageMatch(string(imp.Language), rule.Languages) {
			continue
		}
		fileImports[imp.File] = append(fileImports[imp.File], imp.ImportPath)
	}

	// Per-route evaluation with four possible outcomes per route:
	//   - has binding data + has AuthStrong middleware → strongProtected
	//   - has binding data + no AuthStrong + has AuthWeak → weakOnly
	//   - has binding data + no auth at all → unprotected (evidence of fail)
	//   - no binding data → unknown for this route (cannot determine)
	//
	// Key design: routes WITHOUT binding data are NOT treated as "unprotected".
	// Missing binding data means the analyzer couldn't extract middleware info
	// for that route, which is different from "route explicitly has no auth".
	var unprotected []Evidence
	routesWithBinding := 0
	routesWeakOnly := 0
	routesWithoutBinding := 0
	totalNonPublic := 0

	for _, route := range fs.Routes {
		if !languageMatch(string(route.Language), rule.Languages) {
			continue
		}
		if isPublicRoute(route.Path) {
			continue
		}
		totalNonPublic++

		if route.Middlewares == nil {
			// nil means the analyzer could not extract binding data for this route.
			// This is different from an empty slice (explicitly no middleware).
			// Do NOT count as unprotected — treat as unknown for this route.
			routesWithoutBinding++
			continue
		}

		routesWithBinding++
		bestClass := AuthNotDetected

		for _, mwName := range route.Middlewares {
			hasAuth, hasContra := ClassifyMiddlewareName(mwName)
			hasImport := HasKnownAuthImport(string(route.Language), fileImports[route.File])

			ev := AuthEvidence{
				HasMiddlewareBinding: true, // bound to route
				HasAuthImport:        hasImport,
				HasAuthName:          hasAuth,
				HasContradictoryName: hasContra,
				MiddlewareName:       mwName,
			}
			class := ClassifyAuth(ev)
			if class > bestClass {
				bestClass = class
			}
			if bestClass == AuthStrong {
				break // no need to check remaining middlewares
			}
		}

		switch bestClass {
		case AuthStrong:
			// Route is protected — no evidence added.
		case AuthWeak:
			routesWeakOnly++
		default:
			// AuthNotDetected: route has binding but no auth → unprotected
			unprotected = append(unprotected, Evidence{
				File:      route.File,
				LineStart: route.Span.Start,
				LineEnd:   route.Span.End,
				Symbol:    route.Handler,
			})
		}
	}

	if totalNonPublic == 0 {
		// No non-public routes to check
		finding.Status = StatusUnknown
		finding.Confidence = ConfidenceLow
		finding.VerificationLevel = VerificationWeakInference
		finding.UnknownReasons = []string{UnknownInsufficientEvidence, "no non-public routes detected"}
		return finding
	}

	if routesWithBinding == 0 {
		// No routes have binding data at all — cannot verify
		finding.Status = StatusUnknown
		finding.Confidence = ConfidenceLow
		finding.VerificationLevel = VerificationWeakInference
		finding.UnknownReasons = []string{
			UnknownMissingBindingData,
			"per-route middleware data not available from current analyzers",
		}
		return finding
	}

	if len(unprotected) > 0 {
		// At least one route WITH binding data lacks auth middleware
		// Per spec: route protection never produces VerificationVerified
		finding.Status = StatusFail
		finding.Confidence = ConfidenceHigh
		finding.VerificationLevel = VerificationStrongInference
		finding.Evidence = unprotected
		return finding
	}

	// No outright unprotected routes. Check if all binding routes are AuthWeak only.
	protectedRoutes := routesWithBinding - routesWeakOnly
	if protectedRoutes == 0 {
		// All routes with binding have only AuthWeak evidence → insufficient to determine
		finding.Status = StatusUnknown
		finding.Confidence = ConfidenceLow
		finding.VerificationLevel = VerificationWeakInference
		finding.UnknownReasons = []string{
			UnknownInsufficientEvidence,
			"all bound middlewares have weak auth evidence only; import confirmation required",
		}
		return finding
	}

	// At least some routes with binding have AuthStrong middlewares.
	// Per spec: route protection never produces VerificationVerified.
	if routesWithoutBinding > 0 || routesWeakOnly > 0 {
		finding.Status = StatusPass
		finding.Confidence = ConfidenceMedium
		finding.VerificationLevel = VerificationStrongInference
	} else {
		finding.Status = StatusPass
		finding.Confidence = ConfidenceHigh
		finding.VerificationLevel = VerificationStrongInference
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
