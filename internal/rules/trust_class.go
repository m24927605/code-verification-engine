package rules

// machineTrustedRules is the canonical set of rule IDs whose matchers produce
// evidence strong enough for automated consumption without human review.
//
// Admission criteria (from trusted-verdict-design.md):
//   - Matcher must be proof-oriented, not symbol-name heuristic
//   - Both pass and fail semantics must be documented
//   - Evidence spans must be stable and replayable
//
// NOT included (currently heuristic, pending matcher upgrades):
//   - FE-XSS-001, FE-XSS-002: symbol-name substring match, not AST/sink analysis
//   - FE-TOKEN-001: symbol-name substring match for "localstorage"/"token"
//   - FE-ENV-001: symbol-name substring match for public env prefixes
//   - FE-LOG-001: symbol-name substring match for "console.log"
//   - ARCH-LAYER-001: controller identification uses name/path heuristics (not semantic)
//   - ARCH-PATTERN-001: repo-layer identification uses path substring heuristics (not semantic)
var machineTrustedRules = map[string]bool{
	"SEC-SECRET-001": true, // negative: concrete secret evidence spans
	"SEC-SECRET-003": true, // negative: file existence is mechanically decidable
	"FE-DEP-001":     true, // exists: lockfile presence is mechanically decidable
}

// humanOrRuntimeRequiredRules is the set of rule IDs that cannot be resolved
// from static source analysis alone.
var humanOrRuntimeRequiredRules = map[string]bool{
	"SEC-AUTH-002":  true,
	"SEC-ROUTE-001": true,
}

// ClassifyTrustClass returns the trust class for a given rule ID.
// Rules not in the machine_trusted or human_or_runtime_required sets
// default to advisory.
func ClassifyTrustClass(ruleID string) TrustClass {
	if machineTrustedRules[ruleID] {
		return TrustMachineTrusted
	}
	if humanOrRuntimeRequiredRules[ruleID] {
		return TrustHumanOrRuntimeRequired
	}
	return TrustAdvisory
}

// NormalizeTrust assigns trust_class to a finding and enforces trust boundary
// invariants:
//   - advisory findings must not retain verification_level=verified;
//     they are downgraded to strong_inference.
//   - human_or_runtime_required findings must not have verified either.
//   - machine_trusted findings are left unchanged.
func NormalizeTrust(f *Finding) {
	f.TrustClass = ClassifyTrustClass(f.RuleID)

	// Test-scope-only evidence downgrade: machine_trusted findings whose evidence
	// is entirely from test/fixture files should be downgraded to advisory.
	// This prevents test-fixture secrets from producing machine_trusted fails.
	if f.TrustClass == TrustMachineTrusted && f.Status == StatusFail && hasTestScopeOnlyAnnotation(f) {
		f.TrustClass = TrustAdvisory
	}

	switch f.TrustClass {
	case TrustAdvisory:
		if f.VerificationLevel == VerificationVerified {
			f.VerificationLevel = VerificationStrongInference
		}
	case TrustHumanOrRuntimeRequired:
		if f.VerificationLevel == VerificationVerified {
			f.VerificationLevel = VerificationStrongInference
		}
	case TrustMachineTrusted:
		// no downgrade
	}
}

// hasTestScopeOnlyAnnotation checks if a finding was annotated as test-scope-only
// by the matcher (via unknown_reasons containing "test_scope_only_evidence").
func hasTestScopeOnlyAnnotation(f *Finding) bool {
	for _, reason := range f.UnknownReasons {
		if reason == "test_scope_only_evidence" {
			return true
		}
	}
	return false
}

// applyMatcherClassCeiling enforces verification level ceilings based on
// the matcher class of the rule that produced the finding.
func applyMatcherClassCeiling(f *Finding) {
	switch f.MatcherClass {
	case MatcherProof:
		// No ceiling
	case MatcherStructural, MatcherHeuristic:
		if f.VerificationLevel == VerificationVerified {
			f.VerificationLevel = VerificationStrongInference
		}
	case MatcherAttestation:
		if f.Status != StatusUnknown {
			f.Status = StatusUnknown
			f.Confidence = ConfidenceLow
			f.VerificationLevel = VerificationWeakInference
			if len(f.UnknownReasons) == 0 {
				f.UnknownReasons = []string{UnknownNeedsHumanAttestation}
			}
		}
	}
}

// ValidTrustClass returns true if tc is one of the three allowed values.
func ValidTrustClass(tc TrustClass) bool {
	switch tc {
	case TrustMachineTrusted, TrustAdvisory, TrustHumanOrRuntimeRequired:
		return true
	default:
		return false
	}
}

// MachineTrustedRuleIDs returns a sorted-stable copy of all machine-trusted rule IDs.
func MachineTrustedRuleIDs() []string {
	ids := make([]string, 0, len(machineTrustedRules))
	for id := range machineTrustedRules {
		ids = append(ids, id)
	}
	return ids
}
