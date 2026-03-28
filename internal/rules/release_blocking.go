package rules

import "sort"

// ReleaseBlockingPriorityRuleIDs returns the audited set of rule IDs whose
// native rule-to-issue migration state is release-blocking for closeout.
func ReleaseBlockingPriorityRuleIDs() []string {
	ids := []string{
		"SEC-SECRET-001",
		"SEC-SECRET-003",
		"FE-DEP-001",
		"SEC-STRICT-001",
		"SEC-STRICT-002",
		"TEST-AUTH-001",
		"TEST-PAYMENT-001",
		"ARCH-LAYER-001",
		"ARCH-LAYER-002",
		"ARCH-LAYER-003",
		"ARCH-PATTERN-001",
		"ARCH-PATTERN-002",
		"ARCH-PATTERN-003",
	}
	sort.Strings(ids)
	return ids
}

// ReleaseBlockingMigrationAudits returns the explicit audited migration state
// for every release-blocking priority rule ID.
func ReleaseBlockingMigrationAudits() map[string]RuleMigrationAudit {
	out := make(map[string]RuleMigrationAudit)
	for _, ruleID := range ReleaseBlockingPriorityRuleIDs() {
		rule, ok := RuleIndexFromFile(ProfileToRuleFile(mustTrustedCoreProfile()))[ruleID]
		if !ok {
			// Fall back to an ID-only rule; explicit audits still resolve by ID.
			rule = Rule{ID: ruleID}
		}
		out[ruleID] = RuleMigrationAuditForRule(rule)
	}
	return out
}

func mustTrustedCoreProfile() *Profile {
	profile, ok := GetProfile("trusted-core")
	if !ok || profile == nil {
		panic("trusted-core profile is required for release-blocking migration audits")
	}
	return profile
}
