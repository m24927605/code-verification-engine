package artifactsv2

import "strings"

// RuleFamilyMergePolicy captures the explicit deterministic merge contract for
// a normalized rule family.
type RuleFamilyMergePolicy struct {
	AllowSameSymbol  bool
	AllowLineOverlap bool
}

var explicitRuleFamilyMergePolicies = map[string]RuleFamilyMergePolicy{
	"sec_secret":   {AllowSameSymbol: true, AllowLineOverlap: true},
	"fe_dep":       {AllowSameSymbol: false, AllowLineOverlap: false},
	"sec_strict":   {AllowSameSymbol: true, AllowLineOverlap: true},
	"arch_layer":   {AllowSameSymbol: true, AllowLineOverlap: true},
	"arch_pattern": {AllowSameSymbol: true, AllowLineOverlap: true},
	"test_auth":    {AllowSameSymbol: true, AllowLineOverlap: true},
	"test_payment": {AllowSameSymbol: true, AllowLineOverlap: true},
	"fam_security": {AllowSameSymbol: true, AllowLineOverlap: true},
	"fam_design":   {AllowSameSymbol: true, AllowLineOverlap: true},
	"fam_bug":      {AllowSameSymbol: true, AllowLineOverlap: true},
}

func mergePolicyForRuleFamily(family string) RuleFamilyMergePolicy {
	family = strings.TrimSpace(family)
	if policy, ok := explicitRuleFamilyMergePolicies[family]; ok {
		return policy
	}
	return RuleFamilyMergePolicy{AllowSameSymbol: true, AllowLineOverlap: true}
}

func sameSymbolMergeAllowed(clusterFamily, seedFamily string) bool {
	clusterPolicy := mergePolicyForRuleFamily(clusterFamily)
	seedPolicy := mergePolicyForRuleFamily(seedFamily)
	if !clusterPolicy.AllowSameSymbol || !seedPolicy.AllowSameSymbol {
		return false
	}
	if clusterFamily == seedFamily {
		return true
	}
	// Architecture layer and pattern families must remain separated even when
	// they point at the same symbol. They model different issue semantics.
	if strings.HasPrefix(clusterFamily, "arch_") || strings.HasPrefix(seedFamily, "arch_") {
		return false
	}
	return true
}

func lineOverlapMergeAllowed(clusterFamily, seedFamily string) bool {
	clusterPolicy := mergePolicyForRuleFamily(clusterFamily)
	seedPolicy := mergePolicyForRuleFamily(seedFamily)
	if !clusterPolicy.AllowLineOverlap || !seedPolicy.AllowLineOverlap {
		return false
	}
	return clusterFamily == seedFamily
}
