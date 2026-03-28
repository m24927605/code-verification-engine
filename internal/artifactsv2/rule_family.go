package artifactsv2

import "strings"

func compatRuleMergeFamily(ruleIDs []string, category string) string {
	families := make(map[string]struct{})
	for _, ruleID := range dedupeStringsSorted(ruleIDs) {
		if family := compatRuleFamily(ruleID, category); family != "" {
			families[family] = struct{}{}
		}
	}
	if len(families) == 0 {
		return compatCategoryMergeFamily(category)
	}
	return strings.Join(sortedStringKeys(families), "+")
}

func compatRuleFamily(ruleID, category string) string {
	id := strings.ToUpper(strings.TrimSpace(ruleID))
	switch {
	case strings.HasPrefix(id, "SEC-SECRET-"):
		return "sec_secret"
	case strings.HasPrefix(id, "SEC-STRICT-"):
		return "sec_strict"
	case strings.HasPrefix(id, "ARCH-LAYER-"):
		return "arch_layer"
	case strings.HasPrefix(id, "ARCH-PATTERN-"):
		return "arch_pattern"
	case strings.HasPrefix(id, "TEST-AUTH-"):
		return "test_auth"
	case strings.HasPrefix(id, "TEST-PAYMENT-"):
		return "test_payment"
	case strings.HasPrefix(id, "FE-DEP-"):
		return "fe_dep"
	case strings.HasPrefix(id, "FAM-SEC-"):
		return "fam_security"
	case strings.HasPrefix(id, "FAM-DES-"):
		return "fam_design"
	case strings.HasPrefix(id, "FAM-BUG-"):
		return "fam_bug"
	default:
		return compatCategoryMergeFamily(category)
	}
}
