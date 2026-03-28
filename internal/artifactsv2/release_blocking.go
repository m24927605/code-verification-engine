package artifactsv2

import (
	"github.com/verabase/code-verification-engine/internal/rules"
)

func releaseBlockingRuleFamilies() []string {
	families := make(map[string]struct{})
	for _, ruleID := range rules.ReleaseBlockingPriorityRuleIDs() {
		family := compatRuleFamily(ruleID, "")
		if family == "" {
			continue
		}
		families[family] = struct{}{}
	}
	return sortedStringKeys(families)
}
