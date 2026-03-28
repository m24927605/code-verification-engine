package rules

// FinalizeExecutionResult applies deterministic post-processing to a rule
// execution result so downstream layers can consume a stable, evidence-backed
// product without re-implementing rules-layer semantics.
func FinalizeExecutionResult(rf *RuleFile, result *ExecutionResult) {
	if result == nil {
		return
	}

	var ruleIndex map[string]Rule
	if rf != nil {
		ruleIndex = RuleIndexFromFile(rf)
	}

	for i := range result.Findings {
		for j := range result.Findings[i].Evidence {
			if result.Findings[i].Evidence[j].ID == "" {
				result.Findings[i].Evidence[j].ID = EvidenceID(result.Findings[i].Evidence[j])
			}
		}
		if rule, ok := ruleIndex[result.Findings[i].RuleID]; ok {
			EnforceRulePolicyMetadata(rule, &result.Findings[i])
		}
		NormalizeTrust(&result.Findings[i])
	}

	result.IssueSeeds = BuildIssueSeeds(rf, result.Findings)
}
