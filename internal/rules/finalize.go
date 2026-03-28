package rules

// FinalizeExecutionResult applies deterministic post-processing to a rule
// execution result so downstream layers can consume a stable, evidence-backed
// product without re-implementing rules-layer semantics.
func FinalizeExecutionResult(rf *RuleFile, result *ExecutionResult) {
	if result == nil {
		return
	}

	for i := range result.Findings {
		for j := range result.Findings[i].Evidence {
			if result.Findings[i].Evidence[j].ID == "" {
				result.Findings[i].Evidence[j].ID = EvidenceID(result.Findings[i].Evidence[j])
			}
		}
		NormalizeTrust(&result.Findings[i])
	}

	result.IssueSeeds = BuildIssueSeeds(rf, result.Findings)
}
