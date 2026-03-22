package rules

// Engine evaluates verification rules against normalized facts.
type Engine struct{}

// NewEngine creates a new rule execution engine.
func NewEngine() *Engine {
	return &Engine{}
}

// Execute evaluates all rules in the rule file against the provided facts.
// Rules are evaluated independently. Language filtering skips inapplicable rules.
func (e *Engine) Execute(rf *RuleFile, fs *FactSet, repoLanguages []string) ExecutionResult {
	var result ExecutionResult

	for _, rule := range rf.Rules {
		if !ruleAppliesToRepo(rule, repoLanguages) {
			result.SkippedRules = append(result.SkippedRules, SkippedRule{
				RuleID: rule.ID,
				Reason: "no matching languages in repository",
			})
			continue
		}
		finding := matchRule(rule, fs, repoLanguages)
		result.Findings = append(result.Findings, finding)
	}

	return result
}

// ruleAppliesToRepo returns true if at least one of the rule's languages
// is present in the repository.
func ruleAppliesToRepo(rule Rule, repoLanguages []string) bool {
	for _, rl := range rule.Languages {
		for _, repoLang := range repoLanguages {
			if rl == repoLang {
				return true
			}
		}
	}
	return false
}
