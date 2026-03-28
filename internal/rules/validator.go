package rules

import (
	"fmt"
	"strings"
)

var supportedVersions = map[string]bool{
	"0.1": true,
}

var supportedTypes = map[string]bool{
	"exists":        true,
	"not_exists":    true,
	"relationship":  true,
	"test_required": true,
}

var supportedLanguages = map[string]bool{
	"go":         true,
	"javascript": true,
	"typescript": true,
	"python":     true,
}

// Validate checks a parsed RuleFile for correctness.
func Validate(rf *RuleFile) error {
	var errs []string

	if !supportedVersions[rf.Version] {
		errs = append(errs, fmt.Sprintf("unsupported DSL version %q (supported: 0.1)", rf.Version))
	}

	for i, r := range rf.Rules {
		prefix := fmt.Sprintf("rule[%d] (%s)", i, r.ID)
		if r.ID == "" {
			errs = append(errs, fmt.Sprintf("rule[%d]: missing required field 'id'", i))
			prefix = fmt.Sprintf("rule[%d]", i)
		}
		if r.Title == "" {
			errs = append(errs, fmt.Sprintf("%s: missing required field 'title'", prefix))
		}
		if r.Category == "" {
			errs = append(errs, fmt.Sprintf("%s: missing required field 'category'", prefix))
		}
		if r.Severity == "" {
			errs = append(errs, fmt.Sprintf("%s: missing required field 'severity'", prefix))
		}
		if len(r.Languages) == 0 {
			errs = append(errs, fmt.Sprintf("%s: missing required field 'languages'", prefix))
		}
		for _, lang := range r.Languages {
			if !supportedLanguages[lang] {
				errs = append(errs, fmt.Sprintf("%s: unsupported language %q", prefix, lang))
			}
		}
		if r.Type == "" {
			errs = append(errs, fmt.Sprintf("%s: missing required field 'type'", prefix))
		} else if !supportedTypes[r.Type] {
			errs = append(errs, fmt.Sprintf("%s: unsupported rule type %q", prefix, r.Type))
		}
		if r.Target == "" {
			errs = append(errs, fmt.Sprintf("%s: missing required field 'target'", prefix))
		} else if !IsValidTarget(r.Target) {
			errs = append(errs, fmt.Sprintf("%s: unsupported target %q", prefix, r.Target))
		}
		if r.Message == "" {
			errs = append(errs, fmt.Sprintf("%s: missing required field 'message'", prefix))
		}
		if err := validateRulePolicyMetadata(r, prefix); err != nil {
			errs = append(errs, err.Error())
		}
		if r.Where != nil {
			if len(r.Where.NameMatches) > 0 && len(r.Where.NameExact) > 0 {
				errs = append(errs, fmt.Sprintf("%s: name_matches and name_exact must not co-exist in where clause", prefix))
			}
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("validation errors:\n  %s", strings.Join(errs, "\n  "))
	}
	return nil
}

func validateRulePolicyMetadata(r Rule, prefix string) error {
	if r.MinimumProofFactQuality != "" && !r.MinimumProofFactQuality.IsValid() {
		return fmt.Errorf("%s: invalid minimum_proof_fact_quality %q", prefix, r.MinimumProofFactQuality)
	}
	if r.MinimumStructuralFactQuality != "" && !r.MinimumStructuralFactQuality.IsValid() {
		return fmt.Errorf("%s: invalid minimum_structural_fact_quality %q", prefix, r.MinimumStructuralFactQuality)
	}
	if r.MinimumProofFactQuality != "" && r.MinimumStructuralFactQuality != "" &&
		!r.MinimumProofFactQuality.AtLeast(r.MinimumStructuralFactQuality) {
		return fmt.Errorf("%s: minimum_proof_fact_quality %q must not be weaker than minimum_structural_fact_quality %q", prefix, r.MinimumProofFactQuality, r.MinimumStructuralFactQuality)
	}
	if r.ScenarioApplicability != nil && !r.ScenarioApplicability.Any() {
		return fmt.Errorf("%s: scenario_applicability must declare at least one scenario", prefix)
	}
	if r.AcceptanceIntent != "" && !r.AcceptanceIntent.IsValid() {
		return fmt.Errorf("%s: invalid acceptance_intent %q", prefix, r.AcceptanceIntent)
	}
	if r.ExhaustiveNegative && r.Type != "not_exists" {
		return fmt.Errorf("%s: exhaustive_negative is only valid for not_exists rules", prefix)
	}
	if r.AcceptanceIntent == AcceptanceIntentNegativeExhaustive {
		if !r.ExhaustiveNegative {
			return fmt.Errorf("%s: acceptance_intent=%q requires exhaustive_negative=true", prefix, r.AcceptanceIntent)
		}
		if r.Type != "not_exists" {
			return fmt.Errorf("%s: acceptance_intent=%q is only valid for not_exists rules", prefix, r.AcceptanceIntent)
		}
	}
	return nil
}
