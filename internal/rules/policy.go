package rules

import "github.com/verabase/code-verification-engine/internal/facts"

const (
	unknownRuleMetadataProofFloorUnmet      = "rule_metadata_proof_floor_unmet"
	unknownRuleMetadataStructuralFloorUnmet = "rule_metadata_structural_floor_unmet"
)

// EnforceRulePolicyMetadata downgrades findings that overstate trust relative
// to the rule's declared proof/structural prerequisites.
func EnforceRulePolicyMetadata(rule Rule, finding *Finding) {
	if finding == nil {
		return
	}

	floor := facts.FactQuality(finding.FactQualityFloor)
	if finding.VerificationLevel == VerificationVerified && rule.MinimumProofFactQuality != "" {
		if !factQualitySatisfiesMinimum(floor, rule.MinimumProofFactQuality) {
			finding.VerificationLevel = VerificationStrongInference
			finding.UnknownReasons = appendIfMissing(finding.UnknownReasons, unknownRuleMetadataProofFloorUnmet)
		}
	}

	if finding.VerificationLevel == VerificationStrongInference && rule.MinimumStructuralFactQuality != "" {
		if !factQualitySatisfiesMinimum(floor, rule.MinimumStructuralFactQuality) {
			finding.VerificationLevel = VerificationWeakInference
			finding.UnknownReasons = appendIfMissing(finding.UnknownReasons, unknownRuleMetadataStructuralFloorUnmet)
		}
	}
}

func factQualitySatisfiesMinimum(actual facts.FactQuality, minimum FactQuality) bool {
	if minimum == "" {
		return true
	}
	switch actual {
	case facts.QualityProof:
		return true
	case facts.QualityStructural:
		return minimum == FactQualityStructural || minimum == FactQualityHeuristic
	case facts.QualityHeuristic, "":
		return minimum == FactQualityHeuristic
	default:
		return false
	}
}

func appendIfMissing(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}
