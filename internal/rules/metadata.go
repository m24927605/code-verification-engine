package rules

import "strings"

// FactQuality represents the minimum fact quality threshold a rule may declare.
type FactQuality string

const (
	FactQualityProof      FactQuality = "proof"
	FactQualityStructural FactQuality = "structural"
	FactQualityHeuristic  FactQuality = "heuristic"
)

var factQualityRank = map[FactQuality]int{
	FactQualityHeuristic:  0,
	FactQualityStructural: 1,
	FactQualityProof:      2,
}

// IsValid reports whether the fact quality is one of the supported values.
func (q FactQuality) IsValid() bool {
	_, ok := factQualityRank[q]
	return ok
}

// Rank returns a relative ordering for fact quality, with higher values being stronger.
func (q FactQuality) Rank() int {
	if rank, ok := factQualityRank[q]; ok {
		return rank
	}
	return -1
}

// AtLeast reports whether q is at least as strong as min.
func (q FactQuality) AtLeast(min FactQuality) bool {
	return q.Rank() >= min.Rank()
}

// ScenarioApplicability declares which scenarios a rule is eligible for.
type ScenarioApplicability struct {
	Hiring              bool `yaml:"hiring,omitempty"`
	OutsourceAcceptance bool `yaml:"outsource_acceptance,omitempty"`
	PMAcceptance        bool `yaml:"pm_acceptance,omitempty"`
}

// Any reports whether the rule applies to at least one scenario.
func (sa *ScenarioApplicability) Any() bool {
	if sa == nil {
		return false
	}
	return sa.Hiring || sa.OutsourceAcceptance || sa.PMAcceptance
}

// Allows reports whether the rule is eligible for the named scenario.
func (sa *ScenarioApplicability) Allows(name string) bool {
	if sa == nil {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "hiring":
		return sa.Hiring
	case "outsource_acceptance":
		return sa.OutsourceAcceptance
	case "pm_acceptance":
		return sa.PMAcceptance
	default:
		return false
	}
}

// AcceptanceIntent describes the type of acceptance proof a rule is intended to support.
type AcceptanceIntent string

const (
	AcceptanceIntentExistence          AcceptanceIntent = "existence_check"
	AcceptanceIntentBinding            AcceptanceIntent = "binding_check"
	AcceptanceIntentBoundary           AcceptanceIntent = "boundary_check"
	AcceptanceIntentMaturity           AcceptanceIntent = "maturity_check"
	AcceptanceIntentNegativeExhaustive AcceptanceIntent = "negative_exhaustive_check"
)

var validAcceptanceIntents = map[AcceptanceIntent]struct{}{
	AcceptanceIntentExistence:          {},
	AcceptanceIntentBinding:            {},
	AcceptanceIntentBoundary:           {},
	AcceptanceIntentMaturity:           {},
	AcceptanceIntentNegativeExhaustive: {},
}

// IsValid reports whether the acceptance intent is one of the supported values.
func (ai AcceptanceIntent) IsValid() bool {
	_, ok := validAcceptanceIntents[ai]
	return ok
}

// MinimumProofFactQuality returns the declared proof-grade fact quality floor.
func (r Rule) MinimumProofFactQualityFloor() FactQuality {
	return r.MinimumProofFactQuality
}

// MinimumStructuralFactQuality returns the declared structural-inference fact quality floor.
func (r Rule) MinimumStructuralFactQualityFloor() FactQuality {
	return r.MinimumStructuralFactQuality
}

// HasScenarioApplicability reports whether the rule has explicit scenario metadata.
func (r Rule) HasScenarioApplicability() bool {
	return r.ScenarioApplicability != nil && r.ScenarioApplicability.Any()
}

// AppliesToScenario reports whether the rule is eligible for the named scenario.
func (r Rule) AppliesToScenario(name string) bool {
	return r.ScenarioApplicability != nil && r.ScenarioApplicability.Allows(name)
}
