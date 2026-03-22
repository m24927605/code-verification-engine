package report

import (
	"strings"

	"github.com/verabase/code-verification-engine/internal/rules"
	"github.com/verabase/code-verification-engine/internal/scope"
)

// SignalClass represents the operational significance of a finding.
type SignalClass string

const (
	SignalActionableFail          SignalClass = "actionable_fail"
	SignalAdvisoryFail            SignalClass = "advisory_fail"
	SignalInformationalDetection  SignalClass = "informational_detection"
	SignalUnknown                 SignalClass = "unknown"
	SignalPass                    SignalClass = "pass"
)

// SignalSummary counts findings by their operational significance.
type SignalSummary struct {
	ActionableFail         int `json:"actionable_fail"`
	AdvisoryFail           int `json:"advisory_fail"`
	InformationalDetection int `json:"informational_detection"`
	Unknown                int `json:"unknown"`
}

// ClassifySignal determines the signal class of a finding based on its
// rule ID, status, severity category, and evidence scope.
func ClassifySignal(f rules.Finding) SignalClass {
	// Non-fail/non-unknown findings are just pass
	if f.Status == rules.StatusUnknown {
		return SignalUnknown
	}
	if f.Status != rules.StatusFail {
		return SignalPass
	}

	// GOF-* findings are always informational detection
	if IsGOFRule(f.RuleID) {
		return SignalInformationalDetection
	}

	// Test-only evidence: if ALL evidence is from test/fixture scope,
	// downgrade to advisory
	if len(f.Evidence) > 0 && allEvidenceFromTestScope(f.Evidence) {
		return SignalAdvisoryFail
	}

	// Classify by rule category derived from ID prefix
	cat := ruleCategory(f.RuleID)
	switch cat {
	case "security":
		return SignalActionableFail
	case "architecture":
		// Architecture rules with high-value targets are actionable
		if isActionableArchRule(f.RuleID) {
			return SignalActionableFail
		}
		return SignalAdvisoryFail
	case "quality":
		return SignalAdvisoryFail
	case "testing":
		return SignalAdvisoryFail
	case "frontend_security":
		return SignalActionableFail
	case "frontend_quality":
		return SignalAdvisoryFail
	default:
		return SignalAdvisoryFail
	}
}

// IsGOFRule returns true if the rule ID belongs to a GoF pattern detection rule.
func IsGOFRule(ruleID string) bool {
	return strings.HasPrefix(ruleID, "GOF-")
}

// ruleCategory infers the category from the rule ID prefix.
func ruleCategory(ruleID string) string {
	switch {
	case strings.HasPrefix(ruleID, "SEC-"):
		return "security"
	case strings.HasPrefix(ruleID, "ARCH-"):
		return "architecture"
	case strings.HasPrefix(ruleID, "QUAL-"):
		return "quality"
	case strings.HasPrefix(ruleID, "TEST-"):
		return "testing"
	case strings.HasPrefix(ruleID, "FE-XSS-"), strings.HasPrefix(ruleID, "FE-TOKEN-"),
		strings.HasPrefix(ruleID, "FE-ENV-"), strings.HasPrefix(ruleID, "FE-AUTH-"),
		strings.HasPrefix(ruleID, "FE-CSP-"):
		return "frontend_security"
	case strings.HasPrefix(ruleID, "FE-"):
		return "frontend_quality"
	default:
		return ""
	}
}

// isActionableArchRule returns true for architecture rules that represent
// actionable violations (not just pattern observations).
func isActionableArchRule(ruleID string) bool {
	switch ruleID {
	case "ARCH-LAYER-001", "ARCH-ERR-001":
		return true
	default:
		return false
	}
}

// allEvidenceFromTestScope returns true if every evidence item is from
// test or fixture scope.
func allEvidenceFromTestScope(evidence []rules.Evidence) bool {
	if len(evidence) == 0 {
		return false
	}
	for _, ev := range evidence {
		if scope.IsProductionPath(ev.File) {
			return false
		}
	}
	return true
}

// ComputeSignalSummary computes the signal summary from a list of findings.
func ComputeSignalSummary(findings []rules.Finding) SignalSummary {
	var ss SignalSummary
	for _, f := range findings {
		switch ClassifySignal(f) {
		case SignalActionableFail:
			ss.ActionableFail++
		case SignalAdvisoryFail:
			ss.AdvisoryFail++
		case SignalInformationalDetection:
			ss.InformationalDetection++
		case SignalUnknown:
			ss.Unknown++
		}
	}
	return ss
}
