package report

import (
	"strings"

	"github.com/verabase/code-verification-engine/internal/rules"
	"github.com/verabase/code-verification-engine/internal/scope"
)

// SignalClass represents the operational significance of an issue or finding.
type SignalClass string

const (
	SignalActionableFail          SignalClass = "actionable_fail"
	SignalAdvisoryFail            SignalClass = "advisory_fail"
	SignalInformationalDetection  SignalClass = "informational_detection"
	SignalUnknown                 SignalClass = "unknown"
	SignalPass                    SignalClass = "pass"
)

// SignalSummary counts issues by their operational significance.
type SignalSummary struct {
	ActionableFail         int `json:"actionable_fail"`
	AdvisoryFail           int `json:"advisory_fail"`
	InformationalDetection int `json:"informational_detection"`
	Unknown                int `json:"unknown"`
}

// ClassifyIssueSignal determines the signal class of an issue based on its
// rule ID, category, and evidence scope.
func ClassifyIssueSignal(issue Issue, metadata map[string]rules.Rule) SignalClass {
	evidence := make([]rules.Evidence, 0, len(issue.Evidence))
	for _, ev := range issue.Evidence {
		evidence = append(evidence, rules.Evidence{
			ID:        ev.ID,
			File:      ev.File,
			LineStart: ev.LineStart,
			LineEnd:   ev.LineEnd,
			Symbol:    ev.Symbol,
		})
	}
	return classifySignal(issue.RuleID, issueStatusToRuleStatus(issue.Status), evidence, issue.Category, metadata)
}

// ClassifySignal preserves the historical finding-centric helper during cutover.
func ClassifySignal(f rules.Finding, metadata map[string]rules.Rule) SignalClass {
	return classifySignal(f.RuleID, f.Status, f.Evidence, "", metadata)
}

func classifySignal(ruleID string, status rules.Status, evidence []rules.Evidence, category string, metadata map[string]rules.Rule) SignalClass {
	if status == rules.StatusUnknown {
		return SignalUnknown
	}
	if status != rules.StatusFail {
		return SignalPass
	}

	// GOF-* findings are always informational detection
	if IsGOFRule(ruleID) {
		return SignalInformationalDetection
	}

	// Test-only evidence: if ALL evidence is from test/fixture scope,
	// downgrade to advisory
	if len(evidence) > 0 && allEvidenceFromTestScope(evidence) {
		return SignalAdvisoryFail
	}

	rule := metadata[ruleID]
	cat := category
	if strings.TrimSpace(cat) == "" {
		cat = rules.CanonicalIssueCategory(rule, ruleID)
	}
	switch cat {
	case "security":
		return SignalActionableFail
	case "architecture":
		// Architecture rules with high-value targets are actionable
		if isActionableArchRule(ruleID) {
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

func issueStatusToRuleStatus(status string) rules.Status {
	switch status {
	case "resolved", "pass":
		return rules.StatusPass
	case "unknown":
		return rules.StatusUnknown
	default:
		return rules.StatusFail
	}
}

// IsGOFRule returns true if the rule ID belongs to a GoF pattern detection rule.
func IsGOFRule(ruleID string) bool {
	return strings.HasPrefix(ruleID, "GOF-")
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

// ComputeIssueSignalSummary computes the signal summary from canonical issues.
func ComputeIssueSignalSummary(issues []Issue, metadata map[string]rules.Rule) SignalSummary {
	var ss SignalSummary
	for _, issue := range issues {
		switch ClassifyIssueSignal(issue, metadata) {
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

// ComputeSignalSummary preserves the historical finding-centric helper during cutover.
func ComputeSignalSummary(findings []rules.Finding, metadata map[string]rules.Rule) SignalSummary {
	var ss SignalSummary
	for _, f := range findings {
		switch ClassifySignal(f, metadata) {
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
