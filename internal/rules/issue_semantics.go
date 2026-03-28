package rules

import "strings"

// IssueSeedSemantics captures the canonical issue-oriented semantics that a
// rule contributes to the native v2 path.
type IssueSeedSemantics struct {
	Title    string
	Category string
	Severity string
	Source   string
}

// RuleMigrationAudit records the currently-audited migration state and reason
// for a rule on the path from finding-first to native issue semantics.
type RuleMigrationAudit struct {
	State  MigrationState
	Reason string
}

var ruleMigrationAudits = map[string]RuleMigrationAudit{
	"SEC-SECRET-001":   {State: MigrationIssueNative, Reason: "proof-grade secret evidence spans are deterministic and replayable"},
	"SEC-SECRET-003":   {State: MigrationIssueNative, Reason: "committed env-file detection is mechanically decidable from file facts"},
	"FE-DEP-001":       {State: MigrationIssueNative, Reason: "lockfile existence is mechanically decidable from file facts"},
	"SEC-STRICT-001":   {State: MigrationIssueNative, Reason: "sql-injection pattern evidence is grounded in structural data-access facts and validated by strict regression coverage"},
	"SEC-STRICT-002":   {State: MigrationIssueNative, Reason: "sensitive-data logging evidence is grounded in structural logging facts and validated by strict regression coverage"},
	"TEST-AUTH-001":    {State: MigrationIssueNative, Reason: "auth test coverage is mechanically inspectable from test and file facts with explicit keyword-domain regression coverage"},
	"TEST-PAYMENT-001": {State: MigrationIssueNative, Reason: "payment test coverage is mechanically inspectable from test and file facts with explicit billing-domain regression coverage"},
	"ARCH-LAYER-001":   {State: MigrationIssueNative, Reason: "controller DB-access violations are grounded in FileRole and route-binding evidence, with explicit service/test/repository false-positive guards"},
	"ARCH-LAYER-002":   {State: MigrationSeedNative, Reason: "repository/service layer presence is explicit in rule semantics, but the matcher still uses conservative symbol-name evidence"},
	"ARCH-LAYER-003":   {State: MigrationSeedNative, Reason: "service layer presence is explicit in rule semantics, but the matcher still uses conservative symbol-name evidence"},
	"ARCH-PATTERN-001": {State: MigrationSeedNative, Reason: "deterministic issue seeds exist, but repository-layer identification still relies on path-oriented heuristics"},
	"ARCH-PATTERN-002": {State: MigrationIssueNative, Reason: "DTO separation violations are grounded in handler/model import evidence, with explicit DTO/response/request false-positive guards"},
	"ARCH-PATTERN-003": {State: MigrationIssueNative, Reason: "singleton/global-state detection is driven by structural symbol facts with explicit false-positive guards for DI tokens, schema files, and test scope"},
}

// RuleIndexFromFile builds a deterministic lookup table for rule definitions.
func RuleIndexFromFile(rf *RuleFile) map[string]Rule {
	if rf == nil {
		return nil
	}
	out := make(map[string]Rule, len(rf.Rules))
	for _, rule := range rf.Rules {
		out[rule.ID] = rule
	}
	return out
}

// CanonicalIssueTitle returns the authoritative issue title for a rule outcome.
func CanonicalIssueTitle(rule Rule, fallback string) string {
	if strings.TrimSpace(rule.Title) != "" {
		return rule.Title
	}
	return fallback
}

// CanonicalIssueCategory returns the normalized issue category for a rule.
func CanonicalIssueCategory(rule Rule, ruleID string) string {
	if strings.TrimSpace(rule.Category) != "" {
		return normalizeIssueCategory(rule.Category, ruleID)
	}
	return inferIssueCategoryFromRuleID(ruleID)
}

// CanonicalIssueSeverity returns the normalized issue severity for a rule outcome.
func CanonicalIssueSeverity(rule Rule, trustClass TrustClass, status Status) string {
	if strings.TrimSpace(rule.Severity) != "" {
		return strings.ToLower(strings.TrimSpace(rule.Severity))
	}
	switch trustClass {
	case TrustMachineTrusted:
		if status == StatusFail {
			return "high"
		}
		return "medium"
	case TrustAdvisory:
		return "medium"
	default:
		return "low"
	}
}

// ResolveIssueSeedSemantics derives the canonical issue semantics for a rule
// and finalized finding pair.
func ResolveIssueSeedSemantics(rule Rule, finding Finding) IssueSeedSemantics {
	return IssueSeedSemantics{
		Title:    CanonicalIssueTitle(rule, finding.Message),
		Category: CanonicalIssueCategory(rule, finding.RuleID),
		Severity: CanonicalIssueSeverity(rule, finding.TrustClass, finding.Status),
		Source:   canonicalIssueSource(finding),
	}
}

// RuleMigrationState returns the current v2 migration state for a rule.
// This is intentionally conservative: only explicitly-audited rule IDs are
// promoted to issue_native. Other deterministic rule families remain
// seed_native until they have rule-level migration approval.
func RuleMigrationState(rule Rule) MigrationState {
	if audit, ok := ruleMigrationAudits[rule.ID]; ok {
		return audit.State
	}
	switch rule.MatcherClass {
	case MatcherProof, MatcherStructural:
		return MigrationSeedNative
	case MatcherHeuristic, MatcherAttestation:
		return MigrationFindingBridged
	default:
		return MigrationLegacyOnly
	}
}

// RuleMigrationAuditForRule returns the current audit record for a rule,
// including conservative defaults when no explicit rule-level audit exists.
func RuleMigrationAuditForRule(rule Rule) RuleMigrationAudit {
	if audit, ok := ruleMigrationAudits[rule.ID]; ok {
		return audit
	}
	switch RuleMigrationState(rule) {
	case MigrationSeedNative:
		return RuleMigrationAudit{State: MigrationSeedNative, Reason: "deterministic issue seeds exist, but rule-level issue-native audit is incomplete"}
	case MigrationFindingBridged:
		return RuleMigrationAudit{State: MigrationFindingBridged, Reason: "v2 path still depends on finding-derived issue semantics"}
	default:
		return RuleMigrationAudit{State: MigrationLegacyOnly, Reason: "no native v2 migration audit recorded"}
	}
}

// RuleMigrationMatrix returns a copy of the explicit audited rule-level
// migration records currently recognized by the native v2 path.
func RuleMigrationMatrix() map[string]RuleMigrationAudit {
	out := make(map[string]RuleMigrationAudit, len(ruleMigrationAudits))
	for ruleID, audit := range ruleMigrationAudits {
		out[ruleID] = audit
	}
	return out
}

func canonicalIssueSource(f Finding) string {
	if f.TrustClass == TrustHumanOrRuntimeRequired {
		return "agent"
	}
	return "rule"
}

func inferIssueCategoryFromRuleID(ruleID string) string {
	id := strings.ToLower(ruleID)
	switch {
	case strings.HasPrefix(id, "sec-"):
		return "security"
	case strings.HasPrefix(id, "arch-"):
		return "architecture"
	case strings.HasPrefix(id, "fe-xss-"), strings.HasPrefix(id, "fe-token-"),
		strings.HasPrefix(id, "fe-env-"), strings.HasPrefix(id, "fe-auth-"),
		strings.HasPrefix(id, "fe-csp-"):
		return "frontend_security"
	case strings.HasPrefix(id, "fe-"):
		return "frontend_quality"
	case strings.Contains(id, "pattern"):
		return "design"
	case strings.HasPrefix(id, "qual-"):
		return "quality"
	case strings.HasPrefix(id, "test-"):
		return "testing"
	default:
		return "bug"
	}
}

func normalizeIssueCategory(category, ruleID string) string {
	c := strings.ToLower(strings.TrimSpace(category))
	switch c {
	case "security":
		return "security"
	case "architecture", "architectural":
		return "architecture"
	case "design":
		if strings.HasPrefix(strings.ToLower(ruleID), "arch-") {
			return "architecture"
		}
		return "design"
	case "quality":
		return "quality"
	case "testing", "test":
		return "testing"
	case "frontend_security":
		return "frontend_security"
	case "frontend_quality":
		return "frontend_quality"
	default:
		return inferIssueCategoryFromRuleID(ruleID)
	}
}
