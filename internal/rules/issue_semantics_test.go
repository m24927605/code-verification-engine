package rules

import (
	"strings"
	"testing"
)

func TestCanonicalIssueSemanticsPreferRuleMetadata(t *testing.T) {
	t.Parallel()

	rule := Rule{
		ID:       "ARCH-001",
		Title:    "Repository pattern violation",
		Category: "Design",
		Severity: "Critical",
	}

	if got := CanonicalIssueTitle(rule, "fallback"); got != "Repository pattern violation" {
		t.Fatalf("expected metadata title, got %q", got)
	}
	if got := CanonicalIssueCategory(rule, rule.ID); got != "architecture" {
		t.Fatalf("expected normalized architecture category, got %q", got)
	}
	if got := CanonicalIssueSeverity(rule, TrustAdvisory, StatusFail); got != "critical" {
		t.Fatalf("expected metadata severity, got %q", got)
	}
}

func TestCanonicalIssueSemanticsFallbacks(t *testing.T) {
	t.Parallel()

	rule := Rule{}

	if got := CanonicalIssueTitle(rule, "fallback"); got != "fallback" {
		t.Fatalf("expected fallback title, got %q", got)
	}
	if got := CanonicalIssueCategory(rule, "SEC-001"); got != "security" {
		t.Fatalf("expected security fallback category, got %q", got)
	}
	if got := CanonicalIssueSeverity(rule, TrustMachineTrusted, StatusFail); got != "high" {
		t.Fatalf("expected fallback high severity, got %q", got)
	}
}

func TestRuleMigrationState(t *testing.T) {
	t.Parallel()

	if got := RuleMigrationState(Rule{ID: "SEC-SECRET-001", MatcherClass: MatcherProof}); got != MigrationIssueNative {
		t.Fatalf("SEC-SECRET-001 migration state = %q, want %q", got, MigrationIssueNative)
	}
	if got := RuleMigrationState(Rule{ID: "ARCH-LAYER-001", MatcherClass: MatcherStructural}); got != MigrationIssueNative {
		t.Fatalf("ARCH-LAYER-001 migration state = %q, want %q", got, MigrationIssueNative)
	}
	if got := RuleMigrationState(Rule{ID: "ARCH-LAYER-002", MatcherClass: MatcherHeuristic}); got != MigrationSeedNative {
		t.Fatalf("ARCH-LAYER-002 migration state = %q, want %q", got, MigrationSeedNative)
	}
	if got := RuleMigrationState(Rule{ID: "ARCH-PATTERN-003", MatcherClass: MatcherStructural}); got != MigrationIssueNative {
		t.Fatalf("ARCH-PATTERN-003 migration state = %q, want %q", got, MigrationIssueNative)
	}
	if got := RuleMigrationState(Rule{ID: "ARCH-PATTERN-002", MatcherClass: MatcherStructural}); got != MigrationIssueNative {
		t.Fatalf("ARCH-PATTERN-002 migration state = %q, want %q", got, MigrationIssueNative)
	}
	if got := RuleMigrationState(Rule{ID: "QUAL-001", MatcherClass: MatcherHeuristic}); got != MigrationFindingBridged {
		t.Fatalf("heuristic matcher migration state = %q, want %q", got, MigrationFindingBridged)
	}
	if got := RuleMigrationState(Rule{ID: "SEC-AUTH-002", MatcherClass: MatcherAttestation}); got != MigrationFindingBridged {
		t.Fatalf("attestation matcher migration state = %q, want %q", got, MigrationFindingBridged)
	}
}

func TestRuleMigrationMatrix(t *testing.T) {
	t.Parallel()

	matrix := RuleMigrationMatrix()
	if got := matrix["SEC-SECRET-001"].State; got != MigrationIssueNative {
		t.Fatalf("expected SEC-SECRET-001 override, got %q", got)
	}
	if got := matrix["SEC-SECRET-003"].State; got != MigrationIssueNative {
		t.Fatalf("expected SEC-SECRET-003 override, got %q", got)
	}
	if got := matrix["FE-DEP-001"].State; got != MigrationIssueNative {
		t.Fatalf("expected FE-DEP-001 override, got %q", got)
	}
	if got := matrix["SEC-STRICT-001"].State; got != MigrationIssueNative {
		t.Fatalf("expected SEC-STRICT-001 explicit issue_native audit, got %q", got)
	}
	if got := matrix["SEC-STRICT-002"].State; got != MigrationIssueNative {
		t.Fatalf("expected SEC-STRICT-002 explicit issue_native audit, got %q", got)
	}
	if got := matrix["TEST-AUTH-001"].State; got != MigrationIssueNative {
		t.Fatalf("expected TEST-AUTH-001 explicit issue_native audit, got %q", got)
	}
	if got := matrix["TEST-PAYMENT-001"].State; got != MigrationIssueNative {
		t.Fatalf("expected TEST-PAYMENT-001 explicit issue_native audit, got %q", got)
	}
	if got := matrix["ARCH-LAYER-001"].State; got != MigrationIssueNative {
		t.Fatalf("expected ARCH-LAYER-001 explicit issue_native audit, got %q", got)
	}
	if got := matrix["ARCH-LAYER-002"].State; got != MigrationSeedNative {
		t.Fatalf("expected ARCH-LAYER-002 explicit seed_native audit, got %q", got)
	}
	if got := matrix["ARCH-LAYER-003"].State; got != MigrationSeedNative {
		t.Fatalf("expected ARCH-LAYER-003 explicit seed_native audit, got %q", got)
	}
	if got := matrix["ARCH-PATTERN-001"].State; got != MigrationSeedNative {
		t.Fatalf("expected ARCH-PATTERN-001 explicit seed_native audit, got %q", got)
	}
	if got := matrix["ARCH-PATTERN-002"].State; got != MigrationIssueNative {
		t.Fatalf("expected ARCH-PATTERN-002 explicit issue_native audit, got %q", got)
	}
	if got := matrix["ARCH-PATTERN-003"].State; got != MigrationIssueNative {
		t.Fatalf("expected ARCH-PATTERN-003 explicit issue_native audit, got %q", got)
	}
	if matrix["SEC-SECRET-001"].Reason == "" {
		t.Fatal("expected audited migration reason for SEC-SECRET-001")
	}
	if matrix["ARCH-LAYER-001"].Reason == "" {
		t.Fatal("expected audited migration reason for ARCH-LAYER-001")
	}
	if matrix["ARCH-LAYER-002"].Reason == "" {
		t.Fatal("expected audited migration reason for ARCH-LAYER-002")
	}
	if matrix["ARCH-PATTERN-001"].Reason == "" {
		t.Fatal("expected audited migration reason for ARCH-PATTERN-001")
	}
	if matrix["ARCH-PATTERN-002"].Reason == "" {
		t.Fatal("expected audited migration reason for ARCH-PATTERN-002")
	}
	if matrix["ARCH-PATTERN-003"].Reason == "" {
		t.Fatal("expected audited migration reason for ARCH-PATTERN-003")
	}
	if matrix["SEC-STRICT-001"].Reason == "" {
		t.Fatal("expected audited migration reason for SEC-STRICT-001")
	}
	if !containsFold(matrix["SEC-STRICT-001"].Reason, "structural data-access facts") {
		t.Fatalf("SEC-STRICT-001 reason = %q, want structural data-access rationale", matrix["SEC-STRICT-001"].Reason)
	}
	if !containsFold(matrix["SEC-STRICT-002"].Reason, "structural logging facts") {
		t.Fatalf("SEC-STRICT-002 reason = %q, want structural logging rationale", matrix["SEC-STRICT-002"].Reason)
	}
	if matrix["TEST-AUTH-001"].Reason == "" {
		t.Fatal("expected audited migration reason for TEST-AUTH-001")
	}
	if !containsFold(matrix["TEST-AUTH-001"].Reason, "mechanically inspectable") {
		t.Fatalf("TEST-AUTH-001 reason = %q, want mechanically inspectable rationale", matrix["TEST-AUTH-001"].Reason)
	}
	if !containsFold(matrix["TEST-PAYMENT-001"].Reason, "billing-domain regression coverage") {
		t.Fatalf("TEST-PAYMENT-001 reason = %q, want billing-domain regression rationale", matrix["TEST-PAYMENT-001"].Reason)
	}
	if !containsFold(matrix["ARCH-LAYER-002"].Reason, "symbol-name evidence") {
		t.Fatalf("ARCH-LAYER-002 reason = %q, want symbol-name evidence rationale", matrix["ARCH-LAYER-002"].Reason)
	}
	if !containsFold(matrix["ARCH-LAYER-003"].Reason, "symbol-name evidence") {
		t.Fatalf("ARCH-LAYER-003 reason = %q, want symbol-name evidence rationale", matrix["ARCH-LAYER-003"].Reason)
	}
	if !containsFold(matrix["ARCH-PATTERN-001"].Reason, "path-oriented heuristics") {
		t.Fatalf("ARCH-PATTERN-001 reason = %q, want path-oriented heuristics rationale", matrix["ARCH-PATTERN-001"].Reason)
	}
}

func TestReleaseBlockingMigrationAudits(t *testing.T) {
	t.Parallel()

	audits := ReleaseBlockingMigrationAudits()
	ids := ReleaseBlockingPriorityRuleIDs()
	if len(audits) != len(ids) {
		t.Fatalf("expected %d release-blocking audits, got %d", len(ids), len(audits))
	}
	for _, ruleID := range ids {
		audit, ok := audits[ruleID]
		if !ok {
			t.Fatalf("missing release-blocking audit for %s", ruleID)
		}
		if audit.State != MigrationIssueNative && audit.State != MigrationSeedNative {
			t.Fatalf("release-blocking rule %s has non-closeout state %q", ruleID, audit.State)
		}
		if strings.TrimSpace(audit.Reason) == "" {
			t.Fatalf("release-blocking rule %s missing audited reason", ruleID)
		}
	}
	if audits["ARCH-LAYER-002"].State != MigrationSeedNative {
		t.Fatalf("expected ARCH-LAYER-002 to remain explicit seed_native, got %q", audits["ARCH-LAYER-002"].State)
	}
	if audits["SEC-STRICT-001"].State != MigrationIssueNative {
		t.Fatalf("expected SEC-STRICT-001 to remain explicit issue_native, got %q", audits["SEC-STRICT-001"].State)
	}
}

func TestResolveIssueSeedSemantics(t *testing.T) {
	t.Parallel()

	semantics := ResolveIssueSeedSemantics(
		Rule{
			ID:           "SEC-001",
			Title:        "Hardcoded secret detected",
			Category:     "Security",
			Severity:     "Critical",
			MatcherClass: MatcherProof,
		},
		Finding{
			RuleID:     "SEC-001",
			Status:     StatusFail,
			TrustClass: TrustMachineTrusted,
			Message:    "fallback",
		},
	)

	if semantics.Title != "Hardcoded secret detected" {
		t.Fatalf("title = %q, want canonical metadata title", semantics.Title)
	}
	if semantics.Category != "security" {
		t.Fatalf("category = %q, want security", semantics.Category)
	}
	if semantics.Severity != "critical" {
		t.Fatalf("severity = %q, want critical", semantics.Severity)
	}
	if semantics.Source != "rule" {
		t.Fatalf("source = %q, want rule", semantics.Source)
	}
}

func TestRuleMigrationAuditForRule_ExplicitAudits(t *testing.T) {
	t.Parallel()

	layerAudit := RuleMigrationAuditForRule(Rule{ID: "ARCH-LAYER-001", MatcherClass: MatcherStructural})
	if layerAudit.State != MigrationIssueNative {
		t.Fatalf("ARCH-LAYER-001 audit state = %q, want %q", layerAudit.State, MigrationIssueNative)
	}
	if layerAudit.Reason == "" {
		t.Fatal("expected audited migration reason for ARCH-LAYER-001")
	}
	if !containsFold(layerAudit.Reason, "filerole") || !containsFold(layerAudit.Reason, "false-positive guards") {
		t.Fatalf("ARCH-LAYER-001 audit reason = %q, want deterministic evidence + guard rationale", layerAudit.Reason)
	}

	patternAudit := RuleMigrationAuditForRule(Rule{ID: "ARCH-PATTERN-002", MatcherClass: MatcherStructural})
	if patternAudit.State != MigrationIssueNative {
		t.Fatalf("ARCH-PATTERN-002 audit state = %q, want %q", patternAudit.State, MigrationIssueNative)
	}
	if patternAudit.Reason == "" {
		t.Fatal("expected audited migration reason for ARCH-PATTERN-002")
	}
	if !containsFold(patternAudit.Reason, "handler/model import evidence") || !containsFold(patternAudit.Reason, "false-positive guards") {
		t.Fatalf("ARCH-PATTERN-002 audit reason = %q, want deterministic evidence + guard rationale", patternAudit.Reason)
	}
}

func TestRuleMigrationAuditForRule_ConservativeSeedsRemainSeedNative(t *testing.T) {
	t.Parallel()

	cases := []struct {
		id           string
		reasonSubstr string
	}{
		{id: "ARCH-LAYER-002", reasonSubstr: "symbol-name evidence"},
		{id: "ARCH-LAYER-003", reasonSubstr: "symbol-name evidence"},
		{id: "ARCH-PATTERN-001", reasonSubstr: "path-oriented heuristics"},
	}

	for _, tc := range cases {
		t.Run(tc.id, func(t *testing.T) {
			audit := RuleMigrationAuditForRule(Rule{ID: tc.id})
			if audit.State != MigrationSeedNative {
				t.Fatalf("%s audit state = %q, want %q", tc.id, audit.State, MigrationSeedNative)
			}
			if audit.Reason == "" {
				t.Fatalf("expected audited migration reason for %s", tc.id)
			}
			if tc.reasonSubstr != "" && !containsFold(audit.Reason, tc.reasonSubstr) {
				t.Fatalf("%s audit reason = %q, want substring %q", tc.id, audit.Reason, tc.reasonSubstr)
			}
		})
	}
}

func TestRuleMigrationMatrix_ConservativeRemainingSeedNative(t *testing.T) {
	t.Parallel()

	matrix := RuleMigrationMatrix()
	cases := []struct {
		id           string
		reasonSubstr string
	}{
		{id: "ARCH-LAYER-002", reasonSubstr: "symbol-name evidence"},
		{id: "ARCH-LAYER-003", reasonSubstr: "symbol-name evidence"},
		{id: "ARCH-PATTERN-001", reasonSubstr: "path-oriented heuristics"},
	}

	for _, tc := range cases {
		audit, ok := matrix[tc.id]
		if !ok {
			t.Fatalf("expected %s in migration matrix", tc.id)
		}
		if audit.State != MigrationSeedNative {
			t.Fatalf("%s matrix state = %q, want %q", tc.id, audit.State, MigrationSeedNative)
		}
		if !containsFold(audit.Reason, tc.reasonSubstr) {
			t.Fatalf("%s matrix reason = %q, want substring %q", tc.id, audit.Reason, tc.reasonSubstr)
		}
	}
}

func TestRuleMigrationAuditForRule_NewlyPromotedIssueNativeFamilies(t *testing.T) {
	t.Parallel()

	cases := []struct {
		id           string
		reasonSubstr string
	}{
		{id: "SEC-STRICT-001", reasonSubstr: "structural data-access facts"},
		{id: "SEC-STRICT-002", reasonSubstr: "structural logging facts"},
		{id: "TEST-AUTH-001", reasonSubstr: "mechanically inspectable"},
		{id: "TEST-PAYMENT-001", reasonSubstr: "billing-domain regression coverage"},
	}

	for _, tc := range cases {
		t.Run(tc.id, func(t *testing.T) {
			audit := RuleMigrationAuditForRule(Rule{ID: tc.id})
			if audit.State != MigrationIssueNative {
				t.Fatalf("%s audit state = %q, want %q", tc.id, audit.State, MigrationIssueNative)
			}
			if !containsFold(audit.Reason, tc.reasonSubstr) {
				t.Fatalf("%s audit reason = %q, want substring %q", tc.id, audit.Reason, tc.reasonSubstr)
			}
		})
	}
}

func containsFold(s, substr string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(substr))
}
