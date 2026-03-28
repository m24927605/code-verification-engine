package artifactsv2

import (
	"testing"

	"github.com/verabase/code-verification-engine/internal/rules"
)

func TestIssueSeedsFromFindingsSkipsPassAndNormalizesFields(t *testing.T) {
	t.Parallel()

	seeds := IssueSeedsFromFindings([]rules.Finding{
		{
			RuleID:     "PASS-001",
			Status:     rules.StatusPass,
			Message:    "all good",
			Confidence: rules.ConfidenceHigh,
			Evidence: []rules.Evidence{{
				ID:        "ev-pass",
				File:      "ignored.ts",
				LineStart: 1,
				LineEnd:   1,
			}},
		},
		{
			RuleID:           "SEC-001",
			Status:           rules.StatusFail,
			Message:          "Missing null check",
			Confidence:       rules.ConfidenceHigh,
			TrustClass:       rules.TrustMachineTrusted,
			VerdictBasis:     "proof",
			FactQualityFloor: "proof",
			Evidence: []rules.Evidence{{
				ID:        "ev-001",
				File:      "service.ts",
				LineStart: 10,
				LineEnd:   12,
				Symbol:    "getUser",
			}},
		},
		{
			RuleID:           "ARCH-001",
			Status:           rules.StatusUnknown,
			Message:          "Needs review",
			Confidence:       rules.ConfidenceLow,
			TrustClass:       rules.TrustHumanOrRuntimeRequired,
			FactQualityFloor: "heuristic",
		},
	})

	if len(seeds) != 2 {
		t.Fatalf("expected 2 non-pass seeds, got %d", len(seeds))
	}
	if seeds[0].RuleID != "SEC-001" || seeds[0].Status != "open" {
		t.Fatalf("unexpected first seed: %#v", seeds[0])
	}
	if seeds[0].Category != "security" || seeds[0].Severity != "high" {
		t.Fatalf("expected security/high normalization, got %#v", seeds[0])
	}
	if len(seeds[0].EvidenceIDs) != 1 || seeds[0].EvidenceIDs[0] != "ev-001" {
		t.Fatalf("expected evidence id to be preserved, got %#v", seeds[0].EvidenceIDs)
	}
	if seeds[1].RuleID != "ARCH-001" || seeds[1].Status != "unknown" {
		t.Fatalf("unexpected second seed: %#v", seeds[1])
	}
	if seeds[1].Source != "agent" {
		t.Fatalf("expected human/runtime required finding to map to agent source, got %q", seeds[1].Source)
	}
	if seeds[1].File != "unknown" || seeds[1].StartLine != 1 || seeds[1].EndLine != 1 {
		t.Fatalf("expected missing evidence to normalize to unknown location, got %#v", seeds[1])
	}
}

func TestIssueSeedsFromFindingsWithMetadataPrefersRuleDefinitions(t *testing.T) {
	t.Parallel()

	seeds := IssueSeedsFromFindingsWithMetadata([]rules.Finding{{
		RuleID:           "ARCH-001",
		Status:           rules.StatusFail,
		Message:          "fallback message",
		Confidence:       rules.ConfidenceMedium,
		TrustClass:       rules.TrustAdvisory,
		FactQualityFloor: "structural",
		Evidence: []rules.Evidence{{
			ID:        "ev-arch",
			File:      "internal/service.ts",
			LineStart: 20,
			LineEnd:   30,
			Symbol:    "Repository",
		}},
	}}, map[string]RuleMetadata{
		"ARCH-001": {
			RuleID:   "ARCH-001",
			Title:    "Repository pattern violation",
			Category: "Design",
			Severity: "Critical",
		},
	})

	if len(seeds) != 1 {
		t.Fatalf("expected 1 seed, got %d", len(seeds))
	}
	if seeds[0].Title != "Repository pattern violation" {
		t.Fatalf("expected metadata title, got %q", seeds[0].Title)
	}
	if seeds[0].Category != "architecture" {
		t.Fatalf("expected metadata category, got %q", seeds[0].Category)
	}
	if seeds[0].Severity != "critical" {
		t.Fatalf("expected metadata severity, got %q", seeds[0].Severity)
	}
}

func TestIssueSeedsFromRuleSeedsBridgesNativeRuleSeeds(t *testing.T) {
	t.Parallel()

	seeds := IssueSeedsFromRuleSeeds([]rules.IssueSeed{{
		RuleID:      "SEC-001",
		Title:       "Missing null check",
		Source:      "rule",
		Category:    "security",
		Severity:    "high",
		Status:      "open",
		Confidence:  0.9,
		Quality:     1.0,
		File:        "service.ts",
		Symbol:      "getUser",
		StartLine:   10,
		EndLine:     10,
		EvidenceIDs: []string{"ev-001"},
	}})

	if len(seeds) != 1 {
		t.Fatalf("expected 1 bridged seed, got %d", len(seeds))
	}
	if seeds[0].RuleID != "SEC-001" || seeds[0].EvidenceIDs[0] != "ev-001" {
		t.Fatalf("unexpected bridged seed: %#v", seeds[0])
	}
}

func TestRuleMetadataFromRuleFileIncludesMigrationState(t *testing.T) {
	t.Parallel()

	metadata := RuleMetadataFromRuleFile(&rules.RuleFile{
		Rules: []rules.Rule{
			{ID: "SEC-SECRET-001", Title: "Hardcoded secret", Category: "Security", Severity: "Critical", MatcherClass: rules.MatcherProof},
			{ID: "QUAL-001", Title: "Graceful shutdown", Category: "Quality", Severity: "Medium", MatcherClass: rules.MatcherHeuristic},
		},
	})

	if got := metadata["SEC-SECRET-001"].MigrationState; got != string(rules.MigrationIssueNative) {
		t.Fatalf("SEC-SECRET-001 migration state = %q, want %q", got, rules.MigrationIssueNative)
	}
	if got := metadata["SEC-SECRET-001"].MatcherClass; got != string(rules.MatcherProof) {
		t.Fatalf("SEC-SECRET-001 matcher class = %q, want %q", got, rules.MatcherProof)
	}
	if got := metadata["SEC-SECRET-001"].TrustClass; got != string(rules.TrustMachineTrusted) {
		t.Fatalf("SEC-SECRET-001 trust class = %q, want %q", got, rules.TrustMachineTrusted)
	}
	if metadata["SEC-SECRET-001"].MigrationReason == "" {
		t.Fatal("expected migration reason to be populated")
	}
	if got := metadata["QUAL-001"].MigrationState; got != string(rules.MigrationFindingBridged) {
		t.Fatalf("QUAL-001 migration state = %q, want %q", got, rules.MigrationFindingBridged)
	}
}

func TestRuleMetadataFromRuleFileUsesAuditedArchitectureMigrationState(t *testing.T) {
	t.Parallel()

	metadata := RuleMetadataFromRuleFile(&rules.RuleFile{
		Rules: []rules.Rule{
			{ID: "ARCH-PATTERN-003", Title: "Mutable global singletons should not exist", Category: "architecture", Severity: "medium", MatcherClass: rules.MatcherStructural},
		},
	})

	if got := metadata["ARCH-PATTERN-003"].MigrationState; got != string(rules.MigrationIssueNative) {
		t.Fatalf("ARCH-PATTERN-003 migration state = %q, want %q", got, rules.MigrationIssueNative)
	}
	if metadata["ARCH-PATTERN-003"].MigrationReason == "" {
		t.Fatal("expected audited migration reason for ARCH-PATTERN-003")
	}
}

func TestRuleMetadataFromRuleFileUsesPromotedStrictAndTestingMigrationStates(t *testing.T) {
	t.Parallel()

	metadata := RuleMetadataFromRuleFile(&rules.RuleFile{
		Rules: []rules.Rule{
			{ID: "SEC-STRICT-001", Title: "SQL injection patterns must not exist", Category: "security", Severity: "critical", MatcherClass: rules.MatcherStructural},
			{ID: "TEST-PAYMENT-001", Title: "Payment module must have tests", Category: "testing", Severity: "high", MatcherClass: rules.MatcherStructural},
		},
	})

	if got := metadata["SEC-STRICT-001"].MigrationState; got != string(rules.MigrationIssueNative) {
		t.Fatalf("SEC-STRICT-001 migration state = %q, want %q", got, rules.MigrationIssueNative)
	}
	if got := metadata["TEST-PAYMENT-001"].MigrationState; got != string(rules.MigrationIssueNative) {
		t.Fatalf("TEST-PAYMENT-001 migration state = %q, want %q", got, rules.MigrationIssueNative)
	}
	if metadata["SEC-STRICT-001"].MigrationReason == "" || metadata["TEST-PAYMENT-001"].MigrationReason == "" {
		t.Fatal("expected migration reasons for promoted strict/testing families")
	}
}

func TestVerificationSourceCloneCopiesAgentResults(t *testing.T) {
	t.Parallel()

	src := VerificationSource{
		AgentResults: []AgentResult{{
			TaskID:             "agent-1",
			Kind:               "security",
			IssueID:            "iss-1",
			ContextSelectionID: "ctx-1",
			Status:             "completed",
			EmittedEvidence: []EvidenceRecord{{
				ID:        "ev-1",
				EntityIDs: []string{"fn-1"},
				Payload:   map[string]any{"k": "v"},
			}},
			UnresolvedReasons: []string{"none"},
		}},
	}

	cloned := src.Clone()
	cloned.AgentResults[0].UnresolvedReasons[0] = "changed"
	cloned.AgentResults[0].EmittedEvidence[0].EntityIDs[0] = "fn-2"
	cloned.AgentResults[0].EmittedEvidence[0].Payload["k"] = "changed"

	if src.AgentResults[0].UnresolvedReasons[0] != "none" {
		t.Fatalf("expected unresolved reasons to be defensively copied, got %#v", src.AgentResults[0])
	}
	if src.AgentResults[0].EmittedEvidence[0].EntityIDs[0] != "fn-1" {
		t.Fatalf("expected emitted evidence entity ids to be defensively copied, got %#v", src.AgentResults[0])
	}
	if src.AgentResults[0].EmittedEvidence[0].Payload["k"] != "v" {
		t.Fatalf("expected emitted evidence payload to be defensively copied, got %#v", src.AgentResults[0])
	}
}
