package rules

import "testing"

func TestBuildIssueSeedsUsesRuleMetadataAndEvidenceIDs(t *testing.T) {
	t.Parallel()

	rf := &RuleFile{
		Rules: []Rule{{
			ID:       "SEC-001",
			Title:    "Missing null check",
			Category: "Security",
			Severity: "Critical",
		}},
	}
	findings := []Finding{
		{
			RuleID:           "SEC-001",
			Status:           StatusFail,
			Confidence:       ConfidenceHigh,
			TrustClass:       TrustMachineTrusted,
			Message:          "fallback",
			FactQualityFloor: "proof",
			Evidence: []Evidence{{
				ID:        "ev-001",
				File:      "service.ts",
				LineStart: 12,
				LineEnd:   12,
				Symbol:    "getUser",
			}},
		},
		{
			RuleID:  "PASS-001",
			Status:  StatusPass,
			Message: "ignored",
		},
	}

	seeds := BuildIssueSeeds(rf, findings)
	if len(seeds) != 1 {
		t.Fatalf("expected 1 seed, got %d", len(seeds))
	}
	if seeds[0].Title != "Missing null check" {
		t.Fatalf("expected metadata title, got %q", seeds[0].Title)
	}
	if seeds[0].Category != "security" || seeds[0].Severity != "critical" {
		t.Fatalf("expected normalized metadata fields, got %#v", seeds[0])
	}
	if len(seeds[0].EvidenceIDs) != 1 || seeds[0].EvidenceIDs[0] != "ev-001" {
		t.Fatalf("expected preserved evidence ids, got %#v", seeds[0].EvidenceIDs)
	}
}

func TestRefreshIssueSeedsRecomputesFromMutatedFindings(t *testing.T) {
	t.Parallel()

	rf := &RuleFile{
		Rules: []Rule{{
			ID:       "ARCH-001",
			Title:    "Repository pattern violation",
			Category: "Design",
			Severity: "High",
		}},
	}
	result := ExecutionResult{
		Findings: []Finding{{
			RuleID:           "ARCH-001",
			Status:           StatusUnknown,
			Confidence:       ConfidenceLow,
			TrustClass:       TrustHumanOrRuntimeRequired,
			Message:          "fallback",
			FactQualityFloor: "heuristic",
			Evidence: []Evidence{{
				File:      "internal/service.ts",
				LineStart: 20,
				LineEnd:   24,
				Symbol:    "Repository",
			}},
		}},
	}
	result.Findings[0].Evidence[0].ID = EvidenceID(result.Findings[0].Evidence[0])

	RefreshIssueSeeds(rf, &result)

	if len(result.IssueSeeds) != 1 {
		t.Fatalf("expected 1 seed, got %d", len(result.IssueSeeds))
	}
	if result.IssueSeeds[0].Source != "agent" {
		t.Fatalf("expected runtime-required trust to map to agent source, got %q", result.IssueSeeds[0].Source)
	}
	if len(result.IssueSeeds[0].EvidenceIDs) != 1 || result.IssueSeeds[0].EvidenceIDs[0] == "" {
		t.Fatalf("expected recomputed evidence ids, got %#v", result.IssueSeeds[0].EvidenceIDs)
	}
}

