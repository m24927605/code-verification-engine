package artifactsv2

import "testing"

func TestProjectIssueCandidates(t *testing.T) {
	t.Parallel()

	candidates := []IssueCandidate{
		{
			ID:                 "iss-b",
			Fingerprint:        "fp-b",
			RuleFamily:         "fam_bug",
			MergeBasis:         "line_overlap",
			Category:           "bug",
			Title:              "B",
			Severity:           "medium",
			Confidence:         0.7,
			ConfidenceClass:    "moderate",
			PolicyClass:        "advisory",
			Status:             "open",
			EvidenceIDs:        []string{"ev-2", "ev-1", "ev-1"},
			CounterEvidenceIDs: []string{"ev-x", "ev-x"},
			Sources:            []string{"rule", "rule"},
			SourceSummary:      IssueSourceSummary{RuleCount: 1, DeterministicSources: 1, AgentSources: 0, TotalSources: 1},
		},
		{
			ID:              "iss-a",
			Fingerprint:     "fp-a",
			RuleFamily:      "sec_secret",
			MergeBasis:      "same_symbol",
			Category:        "security",
			Title:           "A",
			Severity:        "high",
			Confidence:      0.9,
			ConfidenceClass: "high",
			PolicyClass:     "machine_trusted",
			Status:          "open",
			EvidenceIDs:     []string{"ev-3"},
			Sources:         []string{"rule"},
			SourceSummary:   IssueSourceSummary{RuleCount: 1, DeterministicSources: 1, AgentSources: 0, TotalSources: 1},
		},
	}

	issues := ProjectIssueCandidates(candidates)
	if len(issues) != 2 {
		t.Fatalf("expected 2 issues, got %d", len(issues))
	}
	if issues[0].ID != "iss-a" {
		t.Fatalf("expected sorted issues, got first id %q", issues[0].ID)
	}
	if len(issues[1].EvidenceIDs) != 2 {
		t.Fatalf("expected deduped evidence ids, got %d", len(issues[1].EvidenceIDs))
	}
	if len(issues[1].CounterEvidenceIDs) != 1 || issues[1].CounterEvidenceIDs[0] != "ev-x" {
		t.Fatalf("expected deduped counter evidence ids, got %#v", issues[1].CounterEvidenceIDs)
	}
	if issues[0].Fingerprint != "fp-a" {
		t.Fatalf("expected fingerprint to project, got %q", issues[0].Fingerprint)
	}
	if issues[0].MergeBasis != "same_symbol" {
		t.Fatalf("expected merge basis to project, got %q", issues[0].MergeBasis)
	}
	if issues[0].RuleFamily != "sec_secret" {
		t.Fatalf("expected rule family to project, got %q", issues[0].RuleFamily)
	}
	if issues[0].ConfidenceClass != "high" || issues[0].PolicyClass != "machine_trusted" {
		t.Fatalf("expected confidence/policy classes to project, got %q/%q", issues[0].ConfidenceClass, issues[0].PolicyClass)
	}
	if issues[1].SourceSummary.RuleCount != 1 || issues[1].SourceSummary.TotalSources != 1 {
		t.Fatalf("expected source summary to project, got %#v", issues[1].SourceSummary)
	}
}

func TestBuildRuleToIssueIDsFromCandidates(t *testing.T) {
	t.Parallel()

	candidates := []IssueCandidate{
		{ID: "iss-1", RuleIDs: []string{"SEC-001", "QUAL-001"}},
		{ID: "iss-2", RuleIDs: []string{"SEC-001"}},
	}

	got := buildRuleToIssueIDs(candidates)
	if len(got["SEC-001"]) != 2 {
		t.Fatalf("expected SEC-001 to map to 2 issues, got %d", len(got["SEC-001"]))
	}
	if len(got["QUAL-001"]) != 1 || got["QUAL-001"][0] != "iss-1" {
		t.Fatalf("unexpected QUAL-001 mapping: %#v", got["QUAL-001"])
	}
}
