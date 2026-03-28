package artifactsv2

import "testing"

func TestBuildContextBundleRespectsBudgets(t *testing.T) {
	t.Parallel()

	candidate := IssueCandidate{
		ID:                 "iss-1",
		EvidenceIDs:        []string{"ev-1", "ev-2"},
		CounterEvidenceIDs: []string{"ev-3"},
	}
	evidenceIndex := map[string]EvidenceRecord{
		"ev-1": {
			ID:        "ev-1",
			EntityIDs: []string{"fn-1"},
			Locations: []LocationRef{{RepoRelPath: "a.ts", StartLine: 10, EndLine: 10}},
		},
		"ev-2": {
			ID:        "ev-2",
			EntityIDs: []string{"fn-2"},
			Locations: []LocationRef{{RepoRelPath: "b.ts", StartLine: 20, EndLine: 20}},
		},
		"ev-3": {
			ID:        "ev-3",
			EntityIDs: []string{"fn-3"},
			Locations: []LocationRef{{RepoRelPath: "c.ts", StartLine: 30, EndLine: 30}},
		},
	}

	bundle := buildContextBundle(ContextRequest{
		TriggerType: "issue",
		TriggerID:   "iss-1",
		MaxFiles:    2,
		MaxSpans:    2,
		MaxTokens:   1200,
	}, candidate, evidenceIndex)

	if len(bundle.Spans) != 2 {
		t.Fatalf("expected 2 spans under budget, got %d", len(bundle.Spans))
	}
	if bundle.ID == "" {
		t.Fatal("expected deterministic context bundle id")
	}
	if len(bundle.EntityIDs) != 2 {
		t.Fatalf("expected 2 entity ids under budgeted selection, got %d", len(bundle.EntityIDs))
	}
	if bundle.Spans[0].RepoRelPath != "a.ts" || bundle.Spans[1].RepoRelPath != "b.ts" {
		t.Fatalf("expected deterministic span ordering, got %#v", bundle.Spans)
	}
}

func TestBuildContextSelectionsTriggersForUnknownAndConflict(t *testing.T) {
	t.Parallel()

	candidates := []IssueCandidate{
		{
			ID:                 "iss-conflict",
			Status:             "open",
			Severity:           "medium",
			PolicyClass:        "advisory",
			EvidenceIDs:        []string{"ev-1"},
			CounterEvidenceIDs: []string{"ev-2"},
		},
		{
			ID:          "iss-unknown",
			Status:      "unknown",
			Severity:    "high",
			PolicyClass: "unknown_retained",
			EvidenceIDs: []string{"ev-3"},
		},
	}
	evidence := EvidenceArtifact{
		Evidence: []EvidenceRecord{
			{ID: "ev-1", Locations: []LocationRef{{RepoRelPath: "a.ts", StartLine: 10, EndLine: 10}}},
			{ID: "ev-2", Locations: []LocationRef{{RepoRelPath: "a.ts", StartLine: 12, EndLine: 12}}},
			{ID: "ev-3", Locations: []LocationRef{{RepoRelPath: "b.ts", StartLine: 20, EndLine: 20}}},
		},
	}

	selections := buildContextSelections(candidates, evidence)
	if len(selections) != 2 {
		t.Fatalf("expected 2 context selections, got %d", len(selections))
	}
	if selections[0].TriggerID != "iss-conflict" || selections[1].TriggerID != "iss-unknown" {
		t.Fatalf("unexpected deterministic selection ordering: %#v", selections)
	}
	if len(selections[0].SelectionTrace) == 0 || len(selections[1].SelectionTrace) == 0 {
		t.Fatal("expected selection trace to be populated")
	}
	if selections[0].ID == "" || selections[1].ID == "" {
		t.Fatalf("expected context selection ids, got %#v", selections)
	}
	if selections[0].MaxSpans != defaultContextMaxSpans {
		t.Fatalf("expected max spans to propagate, got %d", selections[0].MaxSpans)
	}
}
