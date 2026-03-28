package artifactsv2

import "testing"

func TestEvidenceStoreIndexesRecords(t *testing.T) {
	t.Parallel()

	store := NewEvidenceStoreFromRecords([]EvidenceRecord{
		{
			ID:              "ev-1",
			ProducerID:      "rule:sec-1",
			Claims:          []string{"sec-1", "null"},
			Locations:       []LocationRef{{RepoRelPath: "service.ts", StartLine: 10, EndLine: 10}},
			ProducerVersion: "1.0.0",
			Kind:            "rule_assertion",
			Source:          "rule",
			Repo:            "repo",
			Commit:          "abc",
			BoundaryHash:    "sha256:x",
			FactQuality:     "proof",
			CreatedAt:       "2026-03-27T12:00:00Z",
		},
		{
			ID:              "ev-2",
			ProducerID:      "rule:sec-1",
			Claims:          []string{"null"},
			Locations:       []LocationRef{{RepoRelPath: "service.ts", StartLine: 11, EndLine: 11}},
			ProducerVersion: "1.0.0",
			Kind:            "rule_assertion",
			Source:          "rule",
			Repo:            "repo",
			Commit:          "abc",
			BoundaryHash:    "sha256:x",
			FactQuality:     "proof",
			CreatedAt:       "2026-03-27T12:00:00Z",
		},
	})

	if got := store.IDsByClaim("null"); len(got) != 2 {
		t.Fatalf("expected 2 evidence ids for claim null, got %d", len(got))
	}
	if got := store.IDsByProducer("rule:sec-1"); len(got) != 2 {
		t.Fatalf("expected 2 evidence ids for producer, got %d", len(got))
	}
	if got := store.IDsByFile("service.ts"); len(got) != 2 {
		t.Fatalf("expected 2 evidence ids for file, got %d", len(got))
	}
}

func TestEvidenceStoreUpsertReplacesRecord(t *testing.T) {
	t.Parallel()

	store := NewEvidenceStore()
	record := EvidenceRecord{
		ID:              "ev-1",
		ProducerID:      "rule:a",
		ProducerVersion: "1.0.0",
		Kind:            "rule_assertion",
		Source:          "rule",
		Repo:            "repo",
		Commit:          "abc",
		BoundaryHash:    "sha256:x",
		FactQuality:     "proof",
		CreatedAt:       "2026-03-27T12:00:00Z",
		Locations:       []LocationRef{{RepoRelPath: "a.ts", StartLine: 1, EndLine: 1}},
		Claims:          []string{"a"},
	}
	store.Upsert(record)
	record.Claims = []string{"b"}
	store.Upsert(record)
	store.Finalize()

	if got := store.IDsByClaim("a"); len(got) != 0 {
		t.Fatalf("expected claim a to be replaced")
	}
	if got := store.IDsByClaim("b"); len(got) != 1 {
		t.Fatalf("expected claim b to be indexed")
	}
}
