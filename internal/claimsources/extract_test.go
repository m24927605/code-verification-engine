package claimsources

import (
	"reflect"
	"testing"
)

func TestExtractDeterministicSourceEvidenceIDs(t *testing.T) {
	root := t.TempDir()
	writeClaimsourceFixture(t, root)

	snap := Snapshot{
		RepoPath:  root,
		CommitSHA: "abc123",
		Files: []string{
			"internal/service.go",
			"README.md",
			"eval/adversarial.json",
			"docs/adr/0001.md",
			"internal/service_test.go",
			"docs/architecture.md",
		},
	}

	descriptors := Discover(snap)
	first := Extract(snap, descriptors)
	second := Extract(snap, descriptors)

	if !reflect.DeepEqual(first, second) {
		t.Fatalf("extraction not deterministic:\nfirst=%#v\nsecond=%#v", first, second)
	}

	if len(first) != 7 {
		t.Fatalf("expected 7 source evidence records, got %d", len(first))
	}

	seenTypes := map[SourceType]int{}
	for _, rec := range first {
		if rec.EvidenceID == "" {
			t.Fatalf("record for %s has empty evidence_id", rec.Path)
		}
		if len(rec.Spans) == 0 {
			t.Fatalf("record for %s has no spans", rec.Path)
		}
		seenTypes[rec.SourceType]++
	}

	if seenTypes[SourceTypeReadme] != 2 {
		t.Fatalf("expected 2 README evidence records, got %d", seenTypes[SourceTypeReadme])
	}
	if seenTypes[SourceTypeDoc] != 2 {
		t.Fatalf("expected 2 doc evidence records, got %d", seenTypes[SourceTypeDoc])
	}
	if seenTypes[SourceTypeCode] != 1 {
		t.Fatalf("expected 1 code evidence record, got %d", seenTypes[SourceTypeCode])
	}
	if seenTypes[SourceTypeTest] != 1 {
		t.Fatalf("expected 1 test evidence record, got %d", seenTypes[SourceTypeTest])
	}
	if seenTypes[SourceTypeEval] != 1 {
		t.Fatalf("expected 1 eval evidence record, got %d", seenTypes[SourceTypeEval])
	}

	var readmeCount int
	var codeChecked, testChecked, evalChecked bool
	for _, rec := range first {
		switch rec.SourceType {
		case SourceTypeReadme:
			readmeCount++
			if rec.Metadata["section_title"] == "" {
				t.Fatalf("readme record missing section_title metadata: %#v", rec.Metadata)
			}
			if rec.Metadata["claim_fragments"] == "" {
				t.Fatalf("readme record missing claim_fragments metadata: %#v", rec.Metadata)
			}
		case SourceTypeCode:
			codeChecked = true
			if !containsString(rec.EntityIDs, "NewService") {
				t.Fatalf("code record missing NewService entity id: %#v", rec.EntityIDs)
			}
			if rec.Metadata["module_kind"] != "service" {
				t.Fatalf("code record module_kind = %q, want service", rec.Metadata["module_kind"])
			}
		case SourceTypeTest:
			testChecked = true
			if rec.Metadata["test_kind"] != "unit_test" {
				t.Fatalf("test record test_kind = %q, want unit_test", rec.Metadata["test_kind"])
			}
			if rec.Metadata["target_module"] != "internal/service.go" {
				t.Fatalf("test record target_module = %q, want internal/service.go", rec.Metadata["target_module"])
			}
		case SourceTypeEval:
			evalChecked = true
			if rec.Metadata["adversarial_flag"] != "true" {
				t.Fatalf("eval record adversarial_flag = %q, want true", rec.Metadata["adversarial_flag"])
			}
			if rec.Metadata["benchmark_purpose"] != "adversarial" {
				t.Fatalf("eval record benchmark_purpose = %q, want adversarial", rec.Metadata["benchmark_purpose"])
			}
		}
	}

	if readmeCount != 2 {
		t.Fatalf("expected 2 README sections, got %d", readmeCount)
	}
	if !codeChecked || !testChecked || !evalChecked {
		t.Fatalf("missing expected source types in extracted evidence: code=%v test=%v eval=%v", codeChecked, testChecked, evalChecked)
	}
}

func containsString(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}
