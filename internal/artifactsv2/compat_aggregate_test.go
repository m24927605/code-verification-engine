package artifactsv2

import (
	"testing"
)

func TestCompatMergeBasisBySymbol(t *testing.T) {
	t.Parallel()

	cluster := compatIssueCluster{
		Status:    "open",
		File:      "service.ts",
		Symbol:    "getUser",
		StartLine: 10,
		EndLine:   12,
	}
	seed := IssueSeed{
		Status:    "open",
		File:      "service.ts",
		Symbol:    "getUser",
		StartLine: 40,
		EndLine:   42,
	}
	mergeBasis, ok := compatMergeBasis(cluster, seed)
	if !ok {
		t.Fatalf("expected same symbol in same file to cluster")
	}
	if mergeBasis != "same_symbol" {
		t.Fatalf("expected same_symbol merge basis, got %q", mergeBasis)
	}
}

func TestCompatMergeBasisByLineOverlapWithoutSymbol(t *testing.T) {
	t.Parallel()

	cluster := compatIssueCluster{
		Category:  "bug",
		Status:    "open",
		File:      "service.ts",
		Symbol:    "",
		StartLine: 10,
		EndLine:   12,
	}
	seed := IssueSeed{
		Category:  "bug",
		Status:    "open",
		File:      "service.ts",
		Symbol:    "",
		StartLine: 13,
		EndLine:   14,
	}
	mergeBasis, ok := compatMergeBasis(cluster, seed)
	if !ok {
		t.Fatalf("expected nearby line overlap to cluster when symbol is missing")
	}
	if mergeBasis != "line_overlap" {
		t.Fatalf("expected line_overlap merge basis, got %q", mergeBasis)
	}
}

func TestCompatMergeBasisRejectsLineOverlapAcrossDifferentFamilies(t *testing.T) {
	t.Parallel()

	cluster := compatIssueCluster{
		Category:  "security",
		Status:    "open",
		File:      "service.ts",
		Symbol:    "",
		StartLine: 10,
		EndLine:   12,
	}
	seed := IssueSeed{
		Category:  "quality",
		Status:    "open",
		File:      "service.ts",
		Symbol:    "",
		StartLine: 11,
		EndLine:   13,
	}
	if _, ok := compatMergeBasis(cluster, seed); ok {
		t.Fatal("expected different category families not to merge on line overlap alone")
	}
}

func TestCompatMergeBasisRejectsLineOverlapAcrossDifferentRuleFamiliesWithinCategory(t *testing.T) {
	t.Parallel()

	cluster := compatIssueCluster{
		Category:  "architecture",
		Status:    "open",
		File:      "service.ts",
		Symbol:    "",
		StartLine: 10,
		EndLine:   12,
		RuleIDs:   []string{"ARCH-LAYER-001"},
	}
	seed := IssueSeed{
		RuleID:    "ARCH-PATTERN-001",
		Category:  "architecture",
		Status:    "open",
		File:      "service.ts",
		Symbol:    "",
		StartLine: 11,
		EndLine:   13,
	}
	if _, ok := compatMergeBasis(cluster, seed); ok {
		t.Fatal("expected different architecture rule families not to merge on line overlap alone")
	}
}

func TestCompatMergeBasisRejectsSameSymbolAcrossDifferentArchitectureFamilies(t *testing.T) {
	t.Parallel()

	cluster := compatIssueCluster{
		File:     "service.ts",
		Symbol:   "UserRepo",
		Status:   "open",
		Category: "architecture",
		RuleIDs:  []string{"ARCH-LAYER-001"},
	}
	seed := IssueSeed{
		RuleID:    "ARCH-PATTERN-001",
		Category:  "architecture",
		Status:    "open",
		File:      "service.ts",
		Symbol:    "UserRepo",
		StartLine: 10,
		EndLine:   12,
	}

	if _, ok := compatMergeBasis(cluster, seed); ok {
		t.Fatal("expected same-symbol merge to reject different architecture families")
	}
}

func TestCompatMergeBasisAllowsLineOverlapWithinArchitectureDesignFamily(t *testing.T) {
	t.Parallel()

	cluster := compatIssueCluster{
		Category:  "architecture",
		Status:    "open",
		File:      "service.ts",
		Symbol:    "",
		StartLine: 10,
		EndLine:   12,
	}
	seed := IssueSeed{
		Category:  "design",
		Status:    "open",
		File:      "service.ts",
		Symbol:    "",
		StartLine: 11,
		EndLine:   13,
	}
	mergeBasis, ok := compatMergeBasis(cluster, seed)
	if !ok {
		t.Fatal("expected architecture/design family to merge on overlapping lines")
	}
	if mergeBasis != "line_overlap" {
		t.Fatalf("expected line_overlap merge basis, got %q", mergeBasis)
	}
}

func TestCompatMergeBasisRejectsDifferentFiles(t *testing.T) {
	t.Parallel()

	cluster := compatIssueCluster{
		Status:    "open",
		File:      "service.ts",
		Symbol:    "getUser",
		StartLine: 10,
		EndLine:   12,
	}
	seed := IssueSeed{
		Status:    "open",
		File:      "controller.ts",
		Symbol:    "getUser",
		StartLine: 10,
		EndLine:   12,
	}
	if _, ok := compatMergeBasis(cluster, seed); ok {
		t.Fatalf("expected different files not to cluster")
	}
}

func TestMergeCompatClusterPrefersHigherSeverityAndCategory(t *testing.T) {
	t.Parallel()

	cluster := compatIssueCluster{
		Category:    "bug",
		Severity:    "medium",
		Status:      "open",
		Title:       "short",
		File:        "service.ts",
		Symbol:      "getUser",
		StartLine:   10,
		EndLine:     12,
		EvidenceIDs: []string{"ev-1"},
		Sources:     []string{"rule"},
		RuleIDs:     []string{"QUAL-001"},
		Confidence:  0.7,
		Quality:     0.4,
	}
	seed := IssueSeed{
		RuleID:      "SEC-001",
		Title:       "longer security title",
		EvidenceIDs: []string{"ev-2"},
		Source:      "rule",
		Category:    "security",
		Severity:    "high",
		Status:      "open",
		Confidence:  0.9,
		Quality:     1.0,
		File:        "service.ts",
		Symbol:      "getUser",
		StartLine:   11,
		EndLine:     15,
	}

	merged := mergeCompatCluster(cluster, seed)
	if merged.Category != "security" {
		t.Fatalf("expected security category, got %q", merged.Category)
	}
	if merged.Severity != "high" {
		t.Fatalf("expected high severity, got %q", merged.Severity)
	}
	if merged.Title != "longer security title" {
		t.Fatalf("expected longer title to win, got %q", merged.Title)
	}
	if len(dedupeStringsSorted(merged.RuleIDs)) != 2 {
		t.Fatalf("expected merged rule ids")
	}
}

func TestMergeCompatClusterTieBreaksAreOrderIndependent(t *testing.T) {
	t.Parallel()

	forward := mergeCompatCluster(
		compatIssueCluster{
			Category:    "quality",
			Severity:    "medium",
			Status:      "open",
			Title:       "Alpha",
			File:        "service.ts",
			Symbol:      "getUser",
			StartLine:   10,
			EndLine:     12,
			EvidenceIDs: []string{"ev-1"},
			Sources:     []string{"rule"},
			RuleIDs:     []string{"QUAL-001"},
			Confidence:  0.7,
			Quality:     0.4,
		},
		IssueSeed{
			RuleID:      "TEST-001",
			Title:       "Bravo",
			Source:      "rule",
			Category:    "testing",
			Severity:    "medium",
			Status:      "open",
			Confidence:  0.8,
			Quality:     0.6,
			File:        "service.ts",
			Symbol:      "getUser",
			StartLine:   11,
			EndLine:     15,
			EvidenceIDs: []string{"ev-2"},
		},
	)
	reverse := mergeCompatCluster(
		compatIssueCluster{
			Category:    "testing",
			Severity:    "medium",
			Status:      "open",
			Title:       "Bravo",
			File:        "service.ts",
			Symbol:      "getUser",
			StartLine:   11,
			EndLine:     15,
			EvidenceIDs: []string{"ev-2"},
			Sources:     []string{"rule"},
			RuleIDs:     []string{"TEST-001"},
			Confidence:  0.8,
			Quality:     0.6,
		},
		IssueSeed{
			RuleID:      "QUAL-001",
			Title:       "Alpha",
			Source:      "rule",
			Category:    "quality",
			Severity:    "medium",
			Status:      "open",
			Confidence:  0.7,
			Quality:     0.4,
			File:        "service.ts",
			Symbol:      "getUser",
			StartLine:   10,
			EndLine:     12,
			EvidenceIDs: []string{"ev-1"},
		},
	)

	if forward.Category != reverse.Category {
		t.Fatalf("expected stable category tie-break, got %q vs %q", forward.Category, reverse.Category)
	}
	if forward.Title != reverse.Title {
		t.Fatalf("expected stable title tie-break, got %q vs %q", forward.Title, reverse.Title)
	}
	if forward.Category != "quality" {
		t.Fatalf("expected lexicographically smaller category to win, got %q", forward.Category)
	}
	if forward.Title != "Alpha" {
		t.Fatalf("expected lexicographically smaller equal-length title to win, got %q", forward.Title)
	}
}

func TestCompatClusterFingerprintUsesRuleFamilyBoundary(t *testing.T) {
	t.Parallel()

	layer := compatClusterFingerprint(IssueSeed{
		RuleID:    "ARCH-LAYER-001",
		Category:  "architecture",
		Status:    "open",
		File:      "service.ts",
		StartLine: 10,
		EndLine:   12,
	})
	pattern := compatClusterFingerprint(IssueSeed{
		RuleID:    "ARCH-PATTERN-001",
		Category:  "architecture",
		Status:    "open",
		File:      "service.ts",
		StartLine: 10,
		EndLine:   12,
	})
	if layer == pattern {
		t.Fatalf("expected different rule families to produce different fingerprints, got %q", layer)
	}
}

func TestReleaseBlockingFamiliesHaveExplicitMergePolicies(t *testing.T) {
	t.Parallel()

	for _, family := range releaseBlockingRuleFamilies() {
		if _, ok := explicitRuleFamilyMergePolicies[family]; !ok {
			t.Fatalf("expected explicit merge policy for release-blocking family %q", family)
		}
	}
}

func TestCollectCounterEvidenceIDs(t *testing.T) {
	t.Parallel()

	evidenceIndex := map[string]EvidenceRecord{
		"ev-1": {ID: "ev-1", Contradicts: []string{"ev-3", "ev-2"}},
		"ev-2": {ID: "ev-2"},
		"ev-3": {ID: "ev-3"},
	}

	got := collectCounterEvidenceIDs([]string{"ev-1", "ev-2"}, evidenceIndex)
	if len(got) != 1 || got[0] != "ev-3" {
		t.Fatalf("expected only external counter evidence ev-3, got %#v", got)
	}
}

func TestComputeIssueSourceSummary(t *testing.T) {
	t.Parallel()

	cluster := compatIssueCluster{
		Sources: []string{"rule", "agent", "rule"},
		RuleIDs: []string{"SEC-001", "ARCH-001", "SEC-001"},
	}

	got := computeIssueSourceSummary(cluster)
	if got.RuleCount != 2 {
		t.Fatalf("expected 2 distinct rules, got %d", got.RuleCount)
	}
	if got.DeterministicSources != 1 {
		t.Fatalf("expected 1 deterministic source class, got %d", got.DeterministicSources)
	}
	if got.AgentSources != 1 {
		t.Fatalf("expected 1 agent source class, got %d", got.AgentSources)
	}
	if got.TotalSources != 2 || !got.MultiSource {
		t.Fatalf("expected multi-source summary, got %#v", got)
	}
}
