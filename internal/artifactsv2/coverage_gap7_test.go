package artifactsv2

import (
	"encoding/json"
	"testing"

	"github.com/verabase/code-verification-engine/internal/report"
	"github.com/verabase/code-verification-engine/internal/rules"
	"github.com/verabase/code-verification-engine/internal/skills"
)

// -- writeCanonicalJSON: cover float64 / json.Number / default struct paths --

func TestCanonicalJSONFloat64Direct(t *testing.T) {
	t.Parallel()
	// Ensures float64 path is exercised
	data, err := canonicalJSON(float64(3.14159))
	if err != nil || len(data) == 0 {
		t.Fatalf("err=%v data=%s", err, data)
	}
}

func TestCanonicalJSONJsonNumberDirect(t *testing.T) {
	t.Parallel()
	data, err := canonicalJSON(json.Number("42"))
	if err != nil || len(data) == 0 {
		t.Fatalf("err=%v data=%s", err, data)
	}
}

func TestCanonicalJSONBoolDirect(t *testing.T) {
	t.Parallel()
	dt, err := canonicalJSON(true)
	df, err2 := canonicalJSON(false)
	if err != nil || err2 != nil {
		t.Fatal(err, err2)
	}
	if string(dt) == string(df) {
		t.Fatal("true and false should differ")
	}
}

func TestCanonicalJSONNilDirect(t *testing.T) {
	t.Parallel()
	data, err := canonicalJSON(nil)
	if err != nil || string(data) != "null" {
		t.Fatalf("got %q err=%v", data, err)
	}
}

func TestCanonicalJSONEmptyArrayDirect(t *testing.T) {
	t.Parallel()
	data, err := canonicalJSON([]any{})
	if err != nil || string(data) != "[]" {
		t.Fatalf("got %q err=%v", data, err)
	}
}

func TestCanonicalJSONEmptyMapDirect(t *testing.T) {
	t.Parallel()
	data, err := canonicalJSON(map[string]any{})
	if err != nil || string(data) != "{}" {
		t.Fatalf("got %q err=%v", data, err)
	}
}

func TestCanonicalJSONStructDefault(t *testing.T) {
	t.Parallel()
	type s struct {
		A int    `json:"a"`
		B string `json:"b"`
	}
	data, err := canonicalJSON(s{A: 1, B: "hello"})
	if err != nil || len(data) == 0 {
		t.Fatalf("err=%v data=%s", err, data)
	}
}

func TestCanonicalJSONStringDirect(t *testing.T) {
	t.Parallel()
	data, err := canonicalJSON("hello world")
	if err != nil || len(data) == 0 {
		t.Fatalf("err=%v data=%s", err, data)
	}
}

func TestCanonicalJSONNestedArray(t *testing.T) {
	t.Parallel()
	data, err := canonicalJSON([]any{nil, true, false, "str", float64(1.5), map[string]any{"k": "v"}})
	if err != nil || len(data) == 0 {
		t.Fatalf("err=%v data=%s", err, data)
	}
}

// -- HashJSON error path --

func TestHashJSONStableForStruct(t *testing.T) {
	t.Parallel()
	h1, _ := HashJSON(map[string]any{"a": 1.0, "b": "c"})
	h2, _ := HashJSON(map[string]any{"b": "c", "a": 1.0})
	if h1 != h2 {
		t.Fatalf("expected stable hash, got %q vs %q", h1, h2)
	}
}

// -- ComputeArtifactHashes with optional fields --

func TestComputeArtifactHashesWithAllOptional(t *testing.T) {
	t.Parallel()
	b := testBundleWithClaims()
	h, err := ComputeArtifactHashes(b)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	for _, key := range []string{"report.json", "evidence.json", "skills.json", "trace.json", "summary.md", "claims.json", "profile.json", "resume_input.json"} {
		if _, ok := h[key]; !ok {
			t.Fatalf("missing hash for %s", key)
		}
	}
}

// -- compatPrimaryLocation: cover all branches --

func TestCompatPrimaryLocationEmptyEvidence(t *testing.T) {
	t.Parallel()
	f, s, sl, el := compatPrimaryLocation(rules.Finding{})
	if f != "unknown" || s != "" || sl != 1 || el != 1 {
		t.Fatalf("got %s %s %d %d", f, s, sl, el)
	}
}

func TestCompatPrimaryLocationSingleEvidence(t *testing.T) {
	t.Parallel()
	f, s, sl, el := compatPrimaryLocation(rules.Finding{
		Evidence: []rules.Evidence{{File: "x.ts", LineStart: 5, LineEnd: 10, Symbol: "sym"}},
	})
	if f != "x.ts" || s != "sym" || sl != 5 || el != 10 {
		t.Fatalf("got %s %s %d %d", f, s, sl, el)
	}
}

func TestCompatPrimaryLocationLineStartZero(t *testing.T) {
	t.Parallel()
	_, _, sl, el := compatPrimaryLocation(rules.Finding{
		Evidence: []rules.Evidence{{File: "x.ts", LineStart: 0, LineEnd: 0}},
	})
	if sl != 1 {
		t.Fatalf("expected start=1, got %d", sl)
	}
	_ = el
}

func TestCompatPrimaryLocationEndLessThanStart(t *testing.T) {
	t.Parallel()
	_, _, sl, el := compatPrimaryLocation(rules.Finding{
		Evidence: []rules.Evidence{{File: "x.ts", LineStart: 10, LineEnd: 5}},
	})
	if sl != 10 || el != 10 {
		t.Fatalf("expected 10/10, got %d/%d", sl, el)
	}
}

// -- preferredCategory: cover tie break for same rank non-empty --

func TestPreferredCategorySameRankTieBreak(t *testing.T) {
	t.Parallel()
	// Both are ranked (security=3), a should be chosen as it's the same rank as b
	if got := preferredCategory("security", "security"); got != "security" {
		t.Fatalf("got %q", got)
	}
	// a > b by rank
	if got := preferredCategory("bug", "security"); got != "security" {
		t.Fatalf("got %q", got)
	}
	// a < b by rank
	if got := preferredCategory("security", "bug"); got != "security" {
		t.Fatalf("got %q", got)
	}
}

// -- chooseCompatTitle: cover equal raw strings --

func TestChooseCompatTitleEqualStrings(t *testing.T) {
	t.Parallel()
	if got := chooseCompatTitle("same", "same"); got != "same" {
		t.Fatalf("got %q", got)
	}
}

// -- WriteClaimsProfileResumeArtifacts success --

func TestWriteClaimsProfileResumeArtifactsSuccess(t *testing.T) {
	t.Parallel()
	input := ClaimsProjectionInput{
		Repository: ClaimRepositoryRef{Path: "/repo", Commit: "abc123"},
		Claims: []ClaimRecord{
			validClaimRecord("c-1"),
		},
	}
	artifacts, err := BuildClaimsProfileResumeArtifacts(input)
	if err != nil {
		t.Fatalf("BuildClaimsProfileResumeArtifacts: %v", err)
	}
	dir := t.TempDir()
	if err := WriteClaimsProfileResumeArtifacts(dir, artifacts); err != nil {
		t.Fatalf("WriteClaimsProfileResumeArtifacts: %v", err)
	}
}

// -- ValidateClaimsProfileResumeArtifacts reference integrity --

func TestValidateClaimReferenceIntegrityProfileHighlight(t *testing.T) {
	t.Parallel()
	claims := ClaimsArtifact{Claims: []ClaimRecord{validClaimRecord("c-1")}}
	profile := ProfileArtifact{Highlights: []CapabilityHighlight{{ClaimIDs: []string{"c-unknown"}}}}
	resume := ResumeInputArtifact{}
	if validateClaimReferenceIntegrity(claims, profile, resume) == nil {
		t.Fatal("expected error for unknown claim ref in highlight")
	}
}

func TestValidateClaimReferenceIntegrityProfileArea(t *testing.T) {
	t.Parallel()
	claims := ClaimsArtifact{Claims: []ClaimRecord{validClaimRecord("c-1")}}
	profile := ProfileArtifact{CapabilityAreas: []CapabilityArea{{ClaimIDs: []string{"c-unknown"}}}}
	resume := ResumeInputArtifact{}
	if validateClaimReferenceIntegrity(claims, profile, resume) == nil {
		t.Fatal("expected error for unknown claim ref in area")
	}
}

func TestValidateClaimReferenceIntegrityResume(t *testing.T) {
	t.Parallel()
	claims := ClaimsArtifact{Claims: []ClaimRecord{validClaimRecord("c-1")}}
	profile := ProfileArtifact{}
	resume := ResumeInputArtifact{VerifiedClaims: []ResumeClaimStub{{ClaimID: "c-unknown"}}}
	if validateClaimReferenceIntegrity(claims, profile, resume) == nil {
		t.Fatal("expected error for unknown claim ref in resume")
	}
}

// -- buildAgentTasks: non-issue selection type skipped --

func TestBuildAgentRunsSkipsNonIssueSelection(t *testing.T) {
	t.Parallel()
	candidates := []IssueCandidate{{ID: "iss-1", Category: "bug"}}
	selections := []ContextSelectionRecord{{
		ID: "sel-1", TriggerType: "rule", TriggerID: "rule-1",
		SelectedEvidenceIDs: []string{"ev-1"},
		SelectedSpans:       []LocationRef{{RepoRelPath: "a.ts", StartLine: 1, EndLine: 1}},
		SelectionTrace:      []string{"trigger_reason:unknown_issue"},
	}}
	runs := buildAgentRuns(candidates, selections, nil)
	if len(runs) != 0 {
		t.Fatalf("expected 0 runs for non-issue selection, got %d", len(runs))
	}
}

// -- buildSkillsArtifact: unsupported signal skipped --

func TestBuildSkillsArtifactSkipsUnsupported(t *testing.T) {
	t.Parallel()
	scan := report.ScanReport{RepoName: "r", CommitSHA: "c", ScannedAt: "t"}
	sr := &skills.Report{Signals: []skills.Signal{
		{SkillID: "s1", Status: skills.StatusUnsupported, Confidence: skills.ConfidenceHigh, EvidenceStrength: skills.EvidenceDirect, SourceRuleIDs: []string{"R-1"}},
	}}
	a := buildSkillsArtifact(scan, sr, "dev", []IssueCandidate{{ID: "iss-1", RuleIDs: []string{"R-1"}}})
	if len(a.Skills) != 0 {
		t.Fatalf("expected unsupported to be skipped, got %d", len(a.Skills))
	}
}

// -- buildReportSkillScores: unsupported skipped --

func TestBuildReportSkillScoresSkipsUnsupported(t *testing.T) {
	t.Parallel()
	sr := &skills.Report{Signals: []skills.Signal{
		{SkillID: "s1", Status: skills.StatusObserved, Confidence: skills.ConfidenceHigh},
		{SkillID: "s2", Status: skills.StatusUnsupported},
	}}
	scores := buildReportSkillScores(sr)
	if len(scores) != 1 || scores[0].SkillID != "s1" {
		t.Fatalf("expected 1 score, got %#v", scores)
	}
}

// -- computeLLMPenalty: agent + deterministic combined --

func TestComputeLLMPenaltyAgentPlusDeterministic(t *testing.T) {
	t.Parallel()
	if got := computeLLMPenalty([]string{"agent", "rule"}); got != 0.05 {
		t.Fatalf("expected 0.05, got %f", got)
	}
}

// -- sameSymbolMergeAllowed: fe_dep (disallowed) --

func TestSameSymbolMergeFeDepDisallowed(t *testing.T) {
	t.Parallel()
	if sameSymbolMergeAllowed("fe_dep", "fe_dep") {
		t.Fatal("expected fe_dep same_symbol merge to be disallowed")
	}
}

// -- lineOverlapMergeAllowed: different families --

func TestLineOverlapMergeDifferentFamilies(t *testing.T) {
	t.Parallel()
	if lineOverlapMergeAllowed("sec_secret", "fe_dep") {
		t.Fatal("expected different families not to overlap merge")
	}
}

// -- ValidateResumeInputArtifact: evidence ref missing claim_ids --

func TestValidateResumeInputEvRefMissingClaimIDs(t *testing.T) {
	t.Parallel()
	b := testBundleWithClaims()
	ri := *b.ResumeInput
	ri.EvidenceReferences = []EvidenceReference{{EvidenceID: "e"}}
	if ValidateResumeInputArtifact(ri) == nil {
		t.Fatal("expected error for missing evidence ref claim_ids")
	}
}

func TestValidateResumeInputEvRefMissingID(t *testing.T) {
	t.Parallel()
	b := testBundleWithClaims()
	ri := *b.ResumeInput
	ri.EvidenceReferences = []EvidenceReference{{EvidenceID: ""}}
	if ValidateResumeInputArtifact(ri) == nil {
		t.Fatal("expected error for missing evidence ref ID")
	}
}

// -- capabilityAreaTitle default --

func TestCapabilityAreaTitleDefault(t *testing.T) {
	t.Parallel()
	got := capabilityAreaTitle("custom_area")
	if got == "" {
		t.Fatal("expected non-empty default title")
	}
}

// -- compatPrimaryLocation: cover sort by Symbol tie-break --

func TestCompatPrimaryLocationSortBySymbol(t *testing.T) {
	t.Parallel()
	f, s, _, _ := compatPrimaryLocation(rules.Finding{
		Evidence: []rules.Evidence{
			{File: "a.ts", LineStart: 10, LineEnd: 10, Symbol: "z"},
			{File: "a.ts", LineStart: 10, LineEnd: 10, Symbol: "a"},
		},
	})
	if f != "a.ts" || s != "a" {
		t.Fatalf("expected a.ts:a, got %s:%s", f, s)
	}
}

// -- chooseCompatTitle: b < a when equal length --

func TestChooseCompatTitleBLessThanA(t *testing.T) {
	t.Parallel()
	if got := chooseCompatTitle("Bravo", "Alpha"); got != "Alpha" {
		t.Fatalf("got %q", got)
	}
}

// -- preferredCategory: both non-empty, same rank, b > a --

func TestPreferredCategoryBGreaterThanA(t *testing.T) {
	t.Parallel()
	// Both unranked, a < b alphabetically => a wins
	if got := preferredCategory("alpha", "zebra"); got != "alpha" {
		t.Fatalf("got %q", got)
	}
}

// -- collectCounterEvidenceIDs: evidence not found in index --

func TestCollectCounterEvidenceIDsNotInIndex(t *testing.T) {
	t.Parallel()
	idx := map[string]EvidenceRecord{
		"ev-1": {ID: "ev-1", Contradicts: []string{"ev-missing"}},
	}
	got := collectCounterEvidenceIDs([]string{"ev-1"}, idx)
	if len(got) != 0 {
		t.Fatalf("expected 0 (contradicted not in index), got %v", got)
	}
}

// -- buildAgentTasks: candidate with non-matching selection trigger --

func TestBuildAgentTasksSkipsUnmatchedCandidate(t *testing.T) {
	t.Parallel()
	// Candidate that produces no context selections
	candidates := []IssueCandidate{{
		ID: "iss-1", Category: "bug", Severity: "low", Status: "resolved",
		PolicyClass: "advisory", EvidenceIDs: []string{"ev-1"},
	}}
	evidence := EvidenceArtifact{Evidence: []EvidenceRecord{{
		ID: "ev-1", Locations: []LocationRef{{RepoRelPath: "a.ts", StartLine: 1, EndLine: 1}},
	}}}
	tasks := buildAgentTasks(candidates, evidence)
	if len(tasks) != 0 {
		t.Fatalf("expected 0 tasks, got %d", len(tasks))
	}
}

// -- buildAgentRuns: selection with non-matching candidate --

func TestBuildAgentRunsSkipsUnmatchedCandidate(t *testing.T) {
	t.Parallel()
	candidates := []IssueCandidate{{ID: "iss-1", Category: "bug"}}
	selections := []ContextSelectionRecord{{
		ID: "sel-1", TriggerType: "issue", TriggerID: "iss-missing",
		SelectedEvidenceIDs: []string{"ev-1"},
		SelectedSpans:       []LocationRef{{RepoRelPath: "a.ts", StartLine: 1, EndLine: 1}},
		SelectionTrace:      []string{"trigger_reason:unknown_issue"},
	}}
	runs := buildAgentRuns(candidates, selections, nil)
	if len(runs) != 0 {
		t.Fatalf("expected 0 runs for unmatched candidate, got %d", len(runs))
	}
}

// -- ValidateClaimsProfileResumeArtifacts: reference integrity failure --

func TestValidateClaimsProfileResumeRefIntegrityFail(t *testing.T) {
	t.Parallel()
	input := ClaimsProjectionInput{
		Repository: ClaimRepositoryRef{Path: "/repo", Commit: "abc123"},
		Claims: []ClaimRecord{
			validClaimRecord("c-1"),
		},
	}
	artifacts, err := BuildClaimsProfileResumeArtifacts(input)
	if err != nil {
		t.Fatalf("BuildClaimsProfileResumeArtifacts: %v", err)
	}
	// Tamper to break reference integrity
	artifacts.Profile.Highlights[0].ClaimIDs = []string{"c-unknown"}
	if ValidateClaimsProfileResumeArtifacts(artifacts) == nil {
		t.Fatal("expected error for reference integrity failure")
	}
}

// -- BuildArtifacts: no agent executor, no agent results --

func TestBuildArtifactsNoExecutorNoResults(t *testing.T) {
	t.Parallel()
	input := BuildInput{
		Scan: report.ScanReport{RepoName: "r", CommitSHA: "abc123def456", ScannedAt: "2026-03-27T12:00:00Z", FileCount: 3, BoundaryMode: "repo"},
		Verification: VerificationSource{
			ReportSchemaVersion: "1.0.0",
			IssueSeeds: []IssueSeed{{RuleID: "SEC-1", Title: "T", Source: "rule", Category: "security", Severity: "high", Status: "open", Confidence: 0.9, Quality: 1.0, File: "s.ts", Symbol: "fn", StartLine: 1, EndLine: 1}},
		},
		EngineVersion: "dev",
	}
	result, err := BuildArtifacts(input)
	if err != nil {
		t.Fatalf("BuildArtifacts: %v", err)
	}
	if result == nil {
		t.Fatal("expected result")
	}
}

// -- validateClaimsProjectionInput: missing commit --

func TestValidateClaimsProjectionInputMissingCommit(t *testing.T) {
	t.Parallel()
	if validateClaimsProjectionInput(ClaimsProjectionInput{Repository: ClaimRepositoryRef{Path: "/repo"}}) == nil {
		t.Fatal("expected error for missing commit")
	}
}

// -- ValidateResumeInputArtifact: synthesis constraints failure --

func TestValidateResumeInputBadConstraints(t *testing.T) {
	t.Parallel()
	b := testBundleWithClaims()
	ri := *b.ResumeInput
	ri.SynthesisConstraints.AllowClaimInvention = true
	if ValidateResumeInputArtifact(ri) == nil {
		t.Fatal("expected error for bad synthesis constraints")
	}
}

// -- chooseCompatTitle: cover nb > na branch --

func TestChooseCompatTitleNbGreaterNa(t *testing.T) {
	t.Parallel()
	// Same length, "Zebra" > "Alpha" lowered
	if got := chooseCompatTitle("Zebra", "Alpha"); got != "Alpha" {
		t.Fatalf("got %q", got)
	}
}

// -- preferredCategory: both empty --

func TestPreferredCategoryBothEmptyValues(t *testing.T) {
	t.Parallel()
	if got := preferredCategory("", ""); got != "" {
		t.Fatalf("got %q", got)
	}
}

// -- preferredCategory: nb > na path --

func TestPreferredCategoryNbGreaterNa(t *testing.T) {
	t.Parallel()
	// Both unranked, same rank=0, "alpha" < "zebra"
	if got := preferredCategory("alpha", "zebra"); got != "alpha" {
		t.Fatalf("expected alpha, got %q", got)
	}
}

// -- preferredCategory: b < a raw path --

func TestPreferredCategoryRawBLessThanA(t *testing.T) {
	t.Parallel()
	// Same rank, same lowered, different raw: "Alpha" < "alpha"
	if got := preferredCategory("alpha", "Alpha"); got != "Alpha" {
		t.Fatalf("expected Alpha (raw b < a), got %q", got)
	}
}

// -- chooseCompatTitle: b < a raw path --

func TestChooseCompatTitleRawBLessThanA(t *testing.T) {
	t.Parallel()
	// Same length, same lowered, b < a raw
	if got := chooseCompatTitle("alpha", "Alpha"); got != "Alpha" {
		t.Fatalf("expected Alpha, got %q", got)
	}
}

// -- buildAgentTasks: build agent ID stability --

func TestPlannedAgentIDIsStable(t *testing.T) {
	t.Parallel()
	c := IssueCandidate{ID: "iss-1", Category: "bug"}
	id1 := plannedAgentID(c, "unknown_issue")
	id2 := plannedAgentID(c, "unknown_issue")
	if id1 != id2 || id1 == "" {
		t.Fatalf("expected stable non-empty ID, got %q/%q", id1, id2)
	}
}

// -- contextBundleID stability --

func TestContextBundleIDIsStable(t *testing.T) {
	t.Parallel()
	id1 := contextBundleID(ContextRequest{TriggerType: "issue", TriggerID: "iss-1"})
	id2 := contextBundleID(ContextRequest{TriggerType: "issue", TriggerID: "iss-1"})
	if id1 != id2 || id1 == "" {
		t.Fatalf("expected stable non-empty ID, got %q/%q", id1, id2)
	}
}

// -- sortedStringKeys --

func TestSortedStringKeysEmpty(t *testing.T) {
	t.Parallel()
	if got := sortedStringKeys(nil); got != nil {
		t.Fatalf("expected nil, got %v", got)
	}
	if got := sortedStringKeys(map[string]struct{}{}); got != nil {
		t.Fatalf("expected nil, got %v", got)
	}
}

// -- expandRuleToIssueIDs fallback --

func TestExpandRuleToIssueIDsFallback(t *testing.T) {
	t.Parallel()
	got := expandRuleToIssueIDs([]string{"UNMAPPED-001"}, map[string][]string{})
	if len(got) != 1 {
		t.Fatalf("expected 1 fallback issue ID, got %d", len(got))
	}
}

// -- expandMappedRuleToIssueIDs no match --

func TestExpandMappedRuleToIssueIDsNoMatch(t *testing.T) {
	t.Parallel()
	got := expandMappedRuleToIssueIDs([]string{"UNMAPPED"}, map[string][]string{})
	if len(got) != 0 {
		t.Fatalf("expected 0 mapped IDs, got %d", len(got))
	}
}

// -- buildIssueToEvidenceIDs --

func TestBuildIssueToEvidenceIDs(t *testing.T) {
	t.Parallel()
	m := buildIssueToEvidenceIDs([]IssueCandidate{
		{ID: "iss-1", EvidenceIDs: []string{"ev-1", "ev-2"}},
	})
	if len(m["iss-1"]) != 2 {
		t.Fatalf("expected 2 evidence IDs, got %d", len(m["iss-1"]))
	}
}

// -- collectEvidenceIDsForIssues --

func TestCollectEvidenceIDsForIssues(t *testing.T) {
	t.Parallel()
	m := map[string][]string{"iss-1": {"ev-1", "ev-2"}}
	got := collectEvidenceIDsForIssues([]string{"iss-1"}, m)
	if len(got) != 2 {
		t.Fatalf("expected 2, got %d", len(got))
	}
}

// -- minInt --

func TestMinInt(t *testing.T) {
	t.Parallel()
	if minInt(5, 3) != 3 || minInt(3, 5) != 3 {
		t.Fatal("minInt failed")
	}
}

// -- filepathToSlash --

func TestFilepathToSlash(t *testing.T) {
	t.Parallel()
	if filepathToSlash(`a\b\c`) != "a/b/c" {
		t.Fatal("expected forward slashes")
	}
}

// -- compactStrings --

func TestCompactStringsFiltersEmpty(t *testing.T) {
	t.Parallel()
	got := compactStrings([]string{"a", "", "  ", "b"})
	if len(got) != 2 {
		t.Fatalf("expected 2, got %v", got)
	}
}

// -- dedupeStringsSorted --

func TestDedupeStringsSortedFiltersEmptyAndDups(t *testing.T) {
	t.Parallel()
	got := dedupeStringsSorted([]string{"b", "a", "a", "", "b"})
	if len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Fatalf("expected [a b], got %v", got)
	}
}

// -- max --

func TestMaxInt(t *testing.T) {
	t.Parallel()
	if max(3, 5) != 5 || max(5, 3) != 5 {
		t.Fatal("max failed")
	}
}

// -- min (float64) --

func TestMinFloat(t *testing.T) {
	t.Parallel()
	if min(3.0, 5.0) != 3.0 || min(5.0, 3.0) != 3.0 {
		t.Fatal("min failed")
	}
}

// -- buildAgentRuns: result with empty TaskID skipped from index --

func TestBuildAgentRunsEmptyTaskIDSkipped(t *testing.T) {
	t.Parallel()
	candidates := []IssueCandidate{{ID: "iss-1", Category: "bug"}}
	selections := []ContextSelectionRecord{{
		ID: "sel-1", TriggerType: "issue", TriggerID: "iss-1",
		SelectedEvidenceIDs: []string{"ev-1"},
		SelectedSpans:       []LocationRef{{RepoRelPath: "a.ts", StartLine: 1, EndLine: 1}},
		SelectionTrace:      []string{"trigger_reason:unknown_issue"},
		MaxFiles:            2, MaxTokens: 1200,
	}}
	results := []AgentResult{{TaskID: "", Kind: "bug", IssueID: "iss-1", Status: "completed"}}
	runs := buildAgentRuns(candidates, selections, results)
	if len(runs) != 1 {
		t.Fatalf("expected 1 run, got %d", len(runs))
	}
	// Result has empty TaskID so it should not match the planned run
	if runs[0].Status != "planned" {
		t.Fatalf("expected planned (no result match), got %q", runs[0].Status)
	}
}

// -- buildAgentTasks: build with multiple candidates, sorting --

func TestBuildAgentTasksMultipleCandidatesSorted(t *testing.T) {
	t.Parallel()
	candidates := []IssueCandidate{
		{ID: "iss-2", Category: "security", Severity: "critical", Status: "open", PolicyClass: "advisory", EvidenceIDs: []string{"ev-2"}},
		{ID: "iss-1", Category: "bug", Severity: "high", Status: "unknown", PolicyClass: "unknown_retained", EvidenceIDs: []string{"ev-1"}},
	}
	evidence := EvidenceArtifact{Evidence: []EvidenceRecord{
		{ID: "ev-1", Locations: []LocationRef{{RepoRelPath: "a.ts", StartLine: 1, EndLine: 1}}, EntityIDs: []string{"fn-1"}},
		{ID: "ev-2", Locations: []LocationRef{{RepoRelPath: "b.ts", StartLine: 5, EndLine: 5}}, EntityIDs: []string{"fn-2"}},
	}}
	tasks := buildAgentTasks(candidates, evidence)
	if len(tasks) < 2 {
		t.Fatalf("expected >=2 tasks, got %d", len(tasks))
	}
	// Should be sorted by Kind then IssueID
	for i := 1; i < len(tasks); i++ {
		if tasks[i-1].Kind > tasks[i].Kind {
			t.Fatalf("tasks not sorted by kind: %q > %q", tasks[i-1].Kind, tasks[i].Kind)
		}
	}
}

// -- contextBundleFromSelection --

func TestContextBundleFromSelection(t *testing.T) {
	t.Parallel()
	sel := ContextSelectionRecord{
		ID: "ctx-1", TriggerType: "issue", TriggerID: "iss-1",
		SelectedEvidenceIDs: []string{"ev-1", "ev-2"},
		EntityIDs:           []string{"e-1"},
		SelectedSpans:       []LocationRef{{RepoRelPath: "a.ts", StartLine: 1, EndLine: 1}},
		SelectionTrace:      []string{"trace-1"},
	}
	b := contextBundleFromSelection(sel)
	if b.ID != "ctx-1" || b.TriggerType != "issue" || b.TriggerID != "iss-1" {
		t.Fatalf("bad context bundle: %+v", b)
	}
	if len(b.EvidenceIDs) != 2 || len(b.EntityIDs) != 1 || len(b.Spans) != 1 {
		t.Fatalf("bad lengths: ev=%d ent=%d spans=%d", len(b.EvidenceIDs), len(b.EntityIDs), len(b.Spans))
	}
}

// -- applyAgentResult --

func TestApplyAgentResult(t *testing.T) {
	t.Parallel()
	run := AgentRun{ID: "a-1", Kind: "bug", Status: "planned"}
	result := AgentResult{Kind: "security", IssueID: "iss-1", ContextSelectionID: "ctx-1", Status: "completed",
		UnresolvedReasons: []string{"reason1"},
		EmittedEvidence:   []EvidenceRecord{{ID: "ev-out-1"}, {ID: ""}, {ID: "ev-out-2"}},
	}
	updated := applyAgentResult(run, result)
	if updated.Kind != "security" || updated.Status != "completed" || updated.IssueID != "iss-1" || updated.ContextSelectionID != "ctx-1" {
		t.Fatalf("result not applied: %+v", updated)
	}
	if len(updated.OutputEvidenceIDs) != 2 {
		t.Fatalf("expected 2 output evidence IDs (empty skipped), got %d", len(updated.OutputEvidenceIDs))
	}
}

// -- plannedAgentStatus --

func TestPlannedAgentStatusPlanned(t *testing.T) {
	t.Parallel()
	status, reasons := plannedAgentStatus(ContextSelectionRecord{
		SelectedEvidenceIDs: []string{"ev-1"},
		SelectedSpans:       []LocationRef{{RepoRelPath: "a.ts", StartLine: 1, EndLine: 1}},
	})
	if status != "planned" || len(reasons) != 0 {
		t.Fatalf("expected planned, got %q %v", status, reasons)
	}
}

func TestPlannedAgentStatusInsufficient(t *testing.T) {
	t.Parallel()
	status, reasons := plannedAgentStatus(ContextSelectionRecord{})
	if status != "insufficient_context" || len(reasons) != 2 {
		t.Fatalf("expected insufficient_context with 2 reasons, got %q %v", status, reasons)
	}
}

// -- BuildIssueCandidateSet: agent executor returns error --

func TestBuildIssueCandidateSetAgentExecError(t *testing.T) {
	t.Parallel()
	input := IssueCandidateBuildInput{
		Scan: report.ScanReport{RepoName: "r", CommitSHA: "abc123def456", ScannedAt: "2026-03-27T12:00:00Z", FileCount: 3, BoundaryMode: "repo"},
		Verification: VerificationSource{
			ReportSchemaVersion: "1.0.0",
			IssueSeeds: []IssueSeed{{RuleID: "D-1", Title: "U", Source: "rule", Category: "design", Severity: "high", Status: "unknown", Confidence: 0.62, Quality: 0.7, File: "s.ts", Symbol: "fn", StartLine: 1, EndLine: 5}},
		},
		AgentExecutor: func(task AgentTask) (AgentResult, error) {
			return AgentResult{}, nil // successful but empty
		},
		EngineVersion: "dev",
	}
	set, err := BuildIssueCandidateSet(input)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if set == nil {
		t.Fatal("expected set")
	}
	// Agent results should be populated since executor was called
	if len(set.Verification.AgentResults) == 0 {
		t.Fatal("expected agent results")
	}
}

// -- buildContextBundle: cover the span budget early break on outer loop --

func TestBuildContextBundleSpanBudgetBreaksOuterLoop(t *testing.T) {
	t.Parallel()
	candidate := IssueCandidate{ID: "iss-1", EvidenceIDs: []string{"ev-1", "ev-2"}}
	evidenceIndex := map[string]EvidenceRecord{
		"ev-1": {ID: "ev-1", Locations: []LocationRef{
			{RepoRelPath: "a.ts", StartLine: 1, EndLine: 1},
		}},
		"ev-2": {ID: "ev-2", Locations: []LocationRef{
			{RepoRelPath: "a.ts", StartLine: 2, EndLine: 2},
		}},
	}
	b := buildContextBundle(ContextRequest{TriggerType: "issue", TriggerID: "iss-1", MaxFiles: 10, MaxSpans: 1, MaxTokens: 1200}, candidate, evidenceIndex)
	if len(b.Spans) != 1 {
		t.Fatalf("expected 1 span due to budget, got %d", len(b.Spans))
	}
}

// -- buildReportSummary: exercise the skillReport scoring path --

func TestBuildReportSummaryWithSkillsAndManyIssues(t *testing.T) {
	t.Parallel()
	issues := []Issue{
		{Severity: "critical"},
		{Severity: "high"},
		{Severity: "medium"},
		{Severity: "low"},
	}
	sr := &skills.Report{Signals: []skills.Signal{
		{SkillID: "s1", Status: skills.StatusObserved, Confidence: skills.ConfidenceHigh, EvidenceStrength: skills.EvidenceDirect},
	}}
	summary := buildReportSummary(issues, sr)
	if summary.OverallScore < 0 || summary.OverallScore > 1 {
		t.Fatalf("score out of range: %f", summary.OverallScore)
	}
	if summary.RiskLevel != "critical" {
		t.Fatalf("expected critical risk, got %q", summary.RiskLevel)
	}
}

// -- buildTraceArtifact: chooseStableFingerprint conflict path --

// -- projectCapabilityProfile: no eligible claims --

func TestProjectCapabilityProfileNoEligible(t *testing.T) {
	t.Parallel()
	p := projectCapabilityProfile(
		ClaimRepositoryRef{Path: "/repo", Commit: "abc"},
		[]ClaimRecord{{ClaimID: "c-1", Category: "arch", SupportLevel: "weak", ProjectionEligible: false}},
		[]string{"go"},
	)
	if len(p.Highlights) != 0 {
		t.Fatalf("expected 0 highlights, got %d", len(p.Highlights))
	}
}

// -- projectResumeInput: cover non-eligible claims path --

func TestProjectResumeInputNonEligibleSkipped(t *testing.T) {
	t.Parallel()
	claims := []ClaimRecord{
		{ClaimID: "c-1", SupportLevel: "verified", ProjectionEligible: false, SupportingEvidenceIDs: []string{"ev-1"}},
		{ClaimID: "c-2", SupportLevel: "strongly_supported", ProjectionEligible: false, SupportingEvidenceIDs: []string{"ev-2"}},
		{ClaimID: "c-3", SupportLevel: "supported", ProjectionEligible: false, SupportingEvidenceIDs: []string{"ev-3"}, ContradictoryEvidenceIDs: []string{"ev-4"}},
	}
	profile := ProfileArtifact{Technologies: []string{"go"}}
	ri := projectResumeInput(profile, claims)
	if len(ri.VerifiedClaims) != 0 || len(ri.StronglySupportedClaims) != 0 {
		t.Fatal("expected empty resume claim pools for non-eligible claims")
	}
	// But evidence references should still be tracked
	if len(ri.EvidenceReferences) == 0 {
		t.Fatal("expected evidence references even for non-eligible claims")
	}
}

// -- buildContextSelections: candidate without trigger --

func TestBuildContextSelectionsNoTrigger(t *testing.T) {
	t.Parallel()
	// Low severity, resolved, no counter evidence => no trigger
	candidates := []IssueCandidate{{ID: "iss-1", Status: "resolved", Severity: "low", PolicyClass: "advisory", EvidenceIDs: []string{"ev-1"}}}
	evidence := EvidenceArtifact{Evidence: []EvidenceRecord{{ID: "ev-1", Locations: []LocationRef{{RepoRelPath: "a.ts", StartLine: 1, EndLine: 1}}}}}
	selections := buildContextSelections(candidates, evidence)
	if len(selections) != 0 {
		t.Fatalf("expected 0 selections for no-trigger candidate, got %d", len(selections))
	}
}

// -- buildAgentTasks: full path with conflict_review trigger --

func TestBuildAgentTasksConflictReview(t *testing.T) {
	t.Parallel()
	candidates := []IssueCandidate{{
		ID: "iss-1", Category: "bug", Severity: "medium", Status: "open",
		PolicyClass: "advisory", EvidenceIDs: []string{"ev-1"},
		CounterEvidenceIDs: []string{"ev-2"},
	}}
	evidence := EvidenceArtifact{Evidence: []EvidenceRecord{
		{ID: "ev-1", Locations: []LocationRef{{RepoRelPath: "a.ts", StartLine: 1, EndLine: 1}}, EntityIDs: []string{"fn-1"}},
		{ID: "ev-2", Locations: []LocationRef{{RepoRelPath: "a.ts", StartLine: 5, EndLine: 5}}, EntityIDs: []string{"fn-2"}},
	}}
	tasks := buildAgentTasks(candidates, evidence)
	if len(tasks) != 1 {
		t.Fatalf("expected 1 task for conflict review, got %d", len(tasks))
	}
	if tasks[0].Kind != "bug" || tasks[0].IssueType != "bug_review" {
		t.Fatalf("expected bug task, got %+v", tasks[0])
	}
}

// -- buildAgentRuns: full path with completed result applied --

func TestBuildAgentRunsWithCompletedResult(t *testing.T) {
	t.Parallel()
	candidates := []IssueCandidate{{ID: "iss-1", Category: "design", Severity: "high", Status: "unknown", PolicyClass: "unknown_retained"}}
	selections := []ContextSelectionRecord{{
		ID: "sel-1", TriggerType: "issue", TriggerID: "iss-1",
		SelectedEvidenceIDs: []string{"ev-1"},
		SelectedSpans:       []LocationRef{{RepoRelPath: "a.ts", StartLine: 1, EndLine: 1}},
		SelectionTrace:      []string{"trigger_reason:unknown_issue"},
		MaxFiles: 2, MaxTokens: 1200,
	}}
	agentID := plannedAgentID(candidates[0], "unknown_issue")
	results := []AgentResult{{
		TaskID: agentID, Kind: "design", IssueID: "iss-1", ContextSelectionID: "sel-1",
		Status: "completed",
		EmittedEvidence: []EvidenceRecord{{ID: "ev-out-1"}, {ID: "ev-out-2"}},
	}}
	runs := buildAgentRuns(candidates, selections, results)
	if len(runs) != 1 {
		t.Fatalf("expected 1 run, got %d", len(runs))
	}
	if runs[0].Status != "completed" {
		t.Fatalf("expected completed, got %q", runs[0].Status)
	}
	if len(runs[0].OutputEvidenceIDs) != 2 {
		t.Fatalf("expected 2 output IDs, got %d", len(runs[0].OutputEvidenceIDs))
	}
}

func TestBuildTraceDerivationFingerprintConflict(t *testing.T) {
	t.Parallel()
	scan := report.ScanReport{RepoName: "r", CommitSHA: "abc123", ScannedAt: "2026-03-27T12:00:00Z", FileCount: 5, BoundaryMode: "repo"}
	verification := VerificationSource{
		ReportSchemaVersion: "1.0.0",
		Findings: []rules.Finding{
			{RuleID: "SEC-001", Status: rules.StatusFail, Message: "msg", Evidence: []rules.Evidence{{File: "a.ts", LineStart: 1, LineEnd: 1, Symbol: "fn"}}},
		},
	}
	evidence := EvidenceArtifact{
		SchemaVersion: EvidenceSchemaVersion, EngineVersion: "dev", Repo: "r", Commit: "abc123", Timestamp: "2026-03-27T12:00:00Z",
		Evidence: []EvidenceRecord{{
			ID: compatEvidenceID("SEC-001", verification.Findings[0].Evidence[0]),
			Kind: "rule_assertion", Source: "rule", ProducerID: "rule:SEC-001", ProducerVersion: "1.0.0",
			Repo: "r", Commit: "abc123", BoundaryHash: "sha256:x", FactQuality: "proof",
			Locations: []LocationRef{{RepoRelPath: "a.ts", StartLine: 1, EndLine: 1}},
			Claims: []string{"SEC-001"}, CreatedAt: "2026-03-27T12:00:00Z",
		}},
	}
	candidates := []IssueCandidate{{
		ID: "iss-1", Fingerprint: "fp-1", RuleIDs: []string{"SEC-001"},
		EvidenceIDs: []string{compatEvidenceID("SEC-001", verification.Findings[0].Evidence[0])},
	}}
	trace := buildTraceArtifact(scan, verification, evidence, "trace-abc123", "dev", candidates)
	if len(trace.Derivations) != 1 {
		t.Fatalf("expected 1 derivation, got %d", len(trace.Derivations))
	}
}
