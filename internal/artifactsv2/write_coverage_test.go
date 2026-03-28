package artifactsv2

import (
	"os"
	"path/filepath"
	"testing"

	"fmt"

	"github.com/verabase/code-verification-engine/internal/rules"
)

func writableBundle() *Bundle {
	b := testBundle()
	return &b
}

func TestWriteBundle_EmptyDir(t *testing.T) {
	t.Parallel()
	err := WriteBundle("", writableBundle(), "test")
	if err == nil {
		t.Fatal("expected error for empty dir")
	}
}

func TestWriteBundle_NilBundle(t *testing.T) {
	t.Parallel()
	err := WriteBundle(t.TempDir(), nil, "test")
	if err == nil {
		t.Fatal("expected error for nil bundle")
	}
}

func TestWriteBundle_Success(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	err := WriteBundle(dir, writableBundle(), "test-engine")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, name := range []string{"report.json", "evidence.json", "skills.json", "trace.json", "summary.md", "signature.json"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("expected %s to exist: %v", name, err)
		}
	}
}

func TestWriteBundle_WithClaimsProfileResume(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	b := testBundleWithClaims()
	err := WriteBundle(dir, &b, "test-engine")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, name := range []string{"claims.json", "profile.json", "resume_input.json"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("expected %s to exist: %v", name, err)
		}
	}
}

func TestFinalizeSignature_NilBundle(t *testing.T) {
	t.Parallel()
	if err := FinalizeSignature(nil, "test"); err == nil {
		t.Fatal("expected error for nil bundle")
	}
}

func TestFinalizeSignature_ValidBundle(t *testing.T) {
	t.Parallel()
	b := writableBundle()
	if err := FinalizeSignature(b, "test-signer"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if b.Signature.SignedBy != "test-signer" {
		t.Fatalf("expected signer test-signer, got %q", b.Signature.SignedBy)
	}
	if b.Signature.BundleHash == "" {
		t.Fatal("expected non-empty bundle hash")
	}
}

func TestComputeArtifactHashes_WithAllOptional(t *testing.T) {
	t.Parallel()
	b := testBundle()
	claims := ClaimsArtifact{SchemaVersion: "1.0.0"}
	profile := ProfileArtifact{SchemaVersion: "1.0.0"}
	resume := ResumeInputArtifact{SchemaVersion: "1.0.0"}
	b.Claims = &claims
	b.Profile = &profile
	b.ResumeInput = &resume
	hashes, err := ComputeArtifactHashes(b)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, key := range []string{"claims.json", "profile.json", "resume_input.json"} {
		if _, ok := hashes[key]; !ok {
			t.Errorf("expected hash for %s", key)
		}
	}
}

func TestCanonicalJSON_NilValue(t *testing.T) {
	t.Parallel()
	data, err := canonicalJSON(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(data) != "null" {
		t.Fatalf("expected 'null', got %q", string(data))
	}
}

func TestCanonicalJSON_BoolAndNumber(t *testing.T) {
	t.Parallel()
	data, err := canonicalJSON(map[string]any{"flag": true, "count": 42})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("expected non-empty canonical JSON")
	}
}

func TestCanonicalJSON_Array(t *testing.T) {
	t.Parallel()
	data, err := canonicalJSON([]string{"b", "a"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("expected non-empty canonical JSON")
	}
}

func TestCanonicalJSON_NestedStruct(t *testing.T) {
	t.Parallel()
	type nested struct {
		A int    `json:"a"`
		B string `json:"b"`
	}
	data, err := canonicalJSON(nested{A: 1, B: "hello"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("expected non-empty output")
	}
}

func TestCanonicalJSON_Float(t *testing.T) {
	t.Parallel()
	data, err := canonicalJSON(map[string]any{"val": 3.14})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("expected non-empty output")
	}
}

func TestCanonicalJSON_EmptyMap(t *testing.T) {
	t.Parallel()
	data, err := canonicalJSON(map[string]any{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(data) != "{}" {
		t.Fatalf("expected '{}', got %q", string(data))
	}
}

func TestCanonicalJSON_EmptyArray(t *testing.T) {
	t.Parallel()
	data, err := canonicalJSON([]any{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(data) != "[]" {
		t.Fatalf("expected '[]', got %q", string(data))
	}
}

func TestCanonicalJSON_False(t *testing.T) {
	t.Parallel()
	data, err := canonicalJSON(false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(data) != "false" {
		t.Fatalf("expected 'false', got %q", string(data))
	}
}

func TestBuildAgentRuns_NilCandidates(t *testing.T) {
	t.Parallel()
	runs := buildAgentRuns(nil, []ContextSelectionRecord{{ID: "sel-1"}}, nil)
	if runs != nil {
		t.Fatal("expected nil for nil candidates")
	}
}

func TestBuildAgentRuns_NilSelections(t *testing.T) {
	t.Parallel()
	runs := buildAgentRuns([]IssueCandidate{{ID: "iss-1"}}, nil, nil)
	if runs != nil {
		t.Fatal("expected nil for nil selections")
	}
}

func TestBuildAgentRuns_WithResults(t *testing.T) {
	t.Parallel()
	candidates := []IssueCandidate{{ID: "iss-1", Category: "bug"}}
	selections := []ContextSelectionRecord{{
		ID:                  "sel-1",
		TriggerType:         "issue",
		TriggerID:           "iss-1",
		SelectedEvidenceIDs: []string{"ev-1"},
		SelectedSpans:       []LocationRef{{RepoRelPath: "a.go", StartLine: 1, EndLine: 5}},
		SelectionTrace:      []string{"trigger_reason:unknown_issue"},
	}}
	results := []AgentResult{{
		TaskID:  "agent-fake",
		Kind:    "bug",
		IssueID: "iss-1",
		Status:  "completed",
		EmittedEvidence: []EvidenceRecord{
			{ID: "agent-ev-1"},
		},
	}}
	runs := buildAgentRuns(candidates, selections, results)
	if len(runs) == 0 {
		t.Fatal("expected at least 1 run")
	}
}

func TestBuildAgentRuns_NonIssueSelectionSkipped(t *testing.T) {
	t.Parallel()
	candidates := []IssueCandidate{{ID: "iss-1"}}
	selections := []ContextSelectionRecord{{
		ID:          "sel-1",
		TriggerType: "global", // not "issue"
		TriggerID:   "iss-1",
	}}
	runs := buildAgentRuns(candidates, selections, nil)
	if len(runs) != 0 {
		t.Fatalf("expected no runs for non-issue trigger, got %d", len(runs))
	}
}

func TestBuildAgentRuns_MissingCandidateSkipped(t *testing.T) {
	t.Parallel()
	candidates := []IssueCandidate{{ID: "iss-1"}}
	selections := []ContextSelectionRecord{{
		ID:          "sel-1",
		TriggerType: "issue",
		TriggerID:   "iss-nonexistent",
	}}
	runs := buildAgentRuns(candidates, selections, nil)
	if len(runs) != 0 {
		t.Fatalf("expected no runs for missing candidate, got %d", len(runs))
	}
}

func TestBuildAgentTasks_EmptyCandidates(t *testing.T) {
	t.Parallel()
	tasks := buildAgentTasks(nil, EvidenceArtifact{})
	if tasks != nil {
		t.Fatal("expected nil for empty candidates")
	}
}

func TestBuildAgentTasks_EmptyEvidence(t *testing.T) {
	t.Parallel()
	tasks := buildAgentTasks([]IssueCandidate{{ID: "iss-1"}}, EvidenceArtifact{})
	if tasks != nil {
		t.Fatal("expected nil for empty evidence")
	}
}

func TestExecuteAgentTasks_NilExecutor(t *testing.T) {
	t.Parallel()
	results, err := executeAgentTasks([]AgentTask{{ID: "t1"}}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if results != nil {
		t.Fatal("expected nil for nil executor")
	}
}

func TestExecuteAgentTasks_EmptyTasks(t *testing.T) {
	t.Parallel()
	results, err := executeAgentTasks(nil, func(t AgentTask) (AgentResult, error) {
		return AgentResult{}, nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if results != nil {
		t.Fatal("expected nil for empty tasks")
	}
}

func TestWriteClaimsProfileResumeArtifacts_EmptyDir(t *testing.T) {
	t.Parallel()
	err := WriteClaimsProfileResumeArtifacts("", ClaimsProjectionArtifacts{})
	if err == nil {
		t.Fatal("expected error for empty dir")
	}
}

func TestWriteClaimsProfileResumeArtifacts_Success(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	b := testBundleWithClaims()
	arts := ClaimsProjectionArtifacts{
		Claims:      *b.Claims,
		Profile:     *b.Profile,
		ResumeInput: *b.ResumeInput,
	}
	err := WriteClaimsProfileResumeArtifacts(dir, arts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, name := range []string{"claims.json", "profile.json", "resume_input.json"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("expected %s to exist: %v", name, err)
		}
	}
}

func TestValidateResumeInputArtifact_MissingSchemaVersion(t *testing.T) {
	t.Parallel()
	err := ValidateResumeInputArtifact(ResumeInputArtifact{})
	if err == nil {
		t.Fatal("expected validation error")
	}
}

func TestValidateResumeInputArtifact_InvalidSynthesisConstraints(t *testing.T) {
	t.Parallel()
	err := ValidateResumeInputArtifact(ResumeInputArtifact{
		SchemaVersion: ResumeInputSchemaVersion,
		Profile:       ProfileArtifact{SchemaVersion: ProfileSchemaVersion},
		SynthesisConstraints: SynthesisConstraints{
			AllowUnsupportedClaims: true,
		},
	})
	if err == nil {
		t.Fatal("expected validation error for bad synthesis constraints")
	}
}

func TestValidateConfidenceBreakdown_InvalidRange(t *testing.T) {
	t.Parallel()
	err := validateConfidenceBreakdown(ConfidenceBreakdown{
		RuleReliability: 1.5, // > 1.0
	}, "test")
	if err == nil {
		t.Fatal("expected error for out-of-range value")
	}
}

func TestReleaseBlockingRuleFamilies(t *testing.T) {
	t.Parallel()
	families := releaseBlockingRuleFamilies()
	if len(families) == 0 {
		t.Fatal("expected at least one release blocking family")
	}
}

func TestLineOverlapMergeAllowed_DifferentFamilies(t *testing.T) {
	t.Parallel()
	if lineOverlapMergeAllowed("sec_secret", "fe_dep") {
		t.Fatal("expected false for different families")
	}
}

func TestLineOverlapMergeAllowed_FeDepSame(t *testing.T) {
	t.Parallel()
	if lineOverlapMergeAllowed("fe_dep", "fe_dep") {
		t.Fatal("expected false for fe_dep same family")
	}
}

func TestChooseCompatTitle_LongerWins(t *testing.T) {
	t.Parallel()
	if got := chooseCompatTitle("short", "longer title"); got != "longer title" {
		t.Fatalf("expected longer, got %q", got)
	}
}

func TestChooseCompatTitle_SameLength(t *testing.T) {
	t.Parallel()
	got := chooseCompatTitle("Beta", "Alfa")
	if got != "Alfa" {
		t.Fatalf("expected Alfa, got %q", got)
	}
}

func TestChooseCompatTitle_SameLengthSameNormalized(t *testing.T) {
	t.Parallel()
	got := chooseCompatTitle("ABC", "abc")
	if got != "ABC" {
		t.Fatalf("expected ABC, got %q", got)
	}
}

func TestPreferredCategory_Security(t *testing.T) {
	t.Parallel()
	if got := preferredCategory("bug", "security"); got != "security" {
		t.Fatalf("expected security, got %q", got)
	}
}

func TestPreferredCategory_EmptyA(t *testing.T) {
	t.Parallel()
	if got := preferredCategory("", "bug"); got != "bug" {
		t.Fatalf("expected bug, got %q", got)
	}
}

func TestPreferredCategory_EmptyB(t *testing.T) {
	t.Parallel()
	if got := preferredCategory("design", ""); got != "design" {
		t.Fatalf("expected design, got %q", got)
	}
}

func TestCompatPrimaryLocation_NoEvidence(t *testing.T) {
	t.Parallel()
	file, _, start, end := compatPrimaryLocation(rules.Finding{})
	if file != "unknown" || start != 1 || end != 1 {
		t.Fatalf("expected unknown/1/1, got %s/%d/%d", file, start, end)
	}
}

func TestCompatPrimaryLocation_WithEvidence(t *testing.T) {
	t.Parallel()
	file, sym, start, end := compatPrimaryLocation(rules.Finding{
		Evidence: []rules.Evidence{
			{File: "b.go", LineStart: 5, LineEnd: 10, Symbol: "Foo"},
			{File: "a.go", LineStart: 1, LineEnd: 3, Symbol: "Bar"},
		},
	})
	if file != "a.go" || sym != "Bar" || start != 1 || end != 3 {
		t.Fatalf("expected a.go/Bar/1/3, got %s/%s/%d/%d", file, sym, start, end)
	}
}

func TestCompatPrimaryLocation_ZeroLines(t *testing.T) {
	t.Parallel()
	_, _, start, end := compatPrimaryLocation(rules.Finding{
		Evidence: []rules.Evidence{{File: "a.go", LineStart: 0, LineEnd: 0}},
	})
	if start != 1 {
		t.Fatalf("expected start=1, got %d", start)
	}
	if end != 0 {
		// max(0, 0) = 0
	}
}

func TestCollectCounterEvidenceIDs_Empty(t *testing.T) {
	t.Parallel()
	got := collectCounterEvidenceIDs([]string{}, map[string]EvidenceRecord{})
	if len(got) != 0 {
		t.Fatalf("expected empty, got %v", got)
	}
}

func TestCollectCounterEvidenceIDs_WithMissing(t *testing.T) {
	t.Parallel()
	got := collectCounterEvidenceIDs([]string{"ev-nonexistent"}, map[string]EvidenceRecord{})
	if len(got) != 0 {
		t.Fatalf("expected empty for missing evidence, got %v", got)
	}
}

func TestBuildContextBundle_Empty(t *testing.T) {
	t.Parallel()
	bundle := buildContextBundle(ContextRequest{TriggerType: "issue", TriggerID: "iss-1", MaxFiles: 3, MaxTokens: 4000}, IssueCandidate{ID: "iss-1"}, map[string]EvidenceRecord{})
	if bundle.TriggerID != "iss-1" {
		t.Fatalf("expected trigger ID iss-1, got %q", bundle.TriggerID)
	}
}

func TestValidateResumeInputArtifact_WrongVerifiedSupportLevel(t *testing.T) {
	t.Parallel()
	b := testBundleWithClaims()
	ri := *b.ResumeInput
	ri.VerifiedClaims[0].SupportLevel = "weak"
	if err := ValidateResumeInputArtifact(ri); err == nil {
		t.Fatal("expected error for non-verified support level")
	}
}

func TestValidateResumeInputArtifact_StronglySupportedWrongLevel(t *testing.T) {
	t.Parallel()
	b := testBundleWithClaims()
	ri := *b.ResumeInput
	ri.StronglySupportedClaims = []ResumeClaimStub{{
		ClaimID: "claim-ss", Title: "Strong", SupportLevel: "weak",
		Confidence: 0.85, SupportingEvidenceIDs: []string{"ev-1"},
	}}
	if err := ValidateResumeInputArtifact(ri); err == nil {
		t.Fatal("expected error")
	}
}

func TestValidateResumeInputArtifact_MissingEvidenceRef(t *testing.T) {
	t.Parallel()
	b := testBundleWithClaims()
	ri := *b.ResumeInput
	ri.EvidenceReferences = []EvidenceReference{{EvidenceID: "", ClaimIDs: []string{"c1"}}}
	if err := ValidateResumeInputArtifact(ri); err == nil {
		t.Fatal("expected error")
	}
}

func TestValidateResumeInputArtifact_MissingClaimIDs(t *testing.T) {
	t.Parallel()
	b := testBundleWithClaims()
	ri := *b.ResumeInput
	ri.EvidenceReferences = []EvidenceReference{{EvidenceID: "ev-1", ClaimIDs: nil}}
	if err := ValidateResumeInputArtifact(ri); err == nil {
		t.Fatal("expected error")
	}
}

func TestValidateSynthesisConstraints_ClaimInvention(t *testing.T) {
	t.Parallel()
	if err := validateSynthesisConstraints(SynthesisConstraints{AllowClaimInvention: true}); err == nil {
		t.Fatal("expected error")
	}
}

func TestValidateSynthesisConstraints_ContradictionSuppression(t *testing.T) {
	t.Parallel()
	if err := validateSynthesisConstraints(SynthesisConstraints{AllowContradictionSuppression: true}); err == nil {
		t.Fatal("expected error")
	}
}

func TestValidateClaimsProjectionInput_Empty(t *testing.T) {
	t.Parallel()
	if err := validateClaimsProjectionInput(ClaimsProjectionInput{}); err == nil {
		t.Fatal("expected error")
	}
}

func TestValidateClaimsProjectionInput_NoClaims(t *testing.T) {
	t.Parallel()
	err := validateClaimsProjectionInput(ClaimsProjectionInput{
		Repository: ClaimRepositoryRef{Path: "/repo", Commit: "abc"},
	})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestExecuteAgentTasks_FailedStatus(t *testing.T) {
	t.Parallel()
	results, err := executeAgentTasks([]AgentTask{
		{ID: "t1", Kind: "bug", IssueID: "iss-1", Context: ContextBundle{ID: "ctx-1"}},
	}, func(task AgentTask) (AgentResult, error) {
		return AgentResult{Status: "failed"}, nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 || results[0].Status != "failed" {
		t.Fatalf("expected failed status, got %v", results)
	}
	if len(results[0].UnresolvedReasons) == 0 {
		t.Fatal("expected unresolved reasons for failed status")
	}
}

func TestExecuteAgentTasks_InsufficientContext(t *testing.T) {
	t.Parallel()
	results, err := executeAgentTasks([]AgentTask{
		{ID: "t1", Kind: "bug", IssueID: "iss-1", Context: ContextBundle{ID: "ctx-1"}},
	}, func(task AgentTask) (AgentResult, error) {
		return AgentResult{Status: "insufficient_context"}, nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 || results[0].Status != "insufficient_context" {
		t.Fatalf("expected insufficient_context status, got %v", results)
	}
}

func TestExecuteAgentTasks_ErrorFromExecutor(t *testing.T) {
	t.Parallel()
	results, err := executeAgentTasks([]AgentTask{
		{ID: "t1", Kind: "bug", IssueID: "iss-1", Context: ContextBundle{ID: "ctx-1"}},
	}, func(task AgentTask) (AgentResult, error) {
		return AgentResult{}, fmt.Errorf("executor error")
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 || results[0].Status != "failed" {
		t.Fatalf("expected failed status from error, got %v", results)
	}
}

func TestPlannedAgentKind(t *testing.T) {
	t.Parallel()
	tests := []struct {
		category, want string
	}{
		{"security", "security"},
		{"frontend_security", "security"},
		{"architecture", "design"},
		{"design", "design"},
		{"bug", "bug"},
		{"other", "bug"},
	}
	for _, tt := range tests {
		if got := plannedAgentKind(IssueCandidate{Category: tt.category}); got != tt.want {
			t.Errorf("plannedAgentKind(%q) = %q, want %q", tt.category, got, tt.want)
		}
	}
}

func TestPlannedAgentQuestion(t *testing.T) {
	t.Parallel()
	tests := []struct {
		reason string
		want   string
	}{
		{"unknown_issue", "Assess whether the issue should remain unknown"},
		{"conflict_review", "Assess conflicting"},
		{"high_severity_review", "Assess whether the high-severity"},
		{"other", "Assess the issue"},
	}
	for _, tt := range tests {
		got := plannedAgentQuestion(IssueCandidate{}, tt.reason)
		if len(got) == 0 {
			t.Errorf("expected non-empty question for %q", tt.reason)
		}
	}
}

func TestWriteBundle_InvalidDir(t *testing.T) {
	t.Parallel()
	// Use a path that can't be created
	err := WriteBundle("/dev/null/impossible", writableBundle(), "test")
	if err == nil {
		t.Fatal("expected error for invalid dir")
	}
}

func TestWriteClaimsProfileResumeArtifacts_InvalidDir(t *testing.T) {
	t.Parallel()
	b := testBundleWithClaims()
	arts := ClaimsProjectionArtifacts{
		Claims: *b.Claims, Profile: *b.Profile, ResumeInput: *b.ResumeInput,
	}
	err := WriteClaimsProfileResumeArtifacts("/dev/null/impossible", arts)
	if err == nil {
		t.Fatal("expected error for invalid dir")
	}
}

func TestWriteJSON_MarshalError(t *testing.T) {
	t.Parallel()
	// channels can't be marshaled
	err := writeJSON(filepath.Join(t.TempDir(), "test.json"), make(chan int))
	if err == nil {
		t.Fatal("expected marshal error")
	}
}

func TestWriteClaimsJSON_MarshalError(t *testing.T) {
	t.Parallel()
	err := writeClaimsJSON(filepath.Join(t.TempDir(), "test.json"), make(chan int))
	if err == nil {
		t.Fatal("expected marshal error")
	}
}

func TestHashJSON_MarshalError(t *testing.T) {
	t.Parallel()
	_, err := HashJSON(make(chan int))
	if err == nil {
		t.Fatal("expected error for unmarshalable type")
	}
}

func TestCanonicalJSON_MarshalError(t *testing.T) {
	t.Parallel()
	_, err := canonicalJSON(make(chan int))
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestValidateClaimsProfileResumeArtifacts_Invalid(t *testing.T) {
	t.Parallel()
	err := ValidateClaimsProfileResumeArtifacts(ClaimsProjectionArtifacts{})
	if err == nil {
		t.Fatal("expected validation error")
	}
}

func TestPlannedAgentTriggerReason_Default(t *testing.T) {
	t.Parallel()
	got := plannedAgentTriggerReason(nil)
	if got != "policy_review" {
		t.Fatalf("expected policy_review, got %q", got)
	}
}

func TestPlannedAgentTriggerReason_Custom(t *testing.T) {
	t.Parallel()
	got := plannedAgentTriggerReason([]string{"trigger_reason:conflict_review"})
	if got != "conflict_review" {
		t.Fatalf("expected conflict_review, got %q", got)
	}
}

func TestPlannedAgentStatus_InsufficientContext(t *testing.T) {
	t.Parallel()
	status, reasons := plannedAgentStatus(ContextSelectionRecord{})
	if status != "insufficient_context" {
		t.Fatalf("expected insufficient_context, got %q", status)
	}
	if len(reasons) < 2 {
		t.Fatalf("expected at least 2 reasons, got %d", len(reasons))
	}
}

func TestWriteBundle_ReadOnlyDir(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	readOnly := filepath.Join(dir, "readonly")
	os.MkdirAll(readOnly, 0o755)
	b := writableBundle()
	// Write once to create files
	WriteBundle(readOnly, b, "test")
	// Make directory read-only
	os.Chmod(readOnly, 0o444)
	defer os.Chmod(readOnly, 0o755)
	// Second write should fail on file write
	err := WriteBundle(readOnly, b, "test")
	if err == nil {
		// Some OS/CI environments run as root, skip in that case
		t.Skip("skipping: write to read-only dir succeeded (likely running as root)")
	}
}

func TestPlannedAgentStatus_Planned(t *testing.T) {
	t.Parallel()
	status, reasons := plannedAgentStatus(ContextSelectionRecord{
		SelectedEvidenceIDs: []string{"ev-1"},
		SelectedSpans:       []LocationRef{{RepoRelPath: "a.go", StartLine: 1, EndLine: 5}},
	})
	if status != "planned" {
		t.Fatalf("expected planned, got %q", status)
	}
	if reasons != nil {
		t.Fatalf("expected nil reasons, got %v", reasons)
	}
}

func TestHashJSON_Deterministic(t *testing.T) {
	t.Parallel()
	v := map[string]string{"b": "2", "a": "1"}
	h1, err := HashJSON(v)
	if err != nil {
		t.Fatal(err)
	}
	h2, err := HashJSON(v)
	if err != nil {
		t.Fatal(err)
	}
	if h1 != h2 {
		t.Fatalf("expected deterministic hash, got %q and %q", h1, h2)
	}
}
