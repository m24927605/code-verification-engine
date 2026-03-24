package autobench

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/verabase/code-verification-engine/internal/rules"
)

// ---------- matchesExpectation ----------

func TestMatchesExpectation_ExactStatusMatch(t *testing.T) {
	exp := RuleExpectation{ExpectedStatus: "pass"}
	finding := rules.Finding{Status: rules.StatusPass}
	if !matchesExpectation(exp, finding) {
		t.Fatal("expected match for exact status")
	}
}

func TestMatchesExpectation_ExactStatusMismatch(t *testing.T) {
	exp := RuleExpectation{ExpectedStatus: "pass"}
	finding := rules.Finding{Status: rules.StatusFail}
	if matchesExpectation(exp, finding) {
		t.Fatal("expected mismatch for different status")
	}
}

func TestMatchesExpectation_AllowedStatusesMatch(t *testing.T) {
	exp := RuleExpectation{AllowedStatuses: []string{"pass", "unknown"}}
	finding := rules.Finding{Status: rules.StatusUnknown}
	if !matchesExpectation(exp, finding) {
		t.Fatal("expected match within allowed statuses")
	}
}

func TestMatchesExpectation_AllowedStatusesMismatch(t *testing.T) {
	exp := RuleExpectation{AllowedStatuses: []string{"pass"}}
	finding := rules.Finding{Status: rules.StatusFail}
	if matchesExpectation(exp, finding) {
		t.Fatal("expected mismatch outside allowed statuses")
	}
}

func TestMatchesExpectation_TrustClassMatch(t *testing.T) {
	exp := RuleExpectation{ExpectedTrustClass: "machine_trusted"}
	finding := rules.Finding{Status: rules.StatusPass, TrustClass: rules.TrustMachineTrusted}
	if !matchesExpectation(exp, finding) {
		t.Fatal("expected match for trust class")
	}
}

func TestMatchesExpectation_TrustClassMismatch(t *testing.T) {
	exp := RuleExpectation{ExpectedTrustClass: "machine_trusted"}
	finding := rules.Finding{Status: rules.StatusPass, TrustClass: rules.TrustAdvisory}
	if matchesExpectation(exp, finding) {
		t.Fatal("expected mismatch for trust class")
	}
}

func TestMatchesExpectation_InsufficientEvidence(t *testing.T) {
	exp := RuleExpectation{MinimumEvidenceCount: 3}
	finding := rules.Finding{Status: rules.StatusPass, Evidence: make([]rules.Evidence, 2)}
	if matchesExpectation(exp, finding) {
		t.Fatal("expected mismatch for insufficient evidence")
	}
}

func TestMatchesExpectation_SufficientEvidence(t *testing.T) {
	exp := RuleExpectation{MinimumEvidenceCount: 2}
	finding := rules.Finding{Status: rules.StatusPass, Evidence: make([]rules.Evidence, 3)}
	if !matchesExpectation(exp, finding) {
		t.Fatal("expected match with sufficient evidence")
	}
}

// ---------- expectedStatusLabel ----------

func TestExpectedStatusLabel_WithExpectedStatus(t *testing.T) {
	exp := RuleExpectation{ExpectedStatus: "pass"}
	if got := expectedStatusLabel(exp); got != "pass" {
		t.Fatalf("got %q, want pass", got)
	}
}

func TestExpectedStatusLabel_WithAllowedStatuses(t *testing.T) {
	exp := RuleExpectation{AllowedStatuses: []string{"pass", "unknown"}}
	got := expectedStatusLabel(exp)
	if got != "pass|unknown" {
		t.Fatalf("got %q, want pass|unknown", got)
	}
}

// ---------- discrepancyCauses ----------

func TestDiscrepancyCauses_FactExtractionGap(t *testing.T) {
	exp := RuleExpectation{ExpectedStatus: "pass"}
	finding := rules.Finding{Status: rules.StatusUnknown}
	causes := discrepancyCauses(exp, finding)
	if !contains(causes, "fact_extraction_gap") {
		t.Fatalf("expected fact_extraction_gap, got %v", causes)
	}
}

func TestDiscrepancyCauses_FalsePositive(t *testing.T) {
	exp := RuleExpectation{ExpectedStatus: "pass"}
	finding := rules.Finding{Status: rules.StatusFail}
	causes := discrepancyCauses(exp, finding)
	if !contains(causes, "false_positive") {
		t.Fatalf("expected false_positive, got %v", causes)
	}
}

func TestDiscrepancyCauses_FalseNegative(t *testing.T) {
	exp := RuleExpectation{ExpectedStatus: "fail"}
	finding := rules.Finding{Status: rules.StatusPass}
	causes := discrepancyCauses(exp, finding)
	if !contains(causes, "false_negative") {
		t.Fatalf("expected false_negative, got %v", causes)
	}
}

func TestDiscrepancyCauses_StatusMismatch(t *testing.T) {
	// unknown expected, but got fail (not pass->fail or fail->pass, actual is not unknown)
	exp := RuleExpectation{ExpectedStatus: "unknown"}
	finding := rules.Finding{Status: rules.StatusFail}
	causes := discrepancyCauses(exp, finding)
	if !contains(causes, "status_mismatch") {
		t.Fatalf("expected status_mismatch, got %v", causes)
	}
}

func TestDiscrepancyCauses_StatusOutsideAllowedRange(t *testing.T) {
	exp := RuleExpectation{AllowedStatuses: []string{"pass"}}
	finding := rules.Finding{Status: rules.StatusFail}
	causes := discrepancyCauses(exp, finding)
	if !contains(causes, "status_outside_allowed_range") {
		t.Fatalf("expected status_outside_allowed_range, got %v", causes)
	}
}

func TestDiscrepancyCauses_TrustMiscalibration(t *testing.T) {
	exp := RuleExpectation{ExpectedTrustClass: "machine_trusted"}
	finding := rules.Finding{Status: rules.StatusPass, TrustClass: rules.TrustAdvisory}
	causes := discrepancyCauses(exp, finding)
	if !contains(causes, "trust_miscalibration") {
		t.Fatalf("expected trust_miscalibration, got %v", causes)
	}
}

func TestDiscrepancyCauses_InsufficientEvidence(t *testing.T) {
	exp := RuleExpectation{MinimumEvidenceCount: 5}
	finding := rules.Finding{Status: rules.StatusPass, Evidence: make([]rules.Evidence, 1)}
	causes := discrepancyCauses(exp, finding)
	if !contains(causes, "insufficient_evidence") {
		t.Fatalf("expected insufficient_evidence, got %v", causes)
	}
}

func TestDiscrepancyCauses_ReviewNeeded(t *testing.T) {
	// No mismatch conditions at all, but we still call it with matching data
	// Actually this triggers when none of the branches match. Let's contrive it:
	// All checks pass (matching), so causes is empty -> "review_needed" appended.
	exp := RuleExpectation{}
	finding := rules.Finding{Status: rules.StatusPass}
	causes := discrepancyCauses(exp, finding)
	if !contains(causes, "review_needed") {
		t.Fatalf("expected review_needed, got %v", causes)
	}
}

// ---------- recommendedOwner ----------

func TestRecommendedOwner_FactExtractionGap(t *testing.T) {
	if got := recommendedOwner([]string{"fact_extraction_gap"}); got != OwnerAnalyzer {
		t.Fatalf("got %q, want %q", got, OwnerAnalyzer)
	}
}

func TestRecommendedOwner_InsufficientEvidence(t *testing.T) {
	if got := recommendedOwner([]string{"insufficient_evidence"}); got != OwnerAnalyzer {
		t.Fatalf("got %q, want %q", got, OwnerAnalyzer)
	}
}

func TestRecommendedOwner_FalsePositive(t *testing.T) {
	if got := recommendedOwner([]string{"false_positive"}); got != OwnerRules {
		t.Fatalf("got %q, want %q", got, OwnerRules)
	}
}

func TestRecommendedOwner_FalseNegative(t *testing.T) {
	if got := recommendedOwner([]string{"false_negative"}); got != OwnerRules {
		t.Fatalf("got %q, want %q", got, OwnerRules)
	}
}

func TestRecommendedOwner_StatusMismatch(t *testing.T) {
	if got := recommendedOwner([]string{"status_mismatch"}); got != OwnerRules {
		t.Fatalf("got %q, want %q", got, OwnerRules)
	}
}

func TestRecommendedOwner_TrustMiscalibration(t *testing.T) {
	if got := recommendedOwner([]string{"trust_miscalibration"}); got != OwnerReport {
		t.Fatalf("got %q, want %q", got, OwnerReport)
	}
}

func TestRecommendedOwner_Unknown(t *testing.T) {
	if got := recommendedOwner([]string{"review_needed"}); got != OwnerUnknown {
		t.Fatalf("got %q, want %q", got, OwnerUnknown)
	}
}

func TestRecommendedOwner_MultipleCauses_FirstWins(t *testing.T) {
	// fact_extraction_gap comes first, so analyzer wins
	if got := recommendedOwner([]string{"fact_extraction_gap", "false_positive"}); got != OwnerAnalyzer {
		t.Fatalf("got %q, want %q", got, OwnerAnalyzer)
	}
}

// ---------- recommendedAction ----------

func TestRecommendedAction_FactExtractionGap(t *testing.T) {
	got := recommendedAction([]string{"fact_extraction_gap"})
	if !strings.Contains(got, "fact extraction") {
		t.Fatalf("unexpected action: %q", got)
	}
}

func TestRecommendedAction_InsufficientEvidence(t *testing.T) {
	got := recommendedAction([]string{"insufficient_evidence"})
	if !strings.Contains(got, "evidence") {
		t.Fatalf("unexpected action: %q", got)
	}
}

func TestRecommendedAction_FalsePositive(t *testing.T) {
	got := recommendedAction([]string{"false_positive"})
	if !strings.Contains(got, "matcher guards") {
		t.Fatalf("unexpected action: %q", got)
	}
}

func TestRecommendedAction_FalseNegative(t *testing.T) {
	got := recommendedAction([]string{"false_negative"})
	if !strings.Contains(got, "matcher coverage") {
		t.Fatalf("unexpected action: %q", got)
	}
}

func TestRecommendedAction_TrustMiscalibration(t *testing.T) {
	got := recommendedAction([]string{"trust_miscalibration"})
	if !strings.Contains(got, "trust class") {
		t.Fatalf("unexpected action: %q", got)
	}
}

func TestRecommendedAction_StatusMismatch(t *testing.T) {
	// status_mismatch is not in the switch, falls through to default
	got := recommendedAction([]string{"status_mismatch"})
	if !strings.Contains(got, "Review the discrepancy") {
		t.Fatalf("unexpected action: %q", got)
	}
}

func TestRecommendedAction_ReviewNeeded(t *testing.T) {
	got := recommendedAction([]string{"review_needed"})
	if !strings.Contains(got, "Review the discrepancy") {
		t.Fatalf("unexpected action: %q", got)
	}
}

func TestRecommendedAction_MultipleCauses_FirstMatchWins(t *testing.T) {
	got := recommendedAction([]string{"insufficient_evidence", "false_positive"})
	if !strings.Contains(got, "evidence") {
		t.Fatalf("expected evidence action, got: %q", got)
	}
}

// ---------- matchesFilter ----------

func TestMatchesFilter_EmptyAllowList(t *testing.T) {
	if !matchesFilter("anything", nil) {
		t.Fatal("empty allow list should match all")
	}
}

func TestMatchesFilter_InAllowList(t *testing.T) {
	if !matchesFilter("a", []string{"a", "b"}) {
		t.Fatal("should match when in allow list")
	}
}

func TestMatchesFilter_NotInAllowList(t *testing.T) {
	if matchesFilter("c", []string{"a", "b"}) {
		t.Fatal("should not match when not in allow list")
	}
}

// ---------- accumulateSummary ----------

func TestAccumulateSummary_PassCase(t *testing.T) {
	var s RunSummary
	accumulateSummary(&s, CaseRunResult{ExitCode: 0, BlockingDiscrepancies: 0, AdvisoryDiscrepancies: 0})
	if s.Cases != 1 || s.PassedCases != 1 || s.FailedCases != 0 {
		t.Fatalf("pass case: %+v", s)
	}
}

func TestAccumulateSummary_FailCase_Blocking(t *testing.T) {
	var s RunSummary
	accumulateSummary(&s, CaseRunResult{ExitCode: 0, BlockingDiscrepancies: 1})
	if s.Cases != 1 || s.PassedCases != 0 || s.FailedCases != 1 || s.BlockingDiscrepancies != 1 {
		t.Fatalf("blocking fail: %+v", s)
	}
}

func TestAccumulateSummary_FailCase_Advisory(t *testing.T) {
	var s RunSummary
	accumulateSummary(&s, CaseRunResult{ExitCode: 0, AdvisoryDiscrepancies: 2})
	if s.FailedCases != 1 || s.AdvisoryDiscrepancies != 2 {
		t.Fatalf("advisory fail: %+v", s)
	}
}

func TestAccumulateSummary_FailCase_NonZeroExitCode(t *testing.T) {
	var s RunSummary
	accumulateSummary(&s, CaseRunResult{ExitCode: 1})
	if s.FailedCases != 1 {
		t.Fatalf("non-zero exit code should count as failed: %+v", s)
	}
}

// ---------- incrementDiscrepancySummary ----------

func TestIncrementDiscrepancySummary_Blocking(t *testing.T) {
	var s AdjudicationSummary
	incrementDiscrepancySummary(&s, "blocking")
	if s.Blocking != 1 || s.Advisory != 0 {
		t.Fatalf("got %+v", s)
	}
}

func TestIncrementDiscrepancySummary_Advisory(t *testing.T) {
	var s AdjudicationSummary
	incrementDiscrepancySummary(&s, "advisory")
	if s.Advisory != 1 || s.Blocking != 0 {
		t.Fatalf("got %+v", s)
	}
}

// ---------- evaluateGate ----------

func TestEvaluateGate_AllPass(t *testing.T) {
	manifest := &DatasetManifest{
		GatePolicy: GatePolicy{BlockOnFrozenRegression: true, MaxNewUnknowns: 0},
	}
	g := evaluateGate(manifest, RunSummary{})
	if !g.Passed {
		t.Fatalf("expected gate to pass: %+v", g)
	}
}

func TestEvaluateGate_BlockOnFrozenRegression(t *testing.T) {
	manifest := &DatasetManifest{
		GatePolicy: GatePolicy{BlockOnFrozenRegression: true},
	}
	g := evaluateGate(manifest, RunSummary{BlockingDiscrepancies: 1})
	if g.Passed {
		t.Fatal("expected gate to fail for blocking discrepancies")
	}
	if len(g.Reasons) == 0 {
		t.Fatal("expected reasons")
	}
}

func TestEvaluateGate_AdvisoryDiscrepancies(t *testing.T) {
	manifest := &DatasetManifest{
		GatePolicy: GatePolicy{MaxNewUnknowns: 0},
	}
	g := evaluateGate(manifest, RunSummary{AdvisoryDiscrepancies: 1})
	if g.Passed {
		t.Fatal("expected gate to fail for advisory discrepancies")
	}
}

func TestEvaluateGate_AdvisoryAllowed(t *testing.T) {
	manifest := &DatasetManifest{
		GatePolicy: GatePolicy{MaxNewUnknowns: 5},
	}
	g := evaluateGate(manifest, RunSummary{AdvisoryDiscrepancies: 3})
	if !g.Passed {
		t.Fatal("expected gate to pass when MaxNewUnknowns > 0")
	}
}

// ---------- writeJSON ----------

func TestWriteJSON_Success(t *testing.T) {
	tmp := t.TempDir()
	p := filepath.Join(tmp, "out.json")
	if err := writeJSON(p, map[string]string{"key": "val"}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]string
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	if m["key"] != "val" {
		t.Fatalf("got %v", m)
	}
}

func TestWriteJSON_BadPath(t *testing.T) {
	if err := writeJSON("/nonexistent/dir/out.json", "hello"); err == nil {
		t.Fatal("expected error for bad path")
	}
}

// ---------- initTempGitRepo ----------

func TestInitTempGitRepo_Success(t *testing.T) {
	src := t.TempDir()
	os.WriteFile(filepath.Join(src, "file.txt"), []byte("hello"), 0o644)
	sub := filepath.Join(src, "sub")
	os.MkdirAll(sub, 0o755)
	os.WriteFile(filepath.Join(sub, "nested.txt"), []byte("world"), 0o644)

	repo, err := initTempGitRepo(src)
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(repo)

	// Check that git was initialized
	if _, err := os.Stat(filepath.Join(repo, ".git")); err != nil {
		t.Fatal("expected .git directory")
	}
	// Check that files were copied
	if _, err := os.Stat(filepath.Join(repo, "file.txt")); err != nil {
		t.Fatal("expected file.txt")
	}
	if _, err := os.Stat(filepath.Join(repo, "sub", "nested.txt")); err != nil {
		t.Fatal("expected sub/nested.txt")
	}
}

func TestInitTempGitRepo_NonexistentSource(t *testing.T) {
	_, err := initTempGitRepo("/nonexistent/source/dir")
	if err == nil {
		t.Fatal("expected error for nonexistent source")
	}
}

// ---------- renderDiscrepancyMarkdown ----------

func TestRenderDiscrepancyMarkdown_NoDiscrepancies(t *testing.T) {
	cr := CaseRunResult{
		ID:       "c1",
		RepoPath: "path/to/repo",
		ExitCode: 0,
		Adjudication: AdjudicationReport{
			Verdict: "matches",
		},
	}
	md := renderDiscrepancyMarkdown(cr)
	if !strings.Contains(md, "No discrepancies detected") {
		t.Fatalf("expected no discrepancies message, got:\n%s", md)
	}
	if !strings.Contains(md, "Case: c1") {
		t.Fatalf("expected case id in markdown")
	}
}

func TestRenderDiscrepancyMarkdown_WithDiscrepancies(t *testing.T) {
	cr := CaseRunResult{
		ID:                    "c1",
		RepoPath:              "path/to/repo",
		ExitCode:              1,
		BlockingDiscrepancies: 1,
		AdvisoryDiscrepancies: 1,
		Errors:                []string{"engine error 1"},
		Adjudication: AdjudicationReport{
			Verdict: "mismatch",
			Discrepancies: []RuleDiscrepancy{
				{
					RuleID:            "SEC-AUTH-001",
					ExpectedStatus:    "pass",
					ActualStatus:      "fail",
					ReviewerVerdict:   "mismatch",
					SuspectedCauses:   []string{"false_positive"},
					RecommendedOwner:  OwnerRules,
					RecommendedAction: "Refine matcher guards",
				},
			},
		},
	}
	md := renderDiscrepancyMarkdown(cr)
	if !strings.Contains(md, "SEC-AUTH-001") {
		t.Fatal("expected rule id in markdown")
	}
	if !strings.Contains(md, "Expected: pass") {
		t.Fatal("expected status in markdown")
	}
	if !strings.Contains(md, "Actual: fail") {
		t.Fatal("expected actual in markdown")
	}
	if !strings.Contains(md, "engine error 1") {
		t.Fatal("expected errors in markdown")
	}
	if !strings.Contains(md, "Verdict: mismatch") {
		t.Fatal("expected verdict in markdown")
	}
	if !strings.Contains(md, "Suspected Causes:") {
		t.Fatal("expected suspected causes in markdown")
	}
	if !strings.Contains(md, "Recommended Action:") {
		t.Fatal("expected recommended action in markdown")
	}
}

func TestRenderDiscrepancyMarkdown_DiscrepancyWithoutActual(t *testing.T) {
	cr := CaseRunResult{
		ID: "c1",
		Adjudication: AdjudicationReport{
			Verdict: "mismatch",
			Discrepancies: []RuleDiscrepancy{
				{
					RuleID:           "SEC-AUTH-001",
					ExpectedStatus:   "pass",
					ReviewerVerdict:  "missing_finding",
					RecommendedOwner: OwnerRules,
				},
			},
		},
	}
	md := renderDiscrepancyMarkdown(cr)
	if strings.Contains(md, "Actual:") {
		t.Fatal("should not contain actual status when empty")
	}
}

func TestRenderDiscrepancyMarkdown_DiscrepancyWithoutAction(t *testing.T) {
	cr := CaseRunResult{
		ID: "c1",
		Adjudication: AdjudicationReport{
			Verdict: "mismatch",
			Discrepancies: []RuleDiscrepancy{
				{
					RuleID:           "r1",
					RecommendedOwner: OwnerRules,
				},
			},
		},
	}
	md := renderDiscrepancyMarkdown(cr)
	if strings.Contains(md, "Recommended Action:") {
		t.Fatal("should not contain action when empty")
	}
}

// ---------- buildAdjudication ----------

func TestBuildAdjudication_AllMatch(t *testing.T) {
	manifest := &DatasetManifest{DatasetID: "d1"}
	suite := SuiteManifest{ID: "s1"}
	c := CaseManifest{ID: "c1"}
	expected := ExpectedCase{
		Expectations: []RuleExpectation{
			{RuleID: "r1", ExpectedStatus: "pass", Priority: "blocking", Rationale: "r"},
		},
	}
	findings := []rules.Finding{
		{RuleID: "r1", Status: rules.StatusPass, Evidence: nil},
	}
	adj := buildAdjudication(manifest, suite, c, expected, findings)
	if adj.Verdict != "matches" {
		t.Fatalf("expected matches, got %q", adj.Verdict)
	}
	if len(adj.Discrepancies) != 0 {
		t.Fatalf("expected no discrepancies, got %d", len(adj.Discrepancies))
	}
}

func TestBuildAdjudication_MissingFinding(t *testing.T) {
	manifest := &DatasetManifest{DatasetID: "d1"}
	suite := SuiteManifest{ID: "s1"}
	c := CaseManifest{ID: "c1"}
	expected := ExpectedCase{
		Expectations: []RuleExpectation{
			{RuleID: "r1", ExpectedStatus: "pass", Priority: "blocking", Rationale: "r"},
		},
	}
	adj := buildAdjudication(manifest, suite, c, expected, nil)
	if adj.Verdict != "mismatch" {
		t.Fatalf("expected mismatch, got %q", adj.Verdict)
	}
	if len(adj.Discrepancies) != 1 {
		t.Fatalf("expected 1 discrepancy, got %d", len(adj.Discrepancies))
	}
	d := adj.Discrepancies[0]
	if d.ReviewerVerdict != "missing_finding" {
		t.Fatalf("expected missing_finding, got %q", d.ReviewerVerdict)
	}
}

func TestBuildAdjudication_StatusMismatch(t *testing.T) {
	manifest := &DatasetManifest{DatasetID: "d1"}
	suite := SuiteManifest{ID: "s1"}
	c := CaseManifest{ID: "c1"}
	expected := ExpectedCase{
		Expectations: []RuleExpectation{
			{RuleID: "r1", ExpectedStatus: "pass", Priority: "advisory", Rationale: "r"},
		},
	}
	findings := []rules.Finding{
		{RuleID: "r1", Status: rules.StatusFail},
	}
	adj := buildAdjudication(manifest, suite, c, expected, findings)
	if adj.Verdict != "mismatch" {
		t.Fatalf("expected mismatch, got %q", adj.Verdict)
	}
	if adj.Summary.Advisory != 1 {
		t.Fatalf("expected advisory=1, got %d", adj.Summary.Advisory)
	}
}

// ---------- RunDataset error paths ----------

func TestRunDataset_MissingConfig(t *testing.T) {
	_, err := RunDataset(context.Background(), RunConfig{})
	if err == nil {
		t.Fatal("expected error for empty config")
	}
}

func TestRunDataset_NilContext(t *testing.T) {
	// Just verify nil context doesn't panic (it gets replaced with Background)
	_, err := RunDataset(nil, RunConfig{}) //nolint:staticcheck
	if err == nil {
		t.Fatal("expected error for empty config")
	}
}

func TestRunDataset_BadManifest(t *testing.T) {
	tmp := t.TempDir()
	_, err := RunDataset(context.Background(), RunConfig{
		ModuleRoot:   tmp,
		ManifestPath: filepath.Join(tmp, "no-such-manifest.json"),
		OutputRoot:   filepath.Join(tmp, "out"),
	})
	if err == nil {
		t.Fatal("expected error for missing manifest")
	}
}

// ---------- RunDataset filter edge cases ----------

func TestRunDataset_SuiteFilterNoMatch(t *testing.T) {
	moduleRoot := filepath.Join("..", "..")
	manifestPath := filepath.Join(moduleRoot, "testdata", "autobench", "datasets", "autocal-v1", "manifest.json")
	outputRoot := t.TempDir()

	result, err := RunDataset(context.Background(), RunConfig{
		ModuleRoot:   moduleRoot,
		ManifestPath: manifestPath,
		OutputRoot:   outputRoot,
		SuiteIDs:     []string{"nonexistent-suite"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Suites) != 0 {
		t.Fatalf("expected 0 suites, got %d", len(result.Suites))
	}
}

func TestRunDataset_CaseFilterNoMatch(t *testing.T) {
	moduleRoot := filepath.Join("..", "..")
	manifestPath := filepath.Join(moduleRoot, "testdata", "autobench", "datasets", "autocal-v1", "manifest.json")
	outputRoot := t.TempDir()

	result, err := RunDataset(context.Background(), RunConfig{
		ModuleRoot:   moduleRoot,
		ManifestPath: manifestPath,
		OutputRoot:   outputRoot,
		SuiteIDs:     []string{"frontend-js"},
		CaseIDs:      []string{"nonexistent-case"},
	})
	if err != nil {
		t.Fatal(err)
	}
	// Suite matches but no cases match => suite skipped
	if len(result.Suites) != 0 {
		t.Fatalf("expected 0 suites when no cases match, got %d", len(result.Suites))
	}
}

func TestRunDataset_WithProgressWriter(t *testing.T) {
	moduleRoot := filepath.Join("..", "..")
	manifestPath := filepath.Join(moduleRoot, "testdata", "autobench", "datasets", "autocal-v1", "manifest.json")
	outputRoot := t.TempDir()

	var buf strings.Builder
	result, err := RunDataset(context.Background(), RunConfig{
		ModuleRoot:   moduleRoot,
		ManifestPath: manifestPath,
		OutputRoot:   outputRoot,
		SuiteIDs:     []string{"frontend-js"},
		CaseIDs:      []string{"js-node-no-auth-frontend"},
		Progress:     &buf,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Summary.Cases != 1 {
		t.Fatalf("expected 1 case, got %d", result.Summary.Cases)
	}
	if !strings.Contains(buf.String(), "[AUTO]") {
		t.Fatal("expected progress output")
	}
}

// ---------- helper ----------

func contains(ss []string, s string) bool {
	for _, v := range ss {
		if v == s {
			return true
		}
	}
	return false
}
