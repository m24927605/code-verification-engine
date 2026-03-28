package artifactsv2

import (
	"testing"

	"github.com/verabase/code-verification-engine/internal/report"
	"github.com/verabase/code-verification-engine/internal/rules"
	"github.com/verabase/code-verification-engine/internal/skills"
)

// Store nil receiver
func TestStoreNilReceiver(t *testing.T) {
	t.Parallel()
	var s *EvidenceStore
	s.Upsert(EvidenceRecord{ID: "e"})
	s.Finalize()
	if s.All() != nil {
		t.Fatal("expected nil")
	}
	if _, ok := s.Get("e"); ok {
		t.Fatal("expected false")
	}
	if s.IDsByClaim("c") != nil || s.IDsByProducer("p") != nil || s.IDsByFile("f") != nil {
		t.Fatal("expected nil")
	}
}

func TestStoreUpsertEmptyID(t *testing.T) {
	t.Parallel()
	s := NewEvidenceStore()
	s.Upsert(EvidenceRecord{})
	s.Finalize()
	if len(s.All()) != 0 {
		t.Fatal("expected 0")
	}
}

func TestChooseStableFP(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ a, b, w string }{
		{"", "", ""}, {"", "b", "b"}, {"a", "", "a"}, {"a", "b", "a"}, {"b", "a", "a"},
	} {
		if g := chooseStableFingerprint(tc.a, tc.b); g != tc.w {
			t.Errorf("(%q,%q)=%q want %q", tc.a, tc.b, g, tc.w)
		}
	}
}

func TestCompatEvKindAll(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ vb, w string }{
		{"proof", "rule_assertion"}, {"structural_binding", "structural_fact"}, {"", "heuristic_fact"},
	} {
		if g := compatEvidenceKind(rules.Finding{VerdictBasis: tc.vb}); g != tc.w {
			t.Errorf("vb=%q: %q want %q", tc.vb, g, tc.w)
		}
	}
}

func TestCompatIssCatAll(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ r, w string }{
		{"SEC-001", "security"}, {"ARCH-001", "design"}, {"Q-001", "bug"},
	} {
		if g := compatIssueCategory(rules.Finding{RuleID: tc.r}); g != tc.w {
			t.Errorf("r=%q: %q want %q", tc.r, g, tc.w)
		}
	}
}

func TestCompatSevAll(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		tc rules.TrustClass
		s  rules.Status
		w  string
	}{
		{rules.TrustMachineTrusted, rules.StatusFail, "high"},
		{rules.TrustMachineTrusted, rules.StatusUnknown, "medium"},
		{rules.TrustAdvisory, rules.StatusFail, "medium"},
		{rules.TrustHumanOrRuntimeRequired, rules.StatusFail, "low"},
	} {
		if g := compatSeverity(rules.Finding{TrustClass: tc.tc, Status: tc.s}); g != tc.w {
			t.Errorf("%q/%q: %q want %q", tc.tc, tc.s, g, tc.w)
		}
	}
}

func TestCompatRiskAll(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		c IssueCountSummary
		w string
	}{
		{IssueCountSummary{Critical: 1}, "critical"},
		{IssueCountSummary{High: 1}, "high"},
		{IssueCountSummary{Medium: 1}, "medium"},
		{IssueCountSummary{}, "low"},
	} {
		if g := compatRiskLevel(tc.c); g != tc.w {
			t.Errorf("%+v: %q want %q", tc.c, g, tc.w)
		}
	}
}

func TestCompatSkillConfLow(t *testing.T) {
	t.Parallel()
	if g := compatSkillConfidence(skills.ConfidenceLow); g != 0.45 {
		t.Fatal(g)
	}
}

func TestCompatSkillWtHeur(t *testing.T) {
	t.Parallel()
	if g := compatSkillWeight(skills.EvidenceHeuristic); g != 0.4 {
		t.Fatal(g)
	}
}

func TestTraceIDEdge(t *testing.T) {
	t.Parallel()
	if g := buildTraceID("abc123def456789"); g != "trace-abc123def456" {
		t.Fatal(g)
	}
	if g := buildTraceID(""); g != "trace-unknown" {
		t.Fatal(g)
	}
}

func TestFirstOrEmptyEdge(t *testing.T) {
	t.Parallel()
	if firstOrEmpty(nil) != "" {
		t.Fatal("not empty")
	}
}

func TestFirstNonEmptyMigAllEmpty(t *testing.T) {
	t.Parallel()
	if firstNonEmptyMigrationState("", "  ") != "" {
		t.Fatal("not empty")
	}
}

func TestClampBranches(t *testing.T) {
	t.Parallel()
	if clamp(-1, 0, 1) != 0 || clamp(2, 0, 1) != 1 {
		t.Fatal("clamp fail")
	}
}

func TestSynthEvIDStable(t *testing.T) {
	t.Parallel()
	if compatSyntheticIssueEvidenceID(rules.Finding{RuleID: "R", Status: rules.StatusFail, Message: "m"}) == "" {
		t.Fatal("empty")
	}
}

func TestReportSummaryCritLow(t *testing.T) {
	t.Parallel()
	s := buildReportSummary([]Issue{{Severity: "critical"}, {Severity: "low"}}, nil)
	if s.IssueCounts.Critical != 1 || s.IssueCounts.Low != 1 {
		t.Fatal(s.IssueCounts)
	}
}

func TestReportSkillScoresNil(t *testing.T) {
	t.Parallel()
	if buildReportSkillScores(nil) != nil {
		t.Fatal("not nil")
	}
}

// confidence
func TestRelCatAll(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		c string
		w float64
	}{
		{"security", 0.90}, {"architecture", 0.72}, {"design", 0.68},
		{"frontend_security", 0.82}, {"frontend_quality", 0.62},
		{"quality", 0.58}, {"testing", 0.56}, {"bug", 0.52}, {"x", 0.50},
	} {
		if g := reliabilityForRuleCategory(tc.c); g != tc.w {
			t.Errorf("%q: %f want %f", tc.c, g, tc.w)
		}
	}
}

func TestRelFamAll(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		m, tc string
		w     float64
	}{
		{"", "human_or_runtime_required", 0.30},
		{"proof_matcher", "machine_trusted", 0.85},
		{"structural_matcher", "advisory", 0.65},
		{"heuristic_matcher", "", 0.45},
		{"attestation_matcher", "", 0.30},
		{"", "", 0},
	} {
		if g := reliabilityForRuleFamily(tc.m, tc.tc); g != tc.w {
			t.Errorf("(%q,%q): %f want %f", tc.m, tc.tc, g, tc.w)
		}
	}
}

func TestRelCapMigAll(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		s string
		w float64
	}{
		{"issue_native", 1}, {"seed_native", 0.80}, {"finding_bridged", 0.60}, {"legacy_only", 0.45}, {"", 0},
	} {
		if g := reliabilityCapForMigrationState(tc.s); g != tc.w {
			t.Errorf("%q: %f want %f", tc.s, g, tc.w)
		}
	}
}

func TestRelMigAll(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		s string
		w float64
	}{
		{"issue_native", 0.85}, {"seed_native", 0.68}, {"finding_bridged", 0.50}, {"legacy_only", 0.40}, {"", 0.45},
	} {
		if g := reliabilityForMigrationState(tc.s); g != tc.w {
			t.Errorf("%q: %f want %f", tc.s, g, tc.w)
		}
	}
}

func TestCtxComplAll(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		f, s string
		w    float64
	}{{"f", "s", 1}, {"f", "", 0.75}, {"unknown", "", 0.40}, {"", "", 0.40}} {
		if g := computeContextCompleteness(compatIssueCluster{File: tc.f, Symbol: tc.s}); g != tc.w {
			t.Errorf("(%q,%q): %f want %f", tc.f, tc.s, g, tc.w)
		}
	}
}

func TestSrcAgreeAll(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		s []string
		w float64
	}{
		{nil, 0.30}, {[]string{"r"}, 0.45}, {[]string{"r", "a"}, 0.70}, {[]string{"r", "a", "x"}, 0.90},
	} {
		if g := computeSourceAgreement(tc.s); g != tc.w {
			t.Errorf("%v: %f want %f", tc.s, g, tc.w)
		}
	}
}

func TestContrPenAll(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		i []string
		w float64
	}{
		{nil, 0}, {[]string{"a"}, 0.20}, {[]string{"a", "b"}, 0.45}, {[]string{"a", "b", "c"}, 0.70},
	} {
		if g := computeContradictionPenalty(tc.i); g != tc.w {
			t.Errorf("%v: %f want %f", tc.i, g, tc.w)
		}
	}
}

func TestDerivePolicyNilBD(t *testing.T) {
	t.Parallel()
	if g := deriveIssuePolicyClass(compatIssueCluster{Status: "open"}, nil); g != "unknown_retained" {
		t.Fatal(g)
	}
}

func TestDerivePolicyLowFinal(t *testing.T) {
	t.Parallel()
	if g := deriveIssuePolicyClass(compatIssueCluster{Status: "open"}, &ConfidenceBreakdown{Final: 0.30}); g != "unknown_retained" {
		t.Fatal(g)
	}
}

func TestRuleRelBaseNoMeta(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		q, w float64
	}{{0.95, 0.85}, {0.65, 0.70}, {0.30, 0.50}} {
		if g := computeRuleReliabilityBaseline(compatIssueCluster{Quality: tc.q}, VerificationSource{}); g != tc.w {
			t.Errorf("q=%f: %f want %f", tc.q, g, tc.w)
		}
	}
}

func TestBndComplNonRepo(t *testing.T) {
	t.Parallel()
	if g := computeBoundaryCompleteness(report.ScanReport{BoundaryMode: "subdir"}, VerificationSource{}); g != 0.8 {
		t.Fatal(g)
	}
}

// agent
func TestAgentKindAll(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ c, w string }{
		{"security", "security"}, {"frontend_security", "security"},
		{"architecture", "design"}, {"bug", "bug"},
	} {
		if g := plannedAgentKind(IssueCandidate{Category: tc.c}); g != tc.w {
			t.Errorf("%q: %q want %q", tc.c, g, tc.w)
		}
	}
}

func TestAgentIssTypeAll(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ c, w string }{
		{"security", "security_review"}, {"architecture", "design_review"}, {"bug", "bug_review"},
	} {
		if g := plannedAgentIssueType(IssueCandidate{Category: tc.c}); g != tc.w {
			t.Errorf("%q: %q want %q", tc.c, g, tc.w)
		}
	}
}

func TestAgentTriggerFB(t *testing.T) {
	t.Parallel()
	if g := plannedAgentTriggerReason([]string{"x"}); g != "policy_review" {
		t.Fatal(g)
	}
}

func TestAgentQAll(t *testing.T) {
	t.Parallel()
	for _, r := range []string{"unknown_issue", "conflict_review", "high_severity_review", "other"} {
		if plannedAgentQuestion(IssueCandidate{}, r) == "" {
			t.Errorf("empty for %q", r)
		}
	}
}

func TestExecNilExec(t *testing.T) {
	t.Parallel()
	r, e := executeAgentTasks([]AgentTask{{ID: "a"}}, nil)
	if e != nil || r != nil {
		t.Fatal("expected nil")
	}
}

func TestExecInsuffCtx(t *testing.T) {
	t.Parallel()
	rs, _ := executeAgentTasks([]AgentTask{{ID: "a", Kind: "b", IssueID: "i", Context: ContextBundle{ID: "c"}}}, func(AgentTask) (AgentResult, error) {
		return AgentResult{Status: "insufficient_context"}, nil
	})
	if rs[0].UnresolvedReasons[0] != "insufficient_context" {
		t.Fatal(rs[0].UnresolvedReasons)
	}
}

func TestExecFailedSt(t *testing.T) {
	t.Parallel()
	rs, _ := executeAgentTasks([]AgentTask{{ID: "a", Kind: "b", IssueID: "i", Context: ContextBundle{ID: "c"}}}, func(AgentTask) (AgentResult, error) {
		return AgentResult{Status: "failed"}, nil
	})
	if rs[0].UnresolvedReasons[0] != "executor_failed" {
		t.Fatal(rs[0].UnresolvedReasons)
	}
}

func TestAgentRunsEmpty(t *testing.T) {
	t.Parallel()
	if buildAgentRuns(nil, nil, nil) != nil {
		t.Fatal("expected nil")
	}
}

// context
func TestSortedLocs(t *testing.T) {
	t.Parallel()
	l := sortedLocations([]LocationRef{
		{RepoRelPath: "b", StartLine: 10, EndLine: 15, SymbolID: "z"},
		{RepoRelPath: "a", StartLine: 5, EndLine: 8, SymbolID: "b"},
		{RepoRelPath: "a", StartLine: 5, EndLine: 8, SymbolID: "a"},
		{RepoRelPath: "a", StartLine: 1, EndLine: 3},
	})
	if l[0].StartLine != 1 || l[1].SymbolID != "a" {
		t.Fatal("bad order")
	}
}

func TestCtxBundleMissing(t *testing.T) {
	t.Parallel()
	b := buildContextBundle(ContextRequest{TriggerType: "issue", TriggerID: "i", MaxFiles: 2, MaxSpans: 4, MaxTokens: 1200},
		IssueCandidate{ID: "i", EvidenceIDs: []string{"x"}}, map[string]EvidenceRecord{})
	if len(b.Spans) != 0 {
		t.Fatal("expected 0")
	}
}

func TestCtxTrigHighSev(t *testing.T) {
	t.Parallel()
	r, ok := contextSelectionTrigger(IssueCandidate{Severity: "critical", Status: "open", PolicyClass: "advisory"})
	if !ok || r != "high_severity_review" {
		t.Fatal(r, ok)
	}
}

func TestCtxTrigNone(t *testing.T) {
	t.Parallel()
	_, ok := contextSelectionTrigger(IssueCandidate{Severity: "low", Status: "resolved", PolicyClass: "advisory"})
	if ok {
		t.Fatal("unexpected trigger")
	}
}

// compat_aggregate
func TestCatMergeFamAll(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ c, w string }{
		{"security", "security"}, {"frontend_security", "security"},
		{"architecture", "architecture_design"}, {"design", "architecture_design"},
		{"quality", "quality_testing"}, {"testing", "quality_testing"}, {"frontend_quality", "quality_testing"},
		{"bug", "bug"}, {"", "bug"}, {"custom", "custom"},
	} {
		if g := compatCategoryMergeFamily(tc.c); g != tc.w {
			t.Errorf("%q: %q want %q", tc.c, g, tc.w)
		}
	}
}

func TestSeedFactQAll(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		q float64
		w string
	}{{0.95, "proof"}, {0.65, "structural"}, {0.30, "heuristic"}} {
		if g := compatSeedFactQuality(tc.q); g != tc.w {
			t.Errorf("q=%f: %q want %q", tc.q, g, tc.w)
		}
	}
}

func TestNormSeedDefaults(t *testing.T) {
	t.Parallel()
	s := normalizeIssueSeedDefaults(IssueSeed{RuleID: "T"})
	if s.Title != "T" || s.File != "unknown" || s.StartLine != 1 || s.Status != "open" || s.Category != "bug" || s.Source != "rule" || len(s.EvidenceIDs) != 1 {
		t.Fatal("bad defaults")
	}
}

func TestNormSeedBackslash(t *testing.T) {
	t.Parallel()
	s := normalizeIssueSeedDefaults(IssueSeed{RuleID: "T", Title: "t", File: `a\b`, StartLine: 5, EndLine: 10, Status: "open", Category: "bug", Severity: "medium", Source: "rule"})
	if s.File != "a/b" {
		t.Fatal(s.File)
	}
}

func TestPrimLocSort(t *testing.T) {
	t.Parallel()
	f, _, sl, _ := compatPrimaryLocation(rules.Finding{Evidence: []rules.Evidence{
		{File: "b", LineStart: 20, LineEnd: 25}, {File: "a", LineStart: 10, LineEnd: 12},
	}})
	if f != "a" || sl != 10 {
		t.Fatal(f, sl)
	}
}

func TestCollectCounterEmpty(t *testing.T) {
	t.Parallel()
	if collectCounterEvidenceIDs(nil, nil) != nil {
		t.Fatal("not nil")
	}
}

func TestChooseTitleBreaks(t *testing.T) {
	t.Parallel()
	if chooseCompatTitle("A", "B") != "A" {
		t.Fatal("wrong")
	}
	if chooseCompatTitle("s", "longer") != "longer" {
		t.Fatal("wrong")
	}
	if chooseCompatTitle("Alpha", "alpha") != "Alpha" {
		t.Fatal("wrong")
	}
}

func TestPrefCatBreaks(t *testing.T) {
	t.Parallel()
	if preferredCategory("zebra", "alpha") != "alpha" {
		t.Fatal("wrong")
	}
	if preferredCategory("", "bug") != "bug" {
		t.Fatal("wrong")
	}
}

// rule_family
func TestRuleFamPrefixes(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ r, c, w string }{
		{"SEC-SECRET-001", "", "sec_secret"}, {"SEC-STRICT-001", "", "sec_strict"},
		{"ARCH-LAYER-001", "", "arch_layer"}, {"ARCH-PATTERN-001", "", "arch_pattern"},
		{"TEST-AUTH-001", "", "test_auth"}, {"TEST-PAYMENT-001", "", "test_payment"},
		{"FE-DEP-001", "", "fe_dep"}, {"FAM-SEC-001", "", "fam_security"},
		{"FAM-DES-001", "", "fam_design"}, {"FAM-BUG-001", "", "fam_bug"},
		{"OTHER", "security", "security"},
	} {
		if g := compatRuleFamily(tc.r, tc.c); g != tc.w {
			t.Errorf("(%q,%q): %q want %q", tc.r, tc.c, g, tc.w)
		}
	}
}

// validate
func TestValReportMissSch(t *testing.T) {
	t.Parallel()
	if ValidateReport(ReportArtifact{}) == nil {
		t.Fatal("expected error")
	}
}
func TestValReportMissReq(t *testing.T) {
	t.Parallel()
	if ValidateReport(ReportArtifact{SchemaVersion: "2"}) == nil {
		t.Fatal("expected error")
	}
}
func TestValReportBadScore(t *testing.T) {
	t.Parallel()
	r := testBundle().Report
	r.Summary.OverallScore = 1.5
	if ValidateReport(r) == nil {
		t.Fatal("expected error")
	}
}
func TestValReportBadRisk(t *testing.T) {
	t.Parallel()
	r := testBundle().Report
	r.Summary.RiskLevel = "x"
	if ValidateReport(r) == nil {
		t.Fatal("expected error")
	}
}
func TestValReportNoIssID(t *testing.T) {
	t.Parallel()
	r := testBundle().Report
	r.Issues[0].ID = ""
	if ValidateReport(r) == nil {
		t.Fatal("expected error")
	}
}
func TestValReportNoFP(t *testing.T) {
	t.Parallel()
	r := testBundle().Report
	r.Issues[0].Fingerprint = ""
	if ValidateReport(r) == nil {
		t.Fatal("expected error")
	}
}
func TestValReportBadMB(t *testing.T) {
	t.Parallel()
	r := testBundle().Report
	r.Issues[0].MergeBasis = "x"
	if ValidateReport(r) == nil {
		t.Fatal("expected error")
	}
}
func TestValReportDup(t *testing.T) {
	t.Parallel()
	r := testBundle().Report
	r.Issues = append(r.Issues, r.Issues[0])
	if ValidateReport(r) == nil {
		t.Fatal("expected error")
	}
}
func TestValReportNoCat(t *testing.T) {
	t.Parallel()
	r := testBundle().Report
	r.Issues[0].Category = ""
	if ValidateReport(r) == nil {
		t.Fatal("expected error")
	}
}
func TestValReportBadSev(t *testing.T) {
	t.Parallel()
	r := testBundle().Report
	r.Issues[0].Severity = "x"
	if ValidateReport(r) == nil {
		t.Fatal("expected error")
	}
}
func TestValReportBadSt(t *testing.T) {
	t.Parallel()
	r := testBundle().Report
	r.Issues[0].Status = "x"
	if ValidateReport(r) == nil {
		t.Fatal("expected error")
	}
}
func TestValReportBadCC(t *testing.T) {
	t.Parallel()
	r := testBundle().Report
	r.Issues[0].ConfidenceClass = "x"
	if ValidateReport(r) == nil {
		t.Fatal("expected error")
	}
}
func TestValReportBadPC(t *testing.T) {
	t.Parallel()
	r := testBundle().Report
	r.Issues[0].PolicyClass = "x"
	if ValidateReport(r) == nil {
		t.Fatal("expected error")
	}
}
func TestValReportNegConf(t *testing.T) {
	t.Parallel()
	r := testBundle().Report
	r.Issues[0].Confidence = -1
	if ValidateReport(r) == nil {
		t.Fatal("expected error")
	}
}
func TestValReportNoEv(t *testing.T) {
	t.Parallel()
	r := testBundle().Report
	r.Issues[0].EvidenceIDs = nil
	if ValidateReport(r) == nil {
		t.Fatal("expected error")
	}
}
func TestValReportEmptyCounter(t *testing.T) {
	t.Parallel()
	r := testBundle().Report
	r.Issues[0].CounterEvidenceIDs = []string{""}
	if ValidateReport(r) == nil {
		t.Fatal("expected error")
	}
}
func TestValReportNegSrc(t *testing.T) {
	t.Parallel()
	r := testBundle().Report
	r.Issues[0].SourceSummary.RuleCount = -1
	if ValidateReport(r) == nil {
		t.Fatal("expected error")
	}
}
func TestValReportBadTotal(t *testing.T) {
	t.Parallel()
	r := testBundle().Report
	r.Issues[0].SourceSummary.TotalSources = 0
	r.Issues[0].SourceSummary.DeterministicSources = 1
	r.Issues[0].SourceSummary.AgentSources = 1
	if ValidateReport(r) == nil {
		t.Fatal("expected error")
	}
}
func TestValEvNoSch(t *testing.T) {
	t.Parallel()
	if ValidateEvidence(EvidenceArtifact{}) == nil {
		t.Fatal("expected error")
	}
}
func TestValEvNoReq(t *testing.T) {
	t.Parallel()
	if ValidateEvidence(EvidenceArtifact{SchemaVersion: "2"}) == nil {
		t.Fatal("expected error")
	}
}
func TestValEvNoID(t *testing.T) {
	t.Parallel()
	a := testBundle().Evidence
	a.Evidence[0].ID = ""
	if ValidateEvidence(a) == nil {
		t.Fatal("expected error")
	}
}
func TestValEvDup(t *testing.T) {
	t.Parallel()
	a := testBundle().Evidence
	a.Evidence = append(a.Evidence, a.Evidence[0])
	if ValidateEvidence(a) == nil {
		t.Fatal("expected error")
	}
}
func TestValEvNoKind(t *testing.T) {
	t.Parallel()
	a := testBundle().Evidence
	a.Evidence[0].Kind = ""
	if ValidateEvidence(a) == nil {
		t.Fatal("expected error")
	}
}
func TestValEvBadSrc(t *testing.T) {
	t.Parallel()
	a := testBundle().Evidence
	a.Evidence[0].Source = "x"
	if ValidateEvidence(a) == nil {
		t.Fatal("expected error")
	}
}
func TestValEvBadFQ(t *testing.T) {
	t.Parallel()
	a := testBundle().Evidence
	a.Evidence[0].FactQuality = "x"
	if ValidateEvidence(a) == nil {
		t.Fatal("expected error")
	}
}
func TestValEvNoRepo(t *testing.T) {
	t.Parallel()
	a := testBundle().Evidence
	a.Evidence[0].Repo = ""
	if ValidateEvidence(a) == nil {
		t.Fatal("expected error")
	}
}
func TestValEvNoLoc(t *testing.T) {
	t.Parallel()
	a := testBundle().Evidence
	a.Evidence[0].Locations = nil
	if ValidateEvidence(a) == nil {
		t.Fatal("expected error")
	}
}
func TestValEvNoPath(t *testing.T) {
	t.Parallel()
	a := testBundle().Evidence
	a.Evidence[0].Locations[0].RepoRelPath = ""
	if ValidateEvidence(a) == nil {
		t.Fatal("expected error")
	}
}
func TestValEvBadLine(t *testing.T) {
	t.Parallel()
	a := testBundle().Evidence
	a.Evidence[0].Locations[0].StartLine = 0
	if ValidateEvidence(a) == nil {
		t.Fatal("expected error")
	}
}
func TestValSkNoSch(t *testing.T) {
	t.Parallel()
	if ValidateSkills(SkillsArtifact{}) == nil {
		t.Fatal("expected error")
	}
}
func TestValSkNoReq(t *testing.T) {
	t.Parallel()
	if ValidateSkills(SkillsArtifact{SchemaVersion: "2"}) == nil {
		t.Fatal("expected error")
	}
}
func TestValSkNoSID(t *testing.T) {
	t.Parallel()
	s := testBundle().Skills
	s.Skills[0].SkillID = ""
	if ValidateSkills(s) == nil {
		t.Fatal("expected error")
	}
}
func TestValSkDup(t *testing.T) {
	t.Parallel()
	s := testBundle().Skills
	s.Skills = append(s.Skills, s.Skills[0])
	if ValidateSkills(s) == nil {
		t.Fatal("expected error")
	}
}
func TestValSkBadScore(t *testing.T) {
	t.Parallel()
	s := testBundle().Skills
	s.Skills[0].Score = -1
	if ValidateSkills(s) == nil {
		t.Fatal("expected error")
	}
}
func TestValTrNoSch(t *testing.T) {
	t.Parallel()
	if ValidateTrace(TraceArtifact{}) == nil {
		t.Fatal("expected error")
	}
}
func TestValTrNoMode(t *testing.T) {
	t.Parallel()
	tr := testBundle().Trace
	tr.ScanBoundary.Mode = ""
	if ValidateTrace(tr) == nil {
		t.Fatal("expected error")
	}
}
func TestValBndNoSum(t *testing.T) {
	t.Parallel()
	b := testBundle()
	b.SummaryMD = ""
	if ValidateBundle(b) == nil {
		t.Fatal("expected error")
	}
}
func TestValBndTrMismatch(t *testing.T) {
	t.Parallel()
	b := testBundle()
	b.Trace.TraceID = "x"
	if ValidateBundle(b) == nil {
		t.Fatal("expected error")
	}
}
func TestValBndRepoMismatch(t *testing.T) {
	t.Parallel()
	b := testBundle()
	b.Evidence.Repo = "x"
	if ValidateBundle(b) == nil {
		t.Fatal("expected error")
	}
}

// claims
func TestHlRankAll(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		l string
		w int
	}{{"verified", 0}, {"strongly_supported", 1}, {"supported", 2}, {"weak", 3}, {"unsupported", 4}, {"contradicted", 5}, {"x", 99}} {
		if g := highlightRank(tc.l); g != tc.w {
			t.Errorf("%q: %d want %d", tc.l, g, tc.w)
		}
	}
}

func TestCapAreaAll(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ i, w string }{
		{"architecture", "Architecture and System Design"},
		{"security_maturity", "Security Maturity"},
		{"testing_maturity", "Testing Maturity"},
		{"evaluation_maturity", "Evaluation Maturity"},
		{"operational_maturity", "Operational Maturity"},
	} {
		if g := capabilityAreaTitle(tc.i); g != tc.w {
			t.Errorf("%q: %q want %q", tc.i, g, tc.w)
		}
	}
}

func TestSumClaimsWeak(t *testing.T) {
	t.Parallel()
	s := summarizeClaims([]ClaimRecord{{SupportLevel: "weak"}, {SupportLevel: "supported"}})
	if s.Weak != 1 || s.Supported != 1 {
		t.Fatal(s)
	}
}

func TestValSynthConstr(t *testing.T) {
	t.Parallel()
	if validateSynthesisConstraints(SynthesisConstraints{AllowUnsupportedClaims: true}) == nil {
		t.Fatal("expected error")
	}
	if validateSynthesisConstraints(SynthesisConstraints{AllowClaimInvention: true}) == nil {
		t.Fatal("expected error")
	}
	if validateSynthesisConstraints(SynthesisConstraints{AllowContradictionSuppression: true}) == nil {
		t.Fatal("expected error")
	}
}

func TestValClaimsProjInp(t *testing.T) {
	t.Parallel()
	if validateClaimsProjectionInput(ClaimsProjectionInput{}) == nil {
		t.Fatal("expected error")
	}
}

func TestWriteClaimsEmptyD(t *testing.T) {
	t.Parallel()
	if WriteClaimsProfileResumeArtifacts("", ClaimsProjectionArtifacts{}) == nil {
		t.Fatal("expected error")
	}
}

func TestResStubNoF(t *testing.T) {
	t.Parallel()
	if validateResumeClaimStub(ResumeClaimStub{}, 0, "t") == nil {
		t.Fatal("expected error")
	}
}
func TestResStubBadLvl(t *testing.T) {
	t.Parallel()
	if validateResumeClaimStub(ResumeClaimStub{ClaimID: "c", Title: "t", SupportLevel: "x"}, 0, "t") == nil {
		t.Fatal("expected error")
	}
}
func TestResStubBadConf(t *testing.T) {
	t.Parallel()
	if validateResumeClaimStub(ResumeClaimStub{ClaimID: "c", Title: "t", SupportLevel: "verified", Confidence: 1.5}, 0, "t") == nil {
		t.Fatal("expected error")
	}
}
func TestResStubNoEv(t *testing.T) {
	t.Parallel()
	if validateResumeClaimStub(ResumeClaimStub{ClaimID: "c", Title: "t", SupportLevel: "verified", Confidence: 0.9}, 0, "t") == nil {
		t.Fatal("expected error")
	}
}

// issue_set/write/source
func TestBndFromNilSet(t *testing.T) {
	t.Parallel()
	if _, e := BuildBundleFromIssueCandidateSet(nil, nil); e == nil {
		t.Fatal("expected error")
	}
}
func TestFinSigNil(t *testing.T) {
	t.Parallel()
	if FinalizeSignature(nil, "t") == nil {
		t.Fatal("expected error")
	}
}
func TestWriteBndEmptyD(t *testing.T) {
	t.Parallel()
	b := testBundle()
	if WriteBundle("", &b, "t") == nil {
		t.Fatal("expected error")
	}
}
func TestRuleMetaNilF(t *testing.T) {
	t.Parallel()
	if RuleMetadataFromRuleFile(nil) != nil {
		t.Fatal("expected nil")
	}
}
func TestVerSrcCloneE(t *testing.T) {
	t.Parallel()
	c := VerificationSource{ReportSchemaVersion: "1"}.Clone()
	if c.ReportSchemaVersion != "1" {
		t.Fatal("bad")
	}
}

// Shared helpers
func validClaimRecord(claimID string) ClaimRecord {
	return ClaimRecord{
		ClaimID: claimID, Title: "Test Claim", Category: "architecture",
		ClaimType: "architecture", Status: "accepted", SupportLevel: "verified",
		Confidence: 0.95, SourceOrigins: []string{"code_inferred"},
		SupportingEvidenceIDs: []string{"ev-1"}, ProjectionEligible: true,
	}
}

func testBundleWithClaims() Bundle {
	b := testBundle()
	cl := validClaimRecord("claim-1")
	ca := ClaimsArtifact{SchemaVersion: ClaimsSchemaVersion, Repository: ClaimRepositoryRef{Path: "/repo", Commit: "abc123"}, Claims: []ClaimRecord{cl}, Summary: ClaimSummary{Verified: 1}}
	pr := ProfileArtifact{SchemaVersion: ProfileSchemaVersion, Repository: ClaimRepositoryRef{Path: "/repo", Commit: "abc123"},
		Highlights:      []CapabilityHighlight{{HighlightID: "hl-claim-1", Title: "Test Claim", SupportLevel: "verified", ClaimIDs: []string{"claim-1"}, SupportingEvidenceIDs: []string{"ev-1"}}},
		CapabilityAreas: []CapabilityArea{{AreaID: "architecture", Title: "Architecture and System Design", ClaimIDs: []string{"claim-1"}}},
		ClaimIDs:        []string{"claim-1"}}
	ri := ResumeInputArtifact{SchemaVersion: ResumeInputSchemaVersion, Profile: pr,
		VerifiedClaims:       []ResumeClaimStub{{ClaimID: "claim-1", Title: "Test Claim", SupportLevel: "verified", Confidence: 0.95, SupportingEvidenceIDs: []string{"ev-1"}}},
		EvidenceReferences:   []EvidenceReference{{EvidenceID: "ev-1", ClaimIDs: []string{"claim-1"}}},
		SynthesisConstraints: SynthesisConstraints{}}
	b.Claims = &ca
	b.Profile = &pr
	b.ResumeInput = &ri
	return b
}
