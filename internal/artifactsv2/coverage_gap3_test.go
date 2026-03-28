package artifactsv2

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/verabase/code-verification-engine/internal/report"
	"github.com/verabase/code-verification-engine/internal/skills"
)

// ---------- write.go: WriteBundle all file write paths ----------

func TestWriteBundleWritesSummaryAndSignature(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	bundle := testBundle()
	if err := WriteBundle(dir, &bundle, "test-signer"); err != nil {
		t.Fatalf("WriteBundle(): %v", err)
	}

	// Verify summary.md content
	summaryData, err := os.ReadFile(filepath.Join(dir, "summary.md"))
	if err != nil {
		t.Fatalf("ReadFile(summary.md): %v", err)
	}
	if len(summaryData) == 0 {
		t.Fatal("expected non-empty summary.md")
	}

	// Verify signature.json has correct signer
	var sig SignatureArtifact
	sigData, err := os.ReadFile(filepath.Join(dir, "signature.json"))
	if err != nil {
		t.Fatalf("ReadFile(signature.json): %v", err)
	}
	if err := json.Unmarshal(sigData, &sig); err != nil {
		t.Fatalf("Unmarshal(signature.json): %v", err)
	}
	if sig.SignedBy != "test-signer" {
		t.Fatalf("expected signed_by=test-signer, got %q", sig.SignedBy)
	}

	// Verify all primary JSON files are valid JSON
	for _, name := range []string{"report.json", "evidence.json", "skills.json", "trace.json"} {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("ReadFile(%s): %v", name, err)
		}
		var v any
		if err := json.Unmarshal(data, &v); err != nil {
			t.Fatalf("invalid JSON in %s: %v", name, err)
		}
	}
}

func TestWriteBundleNoClaimsProfileResume(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	bundle := testBundle()
	// Ensure claims/profile/resume are nil
	bundle.Claims = nil
	bundle.Profile = nil
	bundle.ResumeInput = nil
	if err := WriteBundle(dir, &bundle, "verabase"); err != nil {
		t.Fatalf("WriteBundle(): %v", err)
	}

	// claims.json, profile.json, resume_input.json should NOT exist
	for _, name := range []string{"claims.json", "profile.json", "resume_input.json"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err == nil {
			t.Fatalf("expected %s NOT to exist when bundle has no claims/profile/resume", name)
		}
	}
}

// ---------- hash.go: ComputeArtifactHashes all branches ----------

func TestComputeArtifactHashesBasicBundle(t *testing.T) {
	t.Parallel()

	bundle := testBundle()
	hashes, err := ComputeArtifactHashes(bundle)
	if err != nil {
		t.Fatalf("ComputeArtifactHashes(): %v", err)
	}
	expectedKeys := []string{"report.json", "evidence.json", "skills.json", "trace.json", "summary.md"}
	for _, key := range expectedKeys {
		if _, ok := hashes[key]; !ok {
			t.Fatalf("expected hash for %s", key)
		}
	}
	// Claims/profile/resume not present, so those keys should be absent
	for _, key := range []string{"claims.json", "profile.json", "resume_input.json"} {
		if _, ok := hashes[key]; ok {
			t.Fatalf("expected no hash for %s without claims/profile/resume", key)
		}
	}
}

func TestComputeArtifactHashesDeterministic(t *testing.T) {
	t.Parallel()

	bundle := testBundle()
	h1, err := ComputeArtifactHashes(bundle)
	if err != nil {
		t.Fatalf("first ComputeArtifactHashes(): %v", err)
	}
	h2, err := ComputeArtifactHashes(bundle)
	if err != nil {
		t.Fatalf("second ComputeArtifactHashes(): %v", err)
	}
	bh1 := ComputeBundleHash(h1)
	bh2 := ComputeBundleHash(h2)
	if bh1 != bh2 {
		t.Fatalf("expected deterministic bundle hash, got %s vs %s", bh1, bh2)
	}
}

// ---------- hash.go: canonicalJSON / writeCanonicalJSON full type coverage ----------

func TestCanonicalJSONHandlesFloat64(t *testing.T) {
	t.Parallel()

	// float64 values should produce deterministic JSON
	h1, err := HashJSON(map[string]any{"val": float64(3.14)})
	if err != nil {
		t.Fatalf("HashJSON(float64): %v", err)
	}
	if h1 == "" {
		t.Fatal("expected non-empty hash")
	}
}

func TestCanonicalJSONHandlesJsonNumber(t *testing.T) {
	t.Parallel()

	// json.Number type handling
	h1, err := HashJSON(map[string]any{"val": json.Number("42")})
	if err != nil {
		t.Fatalf("HashJSON(json.Number): %v", err)
	}
	if h1 == "" {
		t.Fatal("expected non-empty hash")
	}
}

func TestCanonicalJSONHandlesBool(t *testing.T) {
	t.Parallel()

	h1, err := HashJSON(true)
	if err != nil {
		t.Fatalf("HashJSON(true): %v", err)
	}
	h2, err := HashJSON(false)
	if err != nil {
		t.Fatalf("HashJSON(false): %v", err)
	}
	if h1 == h2 {
		t.Fatal("expected different hashes for true and false")
	}
}

func TestCanonicalJSONHandlesNil(t *testing.T) {
	t.Parallel()

	h, err := HashJSON(nil)
	if err != nil {
		t.Fatalf("HashJSON(nil): %v", err)
	}
	if h == "" {
		t.Fatal("expected non-empty hash for nil")
	}
}

func TestCanonicalJSONHandlesEmptyArray(t *testing.T) {
	t.Parallel()

	h, err := HashJSON([]any{})
	if err != nil {
		t.Fatalf("HashJSON([]): %v", err)
	}
	if h == "" {
		t.Fatal("expected non-empty hash for empty array")
	}
}

func TestCanonicalJSONHandlesEmptyMap(t *testing.T) {
	t.Parallel()

	h, err := HashJSON(map[string]any{})
	if err != nil {
		t.Fatalf("HashJSON({}): %v", err)
	}
	if h == "" {
		t.Fatal("expected non-empty hash for empty map")
	}
}

func TestCanonicalJSONHandlesNestedMixed(t *testing.T) {
	t.Parallel()

	data := map[string]any{
		"arr":    []any{nil, true, false, "str", float64(1.5)},
		"nested": map[string]any{"a": float64(1)},
		"null":   nil,
		"str":    "hello",
		"bool":   true,
	}
	h, err := HashJSON(data)
	if err != nil {
		t.Fatalf("HashJSON(mixed): %v", err)
	}
	if h == "" {
		t.Fatal("expected non-empty hash")
	}
}

func TestCanonicalJSONHandlesStruct(t *testing.T) {
	t.Parallel()

	// Struct should go through the default marshal->decode->canonical path
	type inner struct {
		X int `json:"x"`
	}
	type outer struct {
		A string `json:"a"`
		B inner  `json:"b"`
	}
	h, err := HashJSON(outer{A: "hello", B: inner{X: 42}})
	if err != nil {
		t.Fatalf("HashJSON(struct): %v", err)
	}
	if h == "" {
		t.Fatal("expected non-empty hash")
	}
}

// ---------- builder.go: BuildCompatArtifacts with AgentExecutor that returns no tasks ----------

func TestBuildCompatArtifactsNoAgentTasksNeeded(t *testing.T) {
	t.Parallel()

	// Issue is resolved, so no agent tasks should be generated
	input := CompatBuildInput{
		Scan: report.ScanReport{
			RepoName:     "github.com/acme/repo",
			CommitSHA:    "abc123def456",
			ScannedAt:    "2026-03-27T12:00:00Z",
			FileCount:    3,
			BoundaryMode: "repo",
		},
		Verification: VerificationSource{
			ReportSchemaVersion: "1.0.0",
			IssueSeeds: []IssueSeed{{
				RuleID:     "SEC-001",
				Title:      "Test issue",
				Source:     "rule",
				Category:   "security",
				Severity:   "low",
				Status:     "resolved",
				Confidence: 0.9,
				Quality:    1.0,
				File:       "service.ts",
				Symbol:     "getUser",
				StartLine:  10,
				EndLine:    10,
			}},
		},
		AgentExecutor: func(task AgentTask) (AgentResult, error) {
			t.Fatal("agent executor should not be called for resolved issues")
			return AgentResult{}, nil
		},
		EngineVersion: "dev",
	}

	result, err := BuildCompatArtifacts(input)
	if err != nil {
		t.Fatalf("BuildCompatArtifacts(): %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
}

// ---------- builder.go: BuildCompatBundle error fallback path ----------

func TestBuildCompatBundleReturnsMinimalBundleOnError(t *testing.T) {
	t.Parallel()

	// Force the error path by providing a scan with missing required fields
	// that won't pass validation in the compat pipeline.
	// Actually, BuildCompatBundle catches internal errors and returns a fallback.
	// We can trigger it with completely empty scan + verification.
	scan := report.ScanReport{}
	vr := report.VerificationReport{}
	bundle := BuildCompatBundle(scan, vr, nil, "dev")

	// Should return a fallback bundle with valid structure
	if bundle.Report.SchemaVersion != ReportSchemaVersion {
		t.Fatalf("expected report schema version, got %q", bundle.Report.SchemaVersion)
	}
	if bundle.Report.EngineVersion != "dev" {
		t.Fatalf("expected engine version 'dev', got %q", bundle.Report.EngineVersion)
	}
}

// ---------- claims_profile_resume.go: edge cases ----------

func TestNormalizeClaimRecordsDeduplicatesAndSkipsEmpty(t *testing.T) {
	t.Parallel()

	claims := normalizeClaimRecords([]ClaimRecord{
		{ClaimID: "c-1", Title: " Title ", Category: " cat ", ClaimType: " type ", Status: " accepted ", SupportLevel: " verified ", Reason: " reason "},
		{ClaimID: "c-1", Title: "Duplicate"},
		{ClaimID: "  ", Title: "Empty ID"},
	})
	if len(claims) != 1 {
		t.Fatalf("expected 1 claim after dedup/skip, got %d", len(claims))
	}
	if claims[0].Title != "Title" || claims[0].Category != "cat" {
		t.Fatalf("expected trimmed fields, got %#v", claims[0])
	}
}

// ---------- adapt_current.go: buildReportSkillScores with skill score calculation ----------

func TestBuildReportSummaryWithSkillReport(t *testing.T) {
	t.Parallel()

	issues := []Issue{{Severity: "medium"}}
	sr := &skills.Report{
		Signals: []skills.Signal{
			{SkillID: "backend", Status: skills.StatusObserved, Confidence: skills.ConfidenceHigh, EvidenceStrength: skills.EvidenceDirect},
			{SkillID: "frontend", Status: skills.StatusInferred, Confidence: skills.ConfidenceMedium, EvidenceStrength: skills.EvidenceStructural},
		},
	}
	summary := buildReportSummary(issues, sr)
	if summary.OverallScore < 0 || summary.OverallScore > 1 {
		t.Fatalf("expected score in [0,1], got %f", summary.OverallScore)
	}
}

// ---------- confidence.go: computeRuleMetadataReliability empty ruleIDs ----------

func TestComputeRuleMetadataReliabilityEmptyInputs(t *testing.T) {
	t.Parallel()

	if got := computeRuleMetadataReliability(nil, nil); got != 0 {
		t.Fatalf("expected 0 for nil inputs, got %f", got)
	}
	if got := computeRuleMetadataReliability([]string{"R-1"}, nil); got != 0 {
		t.Fatalf("expected 0 for nil metadata, got %f", got)
	}
	if got := computeRuleMetadataReliability(nil, map[string]RuleMetadata{"R-1": {}}); got != 0 {
		t.Fatalf("expected 0 for nil ruleIDs, got %f", got)
	}
	// Non-matching ruleID
	if got := computeRuleMetadataReliability([]string{"UNKNOWN"}, map[string]RuleMetadata{"R-1": {}}); got != 0 {
		t.Fatalf("expected 0 for non-matching ruleID, got %f", got)
	}
}

// ---------- FinalizeSignature: invalid bundle should fail ----------

func TestFinalizeSignatureInvalidBundle(t *testing.T) {
	t.Parallel()

	bundle := Bundle{} // completely invalid bundle
	if err := FinalizeSignature(&bundle, "test"); err == nil {
		t.Fatal("expected error for invalid bundle")
	}
}

// ---------- BuildBundleFromIssueCandidateSet with valid input ----------

func TestBuildBundleFromIssueCandidateSetValidInput(t *testing.T) {
	t.Parallel()

	input := CompatBuildInput{
		Scan: report.ScanReport{
			RepoName:     "github.com/acme/repo",
			CommitSHA:    "abc123def456",
			ScannedAt:    "2026-03-27T12:00:00Z",
			FileCount:    3,
			BoundaryMode: "repo",
		},
		Verification: VerificationSource{
			ReportSchemaVersion: "1.0.0",
			IssueSeeds: []IssueSeed{{
				RuleID:     "SEC-001",
				Title:      "Test",
				Source:     "rule",
				Category:   "security",
				Severity:   "high",
				Status:     "open",
				Confidence: 0.9,
				Quality:    1.0,
				File:       "service.ts",
				Symbol:     "getUser",
				StartLine:  10,
				EndLine:    10,
			}},
		},
		EngineVersion: "dev",
	}

	set, err := BuildIssueCandidateSet(IssueCandidateBuildInput{
		Scan:          input.Scan,
		Verification:  input.Verification,
		EngineVersion: input.EngineVersion,
	})
	if err != nil {
		t.Fatalf("BuildIssueCandidateSet(): %v", err)
	}

	bundle, err := BuildBundleFromIssueCandidateSet(set, nil)
	if err != nil {
		t.Fatalf("BuildBundleFromIssueCandidateSet(): %v", err)
	}
	if err := ValidateBundle(bundle); err != nil {
		t.Fatalf("ValidateBundle(): %v", err)
	}
}

// ---------- adapt_current.go: buildTraceArtifact with both findings and seeds ----------

func TestBuildTraceArtifactWithFindingsAndResolvedSeedSkipsDerivation(t *testing.T) {
	t.Parallel()

	scan := report.ScanReport{
		RepoName:     "github.com/acme/repo",
		CommitSHA:    "abc123",
		ScannedAt:    "2026-03-27T12:00:00Z",
		FileCount:    5,
		BoundaryMode: "repo",
	}
	verification := VerificationSource{
		ReportSchemaVersion: "1.0.0",
		IssueSeeds: []IssueSeed{{
			RuleID:      "SEC-001",
			Title:       "Resolved issue",
			Source:      "rule",
			Category:    "security",
			Severity:    "high",
			Status:      "resolved",
			Confidence:  0.9,
			Quality:     1.0,
			File:        "service.ts",
			Symbol:      "getUser",
			StartLine:   10,
			EndLine:     10,
			EvidenceIDs: []string{"ev-1"},
		}},
	}
	evidence := EvidenceArtifact{
		SchemaVersion: EvidenceSchemaVersion,
		EngineVersion: "dev",
		Repo:          "github.com/acme/repo",
		Commit:        "abc123",
		Timestamp:     "2026-03-27T12:00:00Z",
		Evidence: []EvidenceRecord{{
			ID:              "ev-1",
			Kind:            "rule_assertion",
			Source:          "rule",
			ProducerID:      "rule:SEC-001",
			ProducerVersion: "1.0.0",
			Repo:            "github.com/acme/repo",
			Commit:          "abc123",
			BoundaryHash:    "sha256:x",
			FactQuality:     "proof",
			Locations:       []LocationRef{{RepoRelPath: "service.ts", StartLine: 10, EndLine: 10}},
			Claims:          []string{"SEC-001"},
			CreatedAt:       "2026-03-27T12:00:00Z",
		}},
	}

	trace := buildTraceArtifact(scan, verification, evidence, "trace-abc123", "dev", nil)
	// Resolved seed should produce a rule trace but skip derivation
	if len(trace.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(trace.Rules))
	}
}

// ---------- source.go: RuleMetadataFromRuleFile nil input ----------

func TestRuleMetadataFromRuleFileNil(t *testing.T) {
	t.Parallel()

	got := RuleMetadataFromRuleFile(nil)
	if got != nil {
		t.Fatalf("expected nil for nil input, got %#v", got)
	}
}

// ---------- adapt_current.go: buildTraceArtifact uses scan.Analyzers fallback ----------

func TestBuildTraceArtifactUsesScanAnalyzersFallback(t *testing.T) {
	t.Parallel()

	scan := report.ScanReport{
		RepoName:     "github.com/acme/repo",
		CommitSHA:    "abc123",
		ScannedAt:    "2026-03-27T12:00:00Z",
		FileCount:    5,
		BoundaryMode: "repo",
		Analyzers:    map[string]string{"go": "ok", "python": "partial"},
	}
	verification := VerificationSource{
		ReportSchemaVersion: "1.0.0",
		// No AnalyzerStatuses -> should use scan.Analyzers
	}
	evidence := EvidenceArtifact{
		SchemaVersion: EvidenceSchemaVersion,
		EngineVersion: "dev",
		Repo:          "github.com/acme/repo",
		Commit:        "abc123",
		Timestamp:     "2026-03-27T12:00:00Z",
	}

	trace := buildTraceArtifact(scan, verification, evidence, "trace-abc123", "dev", nil)
	if len(trace.Analyzers) != 2 {
		t.Fatalf("expected 2 analyzers from scan fallback, got %d", len(trace.Analyzers))
	}
	// Check degraded flag
	for _, a := range trace.Analyzers {
		if a.Name == "python" && !a.Degraded {
			t.Fatal("expected python analyzer to be marked degraded")
		}
	}
}

// ---------- agent.go: executeAgentTasks sorting ----------

func TestExecuteAgentTasksSortsDeterministically(t *testing.T) {
	t.Parallel()

	tasks := []AgentTask{
		{ID: "agent-b", Kind: "security", IssueID: "iss-2", Context: ContextBundle{ID: "ctx-1"}},
		{ID: "agent-a", Kind: "bug", IssueID: "iss-1", Context: ContextBundle{ID: "ctx-2"}},
	}
	results, err := executeAgentTasks(tasks, func(task AgentTask) (AgentResult, error) {
		return AgentResult{Status: "completed"}, nil
	})
	if err != nil {
		t.Fatalf("executeAgentTasks(): %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
	// Should be sorted by TaskID
	if results[0].TaskID != "agent-a" {
		t.Fatalf("expected results sorted by task ID, first got %q", results[0].TaskID)
	}
}

// ---------- adapt_current.go: buildReportSkillScores sorting ----------

func TestBuildReportSkillScoresSortsAlphabetically(t *testing.T) {
	t.Parallel()

	sr := &skills.Report{
		Signals: []skills.Signal{
			{SkillID: "zebra", Status: skills.StatusObserved, Confidence: skills.ConfidenceHigh},
			{SkillID: "alpha", Status: skills.StatusObserved, Confidence: skills.ConfidenceMedium},
		},
	}
	scores := buildReportSkillScores(sr)
	if len(scores) != 2 {
		t.Fatalf("expected 2 scores, got %d", len(scores))
	}
	if scores[0].SkillID != "alpha" {
		t.Fatalf("expected sorted by skill ID, first got %q", scores[0].SkillID)
	}
}

// ---------- validate.go: ValidateBundle evidence/skills/trace errors ----------

func TestValidateBundleRejectsInvalidEvidence(t *testing.T) {
	t.Parallel()

	b := testBundle()
	b.Evidence.SchemaVersion = ""
	if err := ValidateBundle(b); err == nil {
		t.Fatal("expected error for invalid evidence in bundle")
	}
}

func TestValidateBundleRejectsInvalidSkills(t *testing.T) {
	t.Parallel()

	b := testBundle()
	b.Skills.SchemaVersion = ""
	if err := ValidateBundle(b); err == nil {
		t.Fatal("expected error for invalid skills in bundle")
	}
}

func TestValidateBundleRejectsInvalidTrace(t *testing.T) {
	t.Parallel()

	b := testBundle()
	b.Trace.SchemaVersion = ""
	if err := ValidateBundle(b); err == nil {
		t.Fatal("expected error for invalid trace in bundle")
	}
}

func TestValidateBundleRejectsInvalidReport(t *testing.T) {
	t.Parallel()

	b := testBundle()
	b.Report.SchemaVersion = ""
	if err := ValidateBundle(b); err == nil {
		t.Fatal("expected error for invalid report in bundle")
	}
}

// ---------- reliabilityForRuleMetadata: familyBaseline+categoryBaseline both positive ----------

func TestReliabilityForRuleMetadataFamilyAndCategoryBothPositive(t *testing.T) {
	t.Parallel()

	// Has both family baseline (from matcher/trust) and category baseline
	got := reliabilityForRuleMetadata(RuleMetadata{
		RuleID:         "CUSTOM-001",
		MatcherClass:   "proof_matcher",
		TrustClass:     "machine_trusted",
		MigrationState: "issue_native",
		Category:       "security",
	})
	if got <= 0 || got > 1 {
		t.Fatalf("expected valid reliability, got %f", got)
	}
}

func TestReliabilityForRuleMetadataOnlyCategoryNoFamily(t *testing.T) {
	t.Parallel()

	// No matcher/trust class -> familyBaseline is 0, should use categoryBaseline
	got := reliabilityForRuleMetadata(RuleMetadata{
		RuleID:         "CUSTOM-001",
		MatcherClass:   "",
		TrustClass:     "",
		MigrationState: "finding_bridged",
		Category:       "testing",
	})
	if got <= 0 {
		t.Fatalf("expected positive reliability from category, got %f", got)
	}
}
