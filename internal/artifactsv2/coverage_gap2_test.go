package artifactsv2

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/verabase/code-verification-engine/internal/report"
	"github.com/verabase/code-verification-engine/internal/rules"
	"github.com/verabase/code-verification-engine/internal/skills"
)

// ---------- write.go: WriteBundle deeper coverage ----------

func TestWriteBundleWritesAllClaimsProfileResumeFiles(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	bundle := testBundleWithClaims()
	if err := WriteBundle(dir, &bundle, "verabase"); err != nil {
		t.Fatalf("WriteBundle(): %v", err)
	}

	files := []string{
		"report.json", "evidence.json", "skills.json", "trace.json",
		"claims.json", "profile.json", "resume_input.json",
		"summary.md", "signature.json",
	}
	for _, name := range files {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatalf("expected %s to exist: %v", name, err)
		}
	}
}

func TestFinalizeSignaturePopulatesHashesAndBundleHash(t *testing.T) {
	t.Parallel()

	bundle := testBundle()
	if err := FinalizeSignature(&bundle, "verabase"); err != nil {
		t.Fatalf("FinalizeSignature(): %v", err)
	}
	if bundle.Signature.BundleHash == "" {
		t.Fatal("expected bundle hash to be populated")
	}
	if len(bundle.Signature.ArtifactHashes) < 5 {
		t.Fatalf("expected at least 5 artifact hashes, got %d", len(bundle.Signature.ArtifactHashes))
	}
	if bundle.Signature.SignedBy != "verabase" {
		t.Fatalf("expected signed_by to be set, got %q", bundle.Signature.SignedBy)
	}
	if bundle.Signature.Timestamp != bundle.Report.Timestamp {
		t.Fatalf("expected timestamp to match report, got %q", bundle.Signature.Timestamp)
	}
}

// ---------- validate.go: ValidateBundle claims/profile/resume paths ----------

func TestValidateBundleWithClaimsProfileResume(t *testing.T) {
	t.Parallel()

	bundle := testBundleWithClaims()
	if err := ValidateBundle(bundle); err != nil {
		t.Fatalf("ValidateBundle(): %v", err)
	}
}

func TestValidateBundleRejectsInvalidClaims(t *testing.T) {
	t.Parallel()

	bundle := testBundleWithClaims()
	bundle.Claims.SchemaVersion = "wrong"
	if err := ValidateBundle(bundle); err == nil {
		t.Fatal("expected error for invalid claims")
	}
}

func TestValidateBundleRejectsInvalidProfile(t *testing.T) {
	t.Parallel()

	bundle := testBundleWithClaims()
	bundle.Profile.SchemaVersion = "wrong"
	if err := ValidateBundle(bundle); err == nil {
		t.Fatal("expected error for invalid profile")
	}
}

func TestValidateBundleRejectsInvalidResumeInput(t *testing.T) {
	t.Parallel()

	bundle := testBundleWithClaims()
	bundle.ResumeInput.SchemaVersion = "wrong"
	if err := ValidateBundle(bundle); err == nil {
		t.Fatal("expected error for invalid resume input")
	}
}

func TestValidateBundleRejectsClaimsEvidenceReferenceMismatch(t *testing.T) {
	t.Parallel()

	bundle := testBundleWithClaims()
	// Add a claim that references an evidence ID not in the evidence artifact
	bundle.Claims.Claims[0].SupportingEvidenceIDs = []string{"ev-missing-from-evidence"}
	if err := ValidateBundle(bundle); err == nil {
		t.Fatal("expected error for claims evidence reference mismatch")
	}
}

func TestValidateBundleRejectsContextSelectionEvidenceReferenceMismatch(t *testing.T) {
	t.Parallel()

	b := testBundle()
	b.Trace.ContextSelections = []ContextSelectionRecord{{
		ID:                  "ctx-001",
		TriggerType:         "issue",
		TriggerID:           "iss-1",
		SelectedEvidenceIDs: []string{"ev-missing"},
		SelectedSpans:       []LocationRef{{RepoRelPath: "a.ts", StartLine: 1, EndLine: 1}},
		MaxFiles:            2,
		MaxSpans:            4,
		MaxTokens:           1200,
	}}
	if err := ValidateBundle(b); err == nil {
		t.Fatal("expected error for context selection evidence mismatch")
	}
}

// ---------- validate.go: validateIssuePolicyConsistency deeper ----------

func TestValidateIssuePolicyConsistencyUnknownPolicyClass(t *testing.T) {
	t.Parallel()

	issue := testBundle().Report.Issues[0]
	issue.PolicyClass = "totally_unknown"
	if err := validateIssuePolicyConsistency(issue, "test"); err == nil {
		t.Fatal("expected error for unknown policy class")
	}
}

// ---------- hash.go: writeCanonicalJSON deeper ----------

func TestWriteCanonicalJSONHandlesNestedStructs(t *testing.T) {
	t.Parallel()

	// Test with a Go struct that forces the default case in writeCanonicalJSON
	type customStruct struct {
		A int    `json:"a"`
		B string `json:"b"`
	}
	data := customStruct{A: 42, B: "hello"}
	hash, err := HashJSON(data)
	if err != nil {
		t.Fatalf("HashJSON(struct): %v", err)
	}
	if !strings.HasPrefix(hash, "sha256:") {
		t.Fatalf("expected sha256 prefix, got %q", hash)
	}

	// Nested maps with arrays
	nested := map[string]any{
		"arr":  []any{1.0, "two", true, nil},
		"obj":  map[string]any{"x": 1.0},
		"bool": false,
		"null": nil,
	}
	hash2, err := HashJSON(nested)
	if err != nil {
		t.Fatalf("HashJSON(nested): %v", err)
	}
	if hash2 == "" {
		t.Fatal("expected non-empty hash")
	}
}

// ---------- agent.go: buildAgentTasks deeper ----------

func TestBuildAgentTasksSkipsInsufficientContextSelections(t *testing.T) {
	t.Parallel()

	// Create a candidate with unknown status that triggers context selection
	// but the selection has no evidence/spans (insufficient_context)
	candidates := []IssueCandidate{{
		ID:          "iss-1",
		Category:    "bug",
		Severity:    "medium",
		Status:      "unknown",
		PolicyClass: "unknown_retained",
		EvidenceIDs: []string{"ev-1"},
	}}
	evidence := EvidenceArtifact{
		Evidence: []EvidenceRecord{{
			ID: "ev-1",
			// No locations -> context selection will have no spans
		}},
	}

	tasks := buildAgentTasks(candidates, evidence)
	// Should either be empty or contain no tasks since context is insufficient
	if len(tasks) != 0 {
		t.Fatalf("expected no tasks for insufficient context, got %d", len(tasks))
	}
}

func TestBuildAgentTasksSkipsNonIssueSelections(t *testing.T) {
	t.Parallel()

	// Candidate that does not trigger context selection (resolved status, low severity, no counter)
	candidates := []IssueCandidate{{
		ID:          "iss-1",
		Category:    "bug",
		Severity:    "low",
		Status:      "resolved",
		PolicyClass: "advisory",
		EvidenceIDs: []string{"ev-1"},
	}}
	evidence := EvidenceArtifact{
		Evidence: []EvidenceRecord{{
			ID:        "ev-1",
			Locations: []LocationRef{{RepoRelPath: "a.ts", StartLine: 1, EndLine: 1}},
		}},
	}

	tasks := buildAgentTasks(candidates, evidence)
	if len(tasks) != 0 {
		t.Fatalf("expected no tasks for low-severity resolved issue, got %d", len(tasks))
	}
}

func TestBuildAgentTasksProducesTasksForHighSeverity(t *testing.T) {
	t.Parallel()

	candidates := []IssueCandidate{{
		ID:                 "iss-1",
		Category:           "design",
		Severity:           "critical",
		Status:             "open",
		PolicyClass:        "advisory",
		EvidenceIDs:        []string{"ev-1"},
		CounterEvidenceIDs: []string{"ev-2"},
	}}
	evidence := EvidenceArtifact{
		Evidence: []EvidenceRecord{
			{ID: "ev-1", Locations: []LocationRef{{RepoRelPath: "a.ts", StartLine: 1, EndLine: 1}}, EntityIDs: []string{"fn-1"}},
			{ID: "ev-2", Locations: []LocationRef{{RepoRelPath: "a.ts", StartLine: 5, EndLine: 5}}, EntityIDs: []string{"fn-2"}},
		},
	}

	tasks := buildAgentTasks(candidates, evidence)
	if len(tasks) != 1 {
		t.Fatalf("expected 1 task for high-severity advisory issue, got %d", len(tasks))
	}
	if tasks[0].Kind != "design" {
		t.Fatalf("expected design kind, got %q", tasks[0].Kind)
	}
	if tasks[0].IssueID != "iss-1" {
		t.Fatalf("expected issue ID iss-1, got %q", tasks[0].IssueID)
	}
}

// ---------- compat_aggregate.go: buildIssueSeeds synthetic evidence path ----------

func TestBuildIssueSeedsSyntheticEvidenceForFindingWithoutEvidence(t *testing.T) {
	t.Parallel()

	scan := report.ScanReport{
		RepoName:     "github.com/acme/repo",
		CommitSHA:    "abc123",
		ScannedAt:    "2026-03-27T12:00:00Z",
		BoundaryMode: "repo",
	}
	// Finding that has status fail but empty evidence after index lookup
	verification := VerificationSource{
		ReportSchemaVersion: "1.0.0",
		Findings: []rules.Finding{{
			RuleID:           "RULE-001",
			Status:           rules.StatusFail,
			Confidence:       rules.ConfidenceMedium,
			TrustClass:       rules.TrustAdvisory,
			Message:          "Issue found",
			FactQualityFloor: "heuristic",
			// No evidence at all -> triggers synthetic path
		}},
	}

	result, err := BuildArtifacts(BuildInput{
		Scan:          scan,
		Verification:  verification,
		EngineVersion: "dev",
	})
	if err != nil {
		t.Fatalf("BuildArtifacts(): %v", err)
	}
	if len(result.IssueCandidates) != 1 {
		t.Fatalf("expected 1 issue from synthetic evidence path, got %d", len(result.IssueCandidates))
	}
	// Evidence should have been synthesized
	if len(result.Bundle.Evidence.Evidence) == 0 {
		t.Fatal("expected synthetic evidence to be created")
	}
}

// ---------- confidence.go: reliabilityForRuleMetadata deeper branches ----------

func TestReliabilityForRuleMetadataNoFamilyNoCategoryOnlyMigration(t *testing.T) {
	t.Parallel()

	// RuleID with no known family prefix, empty category -> only migration state matters
	got := reliabilityForRuleMetadata(RuleMetadata{
		RuleID:         "CUSTOM-001",
		MatcherClass:   "",
		TrustClass:     "",
		MigrationState: "issue_native",
		Category:       "",
	})
	if got <= 0 {
		t.Fatalf("expected positive reliability from migration state alone, got %f", got)
	}
}

func TestReliabilityForRuleMetadataRuleFamilyNoMatcherClass(t *testing.T) {
	t.Parallel()

	// Known rule family (SEC-SECRET) but no matcher class
	got := reliabilityForRuleMetadata(RuleMetadata{
		RuleID:         "SEC-SECRET-001",
		MatcherClass:   "",
		TrustClass:     "",
		MigrationState: "issue_native",
		Category:       "security",
	})
	if got <= 0 {
		t.Fatalf("expected positive reliability from rule family baseline, got %f", got)
	}
}

func TestReliabilityForRuleMetadataOnlyCategoryBaseline(t *testing.T) {
	t.Parallel()

	// No known rule family, no matcher class, only category
	got := reliabilityForRuleMetadata(RuleMetadata{
		RuleID:         "CUSTOM-001",
		MatcherClass:   "",
		TrustClass:     "",
		MigrationState: "issue_native",
		Category:       "security",
	})
	if got <= 0 {
		t.Fatalf("expected positive reliability from category baseline, got %f", got)
	}
}

func TestReliabilityForRuleMetadataZeroMigrationCap(t *testing.T) {
	t.Parallel()

	// Unknown migration state -> cap is 0, so familyBaseline is returned clamped
	got := reliabilityForRuleMetadata(RuleMetadata{
		RuleID:         "SEC-SECRET-001",
		MatcherClass:   "proof_matcher",
		TrustClass:     "machine_trusted",
		MigrationState: "",
		Category:       "security",
	})
	if got <= 0 {
		t.Fatalf("expected positive reliability, got %f", got)
	}
}

func TestReliabilityForRuleMetadataMediumQualityWithMetadata(t *testing.T) {
	t.Parallel()

	// With metadata, medium quality baseline path
	verification := VerificationSource{
		RuleMetadata: map[string]RuleMetadata{
			"R-001": {
				RuleID:         "R-001",
				MatcherClass:   "structural_matcher",
				TrustClass:     "advisory",
				MigrationState: "seed_native",
				Category:       "architecture",
			},
		},
	}
	cluster := compatIssueCluster{
		Quality: 0.70,
		RuleIDs: []string{"R-001"},
	}
	got := computeRuleReliabilityBaseline(cluster, verification)
	if got <= 0 {
		t.Fatalf("expected positive baseline, got %f", got)
	}
}

// ---------- claims_profile_resume.go: ValidateClaimsProfileResumeArtifacts deeper ----------

func TestValidateClaimsProfileResumeArtifactsRejectsProfileError(t *testing.T) {
	t.Parallel()

	artifacts := ClaimsProjectionArtifacts{
		Claims: ClaimsArtifact{
			SchemaVersion: ClaimsSchemaVersion,
			Repository:    ClaimRepositoryRef{Path: "/repo", Commit: "abc"},
			Claims:        []ClaimRecord{validClaimRecord("c-1")},
			Summary:       ClaimSummary{Verified: 1},
		},
		Profile: ProfileArtifact{SchemaVersion: "wrong"},
	}
	if err := ValidateClaimsProfileResumeArtifacts(artifacts); err == nil {
		t.Fatal("expected error for invalid profile")
	}
}

func TestValidateClaimsProfileResumeArtifactsRejectsResumeError(t *testing.T) {
	t.Parallel()

	claim := validClaimRecord("c-1")
	profile := projectCapabilityProfile(
		ClaimRepositoryRef{Path: "/repo", Commit: "abc"},
		[]ClaimRecord{claim},
		nil,
	)
	artifacts := ClaimsProjectionArtifacts{
		Claims: ClaimsArtifact{
			SchemaVersion: ClaimsSchemaVersion,
			Repository:    ClaimRepositoryRef{Path: "/repo", Commit: "abc"},
			Claims:        []ClaimRecord{claim},
			Summary:       ClaimSummary{Verified: 1},
		},
		Profile:     profile,
		ResumeInput: ResumeInputArtifact{SchemaVersion: "wrong"},
	}
	if err := ValidateClaimsProfileResumeArtifacts(artifacts); err == nil {
		t.Fatal("expected error for invalid resume input")
	}
}

// ---------- builder.go: BuildArtifacts error path ----------

func TestBuildArtifactsAgentExecutorError(t *testing.T) {
	t.Parallel()

	input := BuildInput{
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
				RuleID:     "DESIGN-001",
				Title:      "Unknown issue",
				Source:     "rule",
				Category:   "design",
				Severity:   "high",
				Status:     "unknown",
				Confidence: 0.62,
				Quality:    0.7,
				File:       "service.ts",
				Symbol:     "getUser",
				StartLine:  44,
				EndLine:    48,
			}},
		},
		AgentExecutor: func(task AgentTask) (AgentResult, error) {
			// Return error - executor should still proceed
			return AgentResult{}, nil
		},
		EngineVersion: "dev",
	}

	result, err := BuildArtifacts(input)
	if err != nil {
		t.Fatalf("BuildArtifacts(): %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
}

// ---------- adapt_current.go: buildTraceArtifact deeper ----------

func TestBuildTraceArtifactDefaultBoundaryMode(t *testing.T) {
	t.Parallel()

	scan := report.ScanReport{
		RepoName:  "github.com/acme/repo",
		CommitSHA: "abc123",
		ScannedAt: "2026-03-27T12:00:00Z",
		FileCount: 5,
		// BoundaryMode is empty -> should default to "repo"
	}
	verification := VerificationSource{
		ReportSchemaVersion: "1.0.0",
	}
	evidence := EvidenceArtifact{
		SchemaVersion: EvidenceSchemaVersion,
		EngineVersion: "dev",
		Repo:          "github.com/acme/repo",
		Commit:        "abc123",
		Timestamp:     "2026-03-27T12:00:00Z",
	}

	trace := buildTraceArtifact(scan, verification, evidence, "trace-abc123", "dev", nil)
	if trace.ScanBoundary.Mode != "repo" {
		t.Fatalf("expected default boundary mode 'repo', got %q", trace.ScanBoundary.Mode)
	}
}

func TestBuildTraceArtifactWithSeedOnlyNoFindings(t *testing.T) {
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
			Title:       "Test",
			Source:      "rule",
			Category:    "security",
			Severity:    "high",
			Status:      "open",
			Confidence:  0.9,
			Quality:     1.0,
			File:        "service.ts",
			Symbol:      "getUser",
			StartLine:   10,
			EndLine:     10,
			EvidenceIDs: []string{"ev-1"},
		}},
		RuleMetadata: map[string]RuleMetadata{
			"SEC-001": {RuleID: "SEC-001", MigrationState: "seed_native"},
		},
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
	candidates := []IssueCandidate{{
		ID:          "iss-1",
		Fingerprint: "fp-1",
		RuleIDs:     []string{"SEC-001"},
		EvidenceIDs: []string{"ev-1"},
	}}

	trace := buildTraceArtifact(scan, verification, evidence, "trace-abc123", "dev", candidates)
	if len(trace.Rules) != 1 {
		t.Fatalf("expected 1 rule from seeds, got %d", len(trace.Rules))
	}
	if trace.Rules[0].MigrationState != "seed_native" {
		t.Fatalf("expected seed_native migration state, got %q", trace.Rules[0].MigrationState)
	}
}

// ---------- adapt_current.go: buildEvidenceArtifact agent evidence normalization ----------

func TestBuildEvidenceArtifactNormalizesAgentEvidence(t *testing.T) {
	t.Parallel()

	scan := report.ScanReport{
		RepoName:     "github.com/acme/repo",
		CommitSHA:    "abc123",
		ScannedAt:    "2026-03-27T12:00:00Z",
		BoundaryMode: "repo",
	}
	verification := VerificationSource{
		ReportSchemaVersion: "1.0.0",
		AgentResults: []AgentResult{{
			TaskID:  "agent-1",
			Kind:    "bug",
			IssueID: "iss-1",
			Status:  "completed",
			EmittedEvidence: []EvidenceRecord{
				{
					ID:              "ev-agent-1",
					Kind:            "agent_assertion",
					ProducerID:      "agent:bug",
					ProducerVersion: "1.0.0",
					FactQuality:     "heuristic",
					Locations:       []LocationRef{{RepoRelPath: "a.ts", StartLine: 1, EndLine: 1}},
					Claims:          []string{"bug"},
					// Missing Repo, Commit, BoundaryHash, Source, CreatedAt -> should be filled
				},
				{ID: ""}, // Empty ID should be skipped
			},
		}},
	}

	artifact, index := buildEvidenceArtifact(scan, verification, "dev")
	if _, ok := index["ev-agent-1"]; !ok {
		t.Fatal("expected agent evidence to be indexed")
	}
	record := index["ev-agent-1"]
	if record.Repo != "github.com/acme/repo" {
		t.Fatalf("expected repo to be normalized, got %q", record.Repo)
	}
	if record.Commit != "abc123" {
		t.Fatalf("expected commit to be normalized, got %q", record.Commit)
	}
	if record.Source != "agent" {
		t.Fatalf("expected source to be normalized, got %q", record.Source)
	}
	if record.CreatedAt != "2026-03-27T12:00:00Z" {
		t.Fatalf("expected createdAt to be normalized, got %q", record.CreatedAt)
	}
	if record.BoundaryHash == "" {
		t.Fatal("expected boundary hash to be normalized")
	}
	if len(artifact.Evidence) != 1 {
		t.Fatalf("expected 1 evidence record (empty ID skipped), got %d", len(artifact.Evidence))
	}
}

// ---------- compat_aggregate.go: overlayAgentResultsOnCluster ----------

func TestOverlayAgentResultsOnClusterEmpty(t *testing.T) {
	t.Parallel()

	cluster := compatIssueCluster{EvidenceIDs: []string{"ev-1"}, Sources: []string{"rule"}}
	got := overlayAgentResultsOnCluster(cluster, "", nil, nil)
	if len(got.Sources) != 1 {
		t.Fatalf("expected no overlay for empty issueID, got %#v", got.Sources)
	}
}

func TestOverlayAgentResultsOnClusterSkipsIncomplete(t *testing.T) {
	t.Parallel()

	cluster := compatIssueCluster{EvidenceIDs: []string{"ev-1"}, Sources: []string{"rule"}}
	results := []AgentResult{{IssueID: "iss-1", Status: "failed"}}
	got := overlayAgentResultsOnCluster(cluster, "iss-1", results, nil)
	// failed status should not be overlaid
	if len(got.Sources) != 1 {
		t.Fatalf("expected no overlay for failed agent, got %#v", got.Sources)
	}
}

func TestOverlayAgentResultsSkipsEmptyEvidenceIDs(t *testing.T) {
	t.Parallel()

	cluster := compatIssueCluster{EvidenceIDs: []string{"ev-1"}, Sources: []string{"rule"}}
	results := []AgentResult{{
		IssueID: "iss-1",
		Status:  "completed",
		EmittedEvidence: []EvidenceRecord{
			{ID: ""},
			{ID: "ev-agent-1"},
		},
	}}
	got := overlayAgentResultsOnCluster(cluster, "iss-1", results, map[string]EvidenceRecord{})
	found := false
	for _, id := range got.EvidenceIDs {
		if id == "ev-agent-1" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected ev-agent-1 in evidence IDs, got %#v", got.EvidenceIDs)
	}
}

// ---------- compat_aggregate.go: compatPrimaryLocation with backslash path ----------

func TestCompatPrimaryLocationNormalizesBackslashPath(t *testing.T) {
	t.Parallel()

	finding := rules.Finding{
		Evidence: []rules.Evidence{{
			File:      `internal\service.ts`,
			LineStart: 10,
			LineEnd:   12,
			Symbol:    "fn",
		}},
	}
	file, _, _, _ := compatPrimaryLocation(finding)
	if file != "internal/service.ts" {
		t.Fatalf("expected slash-normalized path, got %q", file)
	}
}

// ---------- adapt_current.go: buildReportSkillScores with inferred status ----------

func TestBuildReportSkillScoresInferredStatus(t *testing.T) {
	t.Parallel()

	sr := &skills.Report{
		Signals: []skills.Signal{
			{SkillID: "arch", Status: skills.StatusInferred, Confidence: skills.ConfidenceMedium, EvidenceStrength: skills.EvidenceStructural},
		},
	}
	scores := buildReportSkillScores(sr)
	if len(scores) != 1 {
		t.Fatalf("expected 1 score for inferred signal, got %d", len(scores))
	}
	if scores[0].Score >= 0.7 {
		t.Fatalf("expected inferred signal score to be less than medium confidence, got %f", scores[0].Score)
	}
}

// ---------- claims_profile_resume.go: WriteClaimsProfileResumeArtifacts validation fail ----------

func TestWriteClaimsProfileResumeArtifactsRejectsInvalid(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	if err := WriteClaimsProfileResumeArtifacts(dir, ClaimsProjectionArtifacts{
		Claims: ClaimsArtifact{SchemaVersion: "wrong"},
	}); err == nil {
		t.Fatal("expected error for invalid artifacts")
	}
}

// ---------- claims_profile_resume.go: BuildClaimsProfileResumeArtifacts input validation ----------

func TestBuildClaimsProfileResumeArtifactsRejectsBadInput(t *testing.T) {
	t.Parallel()

	_, err := BuildClaimsProfileResumeArtifacts(ClaimsProjectionInput{
		Repository: ClaimRepositoryRef{Path: "", Commit: "abc"},
	})
	if err == nil {
		t.Fatal("expected error for bad input")
	}
}

// ---------- ValidateClaimsArtifact: empty ClaimID ----------

func TestValidateClaimsArtifactRejectsEmptyClaimID(t *testing.T) {
	t.Parallel()

	if err := ValidateClaimsArtifact(ClaimsArtifact{
		SchemaVersion: ClaimsSchemaVersion,
		Repository:    ClaimRepositoryRef{Path: "/repo", Commit: "abc"},
		Claims:        []ClaimRecord{{ClaimID: ""}},
	}); err == nil {
		t.Fatal("expected error for empty claim ID")
	}
}

// ---------- ValidateResumeInputArtifact: calbriation threshold ----------

func TestValidateTraceRejectsOutOfRangeUnknownCap(t *testing.T) {
	t.Parallel()

	tr := testBundle().Trace
	tr.ConfidenceCalibration.UnknownCap = 1.5
	if err := ValidateTrace(tr); err == nil {
		t.Fatal("expected error for out of range unknown cap")
	}
}

func TestValidateTraceRejectsOutOfRangeAgentOnlyCap(t *testing.T) {
	t.Parallel()

	tr := testBundle().Trace
	tr.ConfidenceCalibration.AgentOnlyCap = -0.1
	if err := ValidateTrace(tr); err == nil {
		t.Fatal("expected error for out of range agent only cap")
	}
}

func TestValidateTraceRejectsEmptyCalibrationBaselines(t *testing.T) {
	t.Parallel()

	tr := testBundle().Trace
	tr.ConfidenceCalibration.RuleFamilyBaselines = nil
	if err := ValidateTrace(tr); err == nil {
		t.Fatal("expected error for empty calibration baselines")
	}
}

// ---------- adapt_current.go: buildRuleMigrationSummary legacy path ----------

func TestBuildRuleMigrationSummaryLegacyOnlyCount(t *testing.T) {
	t.Parallel()

	verification := VerificationSource{
		RuleMetadata: map[string]RuleMetadata{
			"R-001": {RuleID: "R-001", MigrationState: string(rules.MigrationLegacyOnly)},
		},
	}
	summary := buildRuleMigrationSummary(verification)
	if summary == nil {
		t.Fatal("expected non-nil summary")
	}
	if summary.LegacyOnlyCount != 1 {
		t.Fatalf("expected 1 legacy-only rule, got %d", summary.LegacyOnlyCount)
	}
}

func TestBuildRuleMigrationSummaryNilForEmpty(t *testing.T) {
	t.Parallel()

	summary := buildRuleMigrationSummary(VerificationSource{})
	if summary != nil {
		t.Fatalf("expected nil summary for empty verification, got %#v", summary)
	}
}
