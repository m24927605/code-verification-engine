package artifactsv2

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/verabase/code-verification-engine/internal/report"
)

func TestHashJSONStableAcrossMapInsertionOrder(t *testing.T) {
	t.Parallel()

	ev1 := EvidenceRecord{
		ID:              "ev-1",
		Kind:            "ast_fact",
		Source:          "rule",
		ProducerID:      "rule:test",
		ProducerVersion: "1.0.0",
		Repo:            "github.com/acme/repo",
		Commit:          "abc123",
		BoundaryHash:    "sha256:boundary",
		FactQuality:     "proof",
		EntityIDs:       []string{"fn-1"},
		Locations:       []LocationRef{{RepoRelPath: "service.ts", StartLine: 10, EndLine: 10}},
		Claims:          []string{"null_check_missing"},
		Payload:         map[string]any{"b": "two", "a": "one"},
		Supports:        []string{"iss-1"},
		DerivedFrom:     []string{"src-1"},
		CreatedAt:       "2026-03-27T12:00:00Z",
	}
	ev2 := ev1
	ev2.Payload = map[string]any{"a": "one", "b": "two"}

	h1, err := HashJSON(ev1)
	if err != nil {
		t.Fatalf("HashJSON(ev1): %v", err)
	}
	h2, err := HashJSON(ev2)
	if err != nil {
		t.Fatalf("HashJSON(ev2): %v", err)
	}
	if h1 != h2 {
		t.Fatalf("expected identical hashes, got %s vs %s", h1, h2)
	}
}

func TestValidateBundleCrossReferences(t *testing.T) {
	t.Parallel()

	bundle := testBundle()
	if err := ValidateBundle(bundle); err != nil {
		t.Fatalf("ValidateBundle(): %v", err)
	}

	bundle.Report.Issues[0].EvidenceIDs = []string{"ev-missing"}
	if err := ValidateBundle(bundle); err == nil {
		t.Fatalf("expected cross-reference validation error")
	}
}

func TestBuildArtifactsStableAcrossSeedOrdering(t *testing.T) {
	t.Parallel()

	baseScan := report.ScanReport{
		RepoName:     "github.com/acme/repo",
		CommitSHA:    "abc123",
		ScannedAt:    "2026-03-27T12:00:00Z",
		FileCount:    3,
		BoundaryMode: "repo",
	}
	a := BuildInput{
		Scan: baseScan,
		Verification: VerificationSource{
			ReportSchemaVersion: "1.0.0",
			IssueSeeds: []IssueSeed{
				{
					RuleID:     "SEC-001",
					Title:      "First title",
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
				},
				{
					RuleID:     "QUAL-001",
					Title:      "Second title",
					Source:     "rule",
					Category:   "security",
					Severity:   "high",
					Status:     "open",
					Confidence: 0.8,
					Quality:    0.9,
					File:       "service.ts",
					Symbol:     "getUser",
					StartLine:  12,
					EndLine:    12,
				},
			},
		},
		EngineVersion: "verabase@dev",
	}
	b := a
	b.Verification.IssueSeeds = []IssueSeed{a.Verification.IssueSeeds[1], a.Verification.IssueSeeds[0]}

	first, err := BuildArtifacts(a)
	if err != nil {
		t.Fatalf("BuildArtifacts(first): %v", err)
	}
	second, err := BuildArtifacts(b)
	if err != nil {
		t.Fatalf("BuildArtifacts(second): %v", err)
	}

	if len(first.Bundle.Report.Issues) != 1 || len(second.Bundle.Report.Issues) != 1 {
		t.Fatalf("expected one merged issue from both builds")
	}
	if first.Bundle.Report.Issues[0].ID != second.Bundle.Report.Issues[0].ID {
		t.Fatalf("expected stable issue id, got %q vs %q", first.Bundle.Report.Issues[0].ID, second.Bundle.Report.Issues[0].ID)
	}
	if first.Bundle.Report.Issues[0].Fingerprint != second.Bundle.Report.Issues[0].Fingerprint {
		t.Fatalf("expected stable issue fingerprint, got %q vs %q", first.Bundle.Report.Issues[0].Fingerprint, second.Bundle.Report.Issues[0].Fingerprint)
	}

	firstHashes, err := ComputeArtifactHashes(first.Bundle)
	if err != nil {
		t.Fatalf("ComputeArtifactHashes(first): %v", err)
	}
	secondHashes, err := ComputeArtifactHashes(second.Bundle)
	if err != nil {
		t.Fatalf("ComputeArtifactHashes(second): %v", err)
	}
	if ComputeBundleHash(firstHashes) != ComputeBundleHash(secondHashes) {
		t.Fatal("expected stable bundle hash across seed ordering")
	}
}

func TestWriteBundleWritesAllArtifactsAndSignature(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	bundle := testBundle()
	if err := WriteBundle(dir, &bundle, "verabase"); err != nil {
		t.Fatalf("WriteBundle(): %v", err)
	}

	files := []string{
		"report.json",
		"evidence.json",
		"skills.json",
		"trace.json",
		"summary.md",
		"signature.json",
	}
	for _, name := range files {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatalf("expected %s to exist: %v", name, err)
		}
	}

	var sig SignatureArtifact
	data, err := os.ReadFile(filepath.Join(dir, "signature.json"))
	if err != nil {
		t.Fatalf("ReadFile(signature.json): %v", err)
	}
	if err := json.Unmarshal(data, &sig); err != nil {
		t.Fatalf("Unmarshal(signature.json): %v", err)
	}
	if sig.BundleHash == "" {
		t.Fatalf("expected bundle hash to be populated")
	}
	if len(sig.ArtifactHashes) != 5 {
		t.Fatalf("expected 5 artifact hashes, got %d", len(sig.ArtifactHashes))
	}
}

func testBundle() Bundle {
	timestamp := "2026-03-27T12:00:00Z"
	return Bundle{
		Report: ReportArtifact{
			SchemaVersion: ReportSchemaVersion,
			EngineVersion: "verabase@2.0.0",
			Repo:          "github.com/acme/repo",
			Commit:        "abc123",
			Timestamp:     timestamp,
			TraceID:       "trace-1",
			Summary: ReportSummary{
				OverallScore: 0.82,
				RiskLevel:    "medium",
				IssueCounts:  IssueCountSummary{High: 1},
			},
			Skills: []ReportSkillScore{{SkillID: "backend", Score: 0.85}},
			Issues: []Issue{
				{
					ID:              "iss-1",
					Fingerprint:     "fp-1",
					RuleFamily:      "fam_bug",
					MergeBasis:      "same_symbol",
					Category:        "bug",
					Title:           "Missing null check",
					Severity:        "high",
					Confidence:      0.91,
					ConfidenceClass: "high",
					PolicyClass:     "machine_trusted",
					Status:          "open",
					EvidenceIDs:     []string{"ev-1"},
					SkillImpacts:    []string{"backend"},
					Sources:         []string{"rule", "agent"},
					SourceSummary: IssueSourceSummary{
						RuleCount:            1,
						DeterministicSources: 1,
						AgentSources:         1,
						TotalSources:         2,
						MultiSource:          true,
					},
					ConfidenceBreakdown: &ConfidenceBreakdown{
						RuleReliability:      0.9,
						EvidenceQuality:      1.0,
						BoundaryCompleteness: 1.0,
						ContextCompleteness:  0.8,
						SourceAgreement:      0.9,
						ContradictionPenalty: 0.0,
						LLMPenalty:           0.0,
						Final:                0.91,
					},
				},
			},
		},
		Evidence: EvidenceArtifact{
			SchemaVersion: EvidenceSchemaVersion,
			EngineVersion: "verabase@2.0.0",
			Repo:          "github.com/acme/repo",
			Commit:        "abc123",
			Timestamp:     timestamp,
			Evidence: []EvidenceRecord{
				{
					ID:              "ev-1",
					Kind:            "ast_fact",
					Source:          "rule",
					ProducerID:      "rule:missing_null_check",
					ProducerVersion: "1.0.0",
					Repo:            "github.com/acme/repo",
					Commit:          "abc123",
					BoundaryHash:    "sha256:boundary",
					FactQuality:     "proof",
					EntityIDs:       []string{"fn-1"},
					Locations:       []LocationRef{{RepoRelPath: "service.ts", StartLine: 120, EndLine: 120, SymbolID: "fn-1"}},
					Claims:          []string{"null_check_missing"},
					Payload:         map[string]any{"operator": "member_access"},
					Supports:        []string{"iss-1"},
					Contradicts:     []string{},
					DerivedFrom:     []string{"ast-node-1"},
					CreatedAt:       timestamp,
				},
			},
		},
		Skills: SkillsArtifact{
			SchemaVersion: SkillsSchemaVersion,
			EngineVersion: "verabase@2.0.0",
			Repo:          "github.com/acme/repo",
			Commit:        "abc123",
			Timestamp:     timestamp,
			Skills: []SkillScore{
				{
					SkillID:                 "backend",
					Score:                   0.85,
					Confidence:              0.80,
					ContributingIssueIDs:    []string{"iss-1"},
					ContributingEvidenceIDs: []string{"ev-1"},
				},
			},
		},
		Trace: TraceArtifact{
			SchemaVersion: TraceSchemaVersion,
			EngineVersion: "verabase@2.0.0",
			TraceID:       "trace-1",
			Repo:          "github.com/acme/repo",
			Commit:        "abc123",
			Timestamp:     timestamp,
			ScanBoundary:  TraceScanBoundary{Mode: "repo", IncludedFiles: 10, ExcludedFiles: 1},
			ConfidenceCalibration: &ConfidenceCalibration{
				Version:                 "release-blocking-calibration-1",
				MachineTrustedThreshold: machineTrustedFinalThreshold,
				UnknownCap:              unknownFinalCap,
				AgentOnlyCap:            agentOnlyFinalCap,
				RuleFamilyBaselines: map[string]float64{
					"sec_secret":   0.94,
					"fe_dep":       0.92,
					"sec_strict":   0.72,
					"arch_layer":   0.78,
					"arch_pattern": 0.74,
					"test_auth":    0.62,
					"test_payment": 0.62,
					"fam_bug":      0.55,
				},
				OrderingRules: []string{
					"issue_native > seed_native > finding_bridged",
					"proof > structural > heuristic",
					"deterministic > agent_only",
				},
			},
			Analyzers: []AnalyzerRun{
				{Name: "typescript", Version: "1.0.0", Language: "typescript", Status: "ok"},
			},
			Agents: []AgentRun{
				{ID: "bug-agent-1", Kind: "bug", IssueType: "bug_review", Question: "Assess the issue using the selected bounded context.", TriggerReason: "high_value_issue_confirmation", InputEvidenceIDs: []string{"ev-1"}, OutputEvidenceIDs: []string{"ev-1"}, Status: "completed"},
			},
			Derivations: []IssueDerivation{
				{IssueID: "iss-1", IssueFingerprint: "fp-1", DerivedFromEvidenceIDs: []string{"ev-1"}},
			},
		},
		SummaryMD: "# Verabase Report\n\n- Missing null check\n",
	}
}
