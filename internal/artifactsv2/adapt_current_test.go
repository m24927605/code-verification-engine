package artifactsv2

import (
	"testing"

	"github.com/verabase/code-verification-engine/internal/report"
	"github.com/verabase/code-verification-engine/internal/rules"
	"github.com/verabase/code-verification-engine/internal/skills"
)

func TestBuildCompatBundleProducesValidBundle(t *testing.T) {
	t.Parallel()

	scan := report.ScanReport{
		ScanSchemaVersion: "1.0.0",
		RepoPath:          "/tmp/repo",
		RepoName:          "github.com/acme/repo",
		CommitSHA:         "abc123def456",
		ScannedAt:         "2026-03-27T12:00:00Z",
		FileCount:         12,
		Analyzers:         map[string]string{"typescript": "ok"},
		BoundaryMode:      "repo",
	}
	verification := VerificationSource{
		ReportSchemaVersion: "1.0.0",
		Findings: []rules.Finding{
			{
				RuleID:            "SEC-NULL-001",
				Status:            rules.StatusFail,
				Confidence:        rules.ConfidenceHigh,
				VerificationLevel: rules.VerificationVerified,
				TrustClass:        rules.TrustMachineTrusted,
				Message:           "Missing null check",
				VerdictBasis:      "proof",
				FactQualityFloor:  "proof",
				Evidence: []rules.Evidence{{
					ID:        "",
					File:      "service.ts",
					LineStart: 120,
					LineEnd:   120,
					Symbol:    "getUser",
				}},
			},
		},
	}
	skillReport := &skills.Report{
		SchemaVersion: "1.0.0",
		Signals: []skills.Signal{
			{
				ID:               "backend_auth.jwt_middleware",
				SkillID:          "backend",
				Status:           skills.StatusObserved,
				Confidence:       skills.ConfidenceHigh,
				EvidenceStrength: skills.EvidenceDirect,
				SourceRuleIDs:    []string{"SEC-NULL-001"},
				Evidence: []rules.Evidence{{
					File:      "service.ts",
					LineStart: 120,
					LineEnd:   120,
					Symbol:    "getUser",
				}},
			},
		},
	}

	bundle := BuildCompatBundle(scan, report.VerificationReport{
		ReportSchemaVersion: verification.ReportSchemaVersion,
		Findings:            verification.Findings,
	}, skillReport, "verabase@dev")
	if err := ValidateBundle(bundle); err != nil {
		t.Fatalf("ValidateBundle(): %v", err)
	}
	if len(bundle.Report.Issues) != 1 {
		t.Fatalf("expected 1 issue, got %d", len(bundle.Report.Issues))
	}
	if len(bundle.Evidence.Evidence) != 1 {
		t.Fatalf("expected 1 evidence record, got %d", len(bundle.Evidence.Evidence))
	}
	if len(bundle.Skills.Skills) != 1 {
		t.Fatalf("expected 1 skill score, got %d", len(bundle.Skills.Skills))
	}
	if bundle.Trace.TraceID == "" {
		t.Fatalf("expected trace id")
	}
}

func TestBuildCompatBundleClustersOverlappingFindings(t *testing.T) {
	t.Parallel()

	scan := report.ScanReport{
		ScanSchemaVersion: "1.0.0",
		RepoPath:          "/tmp/repo",
		RepoName:          "github.com/acme/repo",
		CommitSHA:         "abc123def456",
		ScannedAt:         "2026-03-27T12:00:00Z",
		FileCount:         12,
		Analyzers:         map[string]string{"typescript": "ok"},
		BoundaryMode:      "repo",
	}
	vr := report.VerificationReport{
		ReportSchemaVersion: "1.0.0",
		Findings: []rules.Finding{
			{
				RuleID:           "QUAL-NULL-001",
				Status:           rules.StatusFail,
				Confidence:       rules.ConfidenceMedium,
				TrustClass:       rules.TrustAdvisory,
				Message:          "Missing null check on user access",
				VerdictBasis:     "structural_binding",
				FactQualityFloor: "structural",
				Evidence: []rules.Evidence{{
					File:      "service.ts",
					LineStart: 120,
					LineEnd:   121,
					Symbol:    "getUser",
				}},
			},
			{
				RuleID:           "SEC-NULL-002",
				Status:           rules.StatusFail,
				Confidence:       rules.ConfidenceHigh,
				TrustClass:       rules.TrustMachineTrusted,
				Message:          "Nil dereference risk in user access",
				VerdictBasis:     "proof",
				FactQualityFloor: "proof",
				Evidence: []rules.Evidence{{
					File:      "service.ts",
					LineStart: 121,
					LineEnd:   122,
					Symbol:    "getUser",
				}},
			},
		},
	}

	bundle := BuildCompatBundle(scan, vr, nil, "verabase@dev")
	if err := ValidateBundle(bundle); err != nil {
		t.Fatalf("ValidateBundle(): %v", err)
	}
	if len(bundle.Report.Issues) != 1 {
		t.Fatalf("expected clustered single issue, got %d", len(bundle.Report.Issues))
	}
	issue := bundle.Report.Issues[0]
	if len(issue.EvidenceIDs) != 2 {
		t.Fatalf("expected 2 evidence ids, got %d", len(issue.EvidenceIDs))
	}
	if len(issue.Sources) != 1 {
		t.Fatalf("expected deduped source summary, got %d", len(issue.Sources))
	}
}

func TestBuildCompatBundleDoesNotMergeDifferentFiles(t *testing.T) {
	t.Parallel()

	scan := report.ScanReport{
		ScanSchemaVersion: "1.0.0",
		RepoPath:          "/tmp/repo",
		RepoName:          "github.com/acme/repo",
		CommitSHA:         "abc123def456",
		ScannedAt:         "2026-03-27T12:00:00Z",
		FileCount:         12,
		Analyzers:         map[string]string{"typescript": "ok"},
		BoundaryMode:      "repo",
	}
	vr := report.VerificationReport{
		ReportSchemaVersion: "1.0.0",
		Findings: []rules.Finding{
			{
				RuleID:           "QUAL-NULL-001",
				Status:           rules.StatusFail,
				Confidence:       rules.ConfidenceMedium,
				TrustClass:       rules.TrustAdvisory,
				Message:          "Missing null check on user access",
				VerdictBasis:     "structural_binding",
				FactQualityFloor: "structural",
				Evidence: []rules.Evidence{{
					File:      "service.ts",
					LineStart: 120,
					LineEnd:   121,
					Symbol:    "getUser",
				}},
			},
			{
				RuleID:           "SEC-NULL-002",
				Status:           rules.StatusFail,
				Confidence:       rules.ConfidenceHigh,
				TrustClass:       rules.TrustMachineTrusted,
				Message:          "Nil dereference risk in user access",
				VerdictBasis:     "proof",
				FactQualityFloor: "proof",
				Evidence: []rules.Evidence{{
					File:      "controller.ts",
					LineStart: 121,
					LineEnd:   122,
					Symbol:    "getUser",
				}},
			},
		},
	}

	bundle := BuildCompatBundle(scan, vr, nil, "verabase@dev")
	if err := ValidateBundle(bundle); err != nil {
		t.Fatalf("ValidateBundle(): %v", err)
	}
	if len(bundle.Report.Issues) != 2 {
		t.Fatalf("expected 2 separate issues, got %d", len(bundle.Report.Issues))
	}
}

func TestBuildCompatArtifactsIncludesAgentResultEvidenceAndTrace(t *testing.T) {
	t.Parallel()

	scan := report.ScanReport{
		ScanSchemaVersion: "1.0.0",
		RepoPath:          "/tmp/repo",
		RepoName:          "github.com/acme/repo",
		CommitSHA:         "abc123def456",
		ScannedAt:         "2026-03-27T12:00:00Z",
		FileCount:         12,
		Analyzers:         map[string]string{"typescript": "ok"},
		BoundaryMode:      "repo",
	}
	seed := IssueSeed{
		RuleID:     "SEC-001",
		Title:      "Missing auth check",
		Source:     "rule",
		Category:   "security",
		Severity:   "high",
		Status:     "open",
		Confidence: 0.9,
		Quality:    1.0,
		File:       "auth/service.ts",
		Symbol:     "Authorize",
		StartLine:  10,
		EndLine:    14,
	}
	cluster := compatIssueCluster{
		Fingerprint: compatClusterFingerprint(seed),
		Category:    seed.Category,
		Severity:    seed.Severity,
		Status:      seed.Status,
		Title:       seed.Title,
		File:        seed.File,
		Symbol:      seed.Symbol,
		StartLine:   seed.StartLine,
		EndLine:     seed.EndLine,
	}
	candidate := IssueCandidate{ID: compatIssueID(cluster), Category: "security"}

	result, err := BuildCompatArtifacts(CompatBuildInput{
		Scan: scan,
		Verification: VerificationSource{
			ReportSchemaVersion: "1.0.0",
			IssueSeeds:          []IssueSeed{seed},
			RuleMetadata: map[string]RuleMetadata{
				"SEC-001": {RuleID: "SEC-001", MigrationState: "issue_native", MigrationReason: "native issue semantics"},
			},
			AgentResults: []AgentResult{{
				TaskID:  plannedAgentID(candidate, "high_severity_review"),
				Kind:    "security",
				IssueID: candidate.ID,
				Status:  "completed",
				EmittedEvidence: []EvidenceRecord{{
					ID:              "ev-agent-1",
					Kind:            "agent_assertion",
					Source:          "agent",
					ProducerID:      "agent:security",
					ProducerVersion: "1.0.0",
					FactQuality:     "heuristic",
					Locations:       []LocationRef{{RepoRelPath: "auth/service.ts", StartLine: 10, EndLine: 14}},
					Claims:          []string{"SEC-001"},
				}},
			}},
		},
		EngineVersion: "verabase@dev",
	})
	if err != nil {
		t.Fatalf("BuildCompatArtifacts(): %v", err)
	}
	if err := ValidateBundle(result.Bundle); err != nil {
		t.Fatalf("ValidateBundle(): %v", err)
	}
	if _, ok := result.EvidenceStore.Get("ev-agent-1"); !ok {
		t.Fatalf("expected agent emitted evidence to enter evidence store")
	}
	if len(result.Bundle.Trace.Agents) != 1 || result.Bundle.Trace.Agents[0].Status != "completed" {
		t.Fatalf("expected completed agent trace run, got %#v", result.Bundle.Trace.Agents)
	}
	if len(result.Bundle.Trace.Agents[0].OutputEvidenceIDs) != 1 || result.Bundle.Trace.Agents[0].OutputEvidenceIDs[0] != "ev-agent-1" {
		t.Fatalf("expected agent output evidence ids in trace, got %#v", result.Bundle.Trace.Agents[0])
	}
	if len(result.Bundle.Report.Issues) != 1 {
		t.Fatalf("expected 1 issue in report, got %d", len(result.Bundle.Report.Issues))
	}
	issue := result.Bundle.Report.Issues[0]
	if !issue.SourceSummary.MultiSource || issue.SourceSummary.AgentSources != 1 {
		t.Fatalf("expected completed agent result to affect source summary, got %#v", issue.SourceSummary)
	}
	found := false
	for _, evID := range issue.EvidenceIDs {
		if evID == "ev-agent-1" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected completed agent evidence to affect issue evidence ids, got %#v", issue.EvidenceIDs)
	}
	if len(result.Bundle.Trace.Derivations) != 1 {
		t.Fatalf("expected 1 derivation, got %#v", result.Bundle.Trace.Derivations)
	}
	found = false
	for _, evID := range result.Bundle.Trace.Derivations[0].DerivedFromEvidenceIDs {
		if evID == "ev-agent-1" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected derivation to include completed agent evidence, got %#v", result.Bundle.Trace.Derivations[0])
	}
}

func TestBuildCompatBundleBackfillsSkillEvidenceFromIssueCandidates(t *testing.T) {
	t.Parallel()

	scan := report.ScanReport{
		ScanSchemaVersion: "1.0.0",
		RepoPath:          "/tmp/repo",
		RepoName:          "github.com/acme/repo",
		CommitSHA:         "abc123def456",
		ScannedAt:         "2026-03-27T12:00:00Z",
		FileCount:         12,
		Analyzers:         map[string]string{"typescript": "ok"},
		BoundaryMode:      "repo",
	}
	verification := VerificationSource{
		ReportSchemaVersion: "1.0.0",
		Findings: []rules.Finding{
			{
				RuleID:            "SEC-NULL-001",
				Status:            rules.StatusFail,
				Confidence:        rules.ConfidenceHigh,
				VerificationLevel: rules.VerificationVerified,
				TrustClass:        rules.TrustMachineTrusted,
				Message:           "Missing null check",
				VerdictBasis:      "proof",
				FactQualityFloor:  "proof",
				Evidence: []rules.Evidence{{
					File:      "service.ts",
					LineStart: 120,
					LineEnd:   120,
					Symbol:    "getUser",
				}},
			},
		},
	}
	skillReport := &skills.Report{
		SchemaVersion: "1.0.0",
		Signals: []skills.Signal{
			{
				ID:               "backend_auth.jwt_middleware",
				SkillID:          "backend",
				Status:           skills.StatusObserved,
				Confidence:       skills.ConfidenceHigh,
				EvidenceStrength: skills.EvidenceDirect,
				SourceRuleIDs:    []string{"SEC-NULL-001"},
				Evidence:         nil,
			},
		},
	}

	bundle := BuildCompatBundle(scan, report.VerificationReport{
		ReportSchemaVersion: verification.ReportSchemaVersion,
		Findings:            verification.Findings,
	}, skillReport, "verabase@dev")
	if err := ValidateBundle(bundle); err != nil {
		t.Fatalf("ValidateBundle(): %v", err)
	}
	if len(bundle.Skills.Skills) != 1 {
		t.Fatalf("expected 1 skill score, got %d", len(bundle.Skills.Skills))
	}
	if len(bundle.Skills.Skills[0].ContributingEvidenceIDs) == 0 {
		t.Fatalf("expected contributing evidence ids to be backfilled from issue candidates, got %#v", bundle.Skills.Skills[0])
	}
}

func TestBuildCompatBundleSkipsNonTraceableSkillSignalsInV2SkillsArtifact(t *testing.T) {
	t.Parallel()

	scan := report.ScanReport{
		ScanSchemaVersion: "1.0.0",
		RepoPath:          "/tmp/repo",
		RepoName:          "github.com/acme/repo",
		CommitSHA:         "abc123def456",
		ScannedAt:         "2026-03-27T12:00:00Z",
		FileCount:         12,
		Analyzers:         map[string]string{"typescript": "ok"},
		BoundaryMode:      "repo",
	}
	verification := VerificationSource{
		ReportSchemaVersion: "1.0.0",
		Findings: []rules.Finding{
			{
				RuleID:            "SEC-NULL-001",
				Status:            rules.StatusPass,
				Confidence:        rules.ConfidenceHigh,
				VerificationLevel: rules.VerificationVerified,
				TrustClass:        rules.TrustMachineTrusted,
				Message:           "Middleware exists",
				VerdictBasis:      "proof",
				FactQualityFloor:  "proof",
				Evidence: []rules.Evidence{{
					File:      "service.ts",
					LineStart: 120,
					LineEnd:   120,
					Symbol:    "getUser",
				}},
			},
		},
	}
	skillReport := &skills.Report{
		SchemaVersion: "1.0.0",
		Signals: []skills.Signal{
			{
				ID:               "backend_architecture.db_layering",
				SkillID:          "backend_architecture.db_layering",
				Status:           skills.StatusInferred,
				Confidence:       skills.ConfidenceMedium,
				EvidenceStrength: skills.EvidenceStructural,
				SourceRuleIDs:    []string{"ARCH-LAYER-001"},
				Evidence:         nil,
			},
		},
	}

	bundle := BuildCompatBundle(scan, report.VerificationReport{
		ReportSchemaVersion: verification.ReportSchemaVersion,
		Findings:            verification.Findings,
	}, skillReport, "verabase@dev")
	if err := ValidateBundle(bundle); err != nil {
		t.Fatalf("ValidateBundle(): %v", err)
	}
	if len(bundle.Skills.Skills) != 0 {
		t.Fatalf("expected non-traceable legacy skill signal to be skipped from v2 skills artifact, got %#v", bundle.Skills.Skills)
	}
}

func TestBuildCompatBundleSkipsSkillSignalWhenRuleHasNoAggregatedIssueID(t *testing.T) {
	t.Parallel()

	scan := report.ScanReport{
		ScanSchemaVersion: "1.0.0",
		RepoPath:          "/tmp/repo",
		RepoName:          "github.com/acme/repo",
		CommitSHA:         "abc123def456",
		ScannedAt:         "2026-03-27T12:00:00Z",
		FileCount:         12,
		Analyzers:         map[string]string{"typescript": "ok"},
		BoundaryMode:      "repo",
	}
	verification := VerificationSource{
		ReportSchemaVersion: "1.0.0",
		Findings: []rules.Finding{
			{
				RuleID:            "SEC-AUTH-001",
				Status:            rules.StatusPass,
				Confidence:        rules.ConfidenceHigh,
				VerificationLevel: rules.VerificationVerified,
				TrustClass:        rules.TrustAdvisory,
				Message:           "Middleware exists",
				VerdictBasis:      "proof",
				FactQualityFloor:  "proof",
				Evidence: []rules.Evidence{{
					File:      "service.ts",
					LineStart: 120,
					LineEnd:   120,
					Symbol:    "getUser",
				}},
			},
		},
	}
	skillReport := &skills.Report{
		SchemaVersion: "1.0.0",
		Signals: []skills.Signal{
			{
				ID:               "backend_auth.jwt_middleware",
				SkillID:          "backend_auth.jwt_middleware",
				Status:           skills.StatusObserved,
				Confidence:       skills.ConfidenceHigh,
				EvidenceStrength: skills.EvidenceDirect,
				SourceRuleIDs:    []string{"SEC-AUTH-001"},
			},
		},
	}

	bundle := BuildCompatBundle(scan, report.VerificationReport{
		ReportSchemaVersion: verification.ReportSchemaVersion,
		Findings:            verification.Findings,
	}, skillReport, "verabase@dev")
	if err := ValidateBundle(bundle); err != nil {
		t.Fatalf("ValidateBundle(): %v", err)
	}
	if len(bundle.Skills.Skills) != 0 {
		t.Fatalf("expected skill signal without aggregated issue id to be skipped from v2 skills artifact, got %#v", bundle.Skills.Skills)
	}
}
