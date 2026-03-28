package artifactsv2

import (
	"testing"

	"github.com/verabase/code-verification-engine/internal/report"
	"github.com/verabase/code-verification-engine/internal/rules"
	"github.com/verabase/code-verification-engine/internal/skills"
)

func TestBuildCompatArtifactsReturnsIntermediateResults(t *testing.T) {
	t.Parallel()

	input := CompatBuildInput{
		Scan: report.ScanReport{
			ScanSchemaVersion: "1.0.0",
			RepoPath:          "/tmp/repo",
			RepoName:          "github.com/acme/repo",
			CommitSHA:         "abc123def456",
			ScannedAt:         "2026-03-27T12:00:00Z",
			FileCount:         12,
			Analyzers:         map[string]string{"typescript": "ok"},
			BoundaryMode:      "repo",
		},
		Verification: VerificationSource{
			ReportSchemaVersion: "1.0.0",
			Findings: []rules.Finding{
				{
					RuleID:           "SEC-NULL-001",
					Status:           rules.StatusFail,
					Confidence:       rules.ConfidenceHigh,
					TrustClass:       rules.TrustMachineTrusted,
					Message:          "Missing null check",
					VerdictBasis:     "proof",
					FactQualityFloor: "proof",
					Evidence: []rules.Evidence{{
						File:      "service.ts",
						LineStart: 10,
						LineEnd:   10,
						Symbol:    "getUser",
					}},
				},
			},
			SkippedRules: []rules.SkippedRule{{RuleID: "SKIP-001", Reason: "capability_unsupported"}},
			Partial:      true,
			Degraded:     true,
			AnalyzerStatuses: map[string]string{
				"typescript": "partial",
			},
			Errors: []string{"analyzer degraded"},
		},
		SkillReport: &skills.Report{
			Signals: []skills.Signal{
				{
					SkillID:          "backend",
					Status:           skills.StatusObserved,
					Confidence:       skills.ConfidenceHigh,
					EvidenceStrength: skills.EvidenceDirect,
					SourceRuleIDs:    []string{"SEC-NULL-001"},
					Evidence: []rules.Evidence{{
						File:      "service.ts",
						LineStart: 10,
						LineEnd:   10,
						Symbol:    "getUser",
					}},
				},
			},
		},
		EngineVersion: "verabase@dev",
	}

	result, err := BuildCompatArtifacts(input)
	if err != nil {
		t.Fatalf("BuildCompatArtifacts(): %v", err)
	}
	if result.EvidenceStore == nil {
		t.Fatalf("expected evidence store")
	}
	if result.IssueSet == nil {
		t.Fatalf("expected canonical issue set")
	}
	if len(result.IssueCandidates) != 1 {
		t.Fatalf("expected 1 issue candidate, got %d", len(result.IssueCandidates))
	}
	if len(result.IssueSet.IssueCandidates) != 1 {
		t.Fatalf("expected issue set to retain 1 issue candidate, got %d", len(result.IssueSet.IssueCandidates))
	}
	if len(result.Bundle.Report.Issues) != 1 {
		t.Fatalf("expected 1 projected issue, got %d", len(result.Bundle.Report.Issues))
	}
	if _, ok := result.EvidenceStore.Get(result.Bundle.Report.Issues[0].EvidenceIDs[0]); !ok {
		t.Fatalf("expected projected issue evidence to exist in store")
	}
	if !result.Bundle.Trace.Partial || !result.Bundle.Trace.Degraded {
		t.Fatalf("expected trace to preserve partial/degraded state")
	}
	if len(result.Bundle.Trace.SkippedRules) != 1 {
		t.Fatalf("expected skipped rules in trace, got %d", len(result.Bundle.Trace.SkippedRules))
	}
}

func TestBuildCompatArtifactsSupportsIssueSeedSource(t *testing.T) {
	t.Parallel()

	input := CompatBuildInput{
		Scan: report.ScanReport{
			ScanSchemaVersion: "1.0.0",
			RepoPath:          "/tmp/repo",
			RepoName:          "github.com/acme/repo",
			CommitSHA:         "abc123def456",
			ScannedAt:         "2026-03-27T12:00:00Z",
			FileCount:         12,
			Analyzers:         map[string]string{"typescript": "ok"},
			BoundaryMode:      "repo",
		},
		Verification: VerificationSource{
			ReportSchemaVersion: "1.0.0",
			IssueSeeds: []IssueSeed{{
				RuleID:     "SEC-NULL-001",
				Title:      "Missing null check",
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
		EngineVersion: "verabase@dev",
	}

	result, err := BuildCompatArtifacts(input)
	if err != nil {
		t.Fatalf("BuildCompatArtifacts(): %v", err)
	}
	if len(result.IssueCandidates) != 1 {
		t.Fatalf("expected 1 issue candidate, got %d", len(result.IssueCandidates))
	}
	if got := len(result.Bundle.Evidence.Evidence); got != 1 {
		t.Fatalf("expected 1 synthetic evidence record, got %d", got)
	}
	if got := result.Bundle.Report.Issues[0].EvidenceIDs; len(got) != 1 {
		t.Fatalf("expected projected issue to reference synthetic evidence, got %v", got)
	}
	if result.Bundle.Trace.Partial {
		t.Fatalf("expected partial=false for seed-only source")
	}
	if len(result.Bundle.Trace.Rules) != 1 || result.Bundle.Trace.Rules[0].ID != "SEC-NULL-001" {
		t.Fatalf("expected seed-only source to populate trace rules, got %#v", result.Bundle.Trace.Rules)
	}
	if len(result.Bundle.Trace.Derivations) != 1 {
		t.Fatalf("expected seed-only source to populate derivations, got %#v", result.Bundle.Trace.Derivations)
	}
	evidenceID := result.Bundle.Evidence.Evidence[0].ID
	if result.Bundle.Report.Issues[0].EvidenceIDs[0] != evidenceID {
		t.Fatalf("expected report issue to reference synthesized evidence %q, got %#v", evidenceID, result.Bundle.Report.Issues[0].EvidenceIDs)
	}
	if result.Bundle.Trace.Rules[0].EmittedEvidenceIDs[0] != evidenceID {
		t.Fatalf("expected trace rule to reference synthesized evidence %q, got %#v", evidenceID, result.Bundle.Trace.Rules[0].EmittedEvidenceIDs)
	}
}

func TestBuildCompatArtifactsPreservesExplicitSeedEvidenceID(t *testing.T) {
	t.Parallel()

	input := CompatBuildInput{
		Scan: report.ScanReport{
			ScanSchemaVersion: "1.0.0",
			RepoPath:          "/tmp/repo",
			RepoName:          "github.com/acme/repo",
			CommitSHA:         "abc123def456",
			ScannedAt:         "2026-03-27T12:00:00Z",
			FileCount:         12,
			BoundaryMode:      "repo",
		},
		Verification: VerificationSource{
			ReportSchemaVersion: "1.0.0",
			IssueSeeds: []IssueSeed{{
				RuleID:      "DESIGN-001",
				Title:       "Layering violation",
				Source:      "rule",
				Category:    "design",
				Severity:    "medium",
				Status:      "open",
				Confidence:  0.7,
				Quality:     0.7,
				File:        "service.ts",
				StartLine:   44,
				EndLine:     48,
				EvidenceIDs: []string{"ev-native-001"},
			}},
		},
		EngineVersion: "verabase@dev",
	}

	result, err := BuildCompatArtifacts(input)
	if err != nil {
		t.Fatalf("BuildCompatArtifacts(): %v", err)
	}
	if got := result.Bundle.Evidence.Evidence[0].ID; got != "ev-native-001" {
		t.Fatalf("expected explicit seed evidence id to be preserved, got %q", got)
	}
	if _, ok := result.EvidenceStore.Get("ev-native-001"); !ok {
		t.Fatalf("expected explicit seed evidence id to be present in evidence store")
	}
}

func TestBuildCompatArtifactsExecutesAgentTasksAndRebuildsIssueSet(t *testing.T) {
	t.Parallel()

	input := CompatBuildInput{
		Scan: report.ScanReport{
			ScanSchemaVersion: "1.0.0",
			RepoPath:          "/tmp/repo",
			RepoName:          "github.com/acme/repo",
			CommitSHA:         "abc123def456",
			ScannedAt:         "2026-03-27T12:00:00Z",
			FileCount:         12,
			BoundaryMode:      "repo",
		},
		Verification: VerificationSource{
			ReportSchemaVersion: "1.0.0",
			IssueSeeds: []IssueSeed{{
				RuleID:     "DESIGN-001",
				Title:      "Unknown layering issue",
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
			return AgentResult{
				Status: "completed",
				EmittedEvidence: []EvidenceRecord{{
					ID:              "ev-agent-001",
					Kind:            "agent_assertion",
					Source:          "agent",
					ProducerID:      "agent:design",
					ProducerVersion: "1.0.0",
					Repo:            "github.com/acme/repo",
					Commit:          "abc123def456",
					BoundaryHash:    "boundary-abc123def456",
					FactQuality:     "heuristic",
					EntityIDs:       []string{"getUser"},
					Locations:       []LocationRef{{RepoRelPath: "service.ts", StartLine: 44, EndLine: 48, SymbolID: "getUser"}},
					Claims:          []string{"design_review"},
					CreatedAt:       "2026-03-27T12:00:00Z",
				}},
			}, nil
		},
		EngineVersion: "verabase@dev",
	}

	result, err := BuildCompatArtifacts(input)
	if err != nil {
		t.Fatalf("BuildCompatArtifacts(): %v", err)
	}
	if len(result.IssueSet.Verification.AgentResults) != 1 {
		t.Fatalf("expected executed agent result to be retained on issue set, got %#v", result.IssueSet.Verification.AgentResults)
	}
	if _, ok := result.EvidenceStore.Get("ev-agent-001"); !ok {
		t.Fatalf("expected executed agent evidence to exist in evidence store")
	}
	if got := result.IssueCandidates[0].SourceSummary.AgentSources; got != 1 {
		t.Fatalf("expected agent overlay to affect source summary, got %#v", result.IssueCandidates[0].SourceSummary)
	}
	found := false
	for _, evID := range result.IssueCandidates[0].EvidenceIDs {
		if evID == "ev-agent-001" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected agent evidence to be attached to issue candidate, got %#v", result.IssueCandidates[0].EvidenceIDs)
	}
	if len(result.Bundle.Trace.Agents) != 1 || result.Bundle.Trace.Agents[0].Status != "completed" {
		t.Fatalf("expected completed agent run in trace, got %#v", result.Bundle.Trace.Agents)
	}
}
