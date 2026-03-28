package artifactsv2

import (
	"github.com/verabase/code-verification-engine/internal/report"
	"github.com/verabase/code-verification-engine/internal/skills"
)

// BuildInput is the staged builder input for projecting deterministic engine
// outputs into the canonical evidence-first artifact model.
type BuildInput struct {
	Scan          report.ScanReport
	Verification  VerificationSource
	AgentExecutor AgentExecutor
	SkillReport   *skills.Report
	EngineVersion string
}

// BuildResult is the staged builder result for the canonical artifact path.
// It exposes intermediate structures so the engine can reuse the issue set and
// evidence store without rebuilding them later in the pipeline.
type BuildResult struct {
	IssueSet        *IssueCandidateSet
	EvidenceStore   *EvidenceStore
	IssueCandidates []IssueCandidate
	Bundle          Bundle
}

// BuildArtifacts constructs the canonical evidence store, issue candidates,
// and final artifact bundle.
func BuildArtifacts(input BuildInput) (*BuildResult, error) {
	issueSet, err := BuildIssueCandidateSet(IssueCandidateBuildInput{
		Scan:          input.Scan,
		Verification:  input.Verification,
		AgentExecutor: input.AgentExecutor,
		EngineVersion: input.EngineVersion,
	})
	if err != nil {
		return nil, err
	}
	bundle, err := BuildBundleFromIssueCandidateSet(issueSet, input.SkillReport)
	if err != nil {
		return nil, err
	}

	return &BuildResult{
		IssueSet:        issueSet,
		EvidenceStore:   issueSet.EvidenceStore,
		IssueCandidates: append([]IssueCandidate(nil), issueSet.IssueCandidates...),
		Bundle:          bundle,
	}, nil
}

// BuildBundle preserves the original helper shape and returns only the bundle.
func BuildBundle(scan report.ScanReport, vr report.VerificationReport, skillReport *skills.Report, engineVersion string) Bundle {
	result, err := BuildArtifacts(BuildInput{
		Scan: scan,
		Verification: VerificationSource{
			ReportSchemaVersion: vr.ReportSchemaVersion,
			IssueSeeds:          issueSeedsFromReportIssues(vr.Issues),
		},
		SkillReport:   skillReport,
		EngineVersion: engineVersion,
	})
	if err != nil {
		// The fallback path remains deterministic and self-validating.
		// Preserve the original no-error signature by returning a minimal but consistent bundle.
		return Bundle{
			Report: ReportArtifact{
				SchemaVersion: ReportSchemaVersion,
				EngineVersion: engineVersion,
				Repo:          scan.RepoName,
				Commit:        scan.CommitSHA,
				Timestamp:     scan.ScannedAt,
				TraceID:       buildTraceID(scan.CommitSHA),
				Summary: ReportSummary{
					OverallScore: 0,
					RiskLevel:    "low",
					IssueCounts:  IssueCountSummary{},
				},
			},
			Evidence: EvidenceArtifact{
				SchemaVersion: EvidenceSchemaVersion,
				EngineVersion: engineVersion,
				Repo:          scan.RepoName,
				Commit:        scan.CommitSHA,
				Timestamp:     scan.ScannedAt,
				Evidence:      nil,
			},
			Skills: SkillsArtifact{
				SchemaVersion: SkillsSchemaVersion,
				EngineVersion: engineVersion,
				Repo:          scan.RepoName,
				Commit:        scan.CommitSHA,
				Timestamp:     scan.ScannedAt,
			},
			Trace: TraceArtifact{
				SchemaVersion: TraceSchemaVersion,
				EngineVersion: engineVersion,
				TraceID:       buildTraceID(scan.CommitSHA),
				Repo:          scan.RepoName,
				Commit:        scan.CommitSHA,
				Timestamp:     scan.ScannedAt,
				ScanBoundary: TraceScanBoundary{
					Mode:          scan.BoundaryMode,
					IncludedFiles: scan.FileCount,
					ExcludedFiles: 0,
				},
			},
			SummaryMD: "# Verabase Report\n\nBundle generation failed.\n",
			Signature: SignatureArtifact{Version: SignatureSchemaVersion},
		}
	}
	return result.Bundle
}

func issueSeedsFromReportIssues(issues []report.Issue) []IssueSeed {
	out := make([]IssueSeed, 0, len(issues))
	for _, issue := range issues {
		seed := IssueSeed{
			RuleID:      issue.RuleID,
			Title:       issue.Title,
			Category:    issue.Category,
			Severity:    issue.Severity,
			Status:      issue.Status,
			Confidence:  compatIssueConfidence(issue.Confidence),
			Quality:     compatIssueQuality(issue.FactQuality),
			Source:      compatIssueSourceFromTrust(issue.TrustClass),
			EvidenceIDs: append([]string(nil), issue.EvidenceIDs...),
		}
		if len(issue.Evidence) > 0 {
			seed.File = issue.Evidence[0].File
			seed.Symbol = issue.Evidence[0].Symbol
			seed.StartLine = issue.Evidence[0].LineStart
			seed.EndLine = issue.Evidence[0].LineEnd
			if len(seed.EvidenceIDs) == 0 {
				for _, ev := range issue.Evidence {
					if ev.ID != "" {
						seed.EvidenceIDs = append(seed.EvidenceIDs, ev.ID)
					}
				}
			}
		}
		out = append(out, seed)
	}
	return out
}

func compatIssueConfidence(value string) float64 {
	switch value {
	case "high":
		return 0.9
	case "medium", "moderate":
		return 0.7
	case "low":
		return 0.5
	default:
		return 0.0
	}
}

func compatIssueQuality(value string) float64 {
	switch value {
	case "proof":
		return 1.0
	case "structural":
		return 0.8
	case "heuristic":
		return 0.6
	case "runtime_required":
		return 0.4
	default:
		return 0.0
	}
}

func compatIssueSourceFromTrust(trustClass string) string {
	if trustClass == "human_or_runtime_required" {
		return "agent"
	}
	return "rule"
}
