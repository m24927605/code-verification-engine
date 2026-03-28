package artifactsv2

import (
	"github.com/verabase/code-verification-engine/internal/report"
	"github.com/verabase/code-verification-engine/internal/rules"
	"github.com/verabase/code-verification-engine/internal/skills"
)

// CompatBuildInput is the staged builder input for projecting the current
// deterministic engine outputs into the v2 evidence-first artifact model.
type CompatBuildInput struct {
	Scan          report.ScanReport
	Verification  VerificationSource
	AgentExecutor AgentExecutor
	SkillReport   *skills.Report
	EngineVersion string
}

// CompatBuildResult is the staged builder result used by the current
// compatibility path. It exposes intermediate structures so the engine can
// evolve toward an evidence-native pipeline without re-deriving them later.
type CompatBuildResult struct {
	IssueSet        *IssueCandidateSet
	EvidenceStore   *EvidenceStore
	IssueCandidates []IssueCandidate
	Bundle          Bundle
}

// BuildCompatArtifacts constructs the compatibility-path evidence store,
// issue candidates, and final verifiable bundle.
func BuildCompatArtifacts(input CompatBuildInput) (*CompatBuildResult, error) {
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

	return &CompatBuildResult{
		IssueSet:        issueSet,
		EvidenceStore:   issueSet.EvidenceStore,
		IssueCandidates: append([]IssueCandidate(nil), issueSet.IssueCandidates...),
		Bundle:          bundle,
	}, nil
}

// BuildCompatBundle preserves the original helper shape and returns only the bundle.
func BuildCompatBundle(scan report.ScanReport, vr report.VerificationReport, skillReport *skills.Report, engineVersion string) Bundle {
	result, err := BuildCompatArtifacts(CompatBuildInput{
		Scan: scan,
		Verification: VerificationSource{
			ReportSchemaVersion: vr.ReportSchemaVersion,
			Findings:            append([]rules.Finding(nil), vr.Findings...),
		},
		SkillReport:   skillReport,
		EngineVersion: engineVersion,
	})
	if err != nil {
		// The compatibility path is designed to be deterministic and self-validating.
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
			SummaryMD: "# Verabase Report\n\nCompatibility bundle generation failed.\n",
			Signature: SignatureArtifact{Version: SignatureSchemaVersion},
		}
	}
	return result.Bundle
}
