package artifactsv2

import (
	"fmt"

	"github.com/verabase/code-verification-engine/internal/report"
	"github.com/verabase/code-verification-engine/internal/skills"
)

// IssueCandidateSet is the canonical deterministic verification product.
// It captures the normalized evidence store plus aggregated issue candidates
// before any report-specific projection is applied.
type IssueCandidateSet struct {
	Scan            report.ScanReport
	Verification    VerificationSource
	EngineVersion   string
	Evidence        EvidenceArtifact
	EvidenceStore   *EvidenceStore
	IssueCandidates []IssueCandidate
}

// IssueCandidateBuildInput defines the deterministic input required to build
// the canonical issue candidate set.
type IssueCandidateBuildInput struct {
	Scan          report.ScanReport
	Verification  VerificationSource
	AgentExecutor AgentExecutor
	EngineVersion string
}

// BuildIssueCandidateSet constructs the canonical deterministic evidence store
// and issue candidate set for the verification path.
func BuildIssueCandidateSet(input IssueCandidateBuildInput) (*IssueCandidateSet, error) {
	engineVersion := input.EngineVersion
	if engineVersion == "" {
		engineVersion = "dev"
	}

	verification := normalizeVerificationSource(input.Scan, input.Verification)
	set, err := buildIssueCandidateSetCore(input.Scan, verification, engineVersion)
	if err != nil {
		return nil, err
	}
	if input.AgentExecutor != nil && len(set.Verification.AgentResults) == 0 {
		tasks := buildAgentTasks(set.IssueCandidates, set.Evidence)
		if len(tasks) > 0 {
			results, err := executeAgentTasks(tasks, input.AgentExecutor)
			if err != nil {
				return nil, err
			}
			verificationWithResults := set.Verification.Clone()
			verificationWithResults.AgentResults = results
			return buildIssueCandidateSetCore(input.Scan, verificationWithResults, engineVersion)
		}
	}
	return set, nil
}

func buildIssueCandidateSetCore(scan report.ScanReport, verification VerificationSource, engineVersion string) (*IssueCandidateSet, error) {
	evidenceArtifact, evidenceIndex := buildEvidenceArtifact(scan, verification, engineVersion)
	agg := buildIssues(scan, verification, &evidenceArtifact, evidenceIndex)
	store := NewEvidenceStoreFromRecords(evidenceArtifact.Evidence)

	return &IssueCandidateSet{
		Scan:            scan,
		Verification:    verification,
		EngineVersion:   engineVersion,
		Evidence:        evidenceArtifact,
		EvidenceStore:   store,
		IssueCandidates: append([]IssueCandidate(nil), agg.Candidates...),
	}, nil
}

// BuildBundleFromIssueCandidateSet projects the canonical issue candidate set
// into the final verifiable artifact bundle.
func BuildBundleFromIssueCandidateSet(set *IssueCandidateSet, skillReport *skills.Report) (Bundle, error) {
	if set == nil {
		return Bundle{}, fmt.Errorf("issue candidate set is required")
	}

	traceID := buildTraceID(set.Scan.CommitSHA)
	issues := ProjectIssueCandidates(set.IssueCandidates)
	reportArtifact := ReportArtifact{
		SchemaVersion: ReportSchemaVersion,
		EngineVersion: set.EngineVersion,
		Repo:          set.Scan.RepoName,
		Commit:        set.Scan.CommitSHA,
		Timestamp:     set.Scan.ScannedAt,
		TraceID:       traceID,
		Summary:       buildReportSummary(issues, skillReport),
		Skills:        buildReportSkillScores(skillReport),
		Issues:        issues,
	}
	skillsArtifact := buildSkillsArtifact(set.Scan, skillReport, set.EngineVersion, set.IssueCandidates)
	traceArtifact := buildTraceArtifact(set.Scan, set.Verification, set.Evidence, traceID, set.EngineVersion, set.IssueCandidates)

	bundle := Bundle{
		Report:    reportArtifact,
		Evidence:  set.Evidence,
		Skills:    skillsArtifact,
		Trace:     traceArtifact,
		SummaryMD: buildSummaryMarkdown(reportArtifact),
		Signature: SignatureArtifact{Version: SignatureSchemaVersion},
	}
	if err := ValidateBundle(bundle); err != nil {
		return Bundle{}, fmt.Errorf("validate compat bundle: %w", err)
	}
	return bundle, nil
}
