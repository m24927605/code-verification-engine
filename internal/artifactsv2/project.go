package artifactsv2

import "sort"

// ProjectIssueCandidates renders intermediate issue candidates into report issues.
func ProjectIssueCandidates(candidates []IssueCandidate) []Issue {
	issues := make([]Issue, 0, len(candidates))
	for _, candidate := range candidates {
		issues = append(issues, Issue{
			ID:                  candidate.ID,
			Fingerprint:         candidate.Fingerprint,
			RuleFamily:          candidate.RuleFamily,
			MergeBasis:          candidate.MergeBasis,
			Category:            candidate.Category,
			Title:               candidate.Title,
			Severity:            candidate.Severity,
			Confidence:          candidate.Confidence,
			ConfidenceClass:     candidate.ConfidenceClass,
			PolicyClass:         candidate.PolicyClass,
			Status:              candidate.Status,
			EvidenceIDs:         dedupeStringsSorted(candidate.EvidenceIDs),
			CounterEvidenceIDs:  dedupeStringsSorted(candidate.CounterEvidenceIDs),
			SkillImpacts:        dedupeStringsSorted(candidate.SkillImpacts),
			Sources:             dedupeStringsSorted(candidate.Sources),
			SourceSummary:       candidate.SourceSummary,
			ConfidenceBreakdown: candidate.ConfidenceBreakdown,
		})
	}
	sort.Slice(issues, func(i, j int) bool { return issues[i].ID < issues[j].ID })
	return issues
}
