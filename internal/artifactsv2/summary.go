package artifactsv2

import (
	"fmt"
	"sort"
	"strings"
)

// RefreshSummaryMarkdown rebuilds summary.md from the current bundle state.
func RefreshSummaryMarkdown(bundle *Bundle) {
	if bundle == nil {
		return
	}
	bundle.SummaryMD = BuildBundleSummaryMarkdown(*bundle)
}

// BuildBundleSummaryMarkdown renders a reviewer-facing deterministic summary
// from the bundle's report, migration metadata, and optional scenario artifacts.
func BuildBundleSummaryMarkdown(bundle Bundle) string {
	var b strings.Builder
	b.WriteString(buildSummaryMarkdown(bundle.Report))

	if bundle.Claims != nil || bundle.Profile != nil || bundle.ResumeInput != nil {
		b.WriteString("\n## Claim Projection\n")
		if bundle.Claims != nil {
			b.WriteString(fmt.Sprintf("- Claims: %d total, %d verified, %d strongly supported\n",
				len(bundle.Claims.Claims),
				bundle.Claims.Summary.Verified,
				bundle.Claims.Summary.StronglySupported))
		}
		if bundle.ResumeInput != nil {
			b.WriteString(fmt.Sprintf("- Resume-safe verified claims: %d\n", len(bundle.ResumeInput.VerifiedClaims)))
			b.WriteString(fmt.Sprintf("- Resume-safe strongly supported claims: %d\n", len(bundle.ResumeInput.StronglySupportedClaims)))
		}
	}

	if bundle.OutsourceAcceptance != nil || bundle.PMAcceptance != nil {
		b.WriteString("\n## Proof-Grade Scenarios\n")
		if bundle.OutsourceAcceptance != nil {
			s := bundle.OutsourceAcceptance.Summary
			b.WriteString(fmt.Sprintf("- Outsource acceptance: passed=%d failed=%d unknown=%d runtime_required=%d proof_rows=%d blocking_failures=%d\n",
				s.Passed, s.Failed, s.Unknown, s.RuntimeRequired, s.ProofGradeRows, s.BlockingFailures))
		}
		if bundle.PMAcceptance != nil {
			s := bundle.PMAcceptance.Summary
			b.WriteString(fmt.Sprintf("- PM acceptance: implemented=%d partial=%d blocked=%d runtime_required=%d unknown=%d proof_rows=%d\n",
				s.Implemented, s.Partial, s.Blocked, s.RuntimeRequired, s.Unknown, s.ProofGradeRows))
		}
	}

	if bundle.Trace.MigrationSummary != nil {
		summary := bundle.Trace.MigrationSummary
		b.WriteString("\n## Migration Audit\n")
		b.WriteString(fmt.Sprintf("- issue_native=%d seed_native=%d finding_bridged=%d\n",
			summary.IssueNativeCount,
			summary.SeedNativeCount,
			summary.FindingBridgedCount))
		if len(summary.RuleClaimFamilies) > 0 {
			b.WriteString("### Rule to Claim Families\n")
			ruleIDs := make([]string, 0, len(summary.RuleClaimFamilies))
			for ruleID := range summary.RuleClaimFamilies {
				ruleIDs = append(ruleIDs, ruleID)
			}
			sort.Strings(ruleIDs)
			for _, ruleID := range ruleIDs {
				families := append([]string(nil), summary.RuleClaimFamilies[ruleID]...)
				sort.Strings(families)
				b.WriteString(fmt.Sprintf("- %s -> %s\n", ruleID, strings.Join(families, ", ")))
			}
		}
	}

	return b.String()
}
