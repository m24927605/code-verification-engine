package artifactsv2

import (
	"strings"
	"testing"
)

func TestBuildBundleSummaryMarkdown_IncludesProjectionScenarioAndMigrationSections(t *testing.T) {
	t.Parallel()

	b := testBundle()
	b.Claims = scenarioClaimsArtifactWithRows()
	b.Profile = &ProfileArtifact{
		SchemaVersion: "1.0.0",
		Repository:    ClaimRepositoryRef{Path: "/repo", Commit: "abc123"},
	}
	b.ResumeInput = &ResumeInputArtifact{
		SchemaVersion: ResumeInputSchemaVersion,
		Profile: ProfileArtifact{
			SchemaVersion: "1.0.0",
			Repository:    ClaimRepositoryRef{Path: "/repo", Commit: "abc123"},
		},
	}
	b.OutsourceAcceptance = &OutsourceAcceptanceArtifact{
		SchemaVersion:     OutsourceAcceptanceSchemaVersion,
		Repository:        AcceptanceRepositoryRef{Path: b.Report.Repo, Commit: b.Report.Commit},
		TraceID:           b.Report.TraceID,
		AcceptanceProfile: "outsource-default",
		Summary:           OutsourceAcceptanceSummary{Passed: 1, ProofGradeRows: 1},
	}
	b.PMAcceptance = &PMAcceptanceArtifact{
		SchemaVersion:     PMAcceptanceSchemaVersion,
		Repository:        AcceptanceRepositoryRef{Path: b.Report.Repo, Commit: b.Report.Commit},
		TraceID:           b.Report.TraceID,
		AcceptanceProfile: "pm-default",
		Summary:           PMAcceptanceSummary{Implemented: 1, ProofGradeRows: 1},
	}
	b.Trace.MigrationSummary = &RuleMigrationSummary{
		IssueNativeCount:    1,
		SeedNativeCount:     2,
		FindingBridgedCount: 3,
		RuleClaimFamilies: map[string][]string{
			"AUTH-002": {"security.route_auth_binding"},
		},
	}

	text := BuildBundleSummaryMarkdown(b)
	for _, fragment := range []string{
		"## Claim Projection",
		"## Proof-Grade Scenarios",
		"## Migration Audit",
		"AUTH-002 -> security.route_auth_binding",
	} {
		if !strings.Contains(text, fragment) {
			t.Fatalf("summary missing %q:\n%s", fragment, text)
		}
	}
}

func TestRefreshSummaryMarkdown_ReplacesBundleSummary(t *testing.T) {
	t.Parallel()

	b := testBundle()
	b.SummaryMD = "old"
	RefreshSummaryMarkdown(&b)
	if !strings.Contains(b.SummaryMD, "# Verabase Report") {
		t.Fatalf("unexpected refreshed summary: %s", b.SummaryMD)
	}
}
