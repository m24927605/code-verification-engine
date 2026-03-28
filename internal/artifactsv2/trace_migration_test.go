package artifactsv2

import (
	"testing"

	"github.com/verabase/code-verification-engine/internal/rules"
)

func TestBuildRuleMigrationSummary_IncludesRuleClaimFamilies(t *testing.T) {
	t.Parallel()

	summary := buildRuleMigrationSummary(VerificationSource{
		RuleMetadata: map[string]RuleMetadata{
			"SEC-SECRET-002": {
				RuleID:         "SEC-SECRET-002",
				MigrationState: string(rules.MigrationFindingBridged),
			},
		},
	})
	if summary == nil {
		t.Fatal("expected summary")
	}
	if got := len(summary.RuleClaimFamilies["SEC-SECRET-002"]); got != 3 {
		t.Fatalf("rule claim families count = %d, want 3", got)
	}
}

func TestValidateTrace_RejectsEmptyRuleClaimFamilyID(t *testing.T) {
	t.Parallel()

	trace := TraceArtifact{
		SchemaVersion: TraceSchemaVersion,
		EngineVersion: "verabase@dev",
		TraceID:       "trace-1",
		Repo:          "/repo",
		Commit:        "abc123",
		Timestamp:     "2026-03-28T00:00:00Z",
		ScanBoundary:  TraceScanBoundary{Mode: "repo", IncludedFiles: 1},
		ConfidenceCalibration: &ConfidenceCalibration{
			Version:                 "1.0.0",
			MachineTrustedThreshold: 0.85,
			UnknownCap:              0.5,
			AgentOnlyCap:            0.4,
		},
	}
	trace.MigrationSummary = &RuleMigrationSummary{
		RuleStates: map[string]string{"SEC-001": string(rules.MigrationFindingBridged)},
		RuleClaimFamilies: map[string][]string{
			"SEC-001": {""},
		},
	}
	if err := ValidateTrace(trace); err == nil {
		t.Fatal("expected validation error")
	}
}
