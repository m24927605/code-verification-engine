package rules

import (
	"reflect"
	"testing"
)

func TestFinalizeExecutionResultNormalizesFindingsAndSeeds(t *testing.T) {
	t.Parallel()

	rf := &RuleFile{
		Rules: []Rule{{
			ID:       "SEC-SECRET-001",
			Title:    "Hardcoded secret detected",
			Category: "Security",
			Severity: "Critical",
		}},
	}
	result := ExecutionResult{
		Findings: []Finding{{
			RuleID:            "SEC-SECRET-001",
			Status:            StatusFail,
			Confidence:        ConfidenceHigh,
			VerificationLevel: VerificationVerified,
			Message:           "fallback",
			FactQualityFloor:  "proof",
			Evidence: []Evidence{{
				File:      "main.go",
				LineStart: 10,
				LineEnd:   10,
				Symbol:    "main",
			}},
		}},
	}

	FinalizeExecutionResult(rf, &result)

	if got := result.Findings[0].Evidence[0].ID; got == "" {
		t.Fatal("expected finalized evidence id")
	}
	if got := result.Findings[0].TrustClass; got != TrustMachineTrusted {
		t.Fatalf("trust_class = %q, want %q", got, TrustMachineTrusted)
	}
	if len(result.IssueSeeds) != 1 {
		t.Fatalf("expected 1 issue seed, got %d", len(result.IssueSeeds))
	}
	if got := result.IssueSeeds[0].EvidenceIDs; len(got) != 1 || got[0] == "" {
		t.Fatalf("expected issue seed evidence ids, got %#v", got)
	}
	if got := result.IssueSeeds[0].Severity; got != "critical" {
		t.Fatalf("severity = %q, want critical", got)
	}
}

func TestFinalizeExecutionResultIsIdempotent(t *testing.T) {
	t.Parallel()

	rf := &RuleFile{
		Rules: []Rule{{
			ID:       "ARCH-001",
			Title:    "Repository pattern violation",
			Category: "Design",
			Severity: "High",
		}},
	}
	result := ExecutionResult{
		Findings: []Finding{{
			RuleID:            "ARCH-001",
			Status:            StatusUnknown,
			Confidence:        ConfidenceLow,
			VerificationLevel: VerificationVerified,
			Message:           "fallback",
			FactQualityFloor:  "heuristic",
			Evidence: []Evidence{{
				File:      "internal/service.ts",
				LineStart: 20,
				LineEnd:   24,
				Symbol:    "Repository",
			}},
		}},
	}

	FinalizeExecutionResult(rf, &result)
	firstEvidenceID := result.Findings[0].Evidence[0].ID
	firstTrust := result.Findings[0].TrustClass
	firstSeed := result.IssueSeeds[0]

	FinalizeExecutionResult(rf, &result)

	if got := result.Findings[0].Evidence[0].ID; got != firstEvidenceID {
		t.Fatalf("evidence id changed after second finalize: %q != %q", got, firstEvidenceID)
	}
	if got := result.Findings[0].TrustClass; got != firstTrust {
		t.Fatalf("trust class changed after second finalize: %q != %q", got, firstTrust)
	}
	if got := result.IssueSeeds[0]; !reflect.DeepEqual(got, firstSeed) {
		t.Fatalf("issue seed changed after second finalize: %#v != %#v", got, firstSeed)
	}
}
