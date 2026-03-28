package artifactsv2

import "testing"

func TestScenarioSelectionHelpers(t *testing.T) {
	t.Parallel()

	proofPositive := ClaimRecord{
		ClaimID:               "claim-proof",
		Status:                "accepted",
		VerificationClass:     VerificationProofGrade,
		SupportingEvidenceIDs: []string{"ev-1"},
		Reason:                "proof",
	}
	structuralPositive := ClaimRecord{
		ClaimID:               "claim-structural",
		Status:                "accepted",
		VerificationClass:     VerificationStructuralInference,
		SupportingEvidenceIDs: []string{"ev-2"},
		Reason:                "structural",
	}
	runtimePositive := ClaimRecord{
		ClaimID:               "claim-runtime",
		Status:                "accepted",
		VerificationClass:     VerificationHumanOrRuntimeRequired,
		SupportingEvidenceIDs: []string{"ev-3"},
		Reason:                "runtime",
	}
	unknownRuntime := ClaimRecord{
		ClaimID:               "claim-runtime-unknown",
		Status:                "unknown",
		VerificationClass:     VerificationHumanOrRuntimeRequired,
		SupportingEvidenceIDs: []string{"ev-4"},
		Reason:                "runtime unknown",
	}
	rejectedPositive := ClaimRecord{
		ClaimID:                  "claim-rejected",
		Status:                   "rejected",
		VerificationClass:        VerificationStructuralInference,
		ContradictoryEvidenceIDs: []string{"ev-5"},
		Reason:                   "rejected",
	}
	negativeAccepted := ClaimRecord{
		ClaimID:                  "claim-negative",
		Status:                   "accepted",
		VerificationClass:        VerificationStructuralInference,
		ContradictoryEvidenceIDs: []string{"ev-6"},
		Reason:                   "negative",
	}

	if got, status, ok := selectScenarioClaimForOutsource(ClaimRecord{}, false, negativeAccepted, true); !ok || status != "failed" || got.ClaimID != "claim-negative" {
		t.Fatalf("selectScenarioClaimForOutsource(negative accepted) = %#v, %q, %t", got, status, ok)
	}
	if got, status, ok := selectScenarioClaimForOutsource(proofPositive, true, ClaimRecord{}, false); !ok || status != "passed" || got.ClaimID != "claim-proof" {
		t.Fatalf("selectScenarioClaimForOutsource(proof accepted) = %#v, %q, %t", got, status, ok)
	}
	if _, status, ok := selectScenarioClaimForOutsource(runtimePositive, true, ClaimRecord{}, false); !ok || status != "runtime_required" {
		t.Fatalf("selectScenarioClaimForOutsource(runtime accepted) status = %q ok=%t", status, ok)
	}
	if _, status, ok := selectScenarioClaimForOutsource(structuralPositive, true, ClaimRecord{}, false); !ok || status != "unknown" {
		t.Fatalf("selectScenarioClaimForOutsource(structural accepted) status = %q ok=%t", status, ok)
	}
	if _, status, ok := selectScenarioClaimForOutsource(unknownRuntime, true, ClaimRecord{}, false); !ok || status != "runtime_required" {
		t.Fatalf("selectScenarioClaimForOutsource(runtime unknown) status = %q ok=%t", status, ok)
	}
	if _, status, ok := selectScenarioClaimForOutsource(rejectedPositive, true, ClaimRecord{}, false); !ok || status != "failed" {
		t.Fatalf("selectScenarioClaimForOutsource(rejected) status = %q ok=%t", status, ok)
	}
	if _, _, ok := selectScenarioClaimForOutsource(ClaimRecord{}, false, ClaimRecord{}, false); ok {
		t.Fatal("expected no outsource selection when claims are absent")
	}

	if got, status, ok := selectScenarioClaimForPM(ClaimRecord{}, false, negativeAccepted, true); !ok || status != "blocked" || got.ClaimID != "claim-negative" {
		t.Fatalf("selectScenarioClaimForPM(negative accepted) = %#v, %q, %t", got, status, ok)
	}
	if _, status, ok := selectScenarioClaimForPM(proofPositive, true, ClaimRecord{}, false); !ok || status != "implemented" {
		t.Fatalf("selectScenarioClaimForPM(proof accepted) status = %q ok=%t", status, ok)
	}
	if _, status, ok := selectScenarioClaimForPM(runtimePositive, true, ClaimRecord{}, false); !ok || status != "runtime_required" {
		t.Fatalf("selectScenarioClaimForPM(runtime accepted) status = %q ok=%t", status, ok)
	}
	if _, status, ok := selectScenarioClaimForPM(structuralPositive, true, ClaimRecord{}, false); !ok || status != "partial" {
		t.Fatalf("selectScenarioClaimForPM(structural accepted) status = %q ok=%t", status, ok)
	}
	if _, status, ok := selectScenarioClaimForPM(rejectedPositive, true, ClaimRecord{}, false); !ok || status != "blocked" {
		t.Fatalf("selectScenarioClaimForPM(rejected) status = %q ok=%t", status, ok)
	}
	if _, status, ok := selectScenarioClaimForPM(unknownRuntime, true, ClaimRecord{}, false); !ok || status != "runtime_required" {
		t.Fatalf("selectScenarioClaimForPM(runtime unknown) status = %q ok=%t", status, ok)
	}
	if _, _, ok := selectScenarioClaimForPM(ClaimRecord{}, false, ClaimRecord{}, false); ok {
		t.Fatal("expected no PM selection when claims are absent")
	}
}

func TestScenarioSummaryAndTrustHelpers(t *testing.T) {
	t.Parallel()

	if got := trustClassForVerificationClass(VerificationProofGrade); got != TrustClassMachineTrusted {
		t.Fatalf("trustClassForVerificationClass(proof) = %q", got)
	}
	if got := trustClassForVerificationClass(VerificationHumanOrRuntimeRequired); got != TrustClassHumanOrRuntimeRequired {
		t.Fatalf("trustClassForVerificationClass(runtime) = %q", got)
	}
	if got := trustClassForVerificationClass(VerificationStructuralInference); got != TrustClassAdvisory {
		t.Fatalf("trustClassForVerificationClass(structural) = %q", got)
	}

	if got := outsourceUnknownReasons("unknown", ClaimRecord{VerificationClass: VerificationStructuralInference}); len(got) != 1 || got[0] != "advisory_pass_not_promoted" {
		t.Fatalf("outsourceUnknownReasons(unknown) = %#v", got)
	}
	if got := outsourceUnknownReasons("runtime_required", ClaimRecord{VerificationClass: VerificationHumanOrRuntimeRequired}); len(got) != 1 || got[0] != "static_proof_scope_insufficient" {
		t.Fatalf("outsourceUnknownReasons(runtime_required) = %#v", got)
	}
	if got := outsourceUnknownReasons("passed", ClaimRecord{}); len(got) != 0 {
		t.Fatalf("outsourceUnknownReasons(passed) = %#v", got)
	}

	if got := pmFollowUpAction("blocked", VerificationProofGrade); got == "" {
		t.Fatal("expected blocked follow-up action")
	}
	if got := pmFollowUpAction("runtime_required", VerificationHumanOrRuntimeRequired); got == "" {
		t.Fatal("expected runtime follow-up action")
	}
	if got := pmFollowUpAction("unknown", VerificationStructuralInference); got == "" {
		t.Fatal("expected unknown follow-up action")
	}
	if got := pmFollowUpAction("partial", VerificationStructuralInference); got == "" {
		t.Fatal("expected partial follow-up action")
	}
	if got := pmFollowUpAction("implemented", VerificationProofGrade); got != "" {
		t.Fatalf("pmFollowUpAction(implemented) = %q", got)
	}

	outsourceSummary := summarizeOutsourceRequirements([]OutsourceRequirementRow{
		{Status: "passed", VerificationClass: VerificationProofGrade},
		{Status: "failed", Blocking: true},
		{Status: "unknown"},
		{Status: "runtime_required"},
	})
	if outsourceSummary.Passed != 1 || outsourceSummary.Failed != 1 || outsourceSummary.BlockingFailures != 1 || outsourceSummary.Unknown != 1 || outsourceSummary.RuntimeRequired != 1 || outsourceSummary.ProofGradeRows != 1 {
		t.Fatalf("summarizeOutsourceRequirements() = %#v", outsourceSummary)
	}

	pmSummary := summarizePMRequirements([]PMEngineeringRequirement{
		{Status: "implemented", VerificationClass: VerificationProofGrade},
		{Status: "partial"},
		{Status: "blocked"},
		{Status: "unknown"},
		{Status: "runtime_required"},
	})
	if pmSummary.Implemented != 1 || pmSummary.Partial != 1 || pmSummary.Blocked != 1 || pmSummary.Unknown != 1 || pmSummary.RuntimeRequired != 1 || pmSummary.ProofGradeRows != 1 {
		t.Fatalf("summarizePMRequirements() = %#v", pmSummary)
	}
}
