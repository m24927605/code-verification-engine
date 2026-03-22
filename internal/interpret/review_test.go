package interpret

import (
	"context"
	"testing"

	"github.com/verabase/code-verification-engine/internal/rules"
)

func TestShouldReview_MachineTrustedSkipped(t *testing.T) {
	f := rules.Finding{
		RuleID:     "SEC-SECRET-001",
		Status:     rules.StatusFail,
		Confidence: rules.ConfidenceHigh,
		TrustClass: rules.TrustMachineTrusted,
	}
	if shouldReview(f, ReviewPolicyDefault) {
		t.Error("machine-trusted findings should NOT be reviewed by LLM")
	}
}

func TestShouldReview_StrongDeterministicSkipped(t *testing.T) {
	f := rules.Finding{
		RuleID:     "SEC-AUTH-001",
		Status:     rules.StatusPass,
		Confidence: rules.ConfidenceHigh,
		TrustClass: rules.TrustAdvisory,
	}
	if shouldReview(f, ReviewPolicyDefault) {
		t.Error("high-confidence pass should NOT be reviewed by LLM")
	}
}

func TestShouldReview_UnknownReviewed(t *testing.T) {
	f := rules.Finding{
		RuleID:     "SEC-INPUT-001",
		Status:     rules.StatusUnknown,
		Confidence: rules.ConfidenceLow,
		TrustClass: rules.TrustAdvisory,
	}
	if !shouldReview(f, ReviewPolicyDefault) {
		t.Error("unknown findings should be reviewed by LLM")
	}
}

func TestShouldReview_WeakInferenceReviewed(t *testing.T) {
	f := rules.Finding{
		RuleID:            "SEC-AUTH-001",
		Status:            rules.StatusPass,
		Confidence:        rules.ConfidenceMedium,
		VerificationLevel: rules.VerificationWeakInference,
		TrustClass:        rules.TrustAdvisory,
	}
	if !shouldReview(f, ReviewPolicyDefault) {
		t.Error("weak inference findings should be reviewed by LLM")
	}
}

func TestShouldReview_PolicyNone(t *testing.T) {
	f := rules.Finding{
		RuleID:     "SEC-INPUT-001",
		Status:     rules.StatusUnknown,
		Confidence: rules.ConfidenceLow,
		TrustClass: rules.TrustAdvisory,
	}
	if shouldReview(f, ReviewPolicyNone) {
		t.Error("no findings should be reviewed when policy is none")
	}
}

func TestApplyReviewResult_AdvisoryUnknownToPass(t *testing.T) {
	f := rules.Finding{
		Status:     rules.StatusUnknown,
		TrustClass: rules.TrustAdvisory,
	}
	review := ReviewResult{
		RecommendedStatus:    "pass",
		DeterministicPrimary: false,
	}
	result := applyReviewResult(f, review)
	if result != rules.StatusPass {
		t.Errorf("expected pass, got %v", result)
	}
}

func TestApplyReviewResult_AdvisoryFailToPassBlocked(t *testing.T) {
	f := rules.Finding{
		Status:     rules.StatusFail,
		TrustClass: rules.TrustAdvisory,
	}
	review := ReviewResult{
		RecommendedStatus:    "pass",
		DeterministicPrimary: false,
	}
	result := applyReviewResult(f, review)
	if result != rules.StatusFail {
		t.Errorf("LLM should not upgrade fail to pass; got %v", result)
	}
}

func TestApplyReviewResult_HumanRequired_NoChange(t *testing.T) {
	f := rules.Finding{
		Status:     rules.StatusUnknown,
		TrustClass: rules.TrustHumanOrRuntimeRequired,
	}
	review := ReviewResult{
		RecommendedStatus:    "pass",
		DeterministicPrimary: false,
	}
	result := applyReviewResult(f, review)
	if result != rules.StatusUnknown {
		t.Errorf("human_or_runtime_required findings should NOT change; got %v", result)
	}
}

func TestApplyReviewResult_DeterministicPrimary(t *testing.T) {
	f := rules.Finding{
		Status:     rules.StatusFail,
		TrustClass: rules.TrustAdvisory,
	}
	review := ReviewResult{
		RecommendedStatus:    "pass",
		DeterministicPrimary: true,
	}
	result := applyReviewResult(f, review)
	if result != rules.StatusFail {
		t.Errorf("deterministic_primary=true should keep original status; got %v", result)
	}
}

func TestParseReviewResponse(t *testing.T) {
	response := `RECOMMENDED_STATUS: pass
CONFIDENCE: medium
REASONING: The code shows clear validation patterns
CITED_EVIDENCE: ev-abc123, ev-def456
DETERMINISTIC_PRIMARY: false`

	result := parseReviewResponse(response)
	if result.RecommendedStatus != "pass" {
		t.Errorf("status = %q, want pass", result.RecommendedStatus)
	}
	if result.Confidence != "medium" {
		t.Errorf("confidence = %q, want medium", result.Confidence)
	}
	if len(result.CitedEvidenceIDs) != 2 {
		t.Errorf("cited = %d, want 2", len(result.CitedEvidenceIDs))
	}
	if result.DeterministicPrimary {
		t.Error("deterministic_primary should be false")
	}
}

// stubProvider for testing
type stubReviewProvider struct{}

func (p *stubReviewProvider) Complete(_ context.Context, _ string) (string, error) {
	return "RECOMMENDED_STATUS: pass\nCONFIDENCE: medium\nREASONING: test\nCITED_EVIDENCE: none\nDETERMINISTIC_PRIMARY: false", nil
}

func TestReview_Integration(t *testing.T) {
	interp, err := New(&stubReviewProvider{})
	if err != nil {
		t.Fatal(err)
	}

	findings := []rules.Finding{
		{RuleID: "SEC-SECRET-001", Status: rules.StatusFail, Confidence: rules.ConfidenceHigh,
			TrustClass: rules.TrustMachineTrusted},
		{RuleID: "SEC-INPUT-001", Status: rules.StatusUnknown, Confidence: rules.ConfidenceLow,
			TrustClass: rules.TrustAdvisory},
		{RuleID: "SEC-AUTH-001", Status: rules.StatusPass, Confidence: rules.ConfidenceHigh,
			TrustClass: rules.TrustAdvisory},
	}

	report, err := interp.Review(context.Background(), findings, nil, ReviewPolicyDefault)
	if err != nil {
		t.Fatal(err)
	}

	if report.ReviewCount != 1 {
		t.Errorf("expected 1 review (SEC-INPUT-001), got %d", report.ReviewCount)
	}
	if report.SkipCount != 2 {
		t.Errorf("expected 2 skipped, got %d", report.SkipCount)
	}

	// SEC-INPUT-001 should have been reviewed and upgraded from unknown to pass
	for _, f := range report.Findings {
		if f.RuleID == "SEC-INPUT-001" {
			if f.DeterministicStatus != rules.StatusUnknown {
				t.Errorf("deterministic status should be unknown, got %v", f.DeterministicStatus)
			}
			if f.FinalStatus != rules.StatusPass {
				t.Errorf("final status should be pass (LLM recommended), got %v", f.FinalStatus)
			}
		}
		if f.RuleID == "SEC-SECRET-001" {
			if f.FinalStatus != rules.StatusFail {
				t.Errorf("machine-trusted finding should remain fail, got %v", f.FinalStatus)
			}
		}
	}
}
