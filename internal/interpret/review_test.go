package interpret

import (
	"context"
	"fmt"
	"strings"
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

// --- Additional shouldReview tests ---

func TestShouldReview_LowConfidenceReviewed(t *testing.T) {
	f := rules.Finding{
		RuleID:     "SEC-INPUT-001",
		Status:     rules.StatusFail,
		Confidence: rules.ConfidenceLow,
		TrustClass: rules.TrustAdvisory,
	}
	if !shouldReview(f, ReviewPolicyDefault) {
		t.Error("low-confidence findings should be reviewed by LLM")
	}
}

func TestShouldReview_MediumConfidencePassNotReviewed(t *testing.T) {
	// Medium confidence pass without weak inference or unknown reasons -> not reviewed
	f := rules.Finding{
		RuleID:            "SEC-AUTH-001",
		Status:            rules.StatusPass,
		Confidence:        rules.ConfidenceMedium,
		VerificationLevel: rules.VerificationStrongInference,
		TrustClass:        rules.TrustAdvisory,
	}
	if shouldReview(f, ReviewPolicyDefault) {
		t.Error("medium-confidence pass with strong inference should NOT be reviewed")
	}
}

func TestShouldReview_HighConfidenceFailNotReviewed(t *testing.T) {
	f := rules.Finding{
		RuleID:     "SEC-SECRET-001",
		Status:     rules.StatusFail,
		Confidence: rules.ConfidenceHigh,
		TrustClass: rules.TrustAdvisory,
	}
	if shouldReview(f, ReviewPolicyDefault) {
		t.Error("high-confidence fail should NOT be reviewed by LLM")
	}
}

func TestShouldReview_UnknownReasonsReviewed(t *testing.T) {
	f := rules.Finding{
		RuleID:         "SEC-INPUT-001",
		Status:         rules.StatusFail,
		Confidence:     rules.ConfidenceMedium,
		TrustClass:     rules.TrustAdvisory,
		UnknownReasons: []string{"cannot determine binding"},
	}
	if !shouldReview(f, ReviewPolicyDefault) {
		t.Error("findings with unknown reasons should be reviewed by LLM")
	}
}

// --- Additional applyReviewResult tests ---

func TestApplyReviewResult_AdvisoryUnknownToFail(t *testing.T) {
	f := rules.Finding{
		Status:     rules.StatusUnknown,
		TrustClass: rules.TrustAdvisory,
	}
	review := ReviewResult{
		RecommendedStatus:    "fail",
		DeterministicPrimary: false,
	}
	result := applyReviewResult(f, review)
	if result != rules.StatusFail {
		t.Errorf("expected fail, got %v", result)
	}
}

func TestApplyReviewResult_AdvisoryUnknownRecommendation(t *testing.T) {
	f := rules.Finding{
		Status:     rules.StatusFail,
		TrustClass: rules.TrustAdvisory,
	}
	review := ReviewResult{
		RecommendedStatus:    "unknown",
		DeterministicPrimary: false,
	}
	result := applyReviewResult(f, review)
	if result != rules.StatusUnknown {
		t.Errorf("expected unknown, got %v", result)
	}
}

func TestApplyReviewResult_AdvisoryPassToFailBlocked(t *testing.T) {
	f := rules.Finding{
		Status:     rules.StatusPass,
		TrustClass: rules.TrustAdvisory,
	}
	review := ReviewResult{
		RecommendedStatus:    "fail",
		DeterministicPrimary: false,
	}
	result := applyReviewResult(f, review)
	if result != rules.StatusPass {
		t.Errorf("LLM should not downgrade pass to fail; got %v", result)
	}
}

func TestApplyReviewResult_NonAdvisoryNonHumanKeepsStatus(t *testing.T) {
	// TrustMachineTrusted with DeterministicPrimary=false should still keep status
	// (machine-trusted wouldn't normally reach here, but tests the fallthrough)
	f := rules.Finding{
		Status:     rules.StatusFail,
		TrustClass: rules.TrustMachineTrusted,
	}
	review := ReviewResult{
		RecommendedStatus:    "pass",
		DeterministicPrimary: false,
	}
	result := applyReviewResult(f, review)
	if result != rules.StatusFail {
		t.Errorf("machine-trusted should keep original status; got %v", result)
	}
}

// --- Additional Review integration tests ---

func TestReview_LLMError(t *testing.T) {
	interp, err := New(&MockProvider{Err: fmt.Errorf("llm down")})
	if err != nil {
		t.Fatal(err)
	}

	findings := []rules.Finding{
		{RuleID: "SEC-INPUT-001", Status: rules.StatusUnknown, Confidence: rules.ConfidenceLow,
			TrustClass: rules.TrustAdvisory},
	}

	report, err := interp.Review(context.Background(), findings, nil, ReviewPolicyDefault)
	if err != nil {
		t.Fatal(err)
	}
	if report.ErrorCount != 1 {
		t.Errorf("expected 1 error, got %d", report.ErrorCount)
	}
	if report.ReviewCount != 0 {
		t.Errorf("expected 0 reviews, got %d", report.ReviewCount)
	}
	// Finding should keep original status
	if report.Findings[0].FinalStatus != rules.StatusUnknown {
		t.Errorf("expected unknown status preserved, got %v", report.Findings[0].FinalStatus)
	}
	if report.Findings[0].Review != nil {
		t.Error("review should be nil on LLM error")
	}
}

func TestReview_EmptyResponse(t *testing.T) {
	interp, err := New(&StubProvider{}) // returns ""
	if err != nil {
		t.Fatal(err)
	}

	findings := []rules.Finding{
		{RuleID: "SEC-INPUT-001", Status: rules.StatusUnknown, Confidence: rules.ConfidenceLow,
			TrustClass: rules.TrustAdvisory},
	}

	report, err := interp.Review(context.Background(), findings, nil, ReviewPolicyDefault)
	if err != nil {
		t.Fatal(err)
	}
	if report.SkipCount != 1 {
		t.Errorf("expected 1 skip (empty response), got %d", report.SkipCount)
	}
	if report.ReviewCount != 0 {
		t.Errorf("expected 0 reviews, got %d", report.ReviewCount)
	}
}

func TestReview_PolicyNoneSkipsAll(t *testing.T) {
	interp, err := New(&stubReviewProvider{})
	if err != nil {
		t.Fatal(err)
	}

	findings := []rules.Finding{
		{RuleID: "SEC-INPUT-001", Status: rules.StatusUnknown, Confidence: rules.ConfidenceLow,
			TrustClass: rules.TrustAdvisory},
	}

	report, err := interp.Review(context.Background(), findings, nil, ReviewPolicyNone)
	if err != nil {
		t.Fatal(err)
	}
	if report.SkipCount != 1 {
		t.Errorf("expected 1 skip, got %d", report.SkipCount)
	}
	if report.ReviewCount != 0 {
		t.Errorf("expected 0 reviews, got %d", report.ReviewCount)
	}
}

// --- Additional buildReviewPrompt tests ---

func TestBuildReviewPrompt_WithEvidenceAndSnippets(t *testing.T) {
	f := rules.Finding{
		RuleID:            "SEC-AUTH-001",
		Status:            rules.StatusUnknown,
		Confidence:        rules.ConfidenceLow,
		TrustClass:        rules.TrustAdvisory,
		VerificationLevel: rules.VerificationWeakInference,
		Message:           "Auth middleware not detected",
		Evidence: []rules.Evidence{
			{ID: "ev-001", File: "routes.go", LineStart: 10, LineEnd: 20, Symbol: "Setup"},
		},
		UnknownReasons: []string{"binding unknown", "framework unsupported"},
	}

	snippets := map[string]string{
		"routes.go": "func Setup() { r.GET(\"/api\", handler) }",
	}

	prompt := buildReviewPrompt(f, snippets)
	if !strings.Contains(prompt, "SEC-AUTH-001") {
		t.Error("prompt should contain rule ID")
	}
	if !strings.Contains(prompt, "ev-001") {
		t.Error("prompt should contain evidence ID")
	}
	if !strings.Contains(prompt, "routes.go") {
		t.Error("prompt should contain evidence file")
	}
	if !strings.Contains(prompt, "func Setup()") {
		t.Error("prompt should contain code snippet")
	}
	if !strings.Contains(prompt, "binding unknown; framework unsupported") {
		t.Error("prompt should contain unknown reasons")
	}
	if !strings.Contains(prompt, "weak_inference") {
		t.Error("prompt should contain verification level")
	}
}

func TestBuildReviewPrompt_NoEvidenceNoUnknownReasons(t *testing.T) {
	f := rules.Finding{
		RuleID:     "SEC-AUTH-001",
		Status:     rules.StatusUnknown,
		Confidence: rules.ConfidenceLow,
		TrustClass: rules.TrustAdvisory,
		Message:    "Cannot determine",
	}

	prompt := buildReviewPrompt(f, nil)
	if !strings.Contains(prompt, "SEC-AUTH-001") {
		t.Error("prompt should contain rule ID")
	}
	if strings.Contains(prompt, "Evidence:") {
		t.Error("prompt should not contain Evidence section when no evidence")
	}
	if strings.Contains(prompt, "Unknown Reasons:") {
		t.Error("prompt should not contain Unknown Reasons when none present")
	}
}

// --- Additional parseReviewResponse tests ---

func TestParseReviewResponse_InvalidStatus(t *testing.T) {
	response := "RECOMMENDED_STATUS: bogus\nCONFIDENCE: high\nREASONING: test\nCITED_EVIDENCE: none\nDETERMINISTIC_PRIMARY: false"
	result := parseReviewResponse(response)
	if result.RecommendedStatus != "unknown" {
		t.Errorf("invalid status should default to unknown, got %q", result.RecommendedStatus)
	}
}

func TestParseReviewResponse_InvalidConfidence(t *testing.T) {
	response := "RECOMMENDED_STATUS: pass\nCONFIDENCE: bogus\nREASONING: test\nCITED_EVIDENCE: none\nDETERMINISTIC_PRIMARY: true"
	result := parseReviewResponse(response)
	if result.Confidence != "low" {
		t.Errorf("invalid confidence should default to low, got %q", result.Confidence)
	}
}

func TestParseReviewResponse_EmptyCitedEvidence(t *testing.T) {
	response := "RECOMMENDED_STATUS: pass\nCONFIDENCE: high\nREASONING: test\nCITED_EVIDENCE: none\nDETERMINISTIC_PRIMARY: true"
	result := parseReviewResponse(response)
	if len(result.CitedEvidenceIDs) != 0 {
		t.Errorf("expected no cited evidence for 'none', got %v", result.CitedEvidenceIDs)
	}
}

func TestParseReviewResponse_EmptyString(t *testing.T) {
	response := "RECOMMENDED_STATUS: pass\nCONFIDENCE: high\nREASONING: test\nCITED_EVIDENCE: \nDETERMINISTIC_PRIMARY: true"
	result := parseReviewResponse(response)
	if len(result.CitedEvidenceIDs) != 0 {
		t.Errorf("expected no cited evidence for empty string, got %v", result.CitedEvidenceIDs)
	}
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
