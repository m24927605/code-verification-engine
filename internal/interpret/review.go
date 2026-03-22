package interpret

import (
	"context"
	"fmt"
	"strings"

	"github.com/verabase/code-verification-engine/internal/rules"
)

// ReviewPolicy controls when LLM review is invoked.
type ReviewPolicy string

const (
	// ReviewPolicyDefault invokes LLM only for partial/unknown/conflict findings.
	ReviewPolicyDefault ReviewPolicy = "default"
	// ReviewPolicyNone disables LLM review entirely.
	ReviewPolicyNone ReviewPolicy = "none"
)

// ReviewResult holds the structured output of an LLM review.
type ReviewResult struct {
	RecommendedStatus    string `json:"recommended_status"`    // pass, fail, unknown
	Confidence           string `json:"confidence"`            // high, medium, low
	Reasoning            string `json:"reasoning"`             // why the recommendation
	CitedEvidenceIDs     []string `json:"cited_evidence_ids"`  // evidence IDs cited
	DeterministicPrimary bool   `json:"deterministic_primary"` // true if deterministic verdict should remain
	LLMReviewed          bool   `json:"llm_reviewed"`          // always true when LLM actually reviewed
}

// ReviewedFinding extends a finding with LLM review context.
type ReviewedFinding struct {
	rules.Finding
	DeterministicStatus rules.Status `json:"deterministic_status"` // original status before review
	Review              *ReviewResult `json:"review,omitempty"`     // nil if LLM review not invoked
	FinalStatus         rules.Status `json:"final_status"`         // displayed result
}

// ReviewReport holds all reviewed findings.
type ReviewReport struct {
	Findings     []ReviewedFinding `json:"findings"`
	ReviewCount  int               `json:"review_count"`  // number of findings sent to LLM
	SkipCount    int               `json:"skip_count"`    // skipped (strong deterministic)
	ErrorCount   int               `json:"error_count"`   // LLM errors
}

// shouldReview determines if a finding qualifies for LLM review based on policy.
func shouldReview(f rules.Finding, policy ReviewPolicy) bool {
	if policy == ReviewPolicyNone {
		return false
	}

	// Machine-trusted rules NEVER get LLM review
	if f.TrustClass == rules.TrustMachineTrusted {
		return false
	}

	// Strong deterministic pass/fail: do not invoke LLM
	if f.Confidence == rules.ConfidenceHigh &&
		(f.Status == rules.StatusPass || f.Status == rules.StatusFail) {
		return false
	}

	// Invoke LLM for:
	// - unknown status
	// - low/medium confidence
	// - weak inference
	// - findings with unknown reasons
	if f.Status == rules.StatusUnknown {
		return true
	}
	if f.Confidence == rules.ConfidenceLow {
		return true
	}
	if f.VerificationLevel == rules.VerificationWeakInference {
		return true
	}
	if len(f.UnknownReasons) > 0 {
		return true
	}

	return false
}

// Review processes findings through the constrained LLM review layer.
// Rules:
//   - Machine-trusted rules are NEVER reviewed by LLM
//   - Strong deterministic pass/fail are skipped
//   - Only partial/unknown/conflict findings are reviewed
//   - LLM may refine advisory conclusions only
//   - LLM must not override deterministic facts
//   - Human-or-runtime-required findings get explanation only, not verdict change
func (i *Interpreter) Review(ctx context.Context, findings []rules.Finding, codeSnippets map[string]string, policy ReviewPolicy) (*ReviewReport, error) {
	report := &ReviewReport{}

	for _, f := range findings {
		reviewed := ReviewedFinding{
			Finding:             f,
			DeterministicStatus: f.Status,
			FinalStatus:         f.Status, // default: keep deterministic
		}

		if !shouldReview(f, policy) {
			report.SkipCount++
			report.Findings = append(report.Findings, reviewed)
			continue
		}

		// Build structured review prompt
		prompt := buildReviewPrompt(f, codeSnippets)
		response, err := i.provider.Complete(ctx, prompt)
		if err != nil {
			report.ErrorCount++
			report.Findings = append(report.Findings, reviewed)
			continue
		}

		if strings.TrimSpace(response) == "" {
			report.SkipCount++
			report.Findings = append(report.Findings, reviewed)
			continue
		}

		report.ReviewCount++
		result := parseReviewResponse(response)
		result.LLMReviewed = true
		reviewed.Review = &result

		// Apply review result based on trust class constraints
		reviewed.FinalStatus = applyReviewResult(f, result)

		report.Findings = append(report.Findings, reviewed)
	}

	return report, nil
}

// applyReviewResult determines the final status based on LLM review + trust constraints.
func applyReviewResult(f rules.Finding, review ReviewResult) rules.Status {
	// If LLM says deterministic should remain primary, keep it
	if review.DeterministicPrimary {
		return f.Status
	}

	// Human-or-runtime-required: LLM may explain but not change verdict
	if f.TrustClass == rules.TrustHumanOrRuntimeRequired {
		return f.Status
	}

	// Advisory rules: LLM may refine the conclusion
	if f.TrustClass == rules.TrustAdvisory {
		switch review.RecommendedStatus {
		case "pass":
			// Only upgrade from unknown to pass, never from fail to pass
			if f.Status == rules.StatusUnknown {
				return rules.StatusPass
			}
		case "fail":
			// Only downgrade from unknown to fail, never from pass to fail
			if f.Status == rules.StatusUnknown {
				return rules.StatusFail
			}
		case "unknown":
			return rules.StatusUnknown
		}
	}

	return f.Status
}

func buildReviewPrompt(f rules.Finding, snippets map[string]string) string {
	var b strings.Builder
	b.WriteString("You are a code verification reviewer. Analyze this finding and provide a structured review.\n\n")
	b.WriteString("CONSTRAINTS:\n")
	b.WriteString("- You MUST NOT override strong deterministic evidence\n")
	b.WriteString("- You may only refine advisory conclusions\n")
	b.WriteString("- If deterministic evidence is strong, set deterministic_primary=true\n\n")

	b.WriteString(fmt.Sprintf("Rule ID: %s\n", f.RuleID))
	b.WriteString(fmt.Sprintf("Trust Class: %s\n", f.TrustClass))
	b.WriteString(fmt.Sprintf("Deterministic Status: %s\n", f.Status))
	b.WriteString(fmt.Sprintf("Confidence: %s\n", f.Confidence))
	b.WriteString(fmt.Sprintf("Verification Level: %s\n", f.VerificationLevel))
	b.WriteString(fmt.Sprintf("Message: %s\n", f.Message))

	if len(f.Evidence) > 0 {
		b.WriteString("\nEvidence:\n")
		for _, ev := range f.Evidence {
			b.WriteString(fmt.Sprintf("  [%s] File: %s (lines %d-%d) Symbol: %s\n",
				ev.ID, ev.File, ev.LineStart, ev.LineEnd, ev.Symbol))
			if snippet, ok := snippets[ev.File]; ok {
				b.WriteString(fmt.Sprintf("  Code:\n%s\n", snippet))
			}
		}
	}

	if len(f.UnknownReasons) > 0 {
		b.WriteString(fmt.Sprintf("\nUnknown Reasons: %s\n", strings.Join(f.UnknownReasons, "; ")))
	}

	b.WriteString("\nRespond in this exact format:\n")
	b.WriteString("RECOMMENDED_STATUS: <pass|fail|unknown>\n")
	b.WriteString("CONFIDENCE: <high|medium|low>\n")
	b.WriteString("REASONING: <explanation>\n")
	b.WriteString("CITED_EVIDENCE: <comma-separated evidence IDs, or 'none'>\n")
	b.WriteString("DETERMINISTIC_PRIMARY: <true|false>\n")

	return b.String()
}

func parseReviewResponse(response string) ReviewResult {
	result := ReviewResult{
		DeterministicPrimary: true, // default: keep deterministic
	}

	lines := strings.Split(response, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "RECOMMENDED_STATUS:") {
			status := strings.TrimSpace(strings.TrimPrefix(line, "RECOMMENDED_STATUS:"))
			status = strings.ToLower(status)
			switch status {
			case "pass", "fail", "unknown":
				result.RecommendedStatus = status
			default:
				result.RecommendedStatus = "unknown"
			}
		} else if strings.HasPrefix(line, "CONFIDENCE:") {
			conf := strings.TrimSpace(strings.TrimPrefix(line, "CONFIDENCE:"))
			conf = strings.ToLower(conf)
			switch conf {
			case "high", "medium", "low":
				result.Confidence = conf
			default:
				result.Confidence = "low"
			}
		} else if strings.HasPrefix(line, "REASONING:") {
			result.Reasoning = strings.TrimSpace(strings.TrimPrefix(line, "REASONING:"))
		} else if strings.HasPrefix(line, "CITED_EVIDENCE:") {
			cited := strings.TrimSpace(strings.TrimPrefix(line, "CITED_EVIDENCE:"))
			if cited != "none" && cited != "" {
				for _, id := range strings.Split(cited, ",") {
					id = strings.TrimSpace(id)
					if id != "" {
						result.CitedEvidenceIDs = append(result.CitedEvidenceIDs, id)
					}
				}
			}
		} else if strings.HasPrefix(line, "DETERMINISTIC_PRIMARY:") {
			val := strings.TrimSpace(strings.TrimPrefix(line, "DETERMINISTIC_PRIMARY:"))
			result.DeterministicPrimary = strings.ToLower(val) == "true"
		}
	}

	return result
}
