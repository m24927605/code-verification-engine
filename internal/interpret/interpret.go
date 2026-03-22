package interpret

import (
	"context"
	"fmt"
	"strings"

	"github.com/verabase/code-verification-engine/internal/rules"
)

// Interpreter generates human-readable explanations for verification findings.
// It sits after the deterministic engine and never changes verdicts.
type Interpreter struct {
	provider LLMProvider
}

// LLMProvider is the interface for LLM backends.
// Implementations can use Claude, OpenAI, or any other LLM.
type LLMProvider interface {
	Complete(ctx context.Context, prompt string) (string, error)
}

// New creates a new Interpreter with the given LLM provider.
// Returns an error if provider is nil.
func New(provider LLMProvider) (*Interpreter, error) {
	if provider == nil {
		return nil, fmt.Errorf("LLM provider must not be nil")
	}
	return &Interpreter{provider: provider}, nil
}

// InterpretedFinding wraps a deterministic finding with LLM-generated context.
// The original finding is never modified.
type InterpretedFinding struct {
	rules.Finding

	// LLM-generated fields — all optional, all clearly marked as LLM output
	Explanation     string   `json:"explanation,omitempty"`      // Human-readable why this matters
	TriageHint      string   `json:"triage_hint,omitempty"`      // "likely_real", "possible_false_positive", "test_fixture", "needs_review"
	TriageReason    string   `json:"triage_reason,omitempty"`    // Why the triage hint was given
	SuggestedFix    string   `json:"suggested_fix,omitempty"`    // Concrete remediation steps
	RelatedFindings []string `json:"related_findings,omitempty"` // IDs of findings that should be reviewed together

	// For unknown findings only
	UnknownCategory string `json:"unknown_category,omitempty"` // Classification of why it's unknown
	MissingEvidence string `json:"missing_evidence,omitempty"` // What evidence would resolve the unknown
	NextSteps       string `json:"next_steps,omitempty"`       // What to do to resolve

	// Metadata
	LLMGenerated bool `json:"llm_generated"` // Always true for interpreted fields
}

// InterpretedReport wraps the deterministic report with interpretation.
type InterpretedReport struct {
	Findings []InterpretedFinding  `json:"findings"`
	Summary  InterpretationSummary `json:"interpretation_summary"`
}

// InterpretationSummary provides high-level triage info.
type InterpretationSummary struct {
	LikelyRealIssues       int `json:"likely_real_issues"`
	PossibleFalsePositives int `json:"possible_false_positives"`
	NeedsReview            int `json:"needs_review"`
	UnknownsClassified     int `json:"unknowns_classified"`
}

// Interpret processes all findings through the LLM interpretation layer.
// Each finding gets exactly one LLM call. Unknown findings get a second
// call for classification.
func (i *Interpreter) Interpret(ctx context.Context, findings []rules.Finding, codeSnippets map[string]string) (*InterpretedReport, error) {
	report := &InterpretedReport{}

	for _, f := range findings {
		interpreted := InterpretedFinding{
			Finding:      f,
			LLMGenerated: false, // only set true when LLM actually produces content
		}

		// 1. Evidence interpretation for all non-pass findings
		if f.Status != rules.StatusPass {
			prompt := buildEvidencePrompt(f, codeSnippets)
			response, err := i.provider.Complete(ctx, prompt)
			if err != nil {
				// LLM failure is non-fatal — just skip interpretation
				report.Findings = append(report.Findings, interpreted)
				continue
			}
			// Only mark as LLM-generated if the provider returned actual content.
			// Empty responses (e.g., from StubProvider) should not be marked.
			if strings.TrimSpace(response) != "" {
				parseEvidenceResponse(response, &interpreted)
				interpreted.LLMGenerated = true
			}
		}

		// 2. Unknown classification
		if f.Status == rules.StatusUnknown {
			prompt := buildUnknownPrompt(f, codeSnippets)
			response, err := i.provider.Complete(ctx, prompt)
			if err == nil {
				parseUnknownResponse(response, &interpreted)
			}
		}

		// Update summary counts
		switch interpreted.TriageHint {
		case "likely_real":
			report.Summary.LikelyRealIssues++
		case "possible_false_positive", "test_fixture":
			report.Summary.PossibleFalsePositives++
		case "needs_review":
			report.Summary.NeedsReview++
		}
		if interpreted.UnknownCategory != "" {
			report.Summary.UnknownsClassified++
		}

		report.Findings = append(report.Findings, interpreted)
	}

	return report, nil
}

func buildEvidencePrompt(f rules.Finding, snippets map[string]string) string {
	var b strings.Builder
	b.WriteString("You are a code verification evidence interpreter. Analyze this finding and provide:\n")
	b.WriteString("1. EXPLANATION: A clear, concise explanation of why this finding matters (2-3 sentences)\n")
	b.WriteString("2. TRIAGE: One of: likely_real, possible_false_positive, test_fixture, needs_review\n")
	b.WriteString("3. TRIAGE_REASON: Why you chose that triage classification (1 sentence)\n")
	b.WriteString("4. FIX: Concrete remediation steps if status is 'fail' (2-4 bullet points)\n\n")

	b.WriteString(fmt.Sprintf("Rule: %s\n", f.RuleID))
	b.WriteString(fmt.Sprintf("Status: %s\n", f.Status))
	b.WriteString(fmt.Sprintf("Message: %s\n", f.Message))

	if len(f.Evidence) > 0 {
		b.WriteString("\nEvidence:\n")
		for _, ev := range f.Evidence {
			b.WriteString(fmt.Sprintf("  File: %s (lines %d-%d) Symbol: %s\n", ev.File, ev.LineStart, ev.LineEnd, ev.Symbol))
			if snippet, ok := snippets[ev.File]; ok {
				b.WriteString(fmt.Sprintf("  Code:\n%s\n", snippet))
			}
		}
	}

	if len(f.UnknownReasons) > 0 {
		b.WriteString(fmt.Sprintf("\nUnknown reasons: %s\n", strings.Join(f.UnknownReasons, "; ")))
	}

	b.WriteString("\nRespond in this exact format:\n")
	b.WriteString("EXPLANATION: <your explanation>\n")
	b.WriteString("TRIAGE: <likely_real|possible_false_positive|test_fixture|needs_review>\n")
	b.WriteString("TRIAGE_REASON: <reason>\n")
	b.WriteString("FIX: <remediation steps, use \\n for line breaks>\n")

	return b.String()
}

func buildUnknownPrompt(f rules.Finding, snippets map[string]string) string {
	var b strings.Builder
	b.WriteString("You are classifying why a code verification check returned 'unknown'. Analyze and provide:\n")
	b.WriteString("1. CATEGORY: One of: unsupported_framework, missing_binding_data, partial_evidence, needs_runtime_config, needs_human_attestation, analyzer_limitation\n")
	b.WriteString("2. MISSING: What specific evidence would resolve this unknown (1-2 sentences)\n")
	b.WriteString("3. NEXT_STEPS: What the user or engine should do to resolve (2-3 bullet points)\n\n")

	b.WriteString(fmt.Sprintf("Rule: %s\n", f.RuleID))
	b.WriteString(fmt.Sprintf("Message: %s\n", f.Message))

	if len(f.UnknownReasons) > 0 {
		b.WriteString(fmt.Sprintf("Unknown reasons: %s\n", strings.Join(f.UnknownReasons, "; ")))
	}

	if len(f.Evidence) > 0 {
		b.WriteString("\nPartial evidence:\n")
		for _, ev := range f.Evidence {
			b.WriteString(fmt.Sprintf("  File: %s Symbol: %s\n", ev.File, ev.Symbol))
			if snippet, ok := snippets[ev.File]; ok {
				b.WriteString(fmt.Sprintf("  Code:\n%s\n", snippet))
			}
		}
	}

	b.WriteString("\nRespond in this exact format:\n")
	b.WriteString("CATEGORY: <category>\n")
	b.WriteString("MISSING: <missing evidence>\n")
	b.WriteString("NEXT_STEPS: <steps, use \\n for line breaks>\n")

	return b.String()
}

func parseEvidenceResponse(response string, f *InterpretedFinding) {
	lines := strings.Split(response, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "EXPLANATION:") {
			f.Explanation = strings.TrimSpace(strings.TrimPrefix(line, "EXPLANATION:"))
		} else if strings.HasPrefix(line, "TRIAGE:") {
			hint := strings.TrimSpace(strings.TrimPrefix(line, "TRIAGE:"))
			hint = strings.ToLower(hint)
			switch hint {
			case "likely_real", "possible_false_positive", "test_fixture", "needs_review":
				f.TriageHint = hint
			default:
				f.TriageHint = "needs_review"
			}
		} else if strings.HasPrefix(line, "TRIAGE_REASON:") {
			f.TriageReason = strings.TrimSpace(strings.TrimPrefix(line, "TRIAGE_REASON:"))
		} else if strings.HasPrefix(line, "FIX:") {
			f.SuggestedFix = strings.TrimSpace(strings.TrimPrefix(line, "FIX:"))
			f.SuggestedFix = strings.ReplaceAll(f.SuggestedFix, "\\n", "\n")
		}
	}
}

func parseUnknownResponse(response string, f *InterpretedFinding) {
	lines := strings.Split(response, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "CATEGORY:") {
			cat := strings.TrimSpace(strings.TrimPrefix(line, "CATEGORY:"))
			cat = strings.ToLower(cat)
			validCategories := map[string]bool{
				"unsupported_framework":   true,
				"missing_binding_data":    true,
				"partial_evidence":        true,
				"needs_runtime_config":    true,
				"needs_human_attestation": true,
				"analyzer_limitation":     true,
			}
			if validCategories[cat] {
				f.UnknownCategory = cat
			} else {
				f.UnknownCategory = "analyzer_limitation"
			}
		} else if strings.HasPrefix(line, "MISSING:") {
			f.MissingEvidence = strings.TrimSpace(strings.TrimPrefix(line, "MISSING:"))
		} else if strings.HasPrefix(line, "NEXT_STEPS:") {
			f.NextSteps = strings.TrimSpace(strings.TrimPrefix(line, "NEXT_STEPS:"))
			f.NextSteps = strings.ReplaceAll(f.NextSteps, "\\n", "\n")
		}
	}
}
