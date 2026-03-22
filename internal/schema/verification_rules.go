package schema

import (
	"fmt"

	"github.com/verabase/code-verification-engine/internal/rules"
)

// ValidateVerificationLevel enforces hard rules on verification level assignment.
// These are not suggestions — they are invariants.
//
// Rules:
//
//	verified:         requires direct evidence + high confidence
//	strong_inference:  requires evidence + medium or high confidence
//	weak_inference:    allowed with low confidence or partial evidence
//	unknown:           must have unknown_reasons populated
//
// Violations indicate a matcher bug, not a user error.
func ValidateVerificationLevel(f rules.Finding) error {
	switch f.VerificationLevel {
	case rules.VerificationVerified:
		if f.Confidence != rules.ConfidenceHigh {
			return fmt.Errorf("rule %s: verified level requires high confidence, got %s", f.RuleID, f.Confidence)
		}
		if f.Status != rules.StatusPass && f.Status != rules.StatusFail {
			return fmt.Errorf("rule %s: verified level cannot be used with status %s", f.RuleID, f.Status)
		}
		if f.Status == rules.StatusFail && len(f.Evidence) == 0 {
			return fmt.Errorf("rule %s: verified fail requires evidence", f.RuleID)
		}
	case rules.VerificationStrongInference:
		if f.Confidence == rules.ConfidenceLow {
			return fmt.Errorf("rule %s: strong_inference requires medium or high confidence, got low", f.RuleID)
		}
	case rules.VerificationWeakInference:
		// weak_inference is allowed with any confidence
	default:
		if f.Status != rules.StatusUnknown {
			return fmt.Errorf("rule %s: unknown verification level %q for non-unknown status", f.RuleID, f.VerificationLevel)
		}
	}

	// Unknown status invariants
	if f.Status == rules.StatusUnknown {
		if len(f.UnknownReasons) == 0 {
			return fmt.Errorf("rule %s: unknown status requires at least one unknown_reason", f.RuleID)
		}
		if f.VerificationLevel == rules.VerificationVerified {
			return fmt.Errorf("rule %s: unknown status cannot have verified level", f.RuleID)
		}
	}

	return nil
}
