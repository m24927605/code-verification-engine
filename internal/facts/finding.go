package facts

import "fmt"

// Valid status values.
const (
	StatusPass    = "pass"
	StatusFail    = "fail"
	StatusUnknown = "unknown"
)

// Valid confidence values.
const (
	ConfidenceHigh   = "high"
	ConfidenceMedium = "medium"
	ConfidenceLow    = "low"
)

// Valid verification levels.
const (
	VerificationVerified        = "verified"
	VerificationStrongInference = "strong_inference"
	VerificationWeakInference   = "weak_inference"
)

// Finding represents a rule evaluation result.
type Finding struct {
	RuleID            string     `json:"rule_id"`
	Title             string     `json:"title"`
	Status            string     `json:"status"`
	Confidence        string     `json:"confidence"`
	VerificationLevel string     `json:"verification_level"`
	Message           string     `json:"message"`
	Evidence          []Evidence `json:"evidence,omitempty"`
	UnknownReasons    []string   `json:"unknown_reasons,omitempty"`
}

var validStatuses = map[string]bool{StatusPass: true, StatusFail: true, StatusUnknown: true}
var validConfidences = map[string]bool{ConfidenceHigh: true, ConfidenceMedium: true, ConfidenceLow: true}
var validVerificationLevels = map[string]bool{VerificationVerified: true, VerificationStrongInference: true, VerificationWeakInference: true}

// NewFinding creates a validated Finding.
func NewFinding(ruleID, title, status, confidence, verificationLevel, message string, evidence []Evidence, unknownReasons []string) (Finding, error) {
	if ruleID == "" {
		return Finding{}, fmt.Errorf("rule ID is required")
	}
	if !validStatuses[status] {
		return Finding{}, fmt.Errorf("invalid status: %q (must be pass, fail, or unknown)", status)
	}
	if !validConfidences[confidence] {
		return Finding{}, fmt.Errorf("invalid confidence: %q (must be high, medium, or low)", confidence)
	}
	if !validVerificationLevels[verificationLevel] {
		return Finding{}, fmt.Errorf("invalid verification level: %q (must be verified, strong_inference, or weak_inference)", verificationLevel)
	}
	if status == StatusUnknown && len(unknownReasons) == 0 {
		return Finding{}, fmt.Errorf("unknown status requires at least one reason in unknown_reasons")
	}
	return Finding{
		RuleID:            ruleID,
		Title:             title,
		Status:            status,
		Confidence:        confidence,
		VerificationLevel: verificationLevel,
		Message:           message,
		Evidence:          evidence,
		UnknownReasons:    unknownReasons,
	}, nil
}
