package rules

import "testing"

func TestIsValidUnknownReason_AllValid(t *testing.T) {
	for code := range ValidUnknownReasons {
		if !IsValidUnknownReason(code) {
			t.Errorf("expected %q to be a valid unknown reason", code)
		}
	}
}

func TestIsValidUnknownReason_Invalid(t *testing.T) {
	invalid := []string{
		"",
		"not_a_real_reason",
		"unknown",
		"insufficient_evidence_typo",
	}
	for _, code := range invalid {
		if IsValidUnknownReason(code) {
			t.Errorf("expected %q to be invalid, but was accepted", code)
		}
	}
}

func TestValidUnknownReasons_HasDescriptions(t *testing.T) {
	for code, desc := range ValidUnknownReasons {
		if desc == "" {
			t.Errorf("reason code %q has empty description", code)
		}
	}
}

func TestUnknownReasonConstants(t *testing.T) {
	// Verify all constants are present in the map
	constants := []string{
		UnknownUnsupportedFramework,
		UnknownUnsupportedPattern,
		UnknownAnalyzerLimitation,
		UnknownInsufficientEvidence,
		UnknownMissingBindingData,
		UnknownPartialEvidence,
		UnknownAmbiguousStructure,
		UnknownAnalyzerFailure,
		UnknownSkippedFiles,
		UnknownPartialScan,
		UnknownNeedsRuntimeConfig,
		UnknownNeedsHumanAttestation,
	}
	for _, c := range constants {
		if _, ok := ValidUnknownReasons[c]; !ok {
			t.Errorf("constant %q not found in ValidUnknownReasons map", c)
		}
	}
	if len(constants) != len(ValidUnknownReasons) {
		t.Errorf("constant count %d != map size %d", len(constants), len(ValidUnknownReasons))
	}
}
