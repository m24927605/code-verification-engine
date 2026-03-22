package rules

// Unknown reason codes — standardized taxonomy.
// Every unknown finding must use one or more of these codes.
const (
	// Analyzer capability gaps
	UnknownUnsupportedFramework = "unsupported_framework"
	UnknownUnsupportedPattern   = "unsupported_pattern"
	UnknownAnalyzerLimitation   = "analyzer_limitation"

	// Evidence gaps
	UnknownInsufficientEvidence = "insufficient_evidence"
	UnknownMissingBindingData   = "missing_binding_data"
	UnknownPartialEvidence      = "partial_evidence"
	UnknownAmbiguousStructure   = "ambiguous_structure"

	// Scan gaps
	UnknownAnalyzerFailure    = "analyzer_failure"
	UnknownSkippedFiles       = "skipped_files"
	UnknownPartialScan        = "partial_scan"
	UnknownAnalyzerIncomplete = "analyzer_incomplete"

	// External requirements
	UnknownNeedsRuntimeConfig    = "needs_runtime_config"
	UnknownNeedsHumanAttestation = "needs_human_attestation"

	// Capability gaps
	UnknownCapabilityUnsupported = "capability_unsupported"
	UnknownCapabilityPartial     = "capability_partial"
	UnknownCapabilityDegraded    = "capability_degraded"
	UnknownFactExtractionGap     = "fact_extraction_gap"
	UnknownMatcherLimitation     = "matcher_limitation"
)

// ValidUnknownReasons is the set of all valid unknown reason codes.
var ValidUnknownReasons = map[string]string{
	UnknownUnsupportedFramework:  "The analyzer does not support the framework used in this codebase",
	UnknownUnsupportedPattern:    "The verification target requires pattern detection not yet implemented",
	UnknownAnalyzerLimitation:    "The analyzer cannot extract the required facts from this code structure",
	UnknownInsufficientEvidence:  "Not enough evidence to determine pass or fail",
	UnknownMissingBindingData:    "Route-to-middleware or similar binding information not available",
	UnknownPartialEvidence:       "Some evidence exists but is not sufficient for a verdict",
	UnknownAmbiguousStructure:    "Code structure is ambiguous and could match multiple interpretations",
	UnknownAnalyzerFailure:       "The analyzer encountered an error processing relevant files",
	UnknownSkippedFiles:          "One or more files relevant to this rule were skipped during analysis",
	UnknownPartialScan:           "The scan did not cover the full scope needed for this rule",
	UnknownAnalyzerIncomplete:    "One or more language analyzers did not complete successfully for this rule's search space",
	UnknownNeedsRuntimeConfig:    "Verification requires runtime or configuration data not available in source",
	UnknownNeedsHumanAttestation: "This claim requires human review or attestation to verify",
	UnknownCapabilityUnsupported: "The analyzer does not support this capability for the detected languages",
	UnknownCapabilityPartial:     "The analyzer only partially supports this capability for the detected languages",
	UnknownCapabilityDegraded:    "The capability was degraded because a required runtime is unavailable",
	UnknownFactExtractionGap:     "Fact extraction does not cover this target for the detected language/framework",
	UnknownMatcherLimitation:     "The matcher uses heuristic name matching which may produce false positives/negatives",
}

// IsValidUnknownReason checks if a reason code is in the taxonomy.
func IsValidUnknownReason(reason string) bool {
	_, ok := ValidUnknownReasons[reason]
	return ok
}
