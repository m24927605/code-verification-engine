package cve

// Output schema versions — stable contracts for downstream consumers.
const (
	ScanSchemaVersion   = "1.0.0"
	ReportSchemaVersion = "1.0.0"
	ClaimSchemaVersion  = "1.0.0"
	APIVersion          = "1.0.0"
)

// APIInfo returns engine and API version information.
type APIInfo struct {
	EngineVersion       string `json:"engine_version"`
	APIVersion          string `json:"api_version"`
	ScanSchemaVersion   string `json:"scan_schema_version"`
	ReportSchemaVersion string `json:"report_schema_version"`
	ClaimSchemaVersion  string `json:"claim_schema_version"`
}

// GetAPIInfo returns current version information.
func GetAPIInfo() APIInfo {
	return APIInfo{
		EngineVersion:       Version,
		APIVersion:          APIVersion,
		ScanSchemaVersion:   ScanSchemaVersion,
		ReportSchemaVersion: ReportSchemaVersion,
		ClaimSchemaVersion:  ClaimSchemaVersion,
	}
}

// EvidenceOutput is the typed public representation of a piece of evidence.
type EvidenceOutput struct {
	ID        string `json:"evidence_id,omitempty"`
	File      string `json:"file"`
	LineStart int    `json:"line_start"`
	LineEnd   int    `json:"line_end"`
	Symbol    string `json:"symbol"`
	Excerpt   string `json:"excerpt,omitempty"`
}

// FindingOutput is the typed public representation of a single finding.
// Consumers MUST inspect TrustClass before treating any finding as authoritative.
type FindingOutput struct {
	RuleID            string           `json:"rule_id"`
	Status            string           `json:"status"`
	Confidence        string           `json:"confidence"`
	VerificationLevel string           `json:"verification_level"`
	TrustClass        string           `json:"trust_class"`
	Message           string           `json:"message"`
	Evidence          []EvidenceOutput `json:"evidence,omitempty"`
	UnknownReasons    []string         `json:"unknown_reasons,omitempty"`
}

// TrustSummary counts findings by trust class.
type TrustSummary struct {
	MachineTrusted         int `json:"machine_trusted"`
	Advisory               int `json:"advisory"`
	HumanOrRuntimeRequired int `json:"human_or_runtime_required"`
}

// ScanOutput is the typed public representation of scan.json.
type ScanOutput struct {
	ScanSchemaVersion string            `json:"scan_schema_version"`
	RepoPath          string            `json:"repo_path"`
	RepoName          string            `json:"repo_name"`
	Ref               string            `json:"ref"`
	CommitSHA         string            `json:"commit_sha"`
	ScannedAt         string            `json:"scanned_at"`
	Languages         []string          `json:"languages"`
	FileCount         int               `json:"file_count"`
	Partial           bool              `json:"partial"`
	Analyzers         map[string]string `json:"analyzers"`
	Errors            []string          `json:"errors"`
	Profile           string            `json:"profile"`
}

// ReportSummaryOutput is the typed public representation of the report summary.
type ReportSummaryOutput struct {
	Pass    int `json:"pass"`
	Fail    int `json:"fail"`
	Unknown int `json:"unknown"`
}

// SkippedRuleOutput is the typed public representation of a skipped rule.
type SkippedRuleOutput struct {
	RuleID string `json:"rule_id"`
	Reason string `json:"reason"`
}

// TrustGuidance provides consumer-facing guidance on how to treat the
// verification results. This prevents downstream misuse by making
// trust boundaries explicit in the API output.
type TrustGuidance struct {
	CanAutomate      bool   `json:"can_automate"`       // true only if ALL findings are machine_trusted+verified
	RequiresReview   bool   `json:"requires_review"`    // true if any advisory or human_required findings
	DegradedAnalysis bool   `json:"degraded_analysis"`  // true if capability was degraded at runtime
	Summary          string `json:"summary"`            // human-readable one-liner
}

// CapabilitySummaryOutput is the typed public representation of the capability summary.
type CapabilitySummaryOutput struct {
	FullySupported int  `json:"fully_supported"`
	Partial        int  `json:"partial"`
	Unsupported    int  `json:"unsupported"`
	Degraded       bool `json:"degraded"`
}

// SignalSummaryOutput counts findings by operational significance.
// This separates actionable issues from informational detections (e.g., GOF patterns).
type SignalSummaryOutput struct {
	ActionableFail         int `json:"actionable_fail"`
	AdvisoryFail           int `json:"advisory_fail"`
	InformationalDetection int `json:"informational_detection"`
	Unknown                int `json:"unknown"`
}

// ReportOutput is the typed public representation of report.json.
type ReportOutput struct {
	ReportSchemaVersion string                  `json:"report_schema_version"`
	Partial             bool                    `json:"partial"`
	Summary             ReportSummaryOutput     `json:"summary"`
	TrustSummary        TrustSummary            `json:"trust_summary"`
	CapabilitySummary   CapabilitySummaryOutput `json:"capability_summary"`
	SignalSummary       SignalSummaryOutput      `json:"signal_summary"`
	TrustGuidance       TrustGuidance           `json:"trust_guidance"`
	Findings            []FindingOutput         `json:"findings"`
	SkippedRules        []SkippedRuleOutput     `json:"skipped_rules,omitempty"`
	Errors              []string                `json:"errors,omitempty"`
}

// SkillOutput is the typed public representation of skills.json.
type SkillOutput struct {
	SchemaVersion string              `json:"schema_version,omitempty"`
	Profile       string              `json:"profile,omitempty"`
	Signals       []SkillSignalOutput `json:"signals,omitempty"`
	Summary       SkillSummaryOutput  `json:"summary"`
}

// SkillSignalOutput is a single skill signal in the public output.
type SkillSignalOutput struct {
	ID               string           `json:"id"`
	SkillID          string           `json:"skill_id"`
	Category         string           `json:"category"`
	Status           string           `json:"status"`
	Confidence       string           `json:"confidence"`
	TrustClass       string           `json:"trust_class"`
	EvidenceStrength string           `json:"evidence_strength"`
	Message          string           `json:"message"`
	SourceRuleIDs    []string         `json:"source_rule_ids,omitempty"`
	Evidence         []EvidenceOutput `json:"evidence,omitempty"`
	UnknownReasons   []string         `json:"unknown_reasons,omitempty"`
}

// SkillSummaryOutput counts skill signals by status.
type SkillSummaryOutput struct {
	Observed    int `json:"observed"`
	Inferred    int `json:"inferred"`
	Unsupported int `json:"unsupported"`
}
