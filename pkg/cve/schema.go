package cve

// Output schema versions — stable contracts for downstream consumers.
const (
	ScanSchemaVersion                = "1.0.0"
	ReportSchemaVersion              = "1.0.0"
	ClaimSchemaVersion               = "1.0.0"
	ReportV2SchemaVersion            = "2.0.0"
	EvidenceV2SchemaVersion          = "2.0.0"
	SkillsV2SchemaVersion            = "2.0.0"
	TraceV2SchemaVersion             = "2.0.0"
	SignatureSchemaVersion           = "1.0.0"
	OutsourceAcceptanceSchemaVersion = "1.0.0"
	PMAcceptanceSchemaVersion        = "1.0.0"
	APIVersion                       = "1.0.0"
)

// APIInfo returns engine and API version information.
type APIInfo struct {
	EngineVersion           string `json:"engine_version"`
	APIVersion              string `json:"api_version"`
	ScanSchemaVersion       string `json:"scan_schema_version"`
	ReportSchemaVersion     string `json:"report_schema_version"`
	ClaimSchemaVersion      string `json:"claim_schema_version"`
	ReportV2SchemaVersion   string `json:"report_v2_schema_version"`
	EvidenceV2SchemaVersion string `json:"evidence_v2_schema_version"`
	SkillsV2SchemaVersion   string `json:"skills_v2_schema_version"`
	TraceV2SchemaVersion    string `json:"trace_v2_schema_version"`
	SignatureSchemaVersion  string `json:"signature_schema_version"`
}

// GetAPIInfo returns current version information.
func GetAPIInfo() APIInfo {
	return APIInfo{
		EngineVersion:           Version,
		APIVersion:              APIVersion,
		ScanSchemaVersion:       ScanSchemaVersion,
		ReportSchemaVersion:     ReportSchemaVersion,
		ClaimSchemaVersion:      ClaimSchemaVersion,
		ReportV2SchemaVersion:   ReportV2SchemaVersion,
		EvidenceV2SchemaVersion: EvidenceV2SchemaVersion,
		SkillsV2SchemaVersion:   SkillsV2SchemaVersion,
		TraceV2SchemaVersion:    TraceV2SchemaVersion,
		SignatureSchemaVersion:  SignatureSchemaVersion,
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

// ReportOutput is the typed public representation of the canonical issue-centric report.
type ReportOutput struct {
	SchemaVersion string              `json:"schema_version"`
	EngineVersion string              `json:"engine_version"`
	Repo          string              `json:"repo"`
	Commit        string              `json:"commit"`
	Timestamp     string              `json:"timestamp"`
	TraceID       string              `json:"trace_id"`
	Summary       ReportSummaryOutput `json:"summary"`
	Skills        []ReportSkillOutput `json:"skills"`
	Issues        []IssueOutput       `json:"issues"`
}

type ReportSummaryOutput struct {
	OverallScore float64          `json:"overall_score"`
	RiskLevel    string           `json:"risk_level"`
	IssueCounts  IssueCountOutput `json:"issue_counts"`
}

type IssueCountOutput struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
}

type ReportSkillOutput struct {
	SkillID string  `json:"skill_id"`
	Score   float64 `json:"score"`
}

type ConfidenceBreakdownOutput struct {
	RuleReliability      float64 `json:"rule_reliability"`
	EvidenceQuality      float64 `json:"evidence_quality"`
	BoundaryCompleteness float64 `json:"boundary_completeness"`
	ContextCompleteness  float64 `json:"context_completeness"`
	SourceAgreement      float64 `json:"source_agreement"`
	ContradictionPenalty float64 `json:"contradiction_penalty"`
	LLMPenalty           float64 `json:"llm_penalty"`
	Final                float64 `json:"final"`
}

type IssueSourceSummaryOutput struct {
	RuleCount            int  `json:"rule_count"`
	DeterministicSources int  `json:"deterministic_sources"`
	AgentSources         int  `json:"agent_sources"`
	TotalSources         int  `json:"total_sources"`
	MultiSource          bool `json:"multi_source"`
}

type IssueOutput struct {
	ID                  string                     `json:"id"`
	Fingerprint         string                     `json:"fingerprint"`
	RuleFamily          string                     `json:"rule_family"`
	MergeBasis          string                     `json:"merge_basis"`
	Category            string                     `json:"category"`
	Title               string                     `json:"title"`
	Severity            string                     `json:"severity"`
	Confidence          float64                    `json:"confidence"`
	ConfidenceClass     string                     `json:"confidence_class"`
	PolicyClass         string                     `json:"policy_class"`
	Status              string                     `json:"status"`
	EvidenceIDs         []string                   `json:"evidence_ids"`
	CounterEvidenceIDs  []string                   `json:"counter_evidence_ids,omitempty"`
	SkillImpacts        []string                   `json:"skill_impacts,omitempty"`
	Sources             []string                   `json:"sources,omitempty"`
	SourceSummary       IssueSourceSummaryOutput   `json:"source_summary"`
	ConfidenceBreakdown *ConfidenceBreakdownOutput `json:"confidence_breakdown,omitempty"`
}

// TrustGuidance is retained for callers that still consume finding-oriented guidance.
type TrustGuidance struct {
	CanAutomate      bool   `json:"can_automate"`
	RequiresReview   bool   `json:"requires_review"`
	DegradedAnalysis bool   `json:"degraded_analysis"`
	Summary          string `json:"summary"`
}

type CapabilitySummaryOutput struct {
	FullySupported int  `json:"fully_supported"`
	Partial        int  `json:"partial"`
	Unsupported    int  `json:"unsupported"`
	Degraded       bool `json:"degraded"`
}

type SignalSummaryOutput struct {
	ActionableFail         int `json:"actionable_fail"`
	AdvisoryFail           int `json:"advisory_fail"`
	InformationalDetection int `json:"informational_detection"`
	Unknown                int `json:"unknown"`
}

type SkippedRuleOutput struct {
	RuleID string `json:"rule_id"`
	Reason string `json:"reason"`
}

// SkillOutput is the typed public representation of skills.json.
type SkillOutput struct {
	SchemaVersion string              `json:"schema_version,omitempty"`
	Profile       string              `json:"profile,omitempty"`
	Skills        []string            `json:"skills,omitempty"`
	Languages     []string            `json:"languages,omitempty"`
	Frameworks    []string            `json:"frameworks,omitempty"`
	Technologies  []TechnologyOutput  `json:"technologies,omitempty"`
	Signals       []SkillSignalOutput `json:"signals,omitempty"`
	Summary       SkillSummaryOutput  `json:"summary"`
}

// TechnologyOutput is a simplified detected stack component in the public API.
type TechnologyOutput struct {
	Name string `json:"name"`
	Kind string `json:"kind"`
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

// ClaimReportOutput is the typed public representation of claims.json.
type ClaimReportOutput struct {
	SchemaVersion string                    `json:"claim_report_schema_version"`
	ClaimSetName  string                    `json:"claim_set"`
	TotalClaims   int                       `json:"total_claims"`
	Verdicts      ClaimVerdictSummaryOutput `json:"verdict_summary"`
	Claims        []ClaimVerdictOutput      `json:"claims"`
}

// ClaimVerdictSummaryOutput counts claim verdicts.
type ClaimVerdictSummaryOutput struct {
	Verified int `json:"verified"`
	Passed   int `json:"passed"`
	Failed   int `json:"failed"`
	Unknown  int `json:"unknown"`
	Partial  int `json:"partial"`
}

// ClaimVerdictOutput is the typed public representation of a claim verdict.
type ClaimVerdictOutput struct {
	ClaimID           string                    `json:"claim_id"`
	Title             string                    `json:"title"`
	Category          string                    `json:"category"`
	Status            string                    `json:"status"`
	Confidence        string                    `json:"confidence"`
	VerificationLevel string                    `json:"verification_level"`
	TrustBreakdown    ClaimTrustBreakdownOutput `json:"trust_breakdown"`
	Summary           string                    `json:"summary"`
	SupportingRules   []ClaimRuleResultOutput   `json:"supporting_rules"`
	EvidenceChain     []ClaimEvidenceLinkOutput `json:"evidence_chain"`
	UnknownReasons    []string                  `json:"unknown_reasons,omitempty"`
}

// ClaimTrustBreakdownOutput counts trust classes contributing to a claim.
type ClaimTrustBreakdownOutput struct {
	MachineTrusted         int    `json:"machine_trusted"`
	Advisory               int    `json:"advisory"`
	HumanOrRuntimeRequired int    `json:"human_or_runtime_required"`
	EffectiveTrustClass    string `json:"effective_trust_class"`
}

// ClaimRuleResultOutput is the typed public representation of a rule linked to a claim.
type ClaimRuleResultOutput struct {
	RuleID     string `json:"rule_id"`
	Status     string `json:"status"`
	Confidence string `json:"confidence"`
	Message    string `json:"message"`
}

// ClaimEvidenceLinkOutput is the typed public representation of a claim evidence link.
type ClaimEvidenceLinkOutput struct {
	ID        string `json:"evidence_id"`
	Type      string `json:"type"`
	File      string `json:"file"`
	LineStart int    `json:"line_start"`
	LineEnd   int    `json:"line_end"`
	Symbol    string `json:"symbol,omitempty"`
	Excerpt   string `json:"excerpt,omitempty"`
	FromRule  string `json:"from_rule"`
	Relation  string `json:"relation"`
}

// ClaimsProjectionOutput is the typed public representation of the multi-source
// claims/profile/resume artifact set.
type ClaimsProjectionOutput struct {
	Claims      ClaimsArtifactOutput      `json:"claims"`
	Profile     ProfileArtifactOutput     `json:"profile"`
	ResumeInput ResumeInputArtifactOutput `json:"resume_input"`
}

type ClaimsArtifactOutput struct {
	SchemaVersion string              `json:"claim_schema_version"`
	Repository    ClaimRepositoryRef  `json:"repository"`
	Claims        []ClaimRecordOutput `json:"claims"`
	Summary       ClaimSummaryOutput  `json:"summary"`
}

type ClaimRepositoryRef struct {
	Path   string `json:"path"`
	Commit string `json:"commit"`
}

type ClaimRecordOutput struct {
	ClaimID                  string                          `json:"claim_id"`
	Title                    string                          `json:"title"`
	Category                 string                          `json:"category"`
	ClaimType                string                          `json:"claim_type"`
	Status                   string                          `json:"status"`
	SupportLevel             string                          `json:"support_level"`
	Confidence               float64                         `json:"confidence"`
	VerificationClass        string                          `json:"verification_class,omitempty"`
	ScenarioApplicability    *ScenarioApplicabilityOutput    `json:"scenario_applicability,omitempty"`
	SourceOrigins            []string                        `json:"source_origins"`
	SupportingEvidenceIDs    []string                        `json:"supporting_evidence_ids"`
	ContradictoryEvidenceIDs []string                        `json:"contradictory_evidence_ids"`
	Reason                   string                          `json:"reason"`
	ProjectionEligible       bool                            `json:"projection_eligible"`
}

// ScenarioApplicabilityOutput declares which scenarios a claim is eligible for.
type ScenarioApplicabilityOutput struct {
	Hiring              bool `json:"hiring"`
	OutsourceAcceptance bool `json:"outsource_acceptance"`
	PMAcceptance        bool `json:"pm_acceptance"`
}

type ClaimSummaryOutput struct {
	Verified          int `json:"verified"`
	StronglySupported int `json:"strongly_supported"`
	Supported         int `json:"supported"`
	Weak              int `json:"weak"`
	Unsupported       int `json:"unsupported"`
	Contradicted      int `json:"contradicted"`
}

type ProfileArtifactOutput struct {
	SchemaVersion   string                      `json:"profile_schema_version"`
	Repository      ClaimRepositoryRef          `json:"repository"`
	Highlights      []CapabilityHighlightOutput `json:"highlights"`
	CapabilityAreas []CapabilityAreaOutput      `json:"capability_areas"`
	Technologies    []string                    `json:"technologies"`
	ClaimIDs        []string                    `json:"claim_ids"`
}

type CapabilityHighlightOutput struct {
	HighlightID           string   `json:"highlight_id"`
	Title                 string   `json:"title"`
	SupportLevel          string   `json:"support_level"`
	ClaimIDs              []string `json:"claim_ids"`
	SupportingEvidenceIDs []string `json:"supporting_evidence_ids"`
}

type CapabilityAreaOutput struct {
	AreaID   string   `json:"area_id"`
	Title    string   `json:"title"`
	ClaimIDs []string `json:"claim_ids"`
}

type ResumeInputArtifactOutput struct {
	SchemaVersion           string                     `json:"resume_input_schema_version"`
	Profile                 ProfileArtifactOutput      `json:"profile"`
	VerifiedClaims          []ResumeClaimStubOutput    `json:"verified_claims"`
	StronglySupportedClaims []ResumeClaimStubOutput    `json:"strongly_supported_claims"`
	TechnologySummary       []string                   `json:"technology_summary"`
	EvidenceReferences      []EvidenceReferenceOutput  `json:"evidence_references"`
	SynthesisConstraints    SynthesisConstraintsOutput `json:"synthesis_constraints"`
}

type ResumeClaimStubOutput struct {
	ClaimID               string   `json:"claim_id"`
	Title                 string   `json:"title"`
	SupportLevel          string   `json:"support_level"`
	Confidence            float64  `json:"confidence"`
	SupportingEvidenceIDs []string `json:"supporting_evidence_ids"`
}

type EvidenceReferenceOutput struct {
	EvidenceID            string   `json:"evidence_id"`
	ClaimIDs              []string `json:"claim_ids"`
	ContradictoryClaimIDs []string `json:"contradictory_claim_ids,omitempty"`
}

type SynthesisConstraintsOutput struct {
	AllowUnsupportedClaims        bool `json:"allow_unsupported_claims"`
	AllowClaimInvention           bool `json:"allow_claim_invention"`
	AllowContradictionSuppression bool `json:"allow_contradiction_suppression"`
}

// VerifiableOutput is the typed public representation of the verifiable artifact bundle.
type VerifiableOutput struct {
	Report    ReportV2Output    `json:"report"`
	Evidence  EvidenceV2Output  `json:"evidence"`
	Skills    SkillsV2Output    `json:"skills"`
	Trace     TraceV2Output     `json:"trace"`
	SummaryMD string            `json:"summary_md"`
	Signature SignatureV2Output `json:"signature"`
}

// ReportV2Output is the typed public representation of verifiable/report.json.
type ReportV2Output struct {
	SchemaVersion string                `json:"schema_version"`
	EngineVersion string                `json:"engine_version"`
	Repo          string                `json:"repo"`
	Commit        string                `json:"commit"`
	Timestamp     string                `json:"timestamp"`
	TraceID       string                `json:"trace_id"`
	Summary       ReportV2SummaryOutput `json:"summary"`
	Skills        []ReportV2SkillOutput `json:"skills"`
	Issues        []IssueV2Output       `json:"issues"`
}

type ReportV2SummaryOutput struct {
	OverallScore float64            `json:"overall_score"`
	RiskLevel    string             `json:"risk_level"`
	IssueCounts  IssueCountV2Output `json:"issue_counts"`
}

type IssueCountV2Output struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
}

type ReportV2SkillOutput struct {
	SkillID string  `json:"skill_id"`
	Score   float64 `json:"score"`
}

type ConfidenceBreakdownV2Output struct {
	RuleReliability      float64 `json:"rule_reliability"`
	EvidenceQuality      float64 `json:"evidence_quality"`
	BoundaryCompleteness float64 `json:"boundary_completeness"`
	ContextCompleteness  float64 `json:"context_completeness"`
	SourceAgreement      float64 `json:"source_agreement"`
	ContradictionPenalty float64 `json:"contradiction_penalty"`
	LLMPenalty           float64 `json:"llm_penalty"`
	Final                float64 `json:"final"`
}

type IssueSourceSummaryV2Output struct {
	RuleCount            int  `json:"rule_count"`
	DeterministicSources int  `json:"deterministic_sources"`
	AgentSources         int  `json:"agent_sources"`
	TotalSources         int  `json:"total_sources"`
	MultiSource          bool `json:"multi_source"`
}

type IssueV2Output struct {
	ID                  string                       `json:"id"`
	Fingerprint         string                       `json:"fingerprint"`
	RuleFamily          string                       `json:"rule_family"`
	MergeBasis          string                       `json:"merge_basis"`
	Category            string                       `json:"category"`
	Title               string                       `json:"title"`
	Severity            string                       `json:"severity"`
	Confidence          float64                      `json:"confidence"`
	ConfidenceClass     string                       `json:"confidence_class"`
	PolicyClass         string                       `json:"policy_class"`
	Status              string                       `json:"status"`
	EvidenceIDs         []string                     `json:"evidence_ids"`
	CounterEvidenceIDs  []string                     `json:"counter_evidence_ids,omitempty"`
	SkillImpacts        []string                     `json:"skill_impacts,omitempty"`
	Sources             []string                     `json:"sources,omitempty"`
	SourceSummary       IssueSourceSummaryV2Output   `json:"source_summary"`
	ConfidenceBreakdown *ConfidenceBreakdownV2Output `json:"confidence_breakdown,omitempty"`
}

type EvidenceV2Output struct {
	SchemaVersion string             `json:"schema_version"`
	EngineVersion string             `json:"engine_version"`
	Repo          string             `json:"repo"`
	Commit        string             `json:"commit"`
	Timestamp     string             `json:"timestamp"`
	Evidence      []EvidenceV2Record `json:"evidence"`
}

type LocationV2Output struct {
	RepoRelPath string `json:"repo_rel_path"`
	StartLine   int    `json:"start_line"`
	EndLine     int    `json:"end_line"`
	StartCol    int    `json:"start_col,omitempty"`
	EndCol      int    `json:"end_col,omitempty"`
	SymbolID    string `json:"symbol_id,omitempty"`
}

type EvidenceV2Record struct {
	ID              string                 `json:"id"`
	Kind            string                 `json:"kind"`
	Source          string                 `json:"source"`
	ProducerID      string                 `json:"producer_id"`
	ProducerVersion string                 `json:"producer_version"`
	Repo            string                 `json:"repo"`
	Commit          string                 `json:"commit"`
	BoundaryHash    string                 `json:"boundary_hash"`
	FactQuality     string                 `json:"fact_quality"`
	EntityIDs       []string               `json:"entity_ids"`
	Locations       []LocationV2Output     `json:"locations"`
	Claims          []string               `json:"claims"`
	Payload         map[string]interface{} `json:"payload"`
	Supports        []string               `json:"supports"`
	Contradicts     []string               `json:"contradicts"`
	DerivedFrom     []string               `json:"derived_from"`
	CreatedAt       string                 `json:"created_at"`
}

type SkillsV2Output struct {
	SchemaVersion string               `json:"schema_version"`
	EngineVersion string               `json:"engine_version"`
	Repo          string               `json:"repo"`
	Commit        string               `json:"commit"`
	Timestamp     string               `json:"timestamp"`
	Skills        []SkillScoreV2Output `json:"skills"`
}

type SkillScoreV2Output struct {
	SkillID                 string                      `json:"skill_id"`
	Score                   float64                     `json:"score"`
	Confidence              float64                     `json:"confidence"`
	ContributingIssueIDs    []string                    `json:"contributing_issue_ids"`
	ContributingEvidenceIDs []string                    `json:"contributing_evidence_ids"`
	FormulaInputs           *SkillFormulaInputsV2Output `json:"formula_inputs,omitempty"`
}

type SkillFormulaInputsV2Output struct {
	Positive []WeightedContributionV2Output `json:"positive,omitempty"`
	Negative []WeightedContributionV2Output `json:"negative,omitempty"`
}

type WeightedContributionV2Output struct {
	IssueID string  `json:"issue_id"`
	Weight  float64 `json:"weight"`
	Value   float64 `json:"value"`
}

type TraceV2Output struct {
	SchemaVersion         string                         `json:"schema_version"`
	EngineVersion         string                         `json:"engine_version"`
	TraceID               string                         `json:"trace_id"`
	Repo                  string                         `json:"repo"`
	Commit                string                         `json:"commit"`
	Timestamp             string                         `json:"timestamp"`
	Partial               bool                           `json:"partial,omitempty"`
	Degraded              bool                           `json:"degraded,omitempty"`
	Errors                []string                       `json:"errors,omitempty"`
	ScanBoundary          TraceScanBoundaryV2Output      `json:"scan_boundary"`
	MigrationSummary      *RuleMigrationSummaryV2Output  `json:"migration_summary,omitempty"`
	ConfidenceCalibration *ConfidenceCalibrationV2Output `json:"confidence_calibration,omitempty"`
	Analyzers             []AnalyzerRunV2Output          `json:"analyzers,omitempty"`
	Rules                 []RuleRunV2Output              `json:"rules,omitempty"`
	SkippedRules          []SkippedRuleV2Output          `json:"skipped_rules,omitempty"`
	ContextSelections     []ContextSelectionV2Output     `json:"context_selections,omitempty"`
	Agents                []AgentRunV2Output             `json:"agents,omitempty"`
	Derivations           []IssueDerivationV2Output      `json:"derivations,omitempty"`
}

type TraceScanBoundaryV2Output struct {
	Mode          string `json:"mode"`
	IncludedFiles int    `json:"included_files"`
	ExcludedFiles int    `json:"excluded_files"`
}

type RuleMigrationSummaryV2Output struct {
	LegacyOnlyCount     int               `json:"legacy_only_count"`
	FindingBridgedCount int               `json:"finding_bridged_count"`
	SeedNativeCount     int               `json:"seed_native_count"`
	IssueNativeCount    int               `json:"issue_native_count"`
	RuleStates          map[string]string `json:"rule_states,omitempty"`
	RuleReasons         map[string]string `json:"rule_reasons,omitempty"`
}

type ConfidenceCalibrationV2Output struct {
	Version                 string             `json:"version"`
	MachineTrustedThreshold float64            `json:"machine_trusted_threshold"`
	UnknownCap              float64            `json:"unknown_cap"`
	AgentOnlyCap            float64            `json:"agent_only_cap"`
	RuleFamilyBaselines     map[string]float64 `json:"rule_family_baselines,omitempty"`
	OrderingRules           []string           `json:"ordering_rules,omitempty"`
}

type AnalyzerRunV2Output struct {
	Name     string `json:"name"`
	Version  string `json:"version"`
	Language string `json:"language"`
	Status   string `json:"status"`
	Degraded bool   `json:"degraded,omitempty"`
	Reason   string `json:"reason,omitempty"`
}

type RuleRunV2Output struct {
	ID                 string   `json:"id"`
	Version            string   `json:"version"`
	MigrationState     string   `json:"migration_state,omitempty"`
	MigrationReason    string   `json:"migration_reason,omitempty"`
	TriggeredIssueIDs  []string `json:"triggered_issue_ids,omitempty"`
	EmittedEvidenceIDs []string `json:"emitted_evidence_ids,omitempty"`
}

type SkippedRuleV2Output struct {
	ID     string `json:"id"`
	Reason string `json:"reason"`
}

type ContextSelectionV2Output struct {
	ID                  string             `json:"id"`
	TriggerType         string             `json:"trigger_type"`
	TriggerID           string             `json:"trigger_id"`
	SelectedEvidenceIDs []string           `json:"selected_evidence_ids,omitempty"`
	EntityIDs           []string           `json:"entity_ids,omitempty"`
	SelectedSpans       []LocationV2Output `json:"selected_spans,omitempty"`
	MaxFiles            int                `json:"max_files,omitempty"`
	MaxSpans            int                `json:"max_spans,omitempty"`
	MaxTokens           int                `json:"max_tokens,omitempty"`
	SelectionTrace      []string           `json:"selection_trace,omitempty"`
}

type AgentRunV2Output struct {
	ID                 string   `json:"id"`
	Kind               string   `json:"kind"`
	IssueType          string   `json:"issue_type,omitempty"`
	Question           string   `json:"question,omitempty"`
	IssueID            string   `json:"issue_id,omitempty"`
	ContextSelectionID string   `json:"context_selection_id,omitempty"`
	TriggerReason      string   `json:"trigger_reason"`
	InputEvidenceIDs   []string `json:"input_evidence_ids,omitempty"`
	OutputEvidenceIDs  []string `json:"output_evidence_ids,omitempty"`
	UnresolvedReasons  []string `json:"unresolved_reasons,omitempty"`
	MaxFiles           int      `json:"max_files,omitempty"`
	MaxTokens          int      `json:"max_tokens,omitempty"`
	AllowSpeculation   bool     `json:"allow_speculation"`
	Status             string   `json:"status"`
}

type IssueDerivationV2Output struct {
	IssueID                string   `json:"issue_id"`
	IssueFingerprint       string   `json:"issue_fingerprint"`
	DerivedFromEvidenceIDs []string `json:"derived_from_evidence_ids"`
}

type SignatureV2Output struct {
	Version         string            `json:"version"`
	SignedBy        string            `json:"signed_by"`
	Timestamp       string            `json:"timestamp"`
	ArtifactHashes  map[string]string `json:"artifact_hashes"`
	BundleHash      string            `json:"bundle_hash"`
	Signature       *string           `json:"signature"`
	SignatureScheme *string           `json:"signature_scheme"`
}

// --- Outsource Acceptance Public Output ---

// OutsourceAcceptanceOutput is the typed public representation of outsource_acceptance.json.
type OutsourceAcceptanceOutput struct {
	SchemaVersion     string                              `json:"schema_version"`
	Repository        AcceptanceRepositoryOutput          `json:"repository"`
	TraceID           string                              `json:"trace_id"`
	AcceptanceProfile string                              `json:"acceptance_profile"`
	Summary           OutsourceAcceptanceSummaryOutput    `json:"summary"`
	Requirements      []OutsourceRequirementRowOutput     `json:"requirements"`
}

// AcceptanceRepositoryOutput identifies the repository snapshot in acceptance outputs.
type AcceptanceRepositoryOutput struct {
	Path   string `json:"path"`
	Commit string `json:"commit"`
}

// OutsourceAcceptanceSummaryOutput counts requirement statuses in outsource acceptance.
type OutsourceAcceptanceSummaryOutput struct {
	Passed           int `json:"passed"`
	Failed           int `json:"failed"`
	Unknown          int `json:"unknown"`
	RuntimeRequired  int `json:"runtime_required"`
	ProofGradeRows   int `json:"proof_grade_rows"`
	BlockingFailures int `json:"blocking_failures"`
}

// OutsourceRequirementRowOutput is a single requirement row in outsource_acceptance.json.
type OutsourceRequirementRowOutput struct {
	RequirementID            string   `json:"requirement_id"`
	Title                    string   `json:"title"`
	Category                 string   `json:"category"`
	Status                   string   `json:"status"`
	VerificationClass        string   `json:"verification_class"`
	TrustClass               string   `json:"trust_class"`
	Blocking                 bool     `json:"blocking"`
	AcceptanceIntent         string   `json:"acceptance_intent"`
	ClaimIDs                 []string `json:"claim_ids"`
	SupportingEvidenceIDs    []string `json:"supporting_evidence_ids"`
	ContradictoryEvidenceIDs []string `json:"contradictory_evidence_ids"`
	Reason                   string   `json:"reason"`
	UnknownReasons           []string `json:"unknown_reasons"`
}

// --- PM Acceptance Public Output ---

// PMAcceptanceOutput is the typed public representation of pm_acceptance.json.
type PMAcceptanceOutput struct {
	SchemaVersion           string                             `json:"schema_version"`
	Repository              AcceptanceRepositoryOutput         `json:"repository"`
	TraceID                 string                             `json:"trace_id"`
	AcceptanceProfile       string                             `json:"acceptance_profile"`
	Summary                 PMAcceptanceSummaryOutput          `json:"summary"`
	EngineeringRequirements []PMEngineeringRequirementOutput   `json:"engineering_requirements"`
}

// PMAcceptanceSummaryOutput counts engineering requirement statuses.
type PMAcceptanceSummaryOutput struct {
	Implemented     int `json:"implemented"`
	Partial         int `json:"partial"`
	Blocked         int `json:"blocked"`
	Unknown         int `json:"unknown"`
	RuntimeRequired int `json:"runtime_required"`
	ProofGradeRows  int `json:"proof_grade_rows"`
}

// PMEngineeringRequirementOutput is a single engineering requirement row in pm_acceptance.json.
type PMEngineeringRequirementOutput struct {
	RequirementID            string   `json:"requirement_id"`
	Title                    string   `json:"title"`
	Category                 string   `json:"category"`
	Status                   string   `json:"status"`
	VerificationClass        string   `json:"verification_class"`
	TrustClass               string   `json:"trust_class"`
	DeliveryScope            string   `json:"delivery_scope"`
	ClaimIDs                 []string `json:"claim_ids"`
	SupportingEvidenceIDs    []string `json:"supporting_evidence_ids"`
	ContradictoryEvidenceIDs []string `json:"contradictory_evidence_ids"`
	Reason                   string   `json:"reason"`
	FollowUpAction           string   `json:"follow_up_action"`
}
