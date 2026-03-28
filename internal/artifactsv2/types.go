package artifactsv2

// Versioned schema identifiers for the v2 verifiable artifact bundle.
const (
	ReportSchemaVersion    = "2.0.0"
	EvidenceSchemaVersion  = "2.0.0"
	SkillsSchemaVersion    = "2.0.0"
	TraceSchemaVersion     = "2.0.0"
	SignatureSchemaVersion = "1.0.0"
)

// Bundle is the full verifiable artifact set for a single engine run.
type Bundle struct {
	Report    ReportArtifact
	Evidence  EvidenceArtifact
	Skills    SkillsArtifact
	Trace     TraceArtifact
	Claims    *ClaimsArtifact
	Profile   *ProfileArtifact
	ResumeInput *ResumeInputArtifact
	SummaryMD string
	Signature SignatureArtifact
}

// ReportArtifact is the issue-centric final verification artifact.
type ReportArtifact struct {
	SchemaVersion string             `json:"schema_version"`
	EngineVersion string             `json:"engine_version"`
	Repo          string             `json:"repo"`
	Commit        string             `json:"commit"`
	Timestamp     string             `json:"timestamp"`
	TraceID       string             `json:"trace_id"`
	Summary       ReportSummary      `json:"summary"`
	Skills        []ReportSkillScore `json:"skills"`
	Issues        []Issue            `json:"issues"`
}

// ReportSummary is the top-level numeric and categorical summary for report.json.
type ReportSummary struct {
	OverallScore float64           `json:"overall_score"`
	RiskLevel    string            `json:"risk_level"`
	IssueCounts  IssueCountSummary `json:"issue_counts"`
}

// IssueCountSummary counts issues by severity.
type IssueCountSummary struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
}

// ReportSkillScore is the compact skill summary embedded into report.json.
type ReportSkillScore struct {
	SkillID string  `json:"skill_id"`
	Score   float64 `json:"score"`
}

// ConfidenceBreakdown explains how issue confidence was computed.
type ConfidenceBreakdown struct {
	RuleReliability      float64 `json:"rule_reliability"`
	EvidenceQuality      float64 `json:"evidence_quality"`
	BoundaryCompleteness float64 `json:"boundary_completeness"`
	ContextCompleteness  float64 `json:"context_completeness"`
	SourceAgreement      float64 `json:"source_agreement"`
	ContradictionPenalty float64 `json:"contradiction_penalty"`
	LLMPenalty           float64 `json:"llm_penalty"`
	Final                float64 `json:"final"`
}

// IssueSourceSummary captures how many independent supporting source classes
// contributed to an aggregated issue.
type IssueSourceSummary struct {
	RuleCount            int  `json:"rule_count"`
	DeterministicSources int  `json:"deterministic_sources"`
	AgentSources         int  `json:"agent_sources"`
	TotalSources         int  `json:"total_sources"`
	MultiSource          bool `json:"multi_source"`
}

// Issue is the aggregated issue representation projected into report.json.
type Issue struct {
	ID                  string               `json:"id"`
	Fingerprint         string               `json:"fingerprint"`
	RuleFamily          string               `json:"rule_family"`
	MergeBasis          string               `json:"merge_basis"`
	Category            string               `json:"category"`
	Title               string               `json:"title"`
	Severity            string               `json:"severity"`
	Confidence          float64              `json:"confidence"`
	ConfidenceClass     string               `json:"confidence_class"`
	PolicyClass         string               `json:"policy_class"`
	Status              string               `json:"status"`
	EvidenceIDs         []string             `json:"evidence_ids"`
	CounterEvidenceIDs  []string             `json:"counter_evidence_ids,omitempty"`
	SkillImpacts        []string             `json:"skill_impacts,omitempty"`
	Sources             []string             `json:"sources,omitempty"`
	SourceSummary       IssueSourceSummary   `json:"source_summary"`
	ConfidenceBreakdown *ConfidenceBreakdown `json:"confidence_breakdown,omitempty"`
}

// EvidenceArtifact is the source-of-truth normalized evidence store.
type EvidenceArtifact struct {
	SchemaVersion string           `json:"schema_version"`
	EngineVersion string           `json:"engine_version"`
	Repo          string           `json:"repo"`
	Commit        string           `json:"commit"`
	Timestamp     string           `json:"timestamp"`
	Evidence      []EvidenceRecord `json:"evidence"`
}

// LocationRef points to a concrete source location.
type LocationRef struct {
	RepoRelPath string `json:"repo_rel_path"`
	StartLine   int    `json:"start_line"`
	EndLine     int    `json:"end_line"`
	StartCol    int    `json:"start_col,omitempty"`
	EndCol      int    `json:"end_col,omitempty"`
	SymbolID    string `json:"symbol_id,omitempty"`
}

// EvidenceRecord is the normalized evidence unit shared across analyzers, rules, and agents.
type EvidenceRecord struct {
	ID              string         `json:"id"`
	Kind            string         `json:"kind"`
	Source          string         `json:"source"`
	ProducerID      string         `json:"producer_id"`
	ProducerVersion string         `json:"producer_version"`
	Repo            string         `json:"repo"`
	Commit          string         `json:"commit"`
	BoundaryHash    string         `json:"boundary_hash"`
	FactQuality     string         `json:"fact_quality"`
	EntityIDs       []string       `json:"entity_ids"`
	Locations       []LocationRef  `json:"locations"`
	Claims          []string       `json:"claims"`
	Payload         map[string]any `json:"payload"`
	Supports        []string       `json:"supports"`
	Contradicts     []string       `json:"contradicts"`
	DerivedFrom     []string       `json:"derived_from"`
	CreatedAt       string         `json:"created_at"`
}

// IssueCandidate is the pre-projection aggregated issue model.
// It exists as the intermediate representation between evidence aggregation
// and report artifact rendering.
type IssueCandidate struct {
	ID                  string
	Fingerprint         string
	RuleFamily          string
	MergeBasis          string
	Category            string
	Title               string
	Severity            string
	Confidence          float64
	ConfidenceClass     string
	PolicyClass         string
	Status              string
	RuleIDs             []string
	EvidenceIDs         []string
	CounterEvidenceIDs  []string
	SkillImpacts        []string
	Sources             []string
	SourceSummary       IssueSourceSummary
	ConfidenceBreakdown *ConfidenceBreakdown
}

// SkillsArtifact is the explainable skill scoring artifact.
type SkillsArtifact struct {
	SchemaVersion string       `json:"schema_version"`
	EngineVersion string       `json:"engine_version"`
	Repo          string       `json:"repo"`
	Commit        string       `json:"commit"`
	Timestamp     string       `json:"timestamp"`
	Skills        []SkillScore `json:"skills"`
}

// SkillScore is an evidence-derived score for a single skill dimension.
type SkillScore struct {
	SkillID                 string              `json:"skill_id"`
	Score                   float64             `json:"score"`
	Confidence              float64             `json:"confidence"`
	ContributingIssueIDs    []string            `json:"contributing_issue_ids"`
	ContributingEvidenceIDs []string            `json:"contributing_evidence_ids"`
	FormulaInputs           *SkillFormulaInputs `json:"formula_inputs,omitempty"`
}

// SkillFormulaInputs captures explainable positive and negative contributors.
type SkillFormulaInputs struct {
	Positive []WeightedContribution `json:"positive,omitempty"`
	Negative []WeightedContribution `json:"negative,omitempty"`
}

// WeightedContribution captures a single weighted input to a skill score.
type WeightedContribution struct {
	IssueID string  `json:"issue_id"`
	Weight  float64 `json:"weight"`
	Value   float64 `json:"value"`
}

// TraceArtifact is the reproducibility and execution manifest.
type TraceArtifact struct {
	SchemaVersion     string                   `json:"schema_version"`
	EngineVersion     string                   `json:"engine_version"`
	TraceID           string                   `json:"trace_id"`
	Repo              string                   `json:"repo"`
	Commit            string                   `json:"commit"`
	Timestamp         string                   `json:"timestamp"`
	Partial           bool                     `json:"partial,omitempty"`
	Degraded          bool                     `json:"degraded,omitempty"`
	Errors            []string                 `json:"errors,omitempty"`
	ScanBoundary      TraceScanBoundary        `json:"scan_boundary"`
	MigrationSummary  *RuleMigrationSummary    `json:"migration_summary,omitempty"`
	ConfidenceCalibration *ConfidenceCalibration `json:"confidence_calibration,omitempty"`
	Analyzers         []AnalyzerRun            `json:"analyzers,omitempty"`
	Rules             []RuleRun                `json:"rules,omitempty"`
	SkippedRules      []SkippedRuleTrace       `json:"skipped_rules,omitempty"`
	ContextSelections []ContextSelectionRecord `json:"context_selections,omitempty"`
	Agents            []AgentRun               `json:"agents,omitempty"`
	Derivations       []IssueDerivation        `json:"derivations,omitempty"`
}

// TraceScanBoundary captures the executed scan boundary summary.
type TraceScanBoundary struct {
	Mode          string `json:"mode"`
	IncludedFiles int    `json:"included_files"`
	ExcludedFiles int    `json:"excluded_files"`
}

// RuleMigrationSummary captures per-run progress of the native rule-to-issue
// migration matrix.
type RuleMigrationSummary struct {
	LegacyOnlyCount     int               `json:"legacy_only_count"`
	FindingBridgedCount int               `json:"finding_bridged_count"`
	SeedNativeCount     int               `json:"seed_native_count"`
	IssueNativeCount    int               `json:"issue_native_count"`
	RuleStates          map[string]string `json:"rule_states,omitempty"`
	RuleReasons         map[string]string `json:"rule_reasons,omitempty"`
}

// ConfidenceCalibration captures the explicit calibrated policy used to derive
// issue confidence and trust classes for this run.
type ConfidenceCalibration struct {
	Version                string             `json:"version"`
	MachineTrustedThreshold float64           `json:"machine_trusted_threshold"`
	UnknownCap             float64            `json:"unknown_cap"`
	AgentOnlyCap           float64            `json:"agent_only_cap"`
	RuleFamilyBaselines    map[string]float64 `json:"rule_family_baselines,omitempty"`
	OrderingRules          []string           `json:"ordering_rules,omitempty"`
}

// AnalyzerRun records analyzer execution in trace.json.
type AnalyzerRun struct {
	Name     string `json:"name"`
	Version  string `json:"version"`
	Language string `json:"language"`
	Status   string `json:"status"`
	Degraded bool   `json:"degraded,omitempty"`
	Reason   string `json:"reason,omitempty"`
}

// RuleRun records rule execution lineage in trace.json.
type RuleRun struct {
	ID                 string   `json:"id"`
	Version            string   `json:"version"`
	MigrationState     string   `json:"migration_state,omitempty"`
	MigrationReason    string   `json:"migration_reason,omitempty"`
	TriggeredIssueIDs  []string `json:"triggered_issue_ids,omitempty"`
	EmittedEvidenceIDs []string `json:"emitted_evidence_ids,omitempty"`
}

// SkippedRuleTrace records a skipped rule in trace.json for reproducibility.
type SkippedRuleTrace struct {
	ID     string `json:"id"`
	Reason string `json:"reason"`
}

// ContextSelectionRecord records bounded context selection for downstream work.
type ContextSelectionRecord struct {
	ID                  string        `json:"id"`
	TriggerType         string        `json:"trigger_type"`
	TriggerID           string        `json:"trigger_id"`
	SelectedEvidenceIDs []string      `json:"selected_evidence_ids,omitempty"`
	EntityIDs           []string      `json:"entity_ids,omitempty"`
	SelectedSpans       []LocationRef `json:"selected_spans,omitempty"`
	MaxFiles            int           `json:"max_files,omitempty"`
	MaxSpans            int           `json:"max_spans,omitempty"`
	MaxTokens           int           `json:"max_tokens,omitempty"`
	SelectionTrace      []string      `json:"selection_trace,omitempty"`
}

// AgentRun records a single agent task in trace.json.
type AgentRun struct {
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

// IssueDerivation maps issues to their supporting evidence set.
type IssueDerivation struct {
	IssueID                string   `json:"issue_id"`
	IssueFingerprint       string   `json:"issue_fingerprint"`
	DerivedFromEvidenceIDs []string `json:"derived_from_evidence_ids"`
}

// SignatureArtifact is the integrity envelope for the artifact bundle.
type SignatureArtifact struct {
	Version         string            `json:"version"`
	SignedBy        string            `json:"signed_by"`
	Timestamp       string            `json:"timestamp"`
	ArtifactHashes  map[string]string `json:"artifact_hashes"`
	BundleHash      string            `json:"bundle_hash"`
	Signature       *string           `json:"signature"`
	SignatureScheme *string           `json:"signature_scheme"`
}
