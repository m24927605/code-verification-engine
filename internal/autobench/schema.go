package autobench

// SchemaVersion is the version for the autonomous benchmark dataset contract.
const SchemaVersion = "1.0.0"

// Allowed dataset modes.
const (
	ModeFrozen    = "frozen"
	ModeGenerated = "generated"
	ModeShadow    = "shadow"
)

// Allowed case types.
const (
	CasePass               = "pass"
	CaseFail               = "fail"
	CaseUnknown            = "unknown"
	CaseMixed              = "mixed"
	CaseFalsePositiveGuard = "false-positive-guard"
	CaseFalseNegativeGuard = "false-negative-guard"
	CaseEdgeCase           = "edge-case"
)

// Allowed repair owners.
const (
	OwnerAnalyzer = "analyzer"
	OwnerRules    = "rules"
	OwnerReport   = "report"
	OwnerDataset  = "dataset"
	OwnerUnknown  = "unknown"
)

// DatasetManifest describes a machine-readable autonomous calibration dataset.
type DatasetManifest struct {
	SchemaVersion  string            `json:"schema_version"`
	DatasetID      string            `json:"dataset_id"`
	Mode           string            `json:"mode"`
	Description    string            `json:"description"`
	GeneratorPolicy GeneratorPolicy  `json:"generator_policy"`
	Adjudication    AdjudicationSpec `json:"adjudication"`
	GatePolicy      GatePolicy       `json:"gate_policy"`
	Suites          []SuiteManifest  `json:"suites"`
}

// GeneratorPolicy constrains how synthetic repos and truth data are produced.
type GeneratorPolicy struct {
	AllowLLMGeneratedRepos       bool `json:"allow_llm_generated_repos"`
	RequireDistinctAdjudicator   bool `json:"require_distinct_adjudicator"`
	FreezeExpectedAfterPromotion bool `json:"freeze_expected_after_promotion"`
}

// AdjudicationSpec configures automated comparison and escalation behavior.
type AdjudicationSpec struct {
	RequireExpectedDiff     bool     `json:"require_expected_diff"`
	RequireReviewerVerdict  bool     `json:"require_reviewer_verdict"`
	RequireSecondReviewerOn []string `json:"require_second_reviewer_on"`
}

// GatePolicy defines promotion constraints for autonomous repair loops.
type GatePolicy struct {
	BlockOnFrozenRegression         bool              `json:"block_on_frozen_regression"`
	BlockOnSchemaContractViolation  bool              `json:"block_on_schema_contract_violation"`
	RequireTrustedCoreClean         bool              `json:"require_trusted_core_clean"`
	MaxNewUnknowns                  int               `json:"max_new_unknowns"`
	MinPrecisionByTrustClass        map[string]float64 `json:"min_precision_by_trust_class"`
	ProtectedPaths                  []string          `json:"protected_paths"`
}

// SuiteManifest groups benchmark cases around a single execution profile.
type SuiteManifest struct {
	ID          string         `json:"id"`
	Profile     string         `json:"profile"`
	ClaimSet    string         `json:"claim_set,omitempty"`
	Objective   string         `json:"objective"`
	Cases       []CaseManifest `json:"cases"`
}

// CaseManifest points to a repo fixture and its frozen expected outcome file.
type CaseManifest struct {
	ID           string   `json:"id"`
	RepoPath     string   `json:"repo_path"`
	Framework    string   `json:"framework"`
	Languages    []string `json:"languages"`
	CaseType     string   `json:"case_type"`
	TargetRules  []string `json:"target_rules"`
	ExpectedPath string   `json:"expected_path"`
	Tags         []string `json:"tags,omitempty"`
}

// ExpectedCase captures the frozen truth contract for a repo fixture.
type ExpectedCase struct {
	SchemaVersion string            `json:"schema_version"`
	CaseID        string            `json:"case_id"`
	Profile       string            `json:"profile"`
	ClaimSet      string            `json:"claim_set,omitempty"`
	Expectations  []RuleExpectation `json:"expectations"`
}

// RuleExpectation defines acceptable outcomes for a single rule in a case.
type RuleExpectation struct {
	RuleID               string   `json:"rule_id"`
	ExpectedStatus       string   `json:"expected_status,omitempty"`
	AllowedStatuses      []string `json:"allowed_statuses,omitempty"`
	ExpectedTrustClass   string   `json:"expected_trust_class,omitempty"`
	MinimumEvidenceCount int      `json:"minimum_evidence_count,omitempty"`
	Priority             string   `json:"priority"`
	Rationale            string   `json:"rationale"`
}

// AdjudicationReport is the machine-readable handoff from reviewer agents.
type AdjudicationReport struct {
	SchemaVersion string              `json:"schema_version"`
	DatasetID     string              `json:"dataset_id"`
	SuiteID       string              `json:"suite_id"`
	CaseID        string              `json:"case_id"`
	Verdict       string              `json:"verdict"`
	Discrepancies []RuleDiscrepancy   `json:"discrepancies"`
	Summary       AdjudicationSummary `json:"summary"`
}

// RuleDiscrepancy describes a mismatch between expected and actual outcomes.
type RuleDiscrepancy struct {
	RuleID            string   `json:"rule_id"`
	ExpectedStatus    string   `json:"expected_status,omitempty"`
	ActualStatus      string   `json:"actual_status,omitempty"`
	ReviewerVerdict   string   `json:"reviewer_verdict,omitempty"`
	SuspectedCauses   []string `json:"suspected_causes,omitempty"`
	RecommendedOwner  string   `json:"recommended_owner"`
	RecommendedAction string   `json:"recommended_action,omitempty"`
}

// AdjudicationSummary aggregates discrepancy counts for gating.
type AdjudicationSummary struct {
	Blocking int `json:"blocking"`
	Advisory int `json:"advisory"`
}
