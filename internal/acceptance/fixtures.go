package acceptance

import "github.com/verabase/code-verification-engine/internal/artifactsv2"

// FixtureManifest defines the deterministic expectations for a v2 acceptance fixture.
// It is intentionally artifact-focused so the same contract can back local tests,
// CI regression suites, and future fixture runners.
type FixtureManifest struct {
	FixtureID                              string                   `json:"fixture_id"`
	FixtureType                            string                   `json:"fixture_type"`
	ExpectedIssueCount                     int                      `json:"expected_issue_count"`
	ExpectedIssueIDs                       []string                 `json:"expected_issue_ids,omitempty"`
	ExpectedEvidenceIDs                    []string                 `json:"expected_evidence_ids,omitempty"`
	ExpectedRuleIDs                        []string                 `json:"expected_rule_ids,omitempty"`
	ExpectedPartial                        *bool                    `json:"expected_partial,omitempty"`
	ExpectedDegraded                       *bool                    `json:"expected_degraded,omitempty"`
	ExpectedBundleHashStable               bool                     `json:"expected_bundle_hash_stable,omitempty"`
	ExpectedNonMergeIssueIDs               []string                 `json:"expected_non_merge_issue_ids,omitempty"`
	ExpectedMergeRepresentativeID          string                   `json:"expected_merge_representative_id,omitempty"`
	ExpectedIssueNativeCount               *int                     `json:"expected_issue_native_count,omitempty"`
	ExpectedSeedNativeCount                *int                     `json:"expected_seed_native_count,omitempty"`
	ExpectedFindingBridgedCount            *int                     `json:"expected_finding_bridged_count,omitempty"`
	ExpectedContextSelectionCount          *int                     `json:"expected_context_selection_count,omitempty"`
	ExpectedContextSelectionTriggerIDs     []string                 `json:"expected_context_selection_trigger_ids,omitempty"`
	ExpectedContextSelectionTriggerRuleIDs []string                 `json:"expected_context_selection_trigger_rule_ids,omitempty"`
	ExpectedAgentCount                     *int                     `json:"expected_agent_count,omitempty"`
	ExpectedAgentKinds                     []string                 `json:"expected_agent_kinds,omitempty"`
	ExpectedAgentIssueTypes                []string                 `json:"expected_agent_issue_types,omitempty"`
	ExpectedAgentTriggerReasons            []string                 `json:"expected_agent_trigger_reasons,omitempty"`
	ExpectedAgentContracts                 []PlannedAgentConstraint `json:"expected_planned_agent_contracts,omitempty"`
	ExpectedRuleMigrationStates            map[string]string        `json:"expected_rule_migration_states,omitempty"`
	ExpectedIssuePolicyClasses             map[string]string        `json:"expected_issue_policy_classes,omitempty"`
	ExpectedIssueConfidenceClasses         map[string]string        `json:"expected_issue_confidence_classes,omitempty"`
	ExpectedConfidenceConstraints          []ConfidenceConstraint   `json:"expected_confidence_constraints,omitempty"`
}

// ConfidenceConstraint captures a deterministic confidence expectation for a
// specific issue candidate.
type ConfidenceConstraint struct {
	IssueID     string   `json:"issue_id"`
	RuleID      string   `json:"rule_id,omitempty"`
	Min         *float64 `json:"min,omitempty"`
	Max         *float64 `json:"max,omitempty"`
	Class       string   `json:"class,omitempty"`
	PolicyClass string   `json:"policy_class,omitempty"`
}

// PlannedAgentConstraint captures a deterministic planned-agent expectation for
// a specific issue or rule.
type PlannedAgentConstraint struct {
	IssueID           string   `json:"issue_id,omitempty"`
	RuleID            string   `json:"rule_id,omitempty"`
	Kind              string   `json:"kind,omitempty"`
	TriggerReason     string   `json:"trigger_reason,omitempty"`
	Status            string   `json:"status,omitempty"`
	OutputEvidenceIDs []string `json:"output_evidence_ids,omitempty"`
}

// CompatFixture binds a deterministic builder input to its acceptance manifest.
// This is the minimal executable fixture shape for the current v2 migration path.
type CompatFixture struct {
	Input    artifactsv2.CompatBuildInput
	Manifest FixtureManifest
}
