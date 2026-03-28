package acceptance

import (
	"fmt"
	"slices"

	"github.com/verabase/code-verification-engine/internal/artifactsv2"
)

// AssertBundleAgainstFixture validates a verifiable bundle against a deterministic
// fixture manifest. It is designed to be reused by fixture tests and future runners.
func AssertBundleAgainstFixture(bundle artifactsv2.Bundle, manifest FixtureManifest) error {
	if err := artifactsv2.ValidateBundle(bundle); err != nil {
		return fmt.Errorf("bundle contract: %w", err)
	}
	if got := len(bundle.Report.Issues); got != manifest.ExpectedIssueCount {
		return fmt.Errorf("issue count mismatch: got %d want %d", got, manifest.ExpectedIssueCount)
	}
	if manifest.ExpectedPartial != nil && bundle.Trace.Partial != *manifest.ExpectedPartial {
		return fmt.Errorf("partial mismatch: got %t want %t", bundle.Trace.Partial, *manifest.ExpectedPartial)
	}
	if manifest.ExpectedDegraded != nil && bundle.Trace.Degraded != *manifest.ExpectedDegraded {
		return fmt.Errorf("degraded mismatch: got %t want %t", bundle.Trace.Degraded, *manifest.ExpectedDegraded)
	}
	if manifest.ExpectedIssueNativeCount != nil {
		if bundle.Trace.MigrationSummary == nil || bundle.Trace.MigrationSummary.IssueNativeCount != *manifest.ExpectedIssueNativeCount {
			return fmt.Errorf("issue_native_count mismatch: got %v want %d", migrationCountOrNil(bundle.Trace.MigrationSummary, "issue_native"), *manifest.ExpectedIssueNativeCount)
		}
	}
	if manifest.ExpectedSeedNativeCount != nil {
		if bundle.Trace.MigrationSummary == nil || bundle.Trace.MigrationSummary.SeedNativeCount != *manifest.ExpectedSeedNativeCount {
			return fmt.Errorf("seed_native_count mismatch: got %v want %d", migrationCountOrNil(bundle.Trace.MigrationSummary, "seed_native"), *manifest.ExpectedSeedNativeCount)
		}
	}
	if manifest.ExpectedFindingBridgedCount != nil {
		if bundle.Trace.MigrationSummary == nil || bundle.Trace.MigrationSummary.FindingBridgedCount != *manifest.ExpectedFindingBridgedCount {
			return fmt.Errorf("finding_bridged_count mismatch: got %v want %d", migrationCountOrNil(bundle.Trace.MigrationSummary, "finding_bridged"), *manifest.ExpectedFindingBridgedCount)
		}
	}
	if manifest.ExpectedContextSelectionCount != nil && len(bundle.Trace.ContextSelections) != *manifest.ExpectedContextSelectionCount {
		return fmt.Errorf("context selection count mismatch: got %d want %d", len(bundle.Trace.ContextSelections), *manifest.ExpectedContextSelectionCount)
	}
	for _, issueID := range manifest.ExpectedContextSelectionTriggerIDs {
		if !hasContextSelectionTriggerID(bundle.Trace.ContextSelections, issueID) {
			return fmt.Errorf("missing expected context selection trigger id %q", issueID)
		}
	}
	for _, ruleID := range manifest.ExpectedContextSelectionTriggerRuleIDs {
		if !hasContextSelectionTriggerRuleID(bundle.Trace.ContextSelections, bundle.Trace.Rules, ruleID) {
			return fmt.Errorf("missing expected context selection trigger rule id %q", ruleID)
		}
	}
	if manifest.ExpectedAgentCount != nil && len(bundle.Trace.Agents) != *manifest.ExpectedAgentCount {
		return fmt.Errorf("agent count mismatch: got %d want %d", len(bundle.Trace.Agents), *manifest.ExpectedAgentCount)
	}
	for _, kind := range manifest.ExpectedAgentKinds {
		if !hasAgentKind(bundle.Trace.Agents, kind) {
			return fmt.Errorf("missing expected agent kind %q", kind)
		}
	}
	for _, issueType := range manifest.ExpectedAgentIssueTypes {
		if !hasAgentIssueType(bundle.Trace.Agents, issueType) {
			return fmt.Errorf("missing expected agent issue_type %q", issueType)
		}
	}
	for _, triggerReason := range manifest.ExpectedAgentTriggerReasons {
		if !hasAgentTriggerReason(bundle.Trace.Agents, triggerReason) {
			return fmt.Errorf("missing expected agent trigger_reason %q", triggerReason)
		}
	}
	for _, constraint := range manifest.ExpectedAgentContracts {
		agent, ok := findAgentByConstraint(bundle.Trace.Agents, bundle.Trace.Rules, constraint)
		if !ok {
			return fmt.Errorf("missing expected planned agent contract: issue_id=%q rule_id=%q kind=%q trigger_reason=%q status=%q", constraint.IssueID, constraint.RuleID, constraint.Kind, constraint.TriggerReason, constraint.Status)
		}
		if len(constraint.OutputEvidenceIDs) > 0 && !slices.Equal(agent.OutputEvidenceIDs, constraint.OutputEvidenceIDs) {
			return fmt.Errorf("agent output evidence mismatch for issue_id=%q rule_id=%q: got %#v want %#v", constraint.IssueID, constraint.RuleID, agent.OutputEvidenceIDs, constraint.OutputEvidenceIDs)
		}
	}
	for ruleID, expectedState := range manifest.ExpectedRuleMigrationStates {
		if bundle.Trace.MigrationSummary == nil {
			return fmt.Errorf("missing migration_summary while checking rule state for %q", ruleID)
		}
		if got := bundle.Trace.MigrationSummary.RuleStates[ruleID]; got != expectedState {
			return fmt.Errorf("rule migration state mismatch for %q: got %q want %q", ruleID, got, expectedState)
		}
	}
	for issueID, expectedPolicyClass := range manifest.ExpectedIssuePolicyClasses {
		issue, ok := findIssueByID(bundle.Report.Issues, issueID)
		if !ok {
			return fmt.Errorf("missing issue %q while checking policy class", issueID)
		}
		if issue.PolicyClass != expectedPolicyClass {
			return fmt.Errorf("issue policy class mismatch for %q: got %q want %q", issueID, issue.PolicyClass, expectedPolicyClass)
		}
	}
	for issueID, expectedConfidenceClass := range manifest.ExpectedIssueConfidenceClasses {
		issue, ok := findIssueByID(bundle.Report.Issues, issueID)
		if !ok {
			return fmt.Errorf("missing issue %q while checking confidence class", issueID)
		}
		if issue.ConfidenceClass != expectedConfidenceClass {
			return fmt.Errorf("issue confidence class mismatch for %q: got %q want %q", issueID, issue.ConfidenceClass, expectedConfidenceClass)
		}
	}
	for _, constraint := range manifest.ExpectedConfidenceConstraints {
		issue, ok := findIssueByConstraint(bundle.Report.Issues, bundle.Trace.Rules, constraint)
		if !ok {
			return fmt.Errorf("missing issue while checking confidence constraints: issue_id=%q rule_id=%q", constraint.IssueID, constraint.RuleID)
		}
		if constraint.Min != nil && issue.Confidence < *constraint.Min {
			return fmt.Errorf("issue confidence below minimum for %q: got %f want >= %f", constraint.IssueID, issue.Confidence, *constraint.Min)
		}
		if constraint.Max != nil && issue.Confidence > *constraint.Max {
			return fmt.Errorf("issue confidence above maximum for %q: got %f want <= %f", constraint.IssueID, issue.Confidence, *constraint.Max)
		}
		if constraint.Class != "" && issue.ConfidenceClass != constraint.Class {
			return fmt.Errorf("issue confidence class mismatch for %q: got %q want %q", constraint.IssueID, issue.ConfidenceClass, constraint.Class)
		}
		if constraint.PolicyClass != "" && issue.PolicyClass != constraint.PolicyClass {
			return fmt.Errorf("issue policy class mismatch for %q: got %q want %q", constraint.IssueID, issue.PolicyClass, constraint.PolicyClass)
		}
	}

	for _, issueID := range manifest.ExpectedIssueIDs {
		if !hasIssueID(bundle.Report.Issues, issueID) {
			return fmt.Errorf("missing expected issue id %q", issueID)
		}
	}
	for _, evidenceID := range manifest.ExpectedEvidenceIDs {
		if !hasEvidenceID(bundle.Evidence.Evidence, evidenceID) {
			return fmt.Errorf("missing expected evidence id %q", evidenceID)
		}
	}
	for _, ruleID := range manifest.ExpectedRuleIDs {
		if !hasRuleID(bundle.Trace.Rules, ruleID) {
			return fmt.Errorf("missing expected trace rule id %q", ruleID)
		}
	}
	for _, issueID := range manifest.ExpectedNonMergeIssueIDs {
		if !hasIssueID(bundle.Report.Issues, issueID) {
			return fmt.Errorf("expected non-merged issue id %q not found", issueID)
		}
	}
	if manifest.ExpectedMergeRepresentativeID != "" && !hasIssueID(bundle.Report.Issues, manifest.ExpectedMergeRepresentativeID) {
		return fmt.Errorf("missing merge representative issue id %q", manifest.ExpectedMergeRepresentativeID)
	}

	return nil
}

func findIssueByConstraint(issues []artifactsv2.Issue, rulesRun []artifactsv2.RuleRun, constraint ConfidenceConstraint) (artifactsv2.Issue, bool) {
	if constraint.IssueID != "" {
		return findIssueByID(issues, constraint.IssueID)
	}
	if constraint.RuleID == "" {
		return artifactsv2.Issue{}, false
	}
	var candidateIDs []string
	for _, run := range rulesRun {
		if run.ID == constraint.RuleID {
			candidateIDs = append(candidateIDs, run.TriggeredIssueIDs...)
		}
	}
	for _, issueID := range candidateIDs {
		if issue, ok := findIssueByID(issues, issueID); ok {
			return issue, true
		}
	}
	return artifactsv2.Issue{}, false
}

func migrationCountOrNil(summary *artifactsv2.RuleMigrationSummary, kind string) any {
	if summary == nil {
		return nil
	}
	switch kind {
	case "issue_native":
		return summary.IssueNativeCount
	case "seed_native":
		return summary.SeedNativeCount
	case "finding_bridged":
		return summary.FindingBridgedCount
	default:
		return nil
	}
}

// AssertBundleDeterministic validates that two bundles are contract-valid and
// canonically identical at the artifact hash level.
func AssertBundleDeterministic(a, b artifactsv2.Bundle) error {
	if err := artifactsv2.ValidateBundle(a); err != nil {
		return fmt.Errorf("first bundle invalid: %w", err)
	}
	if err := artifactsv2.ValidateBundle(b); err != nil {
		return fmt.Errorf("second bundle invalid: %w", err)
	}
	ah, err := artifactsv2.ComputeArtifactHashes(a)
	if err != nil {
		return fmt.Errorf("compute first artifact hashes: %w", err)
	}
	bh, err := artifactsv2.ComputeArtifactHashes(b)
	if err != nil {
		return fmt.Errorf("compute second artifact hashes: %w", err)
	}
	if !slices.Equal(sortedMapEntries(ah), sortedMapEntries(bh)) {
		return fmt.Errorf("artifact hashes differ")
	}
	if artifactsv2.ComputeBundleHash(ah) != artifactsv2.ComputeBundleHash(bh) {
		return fmt.Errorf("bundle hashes differ")
	}
	return nil
}

func hasIssueID(issues []artifactsv2.Issue, issueID string) bool {
	for _, issue := range issues {
		if issue.ID == issueID {
			return true
		}
	}
	return false
}

func findIssueByID(issues []artifactsv2.Issue, issueID string) (artifactsv2.Issue, bool) {
	for _, issue := range issues {
		if issue.ID == issueID {
			return issue, true
		}
	}
	return artifactsv2.Issue{}, false
}

func hasEvidenceID(evidence []artifactsv2.EvidenceRecord, evidenceID string) bool {
	for _, record := range evidence {
		if record.ID == evidenceID {
			return true
		}
	}
	return false
}

func hasRuleID(rulesRun []artifactsv2.RuleRun, ruleID string) bool {
	for _, run := range rulesRun {
		if run.ID == ruleID {
			return true
		}
	}
	return false
}

func hasContextSelectionTriggerID(selections []artifactsv2.ContextSelectionRecord, triggerID string) bool {
	for _, selection := range selections {
		if selection.TriggerID == triggerID {
			return true
		}
	}
	return false
}

func hasContextSelectionTriggerRuleID(selections []artifactsv2.ContextSelectionRecord, rulesRun []artifactsv2.RuleRun, ruleID string) bool {
	var triggerIDs []string
	for _, run := range rulesRun {
		if run.ID == ruleID {
			triggerIDs = append(triggerIDs, run.TriggeredIssueIDs...)
		}
	}
	if len(triggerIDs) == 0 {
		return false
	}
	for _, selection := range selections {
		if slices.Contains(triggerIDs, selection.TriggerID) {
			return true
		}
	}
	return false
}

func hasAgentKind(agents []artifactsv2.AgentRun, kind string) bool {
	for _, agent := range agents {
		if agent.Kind == kind {
			return true
		}
	}
	return false
}

func hasAgentIssueType(agents []artifactsv2.AgentRun, issueType string) bool {
	for _, agent := range agents {
		if agent.IssueType == issueType {
			return true
		}
	}
	return false
}

func hasAgentTriggerReason(agents []artifactsv2.AgentRun, triggerReason string) bool {
	for _, agent := range agents {
		if agent.TriggerReason == triggerReason {
			return true
		}
	}
	return false
}

func findAgentByConstraint(agents []artifactsv2.AgentRun, rulesRun []artifactsv2.RuleRun, constraint PlannedAgentConstraint) (artifactsv2.AgentRun, bool) {
	matches := func(agent artifactsv2.AgentRun) bool {
		if constraint.Kind != "" && agent.Kind != constraint.Kind {
			return false
		}
		if constraint.TriggerReason != "" && agent.TriggerReason != constraint.TriggerReason {
			return false
		}
		if constraint.Status != "" && agent.Status != constraint.Status {
			return false
		}
		return true
	}

	if constraint.IssueID != "" {
		for _, agent := range agents {
			if agent.IssueID == constraint.IssueID && matches(agent) {
				return agent, true
			}
		}
		return artifactsv2.AgentRun{}, false
	}

	if constraint.RuleID == "" {
		return artifactsv2.AgentRun{}, false
	}

	var candidateIDs []string
	for _, run := range rulesRun {
		if run.ID == constraint.RuleID {
			candidateIDs = append(candidateIDs, run.TriggeredIssueIDs...)
		}
	}
	if len(candidateIDs) == 0 {
		return artifactsv2.AgentRun{}, false
	}
	for _, candidateID := range candidateIDs {
		for _, agent := range agents {
			if agent.IssueID == candidateID && matches(agent) {
				return agent, true
			}
		}
	}
	return artifactsv2.AgentRun{}, false
}

func sortedMapEntries(m map[string]string) []string {
	if len(m) == 0 {
		return nil
	}
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	out := make([]string, 0, len(keys))
	for _, key := range keys {
		out = append(out, key+"="+m[key])
	}
	return out
}
