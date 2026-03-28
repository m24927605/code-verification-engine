package artifactsv2

import (
	"fmt"
	"slices"
	"strings"
)

var (
	validRiskLevels        = []string{"low", "medium", "high", "critical"}
	validSeverities        = []string{"low", "medium", "high", "critical"}
	validIssueStatus       = []string{"open", "resolved", "unknown"}
	validMergeBases        = []string{"same_symbol", "line_overlap"}
	validConfidenceClasses = []string{"high", "moderate", "low", "weak"}
	validPolicyClasses     = []string{"machine_trusted", "advisory", "unknown_retained"}
	validSources           = []string{"analyzer", "rule", "agent"}
	validFactQuality       = []string{"proof", "structural", "heuristic"}
	validAgentStatus       = []string{"planned", "completed", "insufficient_context", "failed"}
	validAgentKinds        = []string{"bug", "design", "security"}
	validAnalyzerStatus    = []string{"ok", "partial", "error"}
)

// ValidateBundle validates all artifacts and their cross references.
func ValidateBundle(b Bundle) error {
	if err := ValidateReport(b.Report); err != nil {
		return fmt.Errorf("report: %w", err)
	}
	if err := ValidateEvidence(b.Evidence); err != nil {
		return fmt.Errorf("evidence: %w", err)
	}
	if err := ValidateSkills(b.Skills); err != nil {
		return fmt.Errorf("skills: %w", err)
	}
	if err := ValidateTrace(b.Trace); err != nil {
		return fmt.Errorf("trace: %w", err)
	}
	if b.Claims != nil {
		if err := ValidateClaimsArtifact(*b.Claims); err != nil {
			return fmt.Errorf("claims: %w", err)
		}
	}
	if b.Profile != nil {
		if err := ValidateProfileArtifact(*b.Profile); err != nil {
			return fmt.Errorf("profile: %w", err)
		}
	}
	if b.ResumeInput != nil {
		if err := ValidateResumeInputArtifact(*b.ResumeInput); err != nil {
			return fmt.Errorf("resume_input: %w", err)
		}
	}
	if b.SummaryMD == "" {
		return fmt.Errorf("summary.md content is required")
	}
	if err := validateCrossReferences(b); err != nil {
		return err
	}
	return nil
}

// ValidateReport validates report.json content.
func ValidateReport(r ReportArtifact) error {
	if r.SchemaVersion == "" {
		return fmt.Errorf("schema_version is required")
	}
	if r.EngineVersion == "" || r.Repo == "" || r.Commit == "" || r.Timestamp == "" || r.TraceID == "" {
		return fmt.Errorf("engine_version, repo, commit, timestamp, and trace_id are required")
	}
	if err := validateUnitInterval(r.Summary.OverallScore, "summary.overall_score"); err != nil {
		return err
	}
	if !slices.Contains(validRiskLevels, r.Summary.RiskLevel) {
		return fmt.Errorf("invalid summary.risk_level %q", r.Summary.RiskLevel)
	}
	issueIDs := make(map[string]struct{}, len(r.Issues))
	for i, issue := range r.Issues {
		if issue.ID == "" {
			return fmt.Errorf("issues[%d]: id is required", i)
		}
		if issue.Fingerprint == "" {
			return fmt.Errorf("issues[%d]: fingerprint is required", i)
		}
		if issue.RuleFamily == "" {
			return fmt.Errorf("issues[%d]: rule_family is required", i)
		}
		if !slices.Contains(validMergeBases, issue.MergeBasis) {
			return fmt.Errorf("issues[%d]: invalid merge_basis %q", i, issue.MergeBasis)
		}
		if _, exists := issueIDs[issue.ID]; exists {
			return fmt.Errorf("issues[%d]: duplicate id %q", i, issue.ID)
		}
		issueIDs[issue.ID] = struct{}{}
		if issue.Category == "" || issue.Title == "" {
			return fmt.Errorf("issues[%d]: category and title are required", i)
		}
		if !slices.Contains(validSeverities, issue.Severity) {
			return fmt.Errorf("issues[%d]: invalid severity %q", i, issue.Severity)
		}
		if !slices.Contains(validIssueStatus, issue.Status) {
			return fmt.Errorf("issues[%d]: invalid status %q", i, issue.Status)
		}
		if !slices.Contains(validConfidenceClasses, issue.ConfidenceClass) {
			return fmt.Errorf("issues[%d]: invalid confidence_class %q", i, issue.ConfidenceClass)
		}
		if !slices.Contains(validPolicyClasses, issue.PolicyClass) {
			return fmt.Errorf("issues[%d]: invalid policy_class %q", i, issue.PolicyClass)
		}
		if err := validateUnitInterval(issue.Confidence, fmt.Sprintf("issues[%d].confidence", i)); err != nil {
			return err
		}
		if classifyConfidence(issue.Confidence) != issue.ConfidenceClass {
			return fmt.Errorf("issues[%d]: confidence_class %q inconsistent with confidence %.3f", i, issue.ConfidenceClass, issue.Confidence)
		}
		if err := validateIssuePolicyConsistency(issue, fmt.Sprintf("issues[%d]", i)); err != nil {
			return err
		}
		if len(issue.EvidenceIDs) == 0 {
			return fmt.Errorf("issues[%d]: evidence_ids is required", i)
		}
		for _, evID := range issue.CounterEvidenceIDs {
			if evID == "" {
				return fmt.Errorf("issues[%d]: counter_evidence_ids must not contain empty ids", i)
			}
		}
		if issue.SourceSummary.RuleCount < 0 || issue.SourceSummary.DeterministicSources < 0 || issue.SourceSummary.AgentSources < 0 || issue.SourceSummary.TotalSources < 0 {
			return fmt.Errorf("issues[%d]: source_summary counts must be non-negative", i)
		}
		if issue.SourceSummary.TotalSources < issue.SourceSummary.DeterministicSources+issue.SourceSummary.AgentSources {
			return fmt.Errorf("issues[%d]: source_summary total_sources is inconsistent", i)
		}
		if issue.ConfidenceBreakdown != nil {
			if err := validateConfidenceBreakdown(*issue.ConfidenceBreakdown, fmt.Sprintf("issues[%d].confidence_breakdown", i)); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateIssuePolicyConsistency(issue Issue, prefix string) error {
	switch issue.PolicyClass {
	case "machine_trusted":
		if issue.Status == "unknown" {
			return fmt.Errorf("%s: machine_trusted policy cannot be unknown status", prefix)
		}
		if issue.ConfidenceClass != "high" {
			return fmt.Errorf("%s: machine_trusted policy requires high confidence class", prefix)
		}
		if issue.ConfidenceBreakdown == nil {
			return fmt.Errorf("%s: machine_trusted policy requires confidence breakdown", prefix)
		}
		if issue.Confidence < machineTrustedFinalThreshold {
			return fmt.Errorf("%s: machine_trusted policy requires confidence >= %.2f", prefix, machineTrustedFinalThreshold)
		}
		if issue.ConfidenceBreakdown.RuleReliability < machineTrustedFinalThreshold ||
			issue.ConfidenceBreakdown.EvidenceQuality < 0.95 ||
			issue.ConfidenceBreakdown.BoundaryCompleteness < 0.75 ||
			issue.ConfidenceBreakdown.ContextCompleteness < 0.75 ||
			issue.ConfidenceBreakdown.ContradictionPenalty > 0 ||
			issue.ConfidenceBreakdown.LLMPenalty > 0 {
			return fmt.Errorf("%s: machine_trusted policy violates confidence breakdown thresholds", prefix)
		}
	case "advisory":
		// advisory remains the default middle tier and only needs the class to be consistent
	case "unknown_retained":
		// unknown retention is allowed when confidence or support is insufficient
	default:
		return fmt.Errorf("%s: unknown policy class %q", prefix, issue.PolicyClass)
	}
	return nil
}

// ValidateEvidence validates evidence.json content.
func ValidateEvidence(a EvidenceArtifact) error {
	if a.SchemaVersion == "" {
		return fmt.Errorf("schema_version is required")
	}
	if a.EngineVersion == "" || a.Repo == "" || a.Commit == "" || a.Timestamp == "" {
		return fmt.Errorf("engine_version, repo, commit, and timestamp are required")
	}
	ids := make(map[string]struct{}, len(a.Evidence))
	for i, ev := range a.Evidence {
		if ev.ID == "" {
			return fmt.Errorf("evidence[%d]: id is required", i)
		}
		if _, exists := ids[ev.ID]; exists {
			return fmt.Errorf("evidence[%d]: duplicate id %q", i, ev.ID)
		}
		ids[ev.ID] = struct{}{}
		if ev.Kind == "" || ev.ProducerID == "" || ev.ProducerVersion == "" || ev.BoundaryHash == "" || ev.CreatedAt == "" {
			return fmt.Errorf("evidence[%d]: missing required identity or provenance fields", i)
		}
		if !slices.Contains(validSources, ev.Source) {
			return fmt.Errorf("evidence[%d]: invalid source %q", i, ev.Source)
		}
		if !slices.Contains(validFactQuality, ev.FactQuality) {
			return fmt.Errorf("evidence[%d]: invalid fact_quality %q", i, ev.FactQuality)
		}
		if ev.Repo == "" || ev.Commit == "" {
			return fmt.Errorf("evidence[%d]: repo and commit are required", i)
		}
		if len(ev.Locations) == 0 {
			return fmt.Errorf("evidence[%d]: at least one location is required", i)
		}
		for j, loc := range ev.Locations {
			if loc.RepoRelPath == "" {
				return fmt.Errorf("evidence[%d].locations[%d]: repo_rel_path is required", i, j)
			}
			if loc.StartLine < 1 || loc.EndLine < loc.StartLine {
				return fmt.Errorf("evidence[%d].locations[%d]: invalid line range", i, j)
			}
		}
	}
	return nil
}

// ValidateSkills validates skills.json content.
func ValidateSkills(a SkillsArtifact) error {
	if a.SchemaVersion == "" {
		return fmt.Errorf("schema_version is required")
	}
	if a.EngineVersion == "" || a.Repo == "" || a.Commit == "" || a.Timestamp == "" {
		return fmt.Errorf("engine_version, repo, commit, and timestamp are required")
	}
	ids := make(map[string]struct{}, len(a.Skills))
	for i, skill := range a.Skills {
		if skill.SkillID == "" {
			return fmt.Errorf("skills[%d]: skill_id is required", i)
		}
		if _, exists := ids[skill.SkillID]; exists {
			return fmt.Errorf("skills[%d]: duplicate skill_id %q", i, skill.SkillID)
		}
		ids[skill.SkillID] = struct{}{}
		if err := validateUnitInterval(skill.Score, fmt.Sprintf("skills[%d].score", i)); err != nil {
			return err
		}
		if err := validateUnitInterval(skill.Confidence, fmt.Sprintf("skills[%d].confidence", i)); err != nil {
			return err
		}
		if len(skill.ContributingIssueIDs) == 0 {
			return fmt.Errorf("skills[%d]: contributing_issue_ids is required", i)
		}
		if len(skill.ContributingEvidenceIDs) == 0 {
			return fmt.Errorf("skills[%d]: contributing_evidence_ids is required", i)
		}
	}
	return nil
}

// ValidateTrace validates trace.json content.
func ValidateTrace(t TraceArtifact) error {
	if t.SchemaVersion == "" {
		return fmt.Errorf("schema_version is required")
	}
	if t.EngineVersion == "" || t.TraceID == "" || t.Repo == "" || t.Commit == "" || t.Timestamp == "" {
		return fmt.Errorf("engine_version, trace_id, repo, commit, and timestamp are required")
	}
	if t.ScanBoundary.Mode == "" {
		return fmt.Errorf("scan_boundary.mode is required")
	}
	if t.MigrationSummary != nil {
		if t.MigrationSummary.LegacyOnlyCount < 0 || t.MigrationSummary.FindingBridgedCount < 0 || t.MigrationSummary.SeedNativeCount < 0 || t.MigrationSummary.IssueNativeCount < 0 {
			return fmt.Errorf("migration_summary counts must be non-negative")
		}
		for ruleID, state := range t.MigrationSummary.RuleStates {
			if ruleID == "" {
				return fmt.Errorf("migration_summary.rule_states must not contain empty rule ids")
			}
			if !slices.Contains([]string{"legacy_only", "finding_bridged", "seed_native", "issue_native"}, state) {
				return fmt.Errorf("migration_summary.rule_states[%q]: invalid state %q", ruleID, state)
			}
		}
		for ruleID := range t.MigrationSummary.RuleReasons {
			if ruleID == "" {
				return fmt.Errorf("migration_summary.rule_reasons must not contain empty rule ids")
			}
		}
	}
	if t.ConfidenceCalibration == nil {
		return fmt.Errorf("confidence_calibration is required")
	}
	if t.ConfidenceCalibration.Version == "" {
		return fmt.Errorf("confidence_calibration.version is required")
	}
	if err := validateUnitInterval(t.ConfidenceCalibration.MachineTrustedThreshold, "confidence_calibration.machine_trusted_threshold"); err != nil {
		return err
	}
	if err := validateUnitInterval(t.ConfidenceCalibration.UnknownCap, "confidence_calibration.unknown_cap"); err != nil {
		return err
	}
	if err := validateUnitInterval(t.ConfidenceCalibration.AgentOnlyCap, "confidence_calibration.agent_only_cap"); err != nil {
		return err
	}
	if len(t.ConfidenceCalibration.RuleFamilyBaselines) == 0 {
		return fmt.Errorf("confidence_calibration.rule_family_baselines is required")
	}
	for family, baseline := range t.ConfidenceCalibration.RuleFamilyBaselines {
		if strings.TrimSpace(family) == "" {
			return fmt.Errorf("confidence_calibration.rule_family_baselines must not contain empty family keys")
		}
		if err := validateUnitInterval(baseline, fmt.Sprintf("confidence_calibration.rule_family_baselines[%q]", family)); err != nil {
			return err
		}
	}
	for _, family := range releaseBlockingRuleFamilies() {
		if _, ok := t.ConfidenceCalibration.RuleFamilyBaselines[family]; !ok {
			return fmt.Errorf("confidence_calibration.rule_family_baselines[%q] is required for release-blocking coverage", family)
		}
	}
	if len(t.ConfidenceCalibration.OrderingRules) == 0 {
		return fmt.Errorf("confidence_calibration.ordering_rules is required")
	}
	for i, sr := range t.SkippedRules {
		if sr.ID == "" || sr.Reason == "" {
			return fmt.Errorf("skipped_rules[%d]: id and reason are required", i)
		}
	}
	for i, run := range t.Analyzers {
		if run.Name == "" || run.Version == "" || run.Language == "" {
			return fmt.Errorf("analyzers[%d]: name, version, and language are required", i)
		}
		if !slices.Contains(validAnalyzerStatus, run.Status) {
			return fmt.Errorf("analyzers[%d]: invalid status %q", i, run.Status)
		}
	}
	validMigrationStates := []string{"legacy_only", "finding_bridged", "seed_native", "issue_native"}
	for i, run := range t.Rules {
		if run.ID == "" || run.Version == "" {
			return fmt.Errorf("rules[%d]: id and version are required", i)
		}
		if run.MigrationState != "" && !slices.Contains(validMigrationStates, run.MigrationState) {
			return fmt.Errorf("rules[%d]: invalid migration_state %q", i, run.MigrationState)
		}
	}
	for i, agent := range t.Agents {
		if agent.ID == "" || agent.TriggerReason == "" {
			return fmt.Errorf("agents[%d]: id and trigger_reason are required", i)
		}
		if !slices.Contains(validAgentKinds, agent.Kind) {
			return fmt.Errorf("agents[%d]: invalid kind %q", i, agent.Kind)
		}
		if agent.IssueType == "" {
			return fmt.Errorf("agents[%d]: issue_type is required", i)
		}
		if agent.Question == "" {
			return fmt.Errorf("agents[%d]: question is required", i)
		}
		if !slices.Contains(validAgentStatus, agent.Status) {
			return fmt.Errorf("agents[%d]: invalid status %q", i, agent.Status)
		}
		if agent.Status == "insufficient_context" && len(agent.UnresolvedReasons) == 0 {
			return fmt.Errorf("agents[%d]: insufficient_context requires unresolved_reasons", i)
		}
		if agent.MaxFiles < 0 || agent.MaxTokens < 0 {
			return fmt.Errorf("agents[%d]: max_files and max_tokens must be non-negative", i)
		}
	}
	validContextTriggerTypes := []string{"rule", "issue", "evidence"}
	for i, selection := range t.ContextSelections {
		if selection.ID == "" {
			return fmt.Errorf("context_selections[%d]: id is required", i)
		}
		if !slices.Contains(validContextTriggerTypes, selection.TriggerType) {
			return fmt.Errorf("context_selections[%d]: invalid trigger_type %q", i, selection.TriggerType)
		}
		if selection.TriggerID == "" {
			return fmt.Errorf("context_selections[%d]: trigger_id is required", i)
		}
		if selection.MaxFiles < 0 || selection.MaxSpans < 0 || selection.MaxTokens < 0 {
			return fmt.Errorf("context_selections[%d]: max_files, max_spans, and max_tokens must be non-negative", i)
		}
		for j, span := range selection.SelectedSpans {
			if span.RepoRelPath == "" {
				return fmt.Errorf("context_selections[%d].selected_spans[%d]: repo_rel_path is required", i, j)
			}
			if span.StartLine < 1 || span.EndLine < span.StartLine {
				return fmt.Errorf("context_selections[%d].selected_spans[%d]: invalid line range", i, j)
			}
		}
	}
	return nil
}

func validateCrossReferences(b Bundle) error {
	if b.Report.TraceID != b.Trace.TraceID {
		return fmt.Errorf("trace_id mismatch between report and trace")
	}
	repo, commit := b.Report.Repo, b.Report.Commit
	if b.Evidence.Repo != repo || b.Evidence.Commit != commit || b.Skills.Repo != repo || b.Skills.Commit != commit || b.Trace.Repo != repo || b.Trace.Commit != commit {
		return fmt.Errorf("repo or commit mismatch across artifacts")
	}

	evidenceIDs := make(map[string]struct{}, len(b.Evidence.Evidence))
	for _, ev := range b.Evidence.Evidence {
		evidenceIDs[ev.ID] = struct{}{}
	}
	issueIDs := make(map[string]struct{}, len(b.Report.Issues))
	issueFingerprints := make(map[string]string, len(b.Report.Issues))
	contextSelectionIDs := make(map[string]struct{}, len(b.Trace.ContextSelections))
	for _, issue := range b.Report.Issues {
		issueIDs[issue.ID] = struct{}{}
		issueFingerprints[issue.ID] = issue.Fingerprint
		for _, evID := range issue.EvidenceIDs {
			if _, ok := evidenceIDs[evID]; !ok {
				return fmt.Errorf("issue %q references unknown evidence id %q", issue.ID, evID)
			}
		}
		for _, evID := range issue.CounterEvidenceIDs {
			if _, ok := evidenceIDs[evID]; !ok {
				return fmt.Errorf("issue %q references unknown counter evidence id %q", issue.ID, evID)
			}
		}
	}
	for _, selection := range b.Trace.ContextSelections {
		contextSelectionIDs[selection.ID] = struct{}{}
		for _, evID := range selection.SelectedEvidenceIDs {
			if _, ok := evidenceIDs[evID]; !ok {
				return fmt.Errorf("context selection %q references unknown evidence id %q", selection.ID, evID)
			}
		}
	}
	for _, skill := range b.Skills.Skills {
		for _, issueID := range skill.ContributingIssueIDs {
			if _, ok := issueIDs[issueID]; !ok {
				return fmt.Errorf("skill %q references unknown issue id %q", skill.SkillID, issueID)
			}
		}
		for _, evID := range skill.ContributingEvidenceIDs {
			if _, ok := evidenceIDs[evID]; !ok {
				return fmt.Errorf("skill %q references unknown evidence id %q", skill.SkillID, evID)
			}
		}
	}
	for _, agent := range b.Trace.Agents {
		if agent.IssueID != "" {
			if _, ok := issueIDs[agent.IssueID]; !ok {
				return fmt.Errorf("agent %q references unknown issue id %q", agent.ID, agent.IssueID)
			}
		}
		if agent.ContextSelectionID != "" {
			if _, ok := contextSelectionIDs[agent.ContextSelectionID]; !ok {
				return fmt.Errorf("agent %q references unknown context selection id %q", agent.ID, agent.ContextSelectionID)
			}
		}
		for _, evID := range agent.InputEvidenceIDs {
			if _, ok := evidenceIDs[evID]; !ok {
				return fmt.Errorf("agent %q references unknown input evidence id %q", agent.ID, evID)
			}
		}
		for _, evID := range agent.OutputEvidenceIDs {
			if _, ok := evidenceIDs[evID]; !ok {
				return fmt.Errorf("agent %q references unknown output evidence id %q", agent.ID, evID)
			}
		}
	}
	for _, deriv := range b.Trace.Derivations {
		if _, ok := issueIDs[deriv.IssueID]; !ok {
			return fmt.Errorf("derivation references unknown issue id %q", deriv.IssueID)
		}
		if deriv.IssueFingerprint == "" {
			return fmt.Errorf("derivation for issue %q is missing issue_fingerprint", deriv.IssueID)
		}
		if expected := issueFingerprints[deriv.IssueID]; expected != deriv.IssueFingerprint {
			return fmt.Errorf("derivation fingerprint mismatch for issue %q: got %q want %q", deriv.IssueID, deriv.IssueFingerprint, expected)
		}
		for _, evID := range deriv.DerivedFromEvidenceIDs {
			if _, ok := evidenceIDs[evID]; !ok {
				return fmt.Errorf("derivation for issue %q references unknown evidence id %q", deriv.IssueID, evID)
			}
		}
	}
	if b.Claims != nil && b.Profile != nil && b.ResumeInput != nil {
		if err := validateClaimReferenceIntegrity(*b.Claims, *b.Profile, *b.ResumeInput); err != nil {
			return err
		}
		for _, claim := range b.Claims.Claims {
			for _, evID := range claim.SupportingEvidenceIDs {
				if _, ok := evidenceIDs[evID]; !ok {
					return fmt.Errorf("claim %q references unknown supporting evidence id %q", claim.ClaimID, evID)
				}
			}
			for _, evID := range claim.ContradictoryEvidenceIDs {
				if _, ok := evidenceIDs[evID]; !ok {
					return fmt.Errorf("claim %q references unknown contradictory evidence id %q", claim.ClaimID, evID)
				}
			}
		}
	}
	return nil
}

func validateUnitInterval(v float64, field string) error {
	if v < 0 || v > 1 {
		return fmt.Errorf("%s must be within [0,1], got %v", field, v)
	}
	return nil
}

func validateConfidenceBreakdown(cb ConfidenceBreakdown, prefix string) error {
	values := map[string]float64{
		"rule_reliability":      cb.RuleReliability,
		"evidence_quality":      cb.EvidenceQuality,
		"boundary_completeness": cb.BoundaryCompleteness,
		"context_completeness":  cb.ContextCompleteness,
		"source_agreement":      cb.SourceAgreement,
		"contradiction_penalty": cb.ContradictionPenalty,
		"llm_penalty":           cb.LLMPenalty,
		"final":                 cb.Final,
	}
	for name, val := range values {
		if err := validateUnitInterval(val, prefix+"."+name); err != nil {
			return err
		}
	}
	return nil
}
