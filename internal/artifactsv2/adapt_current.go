package artifactsv2

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/verabase/code-verification-engine/internal/report"
	"github.com/verabase/code-verification-engine/internal/rules"
	"github.com/verabase/code-verification-engine/internal/skills"
)

func buildEvidenceArtifact(scan report.ScanReport, verification VerificationSource, engineVersion string) (EvidenceArtifact, map[string]EvidenceRecord) {
	records := make(map[string]EvidenceRecord)
	for _, finding := range verification.Findings {
		for _, ev := range finding.Evidence {
			id := ev.ID
			if id == "" {
				id = compatEvidenceID(finding.RuleID, ev)
			}
			record := EvidenceRecord{
				ID:              id,
				Kind:            compatEvidenceKind(finding),
				Source:          compatEvidenceSource(finding),
				ProducerID:      "rule:" + finding.RuleID,
				ProducerVersion: verification.ReportSchemaVersion,
				Repo:            scan.RepoName,
				Commit:          scan.CommitSHA,
				BoundaryHash:    compatBoundaryHash(scan),
				FactQuality:     compatFactQuality(finding),
				EntityIDs:       compactStrings([]string{ev.Symbol}),
				Locations: []LocationRef{{
					RepoRelPath: filepath.ToSlash(ev.File),
					StartLine:   max(1, ev.LineStart),
					EndLine:     max(ev.LineStart, ev.LineEnd),
					SymbolID:    ev.Symbol,
				}},
				Claims:      compactStrings([]string{finding.RuleID}),
				Payload:     map[string]any{"message": finding.Message, "status": string(finding.Status)},
				Supports:    []string{},
				Contradicts: []string{},
				DerivedFrom: compactStrings([]string{finding.RuleID}),
				CreatedAt:   scan.ScannedAt,
			}
			records[id] = record
		}
	}
	for _, seed := range verification.IssueSeeds {
		ensureIssueSeedEvidenceRecords(scan, verification, seed, records)
	}
	for _, result := range verification.AgentResults {
		for _, record := range result.EmittedEvidence {
			if record.ID == "" {
				continue
			}
			normalized := record
			if normalized.Repo == "" {
				normalized.Repo = scan.RepoName
			}
			if normalized.Commit == "" {
				normalized.Commit = scan.CommitSHA
			}
			if normalized.BoundaryHash == "" {
				normalized.BoundaryHash = compatBoundaryHash(scan)
			}
			if normalized.Source == "" {
				normalized.Source = "agent"
			}
			if normalized.CreatedAt == "" {
				normalized.CreatedAt = scan.ScannedAt
			}
			records[normalized.ID] = normalized
		}
	}
	ordered := make([]EvidenceRecord, 0, len(records))
	for _, record := range records {
		ordered = append(ordered, record)
	}
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].ID < ordered[j].ID })
	return EvidenceArtifact{
		SchemaVersion: EvidenceSchemaVersion,
		EngineVersion: engineVersion,
		Repo:          scan.RepoName,
		Commit:        scan.CommitSHA,
		Timestamp:     scan.ScannedAt,
		Evidence:      ordered,
	}, records
}

func buildReportSummary(issues []Issue, skillReport *skills.Report) ReportSummary {
	var counts IssueCountSummary
	var high, medium, low float64
	for _, issue := range issues {
		switch issue.Severity {
		case "critical":
			counts.Critical++
			high += 1.0
		case "high":
			counts.High++
			high += 0.8
		case "medium":
			counts.Medium++
			medium += 0.5
		default:
			counts.Low++
			low += 0.2
		}
	}
	score := 1.0
	if skillReport != nil && len(skillReport.Signals) > 0 {
		reportSkills := buildReportSkillScores(skillReport)
		var sum float64
		for _, s := range reportSkills {
			sum += s.Score
		}
		score = sum / float64(len(reportSkills))
	}
	penalty := min(0.9, high*0.12+medium*0.07+low*0.03)
	score = clamp(score-penalty, 0, 1)
	return ReportSummary{
		OverallScore: score,
		RiskLevel:    compatRiskLevel(counts),
		IssueCounts:  counts,
	}
}

func buildReportSkillScores(skillReport *skills.Report) []ReportSkillScore {
	if skillReport == nil {
		return nil
	}
	var out []ReportSkillScore
	for _, sig := range skillReport.Signals {
		if sig.Status == skills.StatusUnsupported {
			continue
		}
		out = append(out, ReportSkillScore{
			SkillID: sig.SkillID,
			Score:   compatSkillSignalScore(sig),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].SkillID < out[j].SkillID })
	return out
}

func buildSkillsArtifact(scan report.ScanReport, skillReport *skills.Report, engineVersion string, candidates []IssueCandidate) SkillsArtifact {
	artifact := SkillsArtifact{
		SchemaVersion: SkillsSchemaVersion,
		EngineVersion: engineVersion,
		Repo:          scan.RepoName,
		Commit:        scan.CommitSHA,
		Timestamp:     scan.ScannedAt,
	}
	if skillReport == nil {
		return artifact
	}
	ruleToIssueIDs := buildRuleToIssueIDs(candidates)
	issueToEvidenceIDs := buildIssueToEvidenceIDs(candidates)
	for _, sig := range skillReport.Signals {
		if sig.Status == skills.StatusUnsupported {
			continue
		}
		evIDs := make([]string, 0, len(sig.Evidence))
		for _, ev := range sig.Evidence {
			id := ev.ID
			if id == "" {
				id = compatEvidenceID(strings.Join(sig.SourceRuleIDs, "+"), ev)
			}
			evIDs = append(evIDs, id)
		}
		contributingIssueIDs := compactStrings(expandMappedRuleToIssueIDs(sig.SourceRuleIDs, ruleToIssueIDs))
		if len(evIDs) == 0 {
			evIDs = collectEvidenceIDsForIssues(contributingIssueIDs, issueToEvidenceIDs)
		} else {
			evIDs = dedupeStringsSorted(append(evIDs, collectEvidenceIDsForIssues(contributingIssueIDs, issueToEvidenceIDs)...))
		}
		if len(contributingIssueIDs) == 0 || len(evIDs) == 0 {
			// V2 skills.json is evidence-derived. Legacy skill signals that cannot
			// be traced back into issue/evidence contributors must remain in the
			// legacy skill report only, not the verifiable skills artifact.
			continue
		}
		artifact.Skills = append(artifact.Skills, SkillScore{
			SkillID:                 sig.SkillID,
			Score:                   compatSkillSignalScore(sig),
			Confidence:              compatSkillConfidence(sig.Confidence),
			ContributingIssueIDs:    contributingIssueIDs,
			ContributingEvidenceIDs: dedupeStringsSorted(evIDs),
			FormulaInputs: &SkillFormulaInputs{
				Positive: []WeightedContribution{{
					IssueID: firstOrEmpty(contributingIssueIDs),
					Weight:  compatSkillWeight(sig.EvidenceStrength),
					Value:   compatSkillSignalScore(sig),
				}},
			},
		})
	}
	sort.Slice(artifact.Skills, func(i, j int) bool { return artifact.Skills[i].SkillID < artifact.Skills[j].SkillID })
	return artifact
}

func buildIssueToEvidenceIDs(candidates []IssueCandidate) map[string][]string {
	out := make(map[string][]string, len(candidates))
	for _, candidate := range candidates {
		out[candidate.ID] = dedupeStringsSorted(append([]string(nil), candidate.EvidenceIDs...))
	}
	return out
}

func collectEvidenceIDsForIssues(issueIDs []string, issueToEvidenceIDs map[string][]string) []string {
	var out []string
	for _, issueID := range issueIDs {
		out = append(out, issueToEvidenceIDs[issueID]...)
	}
	return dedupeStringsSorted(out)
}

func buildTraceArtifact(scan report.ScanReport, verification VerificationSource, evidence EvidenceArtifact, traceID, engineVersion string, candidates []IssueCandidate) TraceArtifact {
	trace := TraceArtifact{
		SchemaVersion: TraceSchemaVersion,
		EngineVersion: engineVersion,
		TraceID:       traceID,
		Repo:          scan.RepoName,
		Commit:        scan.CommitSHA,
		Timestamp:     scan.ScannedAt,
		Partial:       verification.Partial,
		Degraded:      verification.Degraded,
		Errors:        append([]string(nil), verification.Errors...),
		ScanBoundary: TraceScanBoundary{
			Mode:          scan.BoundaryMode,
			IncludedFiles: scan.FileCount,
			ExcludedFiles: 0,
		},
		ConfidenceCalibration: currentConfidenceCalibration(),
	}
	if trace.ScanBoundary.Mode == "" {
		trace.ScanBoundary.Mode = "repo"
	}
	trace.MigrationSummary = buildRuleMigrationSummary(verification)
	ruleToIssueIDs := buildRuleToIssueIDs(candidates)
	issueFingerprints := make(map[string]string, len(candidates))
	for _, candidate := range candidates {
		issueFingerprints[candidate.ID] = candidate.Fingerprint
	}
	derivationIndex := make(map[string]IssueDerivation)
	appendDerivation := func(issueID, issueFingerprint string, evidenceIDs []string) {
		if issueID == "" {
			return
		}
		current := derivationIndex[issueID]
		current.IssueID = issueID
		if current.IssueFingerprint == "" {
			current.IssueFingerprint = issueFingerprint
		}
		if current.IssueFingerprint == "" || current.IssueFingerprint != issueFingerprint {
			current.IssueFingerprint = chooseStableFingerprint(current.IssueFingerprint, issueFingerprint)
		}
		current.DerivedFromEvidenceIDs = dedupeStringsSorted(append(current.DerivedFromEvidenceIDs, evidenceIDs...))
		derivationIndex[issueID] = current
	}
	analyzerStatuses := scan.Analyzers
	if len(verification.AnalyzerStatuses) > 0 {
		analyzerStatuses = verification.AnalyzerStatuses
	}
	for name, status := range analyzerStatuses {
		trace.Analyzers = append(trace.Analyzers, AnalyzerRun{
			Name:     name,
			Version:  "1.0.0",
			Language: name,
			Status:   status,
			Degraded: status == "partial",
		})
	}
	sort.Slice(trace.Analyzers, func(i, j int) bool { return trace.Analyzers[i].Name < trace.Analyzers[j].Name })
	for _, sr := range verification.SkippedRules {
		trace.SkippedRules = append(trace.SkippedRules, SkippedRuleTrace{
			ID:     sr.RuleID,
			Reason: sr.Reason,
		})
	}
	sort.Slice(trace.SkippedRules, func(i, j int) bool { return trace.SkippedRules[i].ID < trace.SkippedRules[j].ID })
	for _, finding := range verification.Findings {
		evIDs := make([]string, 0, len(finding.Evidence))
		for _, ev := range finding.Evidence {
			id := ev.ID
			if id == "" {
				id = compatEvidenceID(finding.RuleID, ev)
			}
			evIDs = append(evIDs, id)
		}
		triggeredIssueIDs := compactStrings(expandRuleToIssueIDs([]string{finding.RuleID}, ruleToIssueIDs))
		md := verification.RuleMetadata[finding.RuleID]
		migrationState := firstNonEmptyMigrationState(md.MigrationState, string(rules.MigrationFindingBridged))
		trace.Rules = append(trace.Rules, RuleRun{
			ID:                 finding.RuleID,
			Version:            verification.ReportSchemaVersion,
			MigrationState:     migrationState,
			MigrationReason:    md.MigrationReason,
			TriggeredIssueIDs:  triggeredIssueIDs,
			EmittedEvidenceIDs: dedupeStringsSorted(evIDs),
		})
		if finding.Status != rules.StatusPass {
			for _, issueID := range triggeredIssueIDs {
				appendDerivation(issueID, issueFingerprints[issueID], evIDs)
			}
		}
	}
	if len(trace.Rules) == 0 && len(verification.IssueSeeds) > 0 {
		for _, seed := range verification.IssueSeeds {
			triggeredIssueIDs := compactStrings(expandRuleToIssueIDs([]string{seed.RuleID}, ruleToIssueIDs))
			md := verification.RuleMetadata[seed.RuleID]
			migrationState := firstNonEmptyMigrationState(md.MigrationState, string(rules.MigrationSeedNative))
			trace.Rules = append(trace.Rules, RuleRun{
				ID:                 seed.RuleID,
				Version:            verification.ReportSchemaVersion,
				MigrationState:     migrationState,
				MigrationReason:    md.MigrationReason,
				TriggeredIssueIDs:  triggeredIssueIDs,
				EmittedEvidenceIDs: dedupeStringsSorted(seed.EvidenceIDs),
			})
			if seed.Status != "resolved" {
				for _, issueID := range triggeredIssueIDs {
					appendDerivation(issueID, issueFingerprints[issueID], seed.EvidenceIDs)
				}
			}
		}
	}
	sort.Slice(trace.Rules, func(i, j int) bool { return trace.Rules[i].ID < trace.Rules[j].ID })
	trace.ContextSelections = buildContextSelections(candidates, evidence)
	trace.Agents = buildAgentRuns(candidates, trace.ContextSelections, verification.AgentResults)
	for _, candidate := range candidates {
		appendDerivation(candidate.ID, candidate.Fingerprint, candidate.EvidenceIDs)
	}
	if len(derivationIndex) > 0 {
		trace.Derivations = make([]IssueDerivation, 0, len(derivationIndex))
		for _, derivation := range derivationIndex {
			trace.Derivations = append(trace.Derivations, derivation)
		}
		sort.Slice(trace.Derivations, func(i, j int) bool {
			if trace.Derivations[i].IssueID != trace.Derivations[j].IssueID {
				return trace.Derivations[i].IssueID < trace.Derivations[j].IssueID
			}
			if trace.Derivations[i].IssueFingerprint != trace.Derivations[j].IssueFingerprint {
				return trace.Derivations[i].IssueFingerprint < trace.Derivations[j].IssueFingerprint
			}
			return strings.Join(trace.Derivations[i].DerivedFromEvidenceIDs, ",") < strings.Join(trace.Derivations[j].DerivedFromEvidenceIDs, ",")
		})
	}
	return trace
}

func chooseStableFingerprint(a, b string) string {
	switch {
	case a == "":
		return b
	case b == "":
		return a
	case a < b:
		return a
	default:
		return b
	}
}

func buildRuleMigrationSummary(verification VerificationSource) *RuleMigrationSummary {
	ruleStates := make(map[string]string)
	ruleClaimFamilies := make(map[string][]string)
	for ruleID, metadata := range verification.RuleMetadata {
		state := strings.TrimSpace(metadata.MigrationState)
		if state != "" {
			ruleStates[ruleID] = state
		}
		if families := migratedClaimFamiliesForRule(ruleID); len(families) > 0 {
			ruleClaimFamilies[ruleID] = families
		}
	}
	for _, finding := range verification.Findings {
		if _, ok := ruleStates[finding.RuleID]; !ok {
			ruleStates[finding.RuleID] = string(rules.MigrationFindingBridged)
		}
		if families := migratedClaimFamiliesForRule(finding.RuleID); len(families) > 0 {
			ruleClaimFamilies[finding.RuleID] = families
		}
	}
	for _, seed := range verification.IssueSeeds {
		if _, ok := ruleStates[seed.RuleID]; !ok {
			ruleStates[seed.RuleID] = string(rules.MigrationSeedNative)
		}
		if families := migratedClaimFamiliesForRule(seed.RuleID); len(families) > 0 {
			ruleClaimFamilies[seed.RuleID] = families
		}
	}
	if len(ruleStates) == 0 {
		return nil
	}

	summary := &RuleMigrationSummary{
		RuleStates:        make(map[string]string, len(ruleStates)),
		RuleReasons:       make(map[string]string, len(ruleStates)),
		RuleClaimFamilies: make(map[string][]string, len(ruleClaimFamilies)),
	}
	for ruleID, state := range ruleStates {
		summary.RuleStates[ruleID] = state
		if reason := strings.TrimSpace(verification.RuleMetadata[ruleID].MigrationReason); reason != "" {
			summary.RuleReasons[ruleID] = reason
		}
		if families := ruleClaimFamilies[ruleID]; len(families) > 0 {
			summary.RuleClaimFamilies[ruleID] = append([]string(nil), families...)
		}
		switch state {
		case string(rules.MigrationLegacyOnly):
			summary.LegacyOnlyCount++
		case string(rules.MigrationFindingBridged):
			summary.FindingBridgedCount++
		case string(rules.MigrationSeedNative):
			summary.SeedNativeCount++
		case string(rules.MigrationIssueNative):
			summary.IssueNativeCount++
		}
	}
	return summary
}

func migratedClaimFamiliesForRule(ruleID string) []string {
	switch strings.TrimSpace(ruleID) {
	case "SEC-001", "SEC-SECRET-001":
		return []string{"security.hardcoded_secret_present", "security.hardcoded_secret_absent"}
	case "AUTH-002", "SEC-AUTH-002":
		return []string{"security.route_auth_binding"}
	case "TEST-001", "TEST-AUTH-001":
		return []string{"testing.auth_module_tests_present"}
	case "ARCH-001", "ARCH-LAYER-001":
		return []string{"architecture.controller_direct_db_access_present", "architecture.controller_direct_db_access_absent"}
	case "SEC-SECRET-002":
		return []string{"config.env_read_call_exists", "config.secret_key_sourced_from_env", "config.secret_key_not_literal"}
	default:
		return nil
	}
}

func buildSummaryMarkdown(r ReportArtifact) string {
	var b strings.Builder
	b.WriteString("# Verabase Report\n\n")
	b.WriteString(fmt.Sprintf("## Overall Score\n%.2f\n\n", r.Summary.OverallScore))
	b.WriteString("## Top Risks\n")
	if len(r.Issues) == 0 {
		b.WriteString("- No non-pass issues detected\n")
	} else {
		for _, issue := range r.Issues {
			b.WriteString(fmt.Sprintf("- %s: %s\n", strings.Title(issue.Severity), issue.Title))
			b.WriteString(fmt.Sprintf("  Evidence: %s\n", strings.Join(issue.EvidenceIDs, ", ")))
		}
	}
	b.WriteString("\n## Trace\n")
	b.WriteString(fmt.Sprintf("- Commit: `%s`\n", r.Commit))
	b.WriteString(fmt.Sprintf("- Trace ID: `%s`\n", r.TraceID))
	return b.String()
}

func compatEvidenceID(ruleID string, ev rules.Evidence) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s:%s:%d:%d:%s", ruleID, ev.File, ev.LineStart, ev.LineEnd, ev.Symbol)))
	return "ev-" + hex.EncodeToString(sum[:8])
}

func compatSyntheticIssueEvidenceID(f rules.Finding) string {
	sum := sha256.Sum256([]byte("synthetic:" + f.RuleID + ":" + string(f.Status) + ":" + f.Message))
	return "ev-" + hex.EncodeToString(sum[:8])
}

func compatBoundaryHash(scan report.ScanReport) string {
	sum := sha256.Sum256([]byte(scan.RepoPath + ":" + scan.CommitSHA + ":" + scan.ScanSubdir + ":" + scan.BoundaryMode))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func compatEvidenceKind(f rules.Finding) string {
	switch f.VerdictBasis {
	case "proof":
		return "rule_assertion"
	case "structural_binding":
		return "structural_fact"
	default:
		return "heuristic_fact"
	}
}

func compatEvidenceSource(f rules.Finding) string {
	if f.TrustClass == rules.TrustHumanOrRuntimeRequired {
		return "agent"
	}
	return "rule"
}

func compatFactQuality(f rules.Finding) string {
	switch f.FactQualityFloor {
	case "proof":
		return "proof"
	case "structural":
		return "structural"
	default:
		return "heuristic"
	}
}

func compatIssueCategory(f rules.Finding) string {
	if strings.HasPrefix(strings.ToLower(f.RuleID), "sec-") {
		return "security"
	}
	if strings.Contains(strings.ToLower(f.RuleID), "arch") || strings.Contains(strings.ToLower(f.RuleID), "pattern") {
		return "design"
	}
	return "bug"
}

func compatSeverity(f rules.Finding) string {
	switch f.TrustClass {
	case rules.TrustMachineTrusted:
		if f.Status == rules.StatusFail {
			return "high"
		}
		return "medium"
	case rules.TrustAdvisory:
		return "medium"
	default:
		return "low"
	}
}

func compatIssueStatus(s rules.Status) string {
	switch s {
	case rules.StatusFail:
		return "open"
	case rules.StatusUnknown:
		return "unknown"
	default:
		return "resolved"
	}
}

func compatConfidenceValue(c rules.Confidence) float64 {
	switch c {
	case rules.ConfidenceHigh:
		return 0.9
	case rules.ConfidenceMedium:
		return 0.7
	default:
		return 0.45
	}
}

func compatQualityValue(q string) float64 {
	switch q {
	case "proof":
		return 1.0
	case "structural":
		return 0.7
	default:
		return 0.4
	}
}

func compatRiskLevel(c IssueCountSummary) string {
	switch {
	case c.Critical > 0:
		return "critical"
	case c.High > 0:
		return "high"
	case c.Medium > 0:
		return "medium"
	default:
		return "low"
	}
}

func compatSkillSignalScore(sig skills.Signal) float64 {
	base := compatSkillConfidence(sig.Confidence)
	if sig.Status == skills.StatusObserved {
		return clamp(base, 0, 1)
	}
	return clamp(base-0.15, 0, 1)
}

func compatSkillConfidence(c skills.SignalConfidence) float64 {
	switch c {
	case skills.ConfidenceHigh:
		return 0.9
	case skills.ConfidenceMedium:
		return 0.7
	default:
		return 0.45
	}
}

func compatSkillWeight(es skills.EvidenceStrength) float64 {
	switch es {
	case skills.EvidenceDirect:
		return 1.0
	case skills.EvidenceStructural:
		return 0.7
	default:
		return 0.4
	}
}

func buildTraceID(commit string) string {
	if len(commit) > 12 {
		commit = commit[:12]
	}
	if commit == "" {
		commit = "unknown"
	}
	return "trace-" + commit
}

func compactStrings(in []string) []string {
	var out []string
	for _, s := range in {
		if strings.TrimSpace(s) != "" {
			out = append(out, s)
		}
	}
	return dedupeStringsSorted(out)
}

func dedupeStringsSorted(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	var out []string
	for _, s := range in {
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

func firstOrEmpty(ss []string) string {
	if len(ss) == 0 {
		return ""
	}
	return ss[0]
}

func firstNonEmptyMigrationState(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func clamp(v, low, high float64) float64 {
	if v < low {
		return low
	}
	if v > high {
		return high
	}
	return v
}

func min(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
