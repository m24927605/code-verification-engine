package artifactsv2

import (
	"strings"

	"github.com/verabase/code-verification-engine/internal/rules"
)

// VerificationSource is the internal deterministic verification source contract
// for the v2 artifact builder. It is intentionally closer to engine execution
// outputs than to legacy report projection.
type VerificationSource struct {
	ReportSchemaVersion string
	Findings            []rules.Finding
	IssueSeeds          []IssueSeed
	AgentResults        []AgentResult
	RuleMetadata        map[string]RuleMetadata
	SkippedRules        []rules.SkippedRule
	Partial             bool
	Degraded            bool
	AnalyzerStatuses    map[string]string
	Errors              []string
}

// Clone returns a defensive copy suitable for storing on engine results.
func (s VerificationSource) Clone() VerificationSource {
	out := VerificationSource{
		ReportSchemaVersion: s.ReportSchemaVersion,
		Findings:            append([]rules.Finding(nil), s.Findings...),
		IssueSeeds:          append([]IssueSeed(nil), s.IssueSeeds...),
		SkippedRules:        append([]rules.SkippedRule(nil), s.SkippedRules...),
		Partial:             s.Partial,
		Degraded:            s.Degraded,
		Errors:              append([]string(nil), s.Errors...),
	}
	if s.AnalyzerStatuses != nil {
		out.AnalyzerStatuses = make(map[string]string, len(s.AnalyzerStatuses))
		for k, v := range s.AnalyzerStatuses {
			out.AnalyzerStatuses[k] = v
		}
	}
	if s.RuleMetadata != nil {
		out.RuleMetadata = make(map[string]RuleMetadata, len(s.RuleMetadata))
		for k, v := range s.RuleMetadata {
			out.RuleMetadata[k] = v
		}
	}
	if len(s.AgentResults) > 0 {
		out.AgentResults = make([]AgentResult, 0, len(s.AgentResults))
		for _, result := range s.AgentResults {
			cloned := AgentResult{
				TaskID:             result.TaskID,
				Kind:               result.Kind,
				IssueID:            result.IssueID,
				ContextSelectionID: result.ContextSelectionID,
				Status:             result.Status,
				UnresolvedReasons:  append([]string(nil), result.UnresolvedReasons...),
			}
			if len(result.EmittedEvidence) > 0 {
				cloned.EmittedEvidence = make([]EvidenceRecord, 0, len(result.EmittedEvidence))
				for _, record := range result.EmittedEvidence {
					copyRecord := record
					copyRecord.EntityIDs = append([]string(nil), record.EntityIDs...)
					copyRecord.Locations = append([]LocationRef(nil), record.Locations...)
					copyRecord.Claims = append([]string(nil), record.Claims...)
					copyRecord.Supports = append([]string(nil), record.Supports...)
					copyRecord.Contradicts = append([]string(nil), record.Contradicts...)
					copyRecord.DerivedFrom = append([]string(nil), record.DerivedFrom...)
					if record.Payload != nil {
						copyRecord.Payload = make(map[string]any, len(record.Payload))
						for k, v := range record.Payload {
							copyRecord.Payload[k] = v
						}
					}
					cloned.EmittedEvidence = append(cloned.EmittedEvidence, copyRecord)
				}
			}
			out.AgentResults = append(out.AgentResults, cloned)
		}
	}
	return out
}

// AgentResult is the deterministic normalized agent execution output contract
// accepted by the v2 artifact builder. It allows future agent runtimes to feed
// evidence into the same evidence-first pipeline without bypassing validation.
type AgentResult struct {
	TaskID             string
	Kind               string
	IssueID            string
	ContextSelectionID string
	Status             string
	EmittedEvidence    []EvidenceRecord
	UnresolvedReasons  []string
}

// AgentTask is the bounded execution contract for non-deterministic agent work.
// It is constructed deterministically from issue candidates and selected context.
type AgentTask struct {
	ID          string
	Kind        string
	IssueID     string
	IssueType   string
	Question    string
	Context     ContextBundle
	Constraints AgentConstraints
}

// AgentConstraints are the hard limits that apply to an executed agent task.
type AgentConstraints struct {
	MaxFiles         int
	MaxTokens        int
	AllowSpeculation bool
}

// AgentExecutor executes a bounded agent task and returns a normalized result.
type AgentExecutor func(task AgentTask) (AgentResult, error)

// RuleMetadata is the normalized rule-definition subset needed by the v2
// verification path to form issue seeds without heuristic backfilling.
type RuleMetadata struct {
	RuleID          string
	Title           string
	Category        string
	Severity        string
	MatcherClass    string
	TrustClass      string
	MigrationState  string
	MigrationReason string
}

// RuleMetadataFromRuleFile extracts deterministic rule metadata from a rule file.
func RuleMetadataFromRuleFile(rf *rules.RuleFile) map[string]RuleMetadata {
	if rf == nil {
		return nil
	}
	ruleIndex := rules.RuleIndexFromFile(rf)
	out := make(map[string]RuleMetadata, len(ruleIndex))
	for _, rule := range ruleIndex {
		audit := rules.RuleMigrationAuditForRule(rule)
		out[rule.ID] = RuleMetadata{
			RuleID:          rule.ID,
			Title:           rules.CanonicalIssueTitle(rule, rule.Message),
			Category:        rules.CanonicalIssueCategory(rule, rule.ID),
			Severity:        rules.CanonicalIssueSeverity(rule, rules.ClassifyTrustClass(rule.ID), rules.StatusFail),
			MatcherClass:    string(rule.MatcherClass),
			TrustClass:      string(rules.ClassifyTrustClass(rule.ID)),
			MigrationState:  string(audit.State),
			MigrationReason: audit.Reason,
		}
	}
	return out
}

// IssueSeedsFromFindings normalizes legacy deterministic findings into
// aggregation-ready issue seeds. This is the migration bridge between the
// finding-first execution path and the native issue-candidate pipeline.
func IssueSeedsFromFindings(findings []rules.Finding) []IssueSeed {
	return IssueSeedsFromFindingsWithMetadata(findings, nil)
}

// IssueSeedsFromRuleSeeds bridges native rules-layer seeds into the v2 artifact
// source contract without re-deriving them from findings.
func IssueSeedsFromRuleSeeds(seeds []rules.IssueSeed) []IssueSeed {
	out := make([]IssueSeed, 0, len(seeds))
	for _, seed := range seeds {
		out = append(out, IssueSeed{
			RuleID:      seed.RuleID,
			Title:       seed.Title,
			Source:      seed.Source,
			Category:    seed.Category,
			Severity:    seed.Severity,
			Status:      seed.Status,
			Confidence:  seed.Confidence,
			Quality:     seed.Quality,
			File:        seed.File,
			Symbol:      seed.Symbol,
			StartLine:   seed.StartLine,
			EndLine:     seed.EndLine,
			EvidenceIDs: append([]string(nil), seed.EvidenceIDs...),
		})
	}
	return out
}

// IssueSeedsFromFindingsWithMetadata normalizes deterministic findings into
// aggregation-ready seeds using authoritative rule metadata when available.
func IssueSeedsFromFindingsWithMetadata(findings []rules.Finding, metadata map[string]RuleMetadata) []IssueSeed {
	seeds := make([]IssueSeed, 0, len(findings))
	for _, finding := range findings {
		if finding.Status == rules.StatusPass {
			continue
		}
		md, hasMetadata := metadata[finding.RuleID]
		file, symbol, startLine, endLine := compatPrimaryLocation(finding)
		evIDs := make([]string, 0, len(finding.Evidence))
		for _, ev := range finding.Evidence {
			id := ev.ID
			if id == "" {
				id = compatEvidenceID(finding.RuleID, ev)
			}
			evIDs = append(evIDs, id)
		}
		seeds = append(seeds, IssueSeed{
			RuleID:      finding.RuleID,
			Title:       ruleSeedTitle(finding, md, hasMetadata),
			Source:      compatEvidenceSource(finding),
			Category:    ruleSeedCategory(finding, md, hasMetadata),
			Severity:    ruleSeedSeverity(finding, md, hasMetadata),
			Status:      compatIssueStatus(finding.Status),
			Confidence:  compatConfidenceValue(finding.Confidence),
			Quality:     compatQualityValue(compatFactQuality(finding)),
			File:        file,
			Symbol:      symbol,
			StartLine:   startLine,
			EndLine:     endLine,
			EvidenceIDs: dedupeStringsSorted(evIDs),
		})
	}
	return seeds
}

func ruleSeedTitle(finding rules.Finding, md RuleMetadata, hasMetadata bool) string {
	if hasMetadata && strings.TrimSpace(md.Title) != "" {
		return md.Title
	}
	return rules.CanonicalIssueTitle(rules.Rule{}, finding.Message)
}

func ruleSeedCategory(finding rules.Finding, md RuleMetadata, hasMetadata bool) string {
	if hasMetadata && strings.TrimSpace(md.Category) != "" {
		return rules.CanonicalIssueCategory(rules.Rule{Category: md.Category}, finding.RuleID)
	}
	return rules.CanonicalIssueCategory(rules.Rule{}, finding.RuleID)
}

func ruleSeedSeverity(finding rules.Finding, md RuleMetadata, hasMetadata bool) string {
	if hasMetadata && strings.TrimSpace(md.Severity) != "" {
		return rules.CanonicalIssueSeverity(rules.Rule{Severity: md.Severity}, finding.TrustClass, finding.Status)
	}
	return rules.CanonicalIssueSeverity(rules.Rule{}, finding.TrustClass, finding.Status)
}

// IssueSeed is the normalized aggregation input derived from deterministic
// verification outputs. It isolates clustering from the legacy rules.Finding shape.
type IssueSeed struct {
	RuleID      string
	Title       string
	Source      string
	Category    string
	Severity    string
	Status      string
	Confidence  float64
	Quality     float64
	File        string
	Symbol      string
	StartLine   int
	EndLine     int
	EvidenceIDs []string
}
