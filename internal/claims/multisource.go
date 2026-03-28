package claims

import (
	"fmt"
	"sort"
	"strings"

	"github.com/verabase/code-verification-engine/internal/rules"
)

const claimGraphSchemaVersion = "1.0.0"

// BuildMultiSourceClaimGraph extracts claim candidates from the provided
// source evidence, verifies them conservatively, and returns a traceable graph.
func BuildMultiSourceClaimGraph(claimSet *ClaimSet, evidence []SourceEvidenceRecord) *ClaimGraph {
	candidates := ExtractClaimCandidates(claimSet, evidence)
	verified := VerifyClaimCandidates(candidates, evidence)
	return &ClaimGraph{
		SchemaVersion: claimGraphSchemaVersion,
		Claims:        verified,
		Evidence:      cloneSourceEvidenceRecords(evidence),
		Edges:         buildClaimGraphEdges(verified, evidence),
	}
}

// ExtractClaimCandidates deterministically merges claim targets and source
// evidence into candidate claim records without over-claiming strength.
func ExtractClaimCandidates(claimSet *ClaimSet, evidence []SourceEvidenceRecord) []ClaimCandidate {
	definitions := claimDefinitionIndex(claimSet)
	candidates := make(map[string]*ClaimCandidate, len(definitions))

	for _, ev := range evidence {
		sourceType := normalizeSourceType(ev.SourceType)
		origin := inferClaimOrigin(sourceType)
		candidateClaimIDs := normalizeAndFilterClaimIDs(compactStrings(ev.ClaimIDs), sourceType)
		if len(candidateClaimIDs) == 0 {
			candidateClaimIDs = inferClaimIDsFromSourceEvidence(ev)
		}
		for _, rawClaimID := range candidateClaimIDs {
			def, ok := definitions[normalizeClaimKey(rawClaimID)]
			key := normalizeClaimKey(rawClaimID)
			if ok {
				key = normalizeClaimKey(def.ID)
			}
			candidate := candidates[key]
			if candidate == nil {
				if ok {
					candidate = &ClaimCandidate{
						ClaimID:   def.ID,
						Title:     def.Title,
						Category:  normalizeClaimCategory(def.Category),
						ClaimType: inferClaimTypeFromDefinition(def),
						Origin:    string(ClaimOriginRuleInferred),
						Scope:     def.Scope,
					}
				} else {
					candidate = &ClaimCandidate{
						ClaimID:   canonicalClaimID(rawClaimID),
						Title:     humanizeClaimID(rawClaimID),
						Category:  inferClaimCategory(rawClaimID, sourceType),
						ClaimType: inferClaimTypeFromSource(sourceType, rawClaimID),
						Origin:    origin,
					}
				}
				candidates[key] = candidate
			}

			candidate.CandidateEvidenceIDs = append(candidate.CandidateEvidenceIDs, ev.EvidenceID)
			candidate.SourceTypes = append(candidate.SourceTypes, sourceType)
			candidate.Description = firstNonEmpty(candidate.Description, ev.Summary)
			if candidate.Origin == string(ClaimOriginRuleInferred) {
				candidate.Origin = chooseStrongerOrigin(candidate.Origin, origin)
			} else {
				candidate.Origin = chooseStrongerOrigin(candidate.Origin, origin)
			}
			if candidate.Title == "" {
				if ok {
					candidate.Title = def.Title
				} else {
					candidate.Title = humanizeClaimID(rawClaimID)
				}
			}
			if candidate.Category == "" {
				if ok {
					candidate.Category = normalizeClaimCategory(def.Category)
				} else {
					candidate.Category = inferClaimCategory(rawClaimID, sourceType)
				}
			}
		}
	}

	out := make([]ClaimCandidate, 0, len(candidates))
	for _, candidate := range candidates {
		candidate.CandidateEvidenceIDs = dedupeStringsSorted(candidate.CandidateEvidenceIDs)
		candidate.SourceTypes = dedupeStringsSorted(candidate.SourceTypes)
		candidate.Reason = candidateReason(candidate, evidence)
		out = append(out, *candidate)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ClaimID != out[j].ClaimID {
			return out[i].ClaimID < out[j].ClaimID
		}
		if out[i].Origin != out[j].Origin {
			return out[i].Origin < out[j].Origin
		}
		return out[i].Title < out[j].Title
	})
	return out
}

// VerifyClaimCandidates conservatively verifies claim candidates against source
// evidence and returns a stable, traceable list of verified claims.
func VerifyClaimCandidates(candidates []ClaimCandidate, evidence []SourceEvidenceRecord) []VerifiedClaim {
	byID := make(map[string]SourceEvidenceRecord, len(evidence))
	for _, ev := range evidence {
		byID[ev.EvidenceID] = ev
	}

	out := make([]VerifiedClaim, 0, len(candidates))
	for _, candidate := range candidates {
		verified := verifyClaimCandidate(candidate, byID, evidence)
		out = append(out, verified)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ClaimID != out[j].ClaimID {
			return out[i].ClaimID < out[j].ClaimID
		}
		if out[i].Status != out[j].Status {
			return out[i].Status < out[j].Status
		}
		return out[i].SupportLevel < out[j].SupportLevel
	})
	return out
}

func verifyClaimCandidate(candidate ClaimCandidate, byID map[string]SourceEvidenceRecord, evidence []SourceEvidenceRecord) VerifiedClaim {
	supportingEvidenceIDs, contradictoryEvidenceIDs, sourceOrigins, supportSourceTypes, contradictorySourceTypes := collectClaimEvidence(candidate.ClaimID, byID, evidence)

	supportLevel, status, reason, confidence := assessClaimSupport(candidate, supportSourceTypes, contradictorySourceTypes, supportingEvidenceIDs, contradictoryEvidenceIDs)

	return VerifiedClaim{
		ClaimID:                  candidate.ClaimID,
		Title:                    candidate.Title,
		Category:                 candidate.Category,
		ClaimType:                candidate.ClaimType,
		Status:                   status,
		SupportLevel:             supportLevel,
		Confidence:               confidence,
		SupportingEvidenceIDs:    dedupeStringsSorted(supportingEvidenceIDs),
		ContradictoryEvidenceIDs: dedupeStringsSorted(contradictoryEvidenceIDs),
		SourceOrigins:            dedupeStringsSorted(sourceOrigins),
		Reason:                   reason,
	}
}

func collectClaimEvidence(claimID string, byID map[string]SourceEvidenceRecord, evidence []SourceEvidenceRecord) ([]string, []string, []string, []string, []string) {
	var supportingEvidenceIDs []string
	var contradictoryEvidenceIDs []string
	var sourceOrigins []string
	var supportSourceTypes []string
	var contradictorySourceTypes []string

	for _, ev := range evidence {
		if !sourceEvidenceMatchesClaim(ev, claimID) {
			continue
		}

		sourceOrigins = append(sourceOrigins, ev.Origin)
		if isClaimContradiction(ev, claimID) {
			contradictoryEvidenceIDs = append(contradictoryEvidenceIDs, ev.EvidenceID)
			contradictorySourceTypes = append(contradictorySourceTypes, normalizeSourceType(ev.SourceType))
			continue
		}

		supportingEvidenceIDs = append(supportingEvidenceIDs, ev.EvidenceID)
		supportSourceTypes = append(supportSourceTypes, normalizeSourceType(ev.SourceType))
	}

	for _, ev := range evidence {
		if _, ok := byID[ev.EvidenceID]; !ok {
			continue
		}
		for _, target := range compactStrings(ev.Supports) {
			if normalizeClaimKey(target) == normalizeClaimKey(claimID) {
				supportingEvidenceIDs = append(supportingEvidenceIDs, ev.EvidenceID)
				supportSourceTypes = append(supportSourceTypes, normalizeSourceType(ev.SourceType))
				sourceOrigins = append(sourceOrigins, ev.Origin)
			}
		}
		for _, target := range compactStrings(ev.Contradicts) {
			if normalizeClaimKey(target) == normalizeClaimKey(claimID) {
				contradictoryEvidenceIDs = append(contradictoryEvidenceIDs, ev.EvidenceID)
				contradictorySourceTypes = append(contradictorySourceTypes, normalizeSourceType(ev.SourceType))
				sourceOrigins = append(sourceOrigins, ev.Origin)
			}
		}
	}

	return supportingEvidenceIDs, contradictoryEvidenceIDs, compactStrings(sourceOrigins), compactStrings(supportSourceTypes), compactStrings(contradictorySourceTypes)
}

func assessClaimSupport(candidate ClaimCandidate, supportSourceTypes, contradictorySourceTypes, supportingEvidenceIDs, contradictoryEvidenceIDs []string) (string, string, string, float64) {
	supportStrength := maxSourceStrength(supportSourceTypes)
	contradictStrength := maxSourceStrength(contradictorySourceTypes)
	strongSupportCount := countStrongSourceTypes(supportSourceTypes)
	distinctSupportSources := dedupeStringsSorted(supportSourceTypes)

	switch {
	case len(supportingEvidenceIDs) == 0 && len(contradictoryEvidenceIDs) == 0:
		return string(ClaimSupportUnsupported), ClaimStatusUnknown, "no supporting or contradictory evidence", 0.15
	case contradictStrength >= supportStrength && len(contradictoryEvidenceIDs) > 0:
		return string(ClaimSupportContradicted), ClaimStatusRejected, "stronger evidence contradicts the claim", clamp(0.10+0.03*float64(len(distinctSupportSources)), 0, 1)
	case strongSupportCount == 0:
		return string(ClaimSupportWeak), ClaimStatusDowngraded, "documentation-only evidence is insufficient for a verified claim", clamp(0.35+0.03*float64(len(distinctSupportSources)), 0, 1)
	case strongSupportCount >= 2 && len(distinctSupportSources) >= 2 && len(contradictoryEvidenceIDs) == 0:
		return string(ClaimSupportVerified), ClaimStatusAccepted, "direct implementation evidence is reinforced by additional source evidence", clamp(0.92+0.02*float64(len(distinctSupportSources)-2), 0, 1)
	case strongSupportCount >= 1 && len(distinctSupportSources) >= 2 && len(contradictoryEvidenceIDs) == 0:
		return string(ClaimSupportStronglySupported), ClaimStatusAccepted, "strong code-backed evidence is reinforced by a second source", clamp(0.82+0.02*float64(len(distinctSupportSources)-2), 0, 1)
	default:
		if len(contradictoryEvidenceIDs) > 0 {
			return string(ClaimSupportContradicted), ClaimStatusRejected, "claim is contradicted by stronger evidence", clamp(0.20+0.02*float64(len(distinctSupportSources)), 0, 1)
		}
		reason := "strong code-backed evidence exists, but reinforcement is insufficient for a stronger projection"
		if candidate.Origin == string(ClaimOriginReadmeExtracted) || candidate.Origin == string(ClaimOriginDocExtracted) {
			reason = "documentation-derived claim lacks reinforcing implementation evidence"
		}
		return string(ClaimSupportSupported), ClaimStatusDowngraded, reason, clamp(0.66+0.02*float64(len(distinctSupportSources)), 0, 1)
	}
}

func buildClaimGraphEdges(verified []VerifiedClaim, evidence []SourceEvidenceRecord) []ClaimGraphEdge {
	var edges []ClaimGraphEdge
	for _, claim := range verified {
		for _, ev := range evidence {
			if !sourceEvidenceMatchesClaim(ev, claim.ClaimID) {
				continue
			}
			edgeType := edgeTypeForSource(ev.SourceType, claim.Status, claim.SupportLevel, ev, claim.ClaimID)
			if edgeType == "" {
				continue
			}
			edges = append(edges, ClaimGraphEdge{
				FromID:     claim.ClaimID,
				ToID:       ev.EvidenceID,
				Type:       edgeType,
				EvidenceID: ev.EvidenceID,
			})
		}
	}
	sort.Slice(edges, func(i, j int) bool {
		if edges[i].FromID != edges[j].FromID {
			return edges[i].FromID < edges[j].FromID
		}
		if edges[i].Type != edges[j].Type {
			return edges[i].Type < edges[j].Type
		}
		return edges[i].ToID < edges[j].ToID
	})
	return edges
}

func edgeTypeForSource(sourceType string, status string, supportLevel string, ev SourceEvidenceRecord, claimID string) string {
	if isClaimContradiction(ev, claimID) {
		return "contradicted_by"
	}
	normSource := normalizeSourceType(sourceType)
	if normSource == "doc" || normSource == "readme" {
		return "documented_by"
	}
	if normSource == "code" || normSource == "test" || normSource == "eval" {
		return "validated_by"
	}
	if supportLevel == string(ClaimSupportVerified) || supportLevel == string(ClaimSupportStronglySupported) || supportLevel == string(ClaimSupportSupported) {
		return "supported_by"
	}
	if status == ClaimStatusRejected {
		return "contradicted_by"
	}
	return "derived_from"
}

func buildSourceEvidenceFromExecution(claimSet *ClaimSet, execResult rules.ExecutionResult) []SourceEvidenceRecord {
	claimIDsByRule := claimIDsByRuleID(claimSet)
	var records []SourceEvidenceRecord
	for _, finding := range execResult.Findings {
		claimIDs := claimIDsByRule[canonicalClaimID(finding.RuleID)]
		if len(claimIDs) == 0 {
			claimIDs = []string{canonicalClaimID(finding.RuleID)}
		}

		if len(finding.Evidence) == 0 {
			record := SourceEvidenceRecord{
				EvidenceID: claimEvidenceID(finding.RuleID, 0),
				SourceType: "code",
				Origin:     string(ClaimOriginRuleInferred),
				Producer:   "rule:" + finding.RuleID,
				Path:       "rules/" + finding.RuleID,
				Kind:       "rule_result",
				Summary:    finding.Message,
				Metadata:   map[string]string{"status": string(finding.Status), "confidence": string(finding.Confidence), "verification_level": string(finding.VerificationLevel)},
				ClaimIDs:   append([]string(nil), claimIDs...),
			}
			if finding.Status == rules.StatusFail {
				record.Contradicts = append(record.Contradicts, claimIDs...)
			} else if finding.Status == rules.StatusPass {
				record.Supports = append(record.Supports, claimIDs...)
			}
			records = append(records, record)
			continue
		}

		for idx, ev := range finding.Evidence {
			record := SourceEvidenceRecord{
				EvidenceID: claimEvidenceID(finding.RuleID, idx),
				SourceType: "code",
				Origin:     string(ClaimOriginRuleInferred),
				Producer:   "rule:" + finding.RuleID,
				Path:       sourceEvidencePath(ev.File),
				Kind:       "rule_result",
				Summary:    finding.Message,
				Spans: []SourceSpan{{
					File:      sourceEvidencePath(ev.File),
					LineStart: ev.LineStart,
					LineEnd:   ev.LineEnd,
					Symbol:    ev.Symbol,
					Excerpt:   ev.Excerpt,
				}},
				ClaimIDs: append([]string(nil), claimIDs...),
				Metadata: map[string]string{
					"status":             string(finding.Status),
					"confidence":         string(finding.Confidence),
					"verification_level": string(finding.VerificationLevel),
				},
			}
			if finding.Status == rules.StatusFail {
				record.Contradicts = append(record.Contradicts, claimIDs...)
			} else if finding.Status == rules.StatusPass {
				record.Supports = append(record.Supports, claimIDs...)
			}
			records = append(records, record)
		}
	}
	sort.Slice(records, func(i, j int) bool {
		if records[i].EvidenceID != records[j].EvidenceID {
			return records[i].EvidenceID < records[j].EvidenceID
		}
		return records[i].Path < records[j].Path
	})
	return records
}

func claimIDsByRuleID(claimSet *ClaimSet) map[string][]string {
	out := make(map[string][]string)
	if claimSet == nil {
		return out
	}
	for _, claim := range claimSet.Claims {
		for _, ruleID := range compactStrings(claim.RuleIDs) {
			key := canonicalClaimID(ruleID)
			out[key] = append(out[key], claim.ID)
		}
	}
	for key := range out {
		out[key] = dedupeStringsSorted(out[key])
	}
	return out
}

func claimDefinitionIndex(claimSet *ClaimSet) map[string]Claim {
	index := make(map[string]Claim)
	if claimSet == nil {
		return index
	}
	for _, claim := range claimSet.Claims {
		index[normalizeClaimKey(claim.ID)] = claim
		index[normalizeClaimKey(claim.Title)] = claim
	}
	return index
}

func sourceEvidenceMatchesClaim(ev SourceEvidenceRecord, claimID string) bool {
	key := normalizeClaimKey(canonicalizeClaimID(claimID))
	candidates := normalizeAndFilterClaimIDs(compactStrings(ev.ClaimIDs), normalizeSourceType(ev.SourceType))
	if len(candidates) == 0 {
		candidates = inferClaimIDsFromSourceEvidence(ev)
	}
	for _, candidate := range candidates {
		if normalizeClaimKey(canonicalizeClaimID(candidate)) == key {
			return true
		}
	}
	for _, candidate := range compactStrings(ev.Supports) {
		if normalizeClaimKey(canonicalizeClaimID(candidate)) == key {
			return true
		}
	}
	for _, candidate := range compactStrings(ev.Contradicts) {
		if normalizeClaimKey(canonicalizeClaimID(candidate)) == key {
			return true
		}
	}
	return false
}

func isClaimContradiction(ev SourceEvidenceRecord, claimID string) bool {
	key := normalizeClaimKey(claimID)
	for _, candidate := range compactStrings(ev.Contradicts) {
		if normalizeClaimKey(candidate) == key {
			return true
		}
	}
	if strings.EqualFold(ev.Origin, "contradiction") {
		return true
	}
	return false
}

func inferClaimOrigin(sourceType string) string {
	switch normalizeSourceType(sourceType) {
	case "readme":
		return string(ClaimOriginReadmeExtracted)
	case "doc":
		return string(ClaimOriginDocExtracted)
	case "test":
		return string(ClaimOriginTestInferred)
	case "eval":
		return string(ClaimOriginEvalInferred)
	case "code":
		return string(ClaimOriginCodeInferred)
	default:
		return string(ClaimOriginRuleInferred)
	}
}

func inferClaimTypeFromDefinition(claim Claim) string {
	switch normalizeClaimCategory(claim.Category) {
	case "architecture":
		return "architecture"
	case "security":
		return "security_maturity"
	case "testing":
		return "testing_maturity"
	case "evaluation":
		return "evaluation_maturity"
	case "operational":
		return "operational_maturity"
	default:
		return "implementation"
	}
}

func inferClaimTypeFromSource(sourceType, claimText string) string {
	switch normalizeSourceType(sourceType) {
	case "test":
		return "testing_maturity"
	case "eval":
		return "evaluation_maturity"
	case "doc", "readme":
		return inferClaimTypeFromText(claimText)
	case "code":
		return inferClaimTypeFromText(claimText)
	default:
		return "implementation"
	}
}

func inferClaimTypeFromText(text string) string {
	normalized := strings.ToLower(strings.TrimSpace(text))
	switch {
	case strings.Contains(normalized, "security"), strings.Contains(normalized, "auth"), strings.Contains(normalized, "secret"):
		return "security_maturity"
	case strings.Contains(normalized, "architecture"), strings.Contains(normalized, "pipeline"), strings.Contains(normalized, "service"), strings.Contains(normalized, "repository"), strings.Contains(normalized, "layer"):
		return "architecture"
	case strings.Contains(normalized, "test"):
		return "testing_maturity"
	case strings.Contains(normalized, "eval"), strings.Contains(normalized, "benchmark"):
		return "evaluation_maturity"
	case strings.Contains(normalized, "operational"), strings.Contains(normalized, "deploy"), strings.Contains(normalized, "runtime"):
		return "operational_maturity"
	default:
		return "implementation"
	}
}

func inferClaimCategory(claimText, sourceType string) string {
	normalized := strings.ToLower(strings.TrimSpace(claimText))
	switch {
	case strings.Contains(normalized, "security"), strings.Contains(normalized, "auth"), strings.Contains(normalized, "secret"):
		return "security"
	case strings.Contains(normalized, "architecture"), strings.Contains(normalized, "pipeline"), strings.Contains(normalized, "service"), strings.Contains(normalized, "repository"), strings.Contains(normalized, "layer"):
		return "architecture"
	case strings.Contains(normalized, "test"):
		return "testing"
	case strings.Contains(normalized, "eval"), strings.Contains(normalized, "benchmark"):
		return "evaluation"
	case strings.Contains(normalized, "operational"), strings.Contains(normalized, "deploy"), strings.Contains(normalized, "runtime"):
		return "operational"
	case normalizeSourceType(sourceType) == "code":
		return "implementation"
	default:
		return "general"
	}
}

func normalizeClaimCategory(category string) string {
	normalized := strings.ToLower(strings.TrimSpace(category))
	switch normalized {
	case "security", "security_maturity":
		return "security"
	case "architecture", "architectural":
		return "architecture"
	case "testing", "testing_maturity":
		return "testing"
	case "evaluation", "evaluation_maturity":
		return "evaluation"
	case "operational", "operational_maturity":
		return "operational"
	case "implementation":
		return "implementation"
	default:
		return normalized
	}
}

func normalizeSourceType(sourceType string) string {
	switch strings.ToLower(strings.TrimSpace(sourceType)) {
	case "readme":
		return "readme"
	case "doc", "docs", "documentation":
		return "doc"
	case "code":
		return "code"
	case "test", "tests":
		return "test"
	case "eval", "evaluation":
		return "eval"
	default:
		return "code"
	}
}

func claimEvidenceID(ruleID string, index int) string {
	return fmt.Sprintf("claim-%s-%d", canonicalClaimID(ruleID), index)
}

func canonicalClaimID(raw string) string {
	normalized := strings.ToLower(strings.TrimSpace(raw))
	normalized = strings.ReplaceAll(normalized, " ", "_")
	normalized = strings.ReplaceAll(normalized, "/", "_")
	normalized = strings.ReplaceAll(normalized, ":", ".")
	normalized = strings.ReplaceAll(normalized, "-", "_")
	return strings.Trim(normalized, "._")
}

func normalizeClaimKey(raw string) string {
	return canonicalizeClaimID(raw)
}

func humanizeClaimID(raw string) string {
	parts := strings.FieldsFunc(strings.TrimSpace(raw), func(r rune) bool {
		switch r {
		case '.', '_', '-', '/':
			return true
		default:
			return false
		}
	})
	if len(parts) == 0 {
		return raw
	}
	for i, part := range parts {
		parts[i] = strings.ToUpper(part[:1]) + strings.ToLower(part[1:])
	}
	return strings.Join(parts, " ")
}

func candidateReason(candidate *ClaimCandidate, evidence []SourceEvidenceRecord) string {
	if len(candidate.CandidateEvidenceIDs) == 0 {
		return "seeded claim without supporting evidence"
	}
	if candidate.Origin == string(ClaimOriginReadmeExtracted) || candidate.Origin == string(ClaimOriginDocExtracted) {
		return "documentation-derived claim candidate awaiting verification"
	}
	return "evidence-backed claim candidate"
}

func maxSourceStrength(sourceTypes []string) int {
	max := 0
	for _, sourceType := range compactStrings(sourceTypes) {
		if strength := sourceTypeStrength(sourceType); strength > max {
			max = strength
		}
	}
	return max
}

func countStrongSourceTypes(sourceTypes []string) int {
	count := 0
	for _, sourceType := range dedupeStringsSorted(compactStrings(sourceTypes)) {
		switch sourceType {
		case "code", "test", "eval":
			count++
		}
	}
	return count
}

func sourceTypeStrength(sourceType string) int {
	switch normalizeSourceType(sourceType) {
	case "code":
		return 4
	case "test":
		return 3
	case "eval":
		return 3
	case "doc":
		return 2
	case "readme":
		return 1
	default:
		return 0
	}
}

func chooseStrongerOrigin(current, candidate string) string {
	if originRank(candidate) > originRank(current) {
		return candidate
	}
	return current
}

func originRank(origin string) int {
	switch ClaimOrigin(origin) {
	case ClaimOriginCodeInferred:
		return 5
	case ClaimOriginTestInferred:
		return 4
	case ClaimOriginEvalInferred:
		return 4
	case ClaimOriginDocExtracted:
		return 3
	case ClaimOriginReadmeExtracted:
		return 2
	case ClaimOriginRuleInferred:
		return 1
	default:
		return 0
	}
}

func cloneSourceEvidenceRecords(records []SourceEvidenceRecord) []SourceEvidenceRecord {
	out := make([]SourceEvidenceRecord, 0, len(records))
	for _, record := range records {
		cloned := record
		if record.Spans != nil {
			cloned.Spans = append([]SourceSpan(nil), record.Spans...)
		}
		if record.EntityIDs != nil {
			cloned.EntityIDs = append([]string(nil), record.EntityIDs...)
		}
		if record.Metadata != nil {
			cloned.Metadata = make(map[string]string, len(record.Metadata))
			for k, v := range record.Metadata {
				cloned.Metadata[k] = v
			}
		}
		cloned.ClaimIDs = append([]string(nil), record.ClaimIDs...)
		cloned.Supports = append([]string(nil), record.Supports...)
		cloned.Contradicts = append([]string(nil), record.Contradicts...)
		out = append(out, cloned)
	}
	return out
}

func sourceEvidencePath(path string) string {
	if path == "" {
		return "unknown"
	}
	return strings.ReplaceAll(path, "\\", "/")
}

func inferClaimIDsFromSourceEvidence(ev SourceEvidenceRecord) []string {
	text := strings.ToLower(strings.Join([]string{
		ev.Path,
		ev.Kind,
		ev.Summary,
		ev.Metadata["section_title"],
		ev.Metadata["claim_fragments"],
		ev.Metadata["module_kind"],
		ev.Metadata["test_kind"],
		ev.Metadata["benchmark_purpose"],
		ev.Metadata["dataset_id"],
		ev.Metadata["target_module"],
	}, " "))

	var claimIDs []string
	switch {
	case strings.Contains(text, "planner") && strings.Contains(text, "verifier"),
		strings.Contains(text, "multi-agent"),
		strings.Contains(text, "multi agent"),
		strings.Contains(text, "agent architecture"),
		strings.Contains(text, "3-agent"),
		strings.Contains(text, "3 agent"):
		claimIDs = append(claimIDs, "architecture.multi_agent_pipeline")
	case strings.Contains(text, "secure_answer"),
		strings.Contains(text, "secure answer"),
		strings.Contains(text, "guarded generation"),
		strings.Contains(text, "refusal gate"):
		claimIDs = append(claimIDs, "architecture.secure_answer_pipeline")
	case strings.Contains(text, "langfuse"),
		strings.Contains(text, "tracing"),
		strings.Contains(text, "observability"):
		claimIDs = append(claimIDs, "operational_maturity.structured_tracing")
	case strings.Contains(text, "adversarial"),
		strings.Contains(text, "red-team"),
		strings.Contains(text, "red team"):
		claimIDs = append(claimIDs, "evaluation_maturity.adversarial_evaluation")
	case strings.Contains(text, "benchmark"),
		strings.Contains(text, "calibration"),
		strings.Contains(text, "eval"):
		claimIDs = append(claimIDs, "evaluation_maturity.quality_gating")
	case strings.Contains(text, "auth"),
		strings.Contains(text, "jwt"),
		strings.Contains(text, "middleware"):
		claimIDs = append(claimIDs, "security_maturity.auth_middleware")
	case strings.Contains(text, "security"),
		strings.Contains(text, "secret"),
		strings.Contains(text, "hardening"),
		strings.Contains(text, "defense-in-depth"),
		strings.Contains(text, "defense in depth"):
		claimIDs = append(claimIDs, "security_maturity.defense_in_depth")
	}

	if len(claimIDs) > 0 {
		return normalizeAndFilterClaimIDs(claimIDs, normalizeSourceType(ev.SourceType))
	}

	sourceType := normalizeSourceType(ev.SourceType)
	if sourceType == "doc" || sourceType == "readme" {
		return nil
	}

	switch sourceType {
	case "code":
		role := strings.TrimSpace(ev.Metadata["module_kind"])
		if role == "" {
			role = "module"
		}
		return normalizeAndFilterClaimIDs([]string{"architecture." + canonicalClaimID(role)}, sourceType)
	case "test":
		role := strings.TrimSpace(ev.Metadata["test_kind"])
		if role == "security_test" {
			return normalizeAndFilterClaimIDs([]string{"security_maturity.test_strengthened_security"}, sourceType)
		}
		if role == "" {
			role = "test"
		}
		return normalizeAndFilterClaimIDs([]string{"testing_maturity." + canonicalClaimID(role)}, sourceType)
	case "eval":
		id := strings.TrimSpace(ev.Metadata["dataset_id"])
		if id == "" {
			id = "evaluation_asset"
		}
		return normalizeAndFilterClaimIDs([]string{"evaluation_maturity." + canonicalClaimID(id)}, sourceType)
	default:
		return nil
	}
}

func normalizeAndFilterClaimIDs(claimIDs []string, sourceType string) []string {
	out := make([]string, 0, len(claimIDs))
	seen := make(map[string]struct{}, len(claimIDs))
	for _, raw := range compactStrings(claimIDs) {
		canonical := canonicalizeClaimID(raw)
		if canonical == "" || shouldPruneClaimID(canonical, sourceType) {
			continue
		}
		if _, ok := seen[canonical]; ok {
			continue
		}
		seen[canonical] = struct{}{}
		out = append(out, canonical)
	}
	sort.Strings(out)
	return out
}

func canonicalizeClaimID(raw string) string {
	id := canonicalClaimID(raw)
	switch id {
	case "architecture.3_agent_pipeline", "architecture.agent_architecture", "architecture.multi_agent_architecture":
		return "architecture.multi_agent_pipeline"
	case "architecture.secure_answer":
		return "architecture.secure_answer_pipeline"
	case "operational_maturity.langfuse_tracing", "operational_maturity.tracing":
		return "operational_maturity.structured_tracing"
	case "evaluation_maturity.red_team_evaluation", "evaluation_maturity.redteam_evaluation":
		return "evaluation_maturity.adversarial_evaluation"
	default:
		return id
	}
}

func shouldPruneClaimID(claimID string, sourceType string) bool {
	if claimID == "" {
		return true
	}
	if strings.HasPrefix(claimID, "general.") {
		return true
	}
	normalized := strings.ToLower(claimID)
	if strings.Contains(normalized, ".py") || strings.Contains(normalized, ".ts") || strings.Contains(normalized, ".md") {
		return true
	}
	if strings.Contains(normalized, "chunk_") || strings.Contains(normalized, "task_") {
		return true
	}
	if strings.Contains(normalized, "/") || strings.Contains(normalized, "\\") {
		return true
	}
	if (sourceType == "doc" || sourceType == "readme") && !isCuratedDocumentationClaim(normalized) {
		return true
	}
	return false
}

func isCuratedDocumentationClaim(claimID string) bool {
	switch claimID {
	case "architecture.multi_agent_pipeline",
		"architecture.secure_answer_pipeline",
		"operational_maturity.structured_tracing",
		"evaluation_maturity.adversarial_evaluation",
		"evaluation_maturity.quality_gating",
		"security_maturity.auth_middleware",
		"security_maturity.defense_in_depth":
		return true
	default:
		return false
	}
}
