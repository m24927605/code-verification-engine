package artifactsv2

import (
	"strings"

	"github.com/verabase/code-verification-engine/internal/report"
)

const (
	confidenceHighThreshold      = 0.85
	confidenceModerateThreshold  = 0.65
	confidenceLowThreshold       = 0.40
	machineTrustedFinalThreshold = 0.85
	unknownFinalCap              = 0.55
	agentOnlyFinalCap            = 0.60
)

var confidenceRuleFamilyBaselines = map[string]float64{
	"sec_secret":   0.94,
	"fe_dep":       0.92,
	"sec_strict":   0.72,
	"arch_layer":   0.78,
	"arch_pattern": 0.74,
	"test_auth":    0.62,
	"test_payment": 0.62,
	"fam_security": 0.90,
	"fam_design":   0.72,
	"fam_bug":      0.55,
}

var confidenceOrderingRules = []string{
	"issue_native > seed_native > finding_bridged",
	"proof > structural > heuristic",
	"deterministic > agent_only",
}

func currentConfidenceCalibration() *ConfidenceCalibration {
	baselines := make(map[string]float64, len(confidenceRuleFamilyBaselines))
	for family, baseline := range confidenceRuleFamilyBaselines {
		baselines[family] = baseline
	}
	return &ConfidenceCalibration{
		Version:                 "release-blocking-calibration-1",
		MachineTrustedThreshold: machineTrustedFinalThreshold,
		UnknownCap:              unknownFinalCap,
		AgentOnlyCap:            agentOnlyFinalCap,
		RuleFamilyBaselines:     baselines,
		OrderingRules:           append([]string(nil), confidenceOrderingRules...),
	}
}

func computeConfidenceBreakdown(cluster compatIssueCluster, scan report.ScanReport, verification VerificationSource) *ConfidenceBreakdown {
	ruleReliability := computeRuleReliability(cluster, verification)
	evidenceQuality := clamp(cluster.Quality, 0, 1)
	boundaryCompleteness := computeBoundaryCompleteness(scan, verification)
	contextCompleteness := computeContextCompleteness(cluster)
	sourceAgreement := computeSourceAgreement(cluster.Sources)
	contradictionPenalty := computeContradictionPenalty(cluster.CounterEvidenceIDs)
	llmPenalty := computeLLMPenalty(cluster.Sources)

	final := clamp(
		0.30*ruleReliability+
			0.20*evidenceQuality+
			0.15*boundaryCompleteness+
			0.15*contextCompleteness+
			0.20*sourceAgreement-
			0.20*contradictionPenalty-
			0.10*llmPenalty,
		0,
		1,
	)
	final = applyConfidencePolicyCaps(cluster, llmPenalty, final)

	return &ConfidenceBreakdown{
		RuleReliability:      ruleReliability,
		EvidenceQuality:      evidenceQuality,
		BoundaryCompleteness: boundaryCompleteness,
		ContextCompleteness:  contextCompleteness,
		SourceAgreement:      sourceAgreement,
		ContradictionPenalty: contradictionPenalty,
		LLMPenalty:           llmPenalty,
		Final:                final,
	}
}

func classifyConfidence(score float64) string {
	switch {
	case score >= confidenceHighThreshold:
		return "high"
	case score >= confidenceModerateThreshold:
		return "moderate"
	case score >= confidenceLowThreshold:
		return "low"
	default:
		return "weak"
	}
}

func deriveIssuePolicyClass(cluster compatIssueCluster, breakdown *ConfidenceBreakdown) string {
	if breakdown == nil {
		return "unknown_retained"
	}
	if cluster.Status == "unknown" {
		return "unknown_retained"
	}
	if breakdown.Final >= machineTrustedFinalThreshold &&
		breakdown.RuleReliability >= machineTrustedFinalThreshold &&
		breakdown.EvidenceQuality >= 0.95 &&
		breakdown.BoundaryCompleteness >= 0.75 &&
		breakdown.ContextCompleteness >= 0.75 &&
		breakdown.ContradictionPenalty == 0 &&
		breakdown.LLMPenalty == 0 {
		return "machine_trusted"
	}
	if breakdown.Final >= 0.40 {
		return "advisory"
	}
	return "unknown_retained"
}

func applyConfidencePolicyCaps(cluster compatIssueCluster, llmPenalty, current float64) float64 {
	score := current
	if cluster.Status == "unknown" {
		score = min(score, unknownFinalCap)
	}
	if llmPenalty >= 0.40 {
		score = min(score, agentOnlyFinalCap)
	}
	return clamp(score, 0, 1)
}

func computeRuleReliability(cluster compatIssueCluster, verification VerificationSource) float64 {
	base := computeRuleReliabilityBaseline(cluster, verification)

	distinctSources := dedupeStringsSorted(cluster.Sources)
	hasAgent := false
	hasDeterministic := false
	for _, source := range distinctSources {
		switch strings.ToLower(source) {
		case "agent":
			hasAgent = true
		case "rule", "analyzer":
			hasDeterministic = true
		}
	}
	if hasDeterministic {
		base += 0.05
	}
	if hasAgent && !hasDeterministic {
		base = min(base, 0.45)
	}
	if len(dedupeStringsSorted(cluster.RuleIDs)) >= 2 {
		base += 0.03
	}
	if cluster.Status == "unknown" {
		base = min(base, unknownFinalCap)
	}

	base = clamp(base, 0, 1)
	seedConfidence := clamp(cluster.Confidence, 0, 1)
	return clamp(0.6*base+0.4*seedConfidence, 0, 1)
}

func computeRuleReliabilityBaseline(cluster compatIssueCluster, verification VerificationSource) float64 {
	metadataBaseline := computeRuleMetadataReliability(cluster.RuleIDs, verification.RuleMetadata)
	if metadataBaseline > 0 {
		qualityBaseline := 0.50
		switch {
		case cluster.Quality >= 0.95:
			qualityBaseline = 0.85
		case cluster.Quality >= 0.65:
			qualityBaseline = 0.70
		}
		return clamp(0.75*metadataBaseline+0.25*qualityBaseline, 0, 1)
	}

	switch {
	case cluster.Quality >= 0.95:
		return 0.85
	case cluster.Quality >= 0.65:
		return 0.70
	default:
		return 0.50
	}
}

func computeRuleMetadataReliability(ruleIDs []string, metadata map[string]RuleMetadata) float64 {
	if len(ruleIDs) == 0 || len(metadata) == 0 {
		return 0
	}

	var (
		total float64
		count int
	)
	for _, ruleID := range dedupeStringsSorted(ruleIDs) {
		md, ok := metadata[ruleID]
		if !ok {
			continue
		}
		total += reliabilityForRuleMetadata(md)
		count++
	}
	if count == 0 {
		return 0
	}
	return clamp(total/float64(count), 0, 1)
}

func reliabilityForRuleMetadata(md RuleMetadata) float64 {
	familyBaseline := reliabilityForRuleFamily(md.MatcherClass, md.TrustClass)
	categoryBaseline := reliabilityForRuleCategory(md.Category)
	ruleFamilyBaseline := reliabilityForRuleIDFamily(md.RuleID, md.Category)
	migrationBaseline := reliabilityForMigrationState(md.MigrationState)
	migrationCap := reliabilityCapForMigrationState(md.MigrationState)
	if ruleFamilyBaseline > 0 {
		if familyBaseline > 0 {
			familyBaseline = clamp(0.55*ruleFamilyBaseline+0.45*familyBaseline, 0, 1)
		} else if categoryBaseline > 0 {
			familyBaseline = clamp(0.45*ruleFamilyBaseline+0.55*categoryBaseline, 0, 1)
		} else {
			familyBaseline = min(ruleFamilyBaseline, 0.70)
		}
	}
	if familyBaseline > 0 && categoryBaseline > 0 {
		familyBaseline = clamp(0.7*familyBaseline+0.3*categoryBaseline, 0, 1)
	} else if familyBaseline == 0 {
		familyBaseline = categoryBaseline
	}
	if familyBaseline == 0 {
		familyBaseline = migrationBaseline
	} else if migrationBaseline > 0 {
		familyBaseline = clamp(0.8*familyBaseline+0.2*migrationBaseline, 0, 1)
	}
	if migrationCap == 0 {
		return clamp(familyBaseline, 0, 1)
	}
	return clamp(min(familyBaseline, migrationCap), 0, 1)
}

func reliabilityForRuleIDFamily(ruleID, category string) float64 {
	return confidenceRuleFamilyBaselines[compatRuleFamily(ruleID, category)]
}

func reliabilityForRuleCategory(category string) float64 {
	switch strings.ToLower(strings.TrimSpace(category)) {
	case "security":
		return 0.90
	case "architecture":
		return 0.72
	case "design":
		return 0.68
	case "frontend_security":
		return 0.82
	case "frontend_quality":
		return 0.62
	case "quality":
		return 0.58
	case "testing":
		return 0.56
	case "bug":
		return 0.52
	default:
		return 0.50
	}
}

func reliabilityForRuleFamily(matcherClass, trustClass string) float64 {
	switch {
	case strings.EqualFold(strings.TrimSpace(trustClass), "human_or_runtime_required"):
		return 0.30
	case strings.EqualFold(strings.TrimSpace(matcherClass), "proof_matcher"),
		strings.EqualFold(strings.TrimSpace(trustClass), "machine_trusted"):
		return 0.85
	case strings.EqualFold(strings.TrimSpace(matcherClass), "structural_matcher"),
		strings.EqualFold(strings.TrimSpace(trustClass), "advisory"):
		return 0.65
	case strings.EqualFold(strings.TrimSpace(matcherClass), "heuristic_matcher"):
		return 0.45
	case strings.EqualFold(strings.TrimSpace(matcherClass), "attestation_matcher"):
		return 0.30
	default:
		return 0
	}
}

func reliabilityCapForMigrationState(state string) float64 {
	switch strings.ToLower(strings.TrimSpace(state)) {
	case "issue_native":
		return 1.00
	case "seed_native":
		return 0.80
	case "finding_bridged":
		return 0.60
	case "legacy_only":
		return 0.45
	default:
		return 0
	}
}

func reliabilityForMigrationState(state string) float64 {
	switch strings.ToLower(strings.TrimSpace(state)) {
	case "issue_native":
		return 0.85
	case "seed_native":
		return 0.68
	case "finding_bridged":
		return 0.50
	case "legacy_only":
		return 0.40
	default:
		return 0.45
	}
}

func computeBoundaryCompleteness(scan report.ScanReport, verification VerificationSource) float64 {
	score := 1.0
	if scan.BoundaryMode != "" && scan.BoundaryMode != "repo" {
		score = 0.8
	}
	if verification.Partial {
		score = min(score, 0.75)
	}
	if verification.Degraded {
		score = min(score, 0.65)
	}
	if len(verification.Errors) > 0 {
		score = min(score, 0.60)
	}
	return clamp(score, 0, 1)
}

func computeContextCompleteness(cluster compatIssueCluster) float64 {
	switch {
	case cluster.File != "" && cluster.File != "unknown" && cluster.Symbol != "":
		return 1.0
	case cluster.File != "" && cluster.File != "unknown":
		return 0.75
	default:
		return 0.40
	}
}

func computeSourceAgreement(sources []string) float64 {
	distinct := dedupeStringsSorted(sources)
	switch len(distinct) {
	case 0:
		return 0.30
	case 1:
		return 0.45
	case 2:
		return 0.70
	default:
		return 0.90
	}
}

func computeLLMPenalty(sources []string) float64 {
	distinct := dedupeStringsSorted(sources)
	if len(distinct) == 0 {
		return 0
	}
	hasAgent := false
	hasDeterministic := false
	for _, source := range distinct {
		switch strings.ToLower(source) {
		case "agent":
			hasAgent = true
		case "rule", "analyzer":
			hasDeterministic = true
		}
	}
	switch {
	case hasAgent && hasDeterministic:
		return 0.05
	case hasAgent:
		return 0.40
	default:
		return 0.0
	}
}

func computeContradictionPenalty(counterEvidenceIDs []string) float64 {
	switch len(dedupeStringsSorted(counterEvidenceIDs)) {
	case 0:
		return 0.0
	case 1:
		return 0.20
	case 2:
		return 0.45
	default:
		return 0.70
	}
}
