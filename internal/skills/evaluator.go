package skills

import (
	"github.com/verabase/code-verification-engine/internal/rules"
)

// Evaluate generates a skill report from findings, facts, and a profile.
// This is the main entry point for the skill inference pipeline.
// It uses both finding-based mappings AND direct fact-to-signal mappings.
func Evaluate(findings []rules.Finding, profile *Profile, repoPath string, opts ...EvalOption) *Report {
	cfg := evalConfig{}
	for _, opt := range opts {
		opt(&cfg)
	}

	candidates := MapFindings(findings, profile)

	// Direct fact-to-signal mapping (bypasses rules)
	if cfg.factSet != nil {
		factCandidates := MapFacts(cfg.factSet, profile)
		candidates = append(candidates, factCandidates...)
	}

	signals := aggregate(candidates, profile)

	r := &Report{
		SchemaVersion: SkillReportVersion,
		RepoPath:      repoPath,
		Profile:       profile.Name,
		Signals:       signals,
	}
	r.Summary = computeSummary(signals)
	return r
}

// aggregate merges candidate signals per skill_id, applying conservative policy.
func aggregate(candidates []candidateSignal, profile *Profile) []Signal {
	// Group candidates by skill_id
	grouped := make(map[string][]candidateSignal)
	for _, c := range candidates {
		grouped[c.SkillID] = append(grouped[c.SkillID], c)
	}

	// Build signals for every skill in the profile (unsupported if no candidates)
	var signals []Signal
	for _, def := range profile.Signals {
		cands, hasCands := grouped[def.SkillID]
		if !hasCands || len(cands) == 0 {
			signals = append(signals, Signal{
				ID:               def.ID,
				SkillID:          def.SkillID,
				Category:         def.Category,
				Status:           StatusUnsupported,
				Confidence:       ConfidenceLow,
				TrustClass:       "human_or_runtime_required",
				EvidenceStrength: EvidenceHeuristic,
				Message:          "Insufficient evidence for " + def.SkillID,
				UnknownReasons:   []string{"no matching facts or findings"},
			})
			continue
		}

		sig := mergeCandiates(def, cands)
		signals = append(signals, sig)
	}

	return signals
}

// mergeCandiates merges multiple candidates for one skill into a single signal.
// Conservative aggregation: trust floor, confidence cap, lowest evidence strength.
func mergeCandiates(def SignalDefinition, cands []candidateSignal) Signal {
	// Find the best status (observed > inferred)
	bestStatus := StatusInferred
	for _, c := range cands {
		if c.Status == StatusObserved {
			bestStatus = StatusObserved
			break
		}
	}

	// Trust floor: use the lowest trust class across all candidates
	trustFloor := "machine_trusted"
	for _, c := range cands {
		trustFloor = capTrustClass(c.TrustClass, trustFloor)
	}

	// Evidence strength floor: use lowest
	evidenceFloor := EvidenceDirect
	for _, c := range cands {
		evidenceFloor = minEvidenceStrength(evidenceFloor, c.EvidenceStrength)
	}

	// Confidence: use the bounded max across candidates, then apply caps
	bestConfidence := ConfidenceLow
	for _, c := range cands {
		if confidenceRank(c.Confidence) > confidenceRank(bestConfidence) {
			bestConfidence = c.Confidence
		}
	}

	// Apply conservative caps:
	// 1. Heuristic-only evidence cannot produce high-confidence observed
	if evidenceFloor == EvidenceHeuristic && bestConfidence == ConfidenceHigh {
		bestConfidence = ConfidenceMedium
	}
	// 2. human_or_runtime_required trust cannot produce high confidence
	if trustFloor == "human_or_runtime_required" && bestConfidence == ConfidenceHigh {
		bestConfidence = ConfidenceMedium
	}
	// 3. A single advisory signal alone cannot produce high-confidence observed
	if len(cands) == 1 && trustFloor == "advisory" && bestStatus == StatusObserved && bestConfidence == ConfidenceHigh {
		bestConfidence = ConfidenceMedium
	}

	// Collect all evidence and source rule IDs
	var allEvidence []rules.Evidence
	ruleIDSet := make(map[string]bool)
	var sourceRuleIDs []string
	for _, c := range cands {
		allEvidence = append(allEvidence, c.Evidence...)
		for _, rid := range c.SourceRuleIDs {
			if !ruleIDSet[rid] {
				ruleIDSet[rid] = true
				sourceRuleIDs = append(sourceRuleIDs, rid)
			}
		}
	}

	// Determine message
	message := cands[0].Message
	// If any candidate is risk_exposure, override category
	category := def.Category
	for _, c := range cands {
		if c.Category == CategoryRiskExposure {
			category = CategoryRiskExposure
			message = c.Message
			break
		}
	}

	return Signal{
		ID:               def.ID,
		SkillID:          def.SkillID,
		Category:         category,
		Status:           bestStatus,
		Confidence:       bestConfidence,
		TrustClass:       trustFloor,
		EvidenceStrength: evidenceFloor,
		Message:          message,
		SourceRuleIDs:    sourceRuleIDs,
		Evidence:         allEvidence,
	}
}

func minEvidenceStrength(a, b EvidenceStrength) EvidenceStrength {
	rank := map[EvidenceStrength]int{
		EvidenceHeuristic:  0,
		EvidenceStructural: 1,
		EvidenceDirect:     2,
	}
	if rank[a] <= rank[b] {
		return a
	}
	return b
}

func confidenceRank(c SignalConfidence) int {
	switch c {
	case ConfidenceHigh:
		return 2
	case ConfidenceMedium:
		return 1
	default:
		return 0
	}
}

func computeSummary(signals []Signal) Summary {
	var s Summary
	for _, sig := range signals {
		switch sig.Status {
		case StatusObserved:
			s.Observed++
		case StatusInferred:
			s.Inferred++
		case StatusUnsupported:
			s.Unsupported++
		}
	}
	return s
}

// evalConfig holds optional configuration for Evaluate.
type evalConfig struct {
	factSet *rules.FactSet
}

// EvalOption configures the skill evaluator.
type EvalOption func(*evalConfig)

// WithFactSet provides direct fact access for fact-to-signal mapping.
func WithFactSet(fs *rules.FactSet) EvalOption {
	return func(c *evalConfig) { c.factSet = fs }
}
