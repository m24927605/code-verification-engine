package rules

import "github.com/verabase/code-verification-engine/internal/facts"

// Engine evaluates verification rules against normalized facts.
type Engine struct {
	capabilities *CapabilityMatrix
}

// NewEngine creates a new rule execution engine.
func NewEngine() *Engine {
	return &Engine{
		capabilities: NewCapabilityMatrix(),
	}
}

// DegradeLanguageCapability downgrades capability levels for a language when
// the runtime environment is degraded (e.g., python3 not available for AST parsing).
// The reason parameter records why the degradation happened.
func (e *Engine) DegradeLanguageCapability(language, reason string) {
	e.capabilities.DegradeLanguage(language, reason)
}

// Execute evaluates all rules in the rule file against the provided facts.
// Rules are evaluated independently. Language filtering skips inapplicable rules.
// Before evaluating a rule, the engine checks whether the required capability
// is supported for the repo's languages and produces appropriate findings.
func (e *Engine) Execute(rf *RuleFile, fs *FactSet, repoLanguages []string) ExecutionResult {
	var result ExecutionResult

	for _, rule := range rf.Rules {
		if !ruleAppliesToRepo(rule, repoLanguages) {
			result.SkippedRules = append(result.SkippedRules, SkippedRule{
				RuleID: rule.ID,
				Reason: "no matching languages in repository",
			})
			continue
		}

		// Check capability support before running matchers.
		level, detail := e.capabilities.CheckCapability(rule.Target, rule.Languages, repoLanguages)
		if level == Unsupported {
			unknownReasons := []string{UnknownCapabilityUnsupported, detail}
			// Add degradation reason if any relevant language was degraded
			unknownReasons = e.enrichWithDegradationReasons(unknownReasons, rule.Languages, repoLanguages)
			// Add extraction gap info
			unknownReasons = e.enrichWithExtractionInfo(unknownReasons, rule.Target, rule.Languages, repoLanguages)

			result.SkippedRules = append(result.SkippedRules, SkippedRule{
				RuleID: rule.ID,
				Reason: "capability_unsupported: " + detail,
			})
			result.Findings = append(result.Findings, Finding{
				RuleID:            rule.ID,
				Status:            StatusUnknown,
				Confidence:        ConfidenceLow,
				VerificationLevel: VerificationWeakInference,
				Message:           rule.Message,
				UnknownReasons:    unknownReasons,
				MatcherClass:      rule.MatcherClass,
				VerdictBasis:      "runtime_required",
				FactQualityFloor:  string(facts.QualityHeuristic),
			})
			continue
		}

		finding := matchRule(rule, fs, repoLanguages)
		finding.MatcherClass = rule.MatcherClass
		applyMatcherClassCeiling(&finding)
		setVerdictBasis(&finding, fs)

		// If partially supported, annotate the finding.
		if level == PartiallySup {
			if finding.UnknownReasons == nil {
				finding.UnknownReasons = []string{}
			}
			finding.UnknownReasons = append(finding.UnknownReasons, UnknownCapabilityPartial, detail)
			// Add degradation reason if any relevant language was degraded
			finding.UnknownReasons = e.enrichWithDegradationReasons(finding.UnknownReasons, rule.Languages, repoLanguages)
			// Add extraction info (AST vs regex, matcher limitation)
			finding.UnknownReasons = e.enrichWithExtractionInfo(finding.UnknownReasons, rule.Target, rule.Languages, repoLanguages)
		}

		result.Findings = append(result.Findings, finding)
	}

	FinalizeExecutionResult(rf, &result)

	return result
}

// enrichWithDegradationReasons adds degradation-related unknown reasons
// for any relevant language that has been degraded.
func (e *Engine) enrichWithDegradationReasons(reasons []string, ruleLanguages, repoLanguages []string) []string {
	relevant := intersectLanguages(ruleLanguages, repoLanguages)
	for _, lang := range relevant {
		if reason := e.capabilities.GetDegradeReason(lang); reason != "" {
			reasons = append(reasons, UnknownCapabilityDegraded)
			break
		}
	}
	return reasons
}

// enrichWithExtractionInfo adds extraction method and matcher limitation
// reasons based on capability detail.
func (e *Engine) enrichWithExtractionInfo(reasons []string, target string, ruleLanguages, repoLanguages []string) []string {
	relevant := intersectLanguages(ruleLanguages, repoLanguages)
	hasFactGap := false
	hasMatcherLimit := false
	for _, lang := range relevant {
		d := e.capabilities.GetCapabilityDetail(lang, target)
		if d.Level != Unsupported && !d.ASTBacked {
			hasFactGap = true
		}
		if d.Level == PartiallySup && d.ASTBacked {
			// AST-backed but still partial means matcher is the limitation
			hasMatcherLimit = true
		}
	}
	if hasFactGap {
		reasons = append(reasons, UnknownFactExtractionGap)
	}
	if hasMatcherLimit {
		reasons = append(reasons, UnknownMatcherLimitation)
	}
	return reasons
}

// setVerdictBasis assigns VerdictBasis and FactQualityFloor based on the
// finding's MatcherClass, VerificationLevel, and the actual quality of the
// facts that back the finding.
//
// A proof_matcher can only claim "proof" verdict if the underlying facts are
// also proof-grade. If the facts are heuristic-quality, the verdict is
// downgraded even if the matcher class would allow "proof".
func setVerdictBasis(f *Finding, fs *FactSet) {
	// Compute the fact quality floor from evidence backing this finding
	floor := computeFactQualityFloor(f, fs)
	f.FactQualityFloor = string(floor)

	switch f.MatcherClass {
	case MatcherProof:
		// Proof verdict requires BOTH proof matcher AND proof-grade facts.
		// If facts are lower quality, downgrade the verdict accordingly.
		switch floor {
		case facts.QualityProof:
			if f.VerificationLevel == VerificationVerified {
				f.VerdictBasis = "proof"
			} else {
				f.VerdictBasis = "structural_binding"
			}
		case facts.QualityStructural:
			f.VerdictBasis = "structural_binding"
			// Also cap verification level — can't be "verified" with structural facts
			if f.VerificationLevel == VerificationVerified {
				f.VerificationLevel = VerificationStrongInference
			}
		default: // heuristic or empty
			f.VerdictBasis = "heuristic_inference"
			if f.VerificationLevel == VerificationVerified {
				f.VerificationLevel = VerificationStrongInference
			}
		}
	case MatcherStructural:
		f.VerdictBasis = "structural_binding"
	case MatcherHeuristic:
		f.VerdictBasis = "heuristic_inference"
	case MatcherAttestation:
		f.VerdictBasis = "runtime_required"
	default:
		f.VerdictBasis = "heuristic_inference"
	}
}

// computeFactQualityFloor inspects the FactSet for facts that overlap with
// the finding's evidence (by file path) and returns the minimum quality
// across all contributing facts.
//
// When no evidence exists (e.g., not_exists pass), or when facts have no
// Quality set (empty string), returns QualityHeuristic as the conservative
// default.
func computeFactQualityFloor(f *Finding, fs *FactSet) facts.FactQuality {
	if fs == nil || len(f.Evidence) == 0 {
		// Pass findings with no evidence: quality is determined by analyzer coverage,
		// not by individual facts. Default to heuristic conservatively.
		return facts.QualityHeuristic
	}

	// Collect the files referenced by evidence
	evidenceFiles := make(map[string]bool, len(f.Evidence))
	for _, ev := range f.Evidence {
		if ev.File != "" {
			evidenceFiles[ev.File] = true
		}
	}
	if len(evidenceFiles) == 0 {
		return facts.QualityHeuristic
	}

	// Scan all fact slices for qualities matching evidence files
	var qualities []facts.FactQuality
	for _, s := range fs.Secrets {
		if evidenceFiles[s.File] && s.Quality != "" {
			qualities = append(qualities, s.Quality)
		}
	}
	for _, s := range fs.Symbols {
		if evidenceFiles[s.File] && s.Quality != "" {
			qualities = append(qualities, s.Quality)
		}
	}
	for _, s := range fs.Imports {
		if evidenceFiles[s.File] && s.Quality != "" {
			qualities = append(qualities, s.Quality)
		}
	}
	for _, s := range fs.DataAccess {
		if evidenceFiles[s.File] && s.Quality != "" {
			qualities = append(qualities, s.Quality)
		}
	}
	for _, s := range fs.Middlewares {
		if evidenceFiles[s.File] && s.Quality != "" {
			qualities = append(qualities, s.Quality)
		}
	}
	for _, s := range fs.Routes {
		if evidenceFiles[s.File] && s.Quality != "" {
			qualities = append(qualities, s.Quality)
		}
	}
	for _, s := range fs.Files {
		if evidenceFiles[s.File] && s.Quality != "" {
			qualities = append(qualities, s.Quality)
		}
	}

	if len(qualities) == 0 {
		// No quality annotations on any contributing facts — conservative default
		return facts.QualityHeuristic
	}
	return facts.MinQuality(qualities...)
}

// ruleAppliesToRepo returns true if at least one of the rule's languages
// is present in the repository.
func ruleAppliesToRepo(rule Rule, repoLanguages []string) bool {
	for _, rl := range rule.Languages {
		for _, repoLang := range repoLanguages {
			if rl == repoLang {
				return true
			}
		}
	}
	return false
}
