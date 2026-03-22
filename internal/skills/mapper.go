package skills

import (
	"strings"

	"github.com/verabase/code-verification-engine/internal/facts"
	"github.com/verabase/code-verification-engine/internal/rules"
)

// candidateSignal is an intermediate signal before aggregation.
type candidateSignal struct {
	SkillID          string
	Category         SignalCategory
	Status           SignalStatus
	Confidence       SignalConfidence
	TrustClass       string
	EvidenceStrength EvidenceStrength
	Message          string
	SourceRuleIDs    []string
	Evidence         []rules.Evidence
}

// ruleToSignalMapping defines how a verification rule maps to a skill signal.
type ruleToSignalMapping struct {
	RuleID           string
	SkillID          string
	Category         SignalCategory
	PassBehavior     signalBehavior // what to do when the rule passes
	FailBehavior     signalBehavior // what to do when the rule fails
	MaxTrustClass    string         // ceiling for trust_class
	MaxConfidence    SignalConfidence
	EvidenceStrength EvidenceStrength
}

type signalBehavior int

const (
	behaviorIgnore     signalBehavior = iota // don't produce a signal
	behaviorObserved                         // map to observed (if evidence)
	behaviorInferred                         // map to inferred
	behaviorNegative                         // map to risk_exposure category
)

// signalMappings defines the finding-to-signal mapping table.
// This is the core policy of what verification results mean for skills.
var signalMappings = []ruleToSignalMapping{
	{
		RuleID: "SEC-AUTH-001", SkillID: "backend_auth.jwt_middleware",
		Category: CategoryImplementation,
		// pass = middleware exists -> observed implementation
		// fail = middleware missing -> no positive signal
		PassBehavior: behaviorObserved, FailBehavior: behaviorIgnore,
		MaxTrustClass: "advisory", MaxConfidence: ConfidenceMedium,
		EvidenceStrength: EvidenceHeuristic,
	},
	{
		RuleID: "SEC-AUTH-002", SkillID: "backend_routing.middleware_binding",
		Category: CategoryImplementation,
		PassBehavior: behaviorObserved, FailBehavior: behaviorIgnore,
		MaxTrustClass: "advisory", MaxConfidence: ConfidenceMedium,
		EvidenceStrength: EvidenceHeuristic,
	},
	{
		RuleID: "SEC-SECRET-001", SkillID: "backend_security.secret_hygiene",
		Category: CategoryHygiene,
		// pass = no secrets -> positive hygiene signal
		// fail = secrets found -> risk exposure, NOT positive hygiene
		PassBehavior: behaviorObserved, FailBehavior: behaviorNegative,
		MaxTrustClass: "machine_trusted", MaxConfidence: ConfidenceHigh,
		EvidenceStrength: EvidenceDirect,
	},
	{
		RuleID: "ARCH-LAYER-001", SkillID: "backend_architecture.db_layering",
		Category: CategoryImplementation,
		// pass = proper layering -> structural evidence of architecture skill
		// fail = direct DB in controller -> still evidence of contact
		PassBehavior: behaviorObserved, FailBehavior: behaviorInferred,
		MaxTrustClass: "advisory", MaxConfidence: ConfidenceMedium,
		EvidenceStrength: EvidenceStructural,
	},
	{
		RuleID: "ARCH-ERR-001", SkillID: "backend_runtime.error_handling",
		Category: CategoryImplementation,
		PassBehavior: behaviorObserved, FailBehavior: behaviorIgnore,
		MaxTrustClass: "advisory", MaxConfidence: ConfidenceMedium,
		EvidenceStrength: EvidenceHeuristic,
	},
	{
		RuleID: "QUAL-SHUTDOWN-001", SkillID: "backend_runtime.graceful_shutdown",
		Category: CategoryImplementation,
		PassBehavior: behaviorObserved, FailBehavior: behaviorIgnore,
		MaxTrustClass: "advisory", MaxConfidence: ConfidenceMedium,
		EvidenceStrength: EvidenceHeuristic,
	},
	{
		RuleID: "FE-XSS-001", SkillID: "frontend_security.xss_sensitive_api_usage",
		Category: CategoryRiskExposure,
		// fail = dangerous API usage detected -> risk exposure signal
		// pass = no dangerous usage -> no signal (absence is not evidence)
		PassBehavior: behaviorIgnore, FailBehavior: behaviorObserved,
		MaxTrustClass: "advisory", MaxConfidence: ConfidenceMedium,
		EvidenceStrength: EvidenceHeuristic,
	},
	{
		RuleID: "FE-XSS-002", SkillID: "frontend_security.xss_sensitive_api_usage",
		Category: CategoryRiskExposure,
		PassBehavior: behaviorIgnore, FailBehavior: behaviorObserved,
		MaxTrustClass: "advisory", MaxConfidence: ConfidenceMedium,
		EvidenceStrength: EvidenceHeuristic,
	},
	{
		RuleID: "FE-AUTH-001", SkillID: "frontend_auth.route_guarding",
		Category: CategoryImplementation,
		PassBehavior: behaviorObserved, FailBehavior: behaviorIgnore,
		MaxTrustClass: "advisory", MaxConfidence: ConfidenceMedium,
		EvidenceStrength: EvidenceHeuristic,
	},
	{
		RuleID: "TEST-AUTH-001", SkillID: "testing.auth_module_tests",
		Category: CategoryImplementation,
		PassBehavior: behaviorObserved, FailBehavior: behaviorIgnore,
		MaxTrustClass: "advisory", MaxConfidence: ConfidenceMedium,
		EvidenceStrength: EvidenceHeuristic,
	},
	{
		RuleID: "QUAL-LOG-002", SkillID: "observability.request_logging",
		Category: CategoryImplementation,
		PassBehavior: behaviorObserved, FailBehavior: behaviorIgnore,
		MaxTrustClass: "advisory", MaxConfidence: ConfidenceMedium,
		EvidenceStrength: EvidenceHeuristic,
	},
}

// MapFindings generates candidate signals from verification findings.
func MapFindings(findings []rules.Finding, profile *Profile) []candidateSignal {
	// Index profile signals for quick lookup
	profileSkills := make(map[string]SignalDefinition)
	for _, sd := range profile.Signals {
		profileSkills[sd.SkillID] = sd
	}

	// Build a rule-to-mapping index
	ruleMap := make(map[string][]ruleToSignalMapping)
	for _, m := range signalMappings {
		ruleMap[m.RuleID] = append(ruleMap[m.RuleID], m)
	}

	var candidates []candidateSignal

	for _, f := range findings {
		mappings, ok := ruleMap[f.RuleID]
		if !ok {
			continue
		}
		for _, m := range mappings {
			// Check this skill is in the profile
			if _, inProfile := profileSkills[m.SkillID]; !inProfile {
				continue
			}

			var behavior signalBehavior
			switch f.Status {
			case rules.StatusPass:
				behavior = m.PassBehavior
			case rules.StatusFail:
				behavior = m.FailBehavior
			default:
				continue // unknown status -> skip
			}

			if behavior == behaviorIgnore {
				continue
			}

			cs := candidateSignal{
				SkillID:          m.SkillID,
				Category:         m.Category,
				TrustClass:       capTrustClass(string(f.TrustClass), m.MaxTrustClass),
				EvidenceStrength: m.EvidenceStrength,
				SourceRuleIDs:    []string{f.RuleID},
				Evidence:         f.Evidence,
			}

			switch behavior {
			case behaviorObserved:
				if len(f.Evidence) > 0 {
					cs.Status = StatusObserved
				} else {
					cs.Status = StatusInferred
				}
				cs.Confidence = m.MaxConfidence
				cs.Message = "Repository contains evidence of " + m.SkillID
			case behaviorInferred:
				cs.Status = StatusInferred
				cs.Confidence = ConfidenceLow
				cs.Message = "Indirect evidence suggests contact with " + m.SkillID
			case behaviorNegative:
				cs.Category = CategoryRiskExposure
				cs.Status = StatusObserved
				cs.Confidence = m.MaxConfidence
				cs.Message = "Repository shows risk exposure related to " + m.SkillID
			}

			candidates = append(candidates, cs)
		}
	}

	return candidates
}

// MapFacts generates candidate signals directly from facts, bypassing the rule layer.
// This covers cases where skill evidence can be derived from raw fact data
// without needing a verification rule to fire first.
func MapFacts(fs *rules.FactSet, profile *Profile) []candidateSignal {
	if fs == nil {
		return nil
	}

	profileSkills := make(map[string]SignalDefinition)
	for _, sd := range profile.Signals {
		profileSkills[sd.SkillID] = sd
	}

	var candidates []candidateSignal

	// 1. JWT middleware: direct from MiddlewareFact with auth/jwt kind
	if _, inProfile := profileSkills["backend_auth.jwt_middleware"]; inProfile {
		for _, mw := range fs.Middlewares {
			if mw.Kind == "auth" || strings.Contains(strings.ToLower(mw.Name), "jwt") {
				candidates = append(candidates, candidateSignal{
					SkillID:          "backend_auth.jwt_middleware",
					Category:         CategoryImplementation,
					Status:           StatusObserved,
					Confidence:       ConfidenceMedium,
					TrustClass:       "advisory",
					EvidenceStrength: evidenceStrengthFromQuality(mw.Quality),
					Message:          "Direct middleware fact: " + mw.Name,
					Evidence:         []rules.Evidence{{File: mw.File, LineStart: mw.Span.Start, LineEnd: mw.Span.End, Symbol: mw.Name}},
				})
			}
		}
	}

	// 2. Route binding: direct from RouteBindingFact
	if _, inProfile := profileSkills["backend_routing.middleware_binding"]; inProfile {
		for _, rb := range fs.RouteBindings {
			if len(rb.Middlewares) > 0 {
				candidates = append(candidates, candidateSignal{
					SkillID:          "backend_routing.middleware_binding",
					Category:         CategoryImplementation,
					Status:           StatusObserved,
					Confidence:       ConfidenceMedium,
					TrustClass:       "advisory",
					EvidenceStrength: evidenceStrengthFromQuality(rb.Quality),
					Message:          "Direct route binding fact with middleware",
					Evidence:         []rules.Evidence{{File: rb.File, LineStart: rb.Span.Start, LineEnd: rb.Span.End, Symbol: rb.Handler}},
				})
			}
		}
	}

	// 3. DB layering: direct from DataAccessFact + FileRoleFact
	if _, inProfile := profileSkills["backend_architecture.db_layering"]; inProfile {
		if len(fs.DataAccess) > 0 {
			// Check if data access is confined to repository-layer files
			hasRepoLayer := false
			for _, fr := range fs.FileRoles {
				if fr.Role == "repository" || fr.Role == "dao" || fr.Role == "model" {
					hasRepoLayer = true
					break
				}
			}
			if hasRepoLayer {
				for _, da := range fs.DataAccess {
					candidates = append(candidates, candidateSignal{
						SkillID:          "backend_architecture.db_layering",
						Category:         CategoryImplementation,
						Status:           StatusObserved,
						Confidence:       ConfidenceMedium,
						TrustClass:       "advisory",
						EvidenceStrength: EvidenceStructural,
						Message:          "Direct data access fact in layered architecture",
						Evidence:         []rules.Evidence{{File: da.File, LineStart: da.Span.Start, LineEnd: da.Span.End, Symbol: da.Operation}},
					})
					break // one is enough
				}
			}
		}
	}

	// 4. Testing: direct from TestFact for auth-related tests
	if _, inProfile := profileSkills["testing.auth_module_tests"]; inProfile {
		for _, tf := range fs.Tests {
			nameLower := strings.ToLower(tf.TestName)
			fileLower := strings.ToLower(tf.File)
			if strings.Contains(nameLower, "auth") || strings.Contains(fileLower, "auth") {
				candidates = append(candidates, candidateSignal{
					SkillID:          "testing.auth_module_tests",
					Category:         CategoryImplementation,
					Status:           StatusObserved,
					Confidence:       ConfidenceMedium,
					TrustClass:       "advisory",
					EvidenceStrength: evidenceStrengthFromQuality(tf.Quality),
					Message:          "Direct test fact: " + tf.TestName,
					Evidence:         []rules.Evidence{{File: tf.File, LineStart: tf.Span.Start, LineEnd: tf.Span.End, Symbol: tf.TestName}},
				})
			}
		}
	}

	// 5. Config reads: direct from ConfigReadFact for env-based config (observability/hygiene)
	if _, inProfile := profileSkills["backend_security.secret_hygiene"]; inProfile {
		envConfigCount := 0
		for _, cr := range fs.ConfigReads {
			if cr.SourceKind == "env" || cr.SourceKind == "environment" {
				envConfigCount++
			}
		}
		if envConfigCount > 0 && len(fs.Secrets) == 0 {
			candidates = append(candidates, candidateSignal{
				SkillID:          "backend_security.secret_hygiene",
				Category:         CategoryHygiene,
				Status:           StatusInferred,
				Confidence:       ConfidenceLow,
				TrustClass:       "advisory",
				EvidenceStrength: EvidenceStructural,
				Message:          "Environment-based config reads detected without hardcoded secrets",
			})
		}
	}

	return candidates
}

// evidenceStrengthFromQuality maps fact quality to evidence strength.
func evidenceStrengthFromQuality(q facts.FactQuality) EvidenceStrength {
	switch q {
	case facts.QualityProof:
		return EvidenceDirect
	case facts.QualityStructural:
		return EvidenceStructural
	default:
		return EvidenceHeuristic
	}
}

// capTrustClass returns the lower (more conservative) trust class.
func capTrustClass(actual, ceiling string) string {
	rank := map[string]int{
		"human_or_runtime_required": 0,
		"advisory":                  1,
		"machine_trusted":           2,
	}
	a, aOK := rank[actual]
	c, cOK := rank[ceiling]
	if !aOK {
		return ceiling
	}
	if !cOK {
		return actual
	}
	if a < c {
		return actual
	}
	return ceiling
}
