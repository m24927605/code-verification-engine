package rules

import (
	"github.com/verabase/code-verification-engine/internal/facts"
	"github.com/verabase/code-verification-engine/internal/typegraph"
)

// RuleFile represents a parsed YAML rule file.
type RuleFile struct {
	Version string `yaml:"version"`
	Profile string `yaml:"profile"`
	Rules   []Rule `yaml:"rules"`
}

// Rule represents a single verification rule.
type Rule struct {
	ID        string   `yaml:"id"`
	Title     string   `yaml:"title"`
	Category  string   `yaml:"category"`
	Severity  string   `yaml:"severity"`
	Languages []string `yaml:"languages"`
	Type      string   `yaml:"type"`
	Target    string   `yaml:"target"`
	Message   string   `yaml:"message"`
	Where            *Where       `yaml:"where,omitempty"`
	MatcherClass     MatcherClass `yaml:"matcher_class"`
	TrustedPassAllowed bool       `yaml:"trusted_pass_allowed,omitempty"`
}

// Where represents optional filtering constraints.
type Where struct {
	NameMatches  []string `yaml:"name_matches,omitempty"`
	NameExact    []string `yaml:"name_exact,omitempty"`
	PathMatches  []string `yaml:"path_matches,omitempty"`
	PathExcludes []string `yaml:"path_excludes,omitempty"`
}

// Status represents a rule evaluation result status.
type Status string

const (
	StatusPass    Status = "pass"
	StatusFail    Status = "fail"
	StatusUnknown Status = "unknown"
)

// Confidence represents evidence strength.
type Confidence string

const (
	ConfidenceHigh   Confidence = "high"
	ConfidenceMedium Confidence = "medium"
	ConfidenceLow    Confidence = "low"
)

// VerificationLevel represents the reasoning type used.
type VerificationLevel string

const (
	VerificationVerified        VerificationLevel = "verified"
	VerificationStrongInference VerificationLevel = "strong_inference"
	VerificationWeakInference   VerificationLevel = "weak_inference"
)

// MatcherClass categorizes the type of evidence a rule matcher produces.
type MatcherClass string

const (
	MatcherProof       MatcherClass = "proof_matcher"
	MatcherStructural  MatcherClass = "structural_matcher"
	MatcherHeuristic   MatcherClass = "heuristic_matcher"
	MatcherAttestation MatcherClass = "attestation_matcher"
)

// TrustClass indicates how much a finding can be trusted without human review.
type TrustClass string

const (
	TrustMachineTrusted        TrustClass = "machine_trusted"
	TrustAdvisory              TrustClass = "advisory"
	TrustHumanOrRuntimeRequired TrustClass = "human_or_runtime_required"
)

// Finding represents the result of evaluating a single rule.
type Finding struct {
	RuleID            string            `json:"rule_id"`
	Status            Status            `json:"status"`
	Confidence        Confidence        `json:"confidence"`
	VerificationLevel VerificationLevel `json:"verification_level"`
	TrustClass        TrustClass        `json:"trust_class"`
	Message           string            `json:"message"`
	Evidence          []Evidence        `json:"evidence"`
	UnknownReasons    []string          `json:"unknown_reasons,omitempty"`
	MatcherClass      MatcherClass      `json:"matcher_class,omitempty"`
	VerdictBasis      string            `json:"verdict_basis,omitempty"`
	FactQualityFloor  string            `json:"fact_quality_floor,omitempty"`
}

// Evidence represents a piece of evidence supporting a finding.
type Evidence struct {
	ID        string `json:"evidence_id,omitempty"`
	File      string `json:"file"`
	LineStart int    `json:"line_start"`
	LineEnd   int    `json:"line_end"`
	Symbol    string `json:"symbol"`
	Excerpt   string `json:"excerpt,omitempty"`
}

// SkippedRule records a rule that was skipped during evaluation.
type SkippedRule struct {
	RuleID string `json:"rule_id"`
	Reason string `json:"reason"`
}

// ExecutionResult holds the complete result of rule evaluation.
type ExecutionResult struct {
	Findings     []Finding     `json:"findings"`
	SkippedRules []SkippedRule `json:"skipped_rules"`
}

// FactSet groups all fact types for rule evaluation.
type FactSet struct {
	Symbols       []facts.SymbolFact
	Imports       []facts.ImportFact
	Middlewares   []facts.MiddlewareFact
	Routes        []facts.RouteFact
	Tests         []facts.TestFact
	DataAccess    []facts.DataAccessFact
	Secrets       []facts.SecretFact
	Files         []facts.FileFact
	Calls         []facts.CallFact
	RouteBindings []facts.RouteBindingFact
	AppBindings   []facts.AppBindingFact
	ConfigReads   []facts.ConfigReadFact
	FileRoles     []facts.FileRoleFact
	TypeGraph     *typegraph.TypeGraph

	// AnalyzerStatus records the status of each language analyzer.
	// Keys are language names (e.g., "go", "typescript").
	// Values are "ok", "partial", or "error".
	// A missing key means the analyzer did not run for that language.
	AnalyzerStatus map[string]string
}
