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
	Where     *Where   `yaml:"where,omitempty"`
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

// Finding represents the result of evaluating a single rule.
type Finding struct {
	RuleID            string            `json:"rule_id"`
	Status            Status            `json:"status"`
	Confidence        Confidence        `json:"confidence"`
	VerificationLevel VerificationLevel `json:"verification_level"`
	Message           string            `json:"message"`
	Evidence          []Evidence        `json:"evidence"`
	UnknownReasons    []string          `json:"unknown_reasons,omitempty"`
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
	Symbols     []facts.SymbolFact
	Imports     []facts.ImportFact
	Middlewares []facts.MiddlewareFact
	Routes      []facts.RouteFact
	Tests       []facts.TestFact
	DataAccess  []facts.DataAccessFact
	Secrets     []facts.SecretFact
	Files       []facts.FileFact
	TypeGraph   *typegraph.TypeGraph
}
