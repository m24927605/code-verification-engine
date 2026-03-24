package skills

import (
	"github.com/verabase/code-verification-engine/internal/rules"
)

// Mode defines the engine execution mode.
type Mode string

const (
	ModeVerification   Mode = "verification"
	ModeSkillInference Mode = "skill_inference"
	ModeBoth           Mode = "both"
)

// ValidMode returns true if the mode string is a recognized engine mode.
func ValidMode(m string) bool {
	switch Mode(m) {
	case ModeVerification, ModeSkillInference, ModeBoth:
		return true
	}
	return false
}

// DefaultMode returns the backward-compatible default.
func DefaultMode() Mode { return ModeVerification }

// IncludesVerification returns true if the mode includes verification output.
func (m Mode) IncludesVerification() bool {
	return m == ModeVerification || m == ModeBoth
}

// IncludesSkillInference returns true if the mode includes skill inference output.
func (m Mode) IncludesSkillInference() bool {
	return m == ModeSkillInference || m == ModeBoth
}

// SignalStatus is the skill signal outcome.
type SignalStatus string

const (
	StatusObserved    SignalStatus = "observed"
	StatusInferred    SignalStatus = "inferred"
	StatusUnsupported SignalStatus = "unsupported"
)

// SignalConfidence describes how confident the engine is in the signal.
type SignalConfidence string

const (
	ConfidenceHigh   SignalConfidence = "high"
	ConfidenceMedium SignalConfidence = "medium"
	ConfidenceLow    SignalConfidence = "low"
)

// EvidenceStrength describes the quality of the backing evidence.
type EvidenceStrength string

const (
	EvidenceDirect     EvidenceStrength = "direct"
	EvidenceStructural EvidenceStrength = "structural"
	EvidenceHeuristic  EvidenceStrength = "heuristic"
)

// SignalCategory distinguishes between positive skills and risk exposure.
type SignalCategory string

const (
	CategoryImplementation SignalCategory = "implementation"
	CategoryHygiene        SignalCategory = "hygiene"
	CategoryRiskExposure   SignalCategory = "risk_exposure"
)

// Signal is a single skill signal in the skill report.
type Signal struct {
	ID               string           `json:"id"`
	SkillID          string           `json:"skill_id"`
	Category         SignalCategory   `json:"category"`
	Status           SignalStatus     `json:"status"`
	Confidence       SignalConfidence `json:"confidence"`
	TrustClass       string           `json:"trust_class"`
	EvidenceStrength EvidenceStrength `json:"evidence_strength"`
	Message          string           `json:"message"`
	SourceRuleIDs    []string         `json:"source_rule_ids,omitempty"`
	Evidence         []rules.Evidence `json:"evidence,omitempty"`
	UnknownReasons   []string         `json:"unknown_reasons,omitempty"`
}

// Summary counts signals by status.
type Summary struct {
	Observed    int `json:"observed"`
	Inferred    int `json:"inferred"`
	Unsupported int `json:"unsupported"`
}

// Technology is a simplified detected stack component.
type Technology struct {
	Name string `json:"name"`
	Kind string `json:"kind"`
}

// Report is the top-level skill inference report written to skills.json.
type Report struct {
	SchemaVersion string       `json:"schema_version"`
	RepoPath      string       `json:"repo_path"`
	Profile       string       `json:"profile"`
	Skills        []string     `json:"skills,omitempty"`
	Languages     []string     `json:"languages,omitempty"`
	Frameworks    []string     `json:"frameworks,omitempty"`
	Technologies  []Technology `json:"technologies,omitempty"`
	Signals       []Signal     `json:"signals"`
	Summary       Summary      `json:"summary"`
}

// SignalDefinition defines a skill signal within a profile.
type SignalDefinition struct {
	ID       string         `json:"id"`
	SkillID  string         `json:"skill_id"`
	Category SignalCategory `json:"category"`
	Message  string         `json:"message"`
}

// SkillReportVersion is the schema version for skills.json.
const SkillReportVersion = "1.0.0"
