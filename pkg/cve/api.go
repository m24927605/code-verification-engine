// Package cve provides the stable public API for the Code Verification Engine.
//
// This is the ONLY package external consumers should import.
// Internal packages (internal/*) are implementation details and may change
// without notice.
package cve

import (
	"context"
	"io"
)

// Version is the engine version, set via build flags.
var Version = "dev"

// VerifyInput defines the input for a verification run.
type VerifyInput struct {
	RepoPath     string // Local git repository path (required)
	Ref          string // Git ref (branch, tag, SHA). Default: "HEAD"
	Profile      string // Verification profile. Default: "backend-api"
	ClaimSet     string // Optional claim set for claim-centric output
	Format       string // Output format: "json", "md", "both". Default: "both"
	Strict       bool   // Fail on any analyzer error
	OutputDir    string // Output directory (required)
	Mode         string // Engine mode: "verification", "skill_inference", "both". Default: "verification"
	SkillProfile string // Skill inference profile. Default: "github-engineer-core"
}

// VerifyOutput is the complete verification result.
type VerifyOutput struct {
	ExitCode int    `json:"exit_code"`
	Success  bool   `json:"success"`

	// Typed structured outputs — stable contracts with enforced trust boundaries.
	// Consumers MUST use these typed fields to access findings and inspect TrustClass.
	Scan   ScanOutput   `json:"scan"`   // scan.json content
	Report ReportOutput `json:"report"` // report.json content

	// Skills is populated when mode includes skill_inference. Zero-value when verification-only.
	Skills SkillOutput `json:"skills,omitempty"`

	Errors []string `json:"errors,omitempty"`
}

// Engine is the main verification engine interface.
type Engine interface {
	Verify(ctx context.Context, input VerifyInput) (*VerifyOutput, error)
	ListProfiles() []ProfileInfo
	ListClaimSets() []ClaimSetInfo
	ValidateProfile(name string) bool
	ListSkillProfiles() []SkillProfileInfo
	ValidateSkillProfile(name string) bool
}

// SkillProfileInfo describes an available skill inference profile.
type SkillProfileInfo struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	SignalCount int    `json:"signal_count"`
}

// ProfileInfo describes an available profile.
type ProfileInfo struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	RuleCount   int    `json:"rule_count"`
}

// ClaimSetInfo describes an available claim set.
type ClaimSetInfo struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	ClaimCount  int    `json:"claim_count"`
}

// AnalyzerPlugin is the extension interface for custom analyzers.
type AnalyzerPlugin interface {
	Name() string
	Languages() []string
	Extensions() []string // file extensions to scan (e.g., ".rs", ".rb"); empty = use built-in defaults
	Analyze(ctx context.Context, dir string, files []string) ([]byte, error)
}

// ScanHook is called at scan lifecycle points.
type ScanHook func(event ScanEvent)

// ScanEvent represents a scan lifecycle event.
type ScanEvent struct {
	Type string      `json:"type"` // "scan_start", "analyzer_complete", "finding", "scan_complete"
	Data interface{} `json:"data"`
}

// LLMProvider is the interface for LLM backends used by the interpretation layer.
// Implementations can wrap Claude, OpenAI, or any other LLM API.
type LLMProvider interface {
	Complete(ctx context.Context, prompt string) (string, error)
}

// Option configures the engine.
type Option func(*engineConfig)

type engineConfig struct {
	progress    io.Writer
	hooks       []ScanHook
	interpret   bool
	llmProvider LLMProvider
	plugins     []AnalyzerPlugin
}

// WithProgress sets the progress writer (default: discard).
func WithProgress(w io.Writer) Option {
	return func(c *engineConfig) { c.progress = w }
}

// WithHook adds a scan lifecycle hook.
func WithHook(hook ScanHook) Option {
	return func(c *engineConfig) { c.hooks = append(c.hooks, hook) }
}

// WithInterpretation enables the LLM interpretation layer with the given provider.
func WithInterpretation(provider LLMProvider) Option {
	return func(c *engineConfig) {
		c.interpret = true
		c.llmProvider = provider
	}
}

// WithAnalyzerPlugin registers a custom analyzer plugin.
func WithAnalyzerPlugin(plugin AnalyzerPlugin) Option {
	return func(c *engineConfig) { c.plugins = append(c.plugins, plugin) }
}
