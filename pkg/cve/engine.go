package cve

import (
	"context"
	"fmt"
	"io"

	"github.com/verabase/code-verification-engine/internal/claims"
	internalEngine "github.com/verabase/code-verification-engine/internal/engine"
	"github.com/verabase/code-verification-engine/internal/interpret"
	"github.com/verabase/code-verification-engine/internal/rules"
	"github.com/verabase/code-verification-engine/internal/skills"
)

// llmProviderBridge adapts the public LLMProvider interface to the internal one.
type llmProviderBridge struct {
	pub LLMProvider
}

func (b *llmProviderBridge) Complete(ctx context.Context, prompt string) (string, error) {
	return b.pub.Complete(ctx, prompt)
}

type defaultEngine struct {
	config engineConfig
}

// NewEngine creates a new verification engine with the given options.
func NewEngine(opts ...Option) Engine {
	cfg := engineConfig{
		progress: io.Discard,
	}
	for _, opt := range opts {
		opt(&cfg)
	}
	return &defaultEngine{config: cfg}
}

func (e *defaultEngine) Verify(ctx context.Context, input VerifyInput) (*VerifyOutput, error) {
	// Validate mode — fail fast on invalid values (acceptance spec 2.1)
	if input.Mode != "" && !skills.ValidMode(input.Mode) {
		return nil, fmt.Errorf("invalid mode %q: allowed modes are verification, skill_inference, both", input.Mode)
	}

	// Validate skill profile when mode includes skill inference (acceptance spec 2.2)
	mode := skills.Mode(input.Mode)
	if input.Mode == "" {
		mode = skills.DefaultMode()
	}
	if mode.IncludesSkillInference() {
		spName := input.SkillProfile
		if spName == "" {
			spName = "github-engineer-core"
		}
		if !skills.ValidateProfileName(spName) {
			available := skills.ListProfileNames()
			return nil, fmt.Errorf("unknown skill profile %q: available profiles: %v", spName, available)
		}
	}

	profile := input.Profile
	if profile == "" {
		profile = "backend-api"
	}
	ref := input.Ref
	if ref == "" {
		ref = "HEAD"
	}
	format := input.Format
	if format == "" {
		format = "both"
	}

	// Bridge public ScanHook callbacks to internal ScanHooks
	var hooks *internalEngine.ScanHooks
	if len(e.config.hooks) > 0 {
		hooks = &internalEngine.ScanHooks{
			OnScanStart: func(repoPath, ref, profile string) {
				for _, h := range e.config.hooks {
					h(ScanEvent{Type: "scan_start", Data: map[string]string{
						"repo_path": repoPath, "ref": ref, "profile": profile,
					}})
				}
			},
			OnAnalyzerComplete: func(language string, fileCount int, skippedCount int) {
				for _, h := range e.config.hooks {
					h(ScanEvent{Type: "analyzer_complete", Data: map[string]interface{}{
						"language": language, "file_count": fileCount, "skipped_count": skippedCount,
					}})
				}
			},
			OnFindingProduced: func(finding interface{}) {
				for _, h := range e.config.hooks {
					h(ScanEvent{Type: "finding", Data: finding})
				}
			},
			OnScanComplete: func(exitCode int, outputDir string) {
				for _, h := range e.config.hooks {
					h(ScanEvent{Type: "scan_complete", Data: map[string]interface{}{
						"exit_code": exitCode, "output_dir": outputDir,
					}})
				}
			},
		}
	}

	// Bridge LLM provider if interpretation is enabled, wrapping with SafeProvider
	// for production hardening (timeout, retry, budget, response size guard).
	var llmProvider interpret.LLMProvider
	if e.config.interpret && e.config.llmProvider != nil {
		bridged := &llmProviderBridge{pub: e.config.llmProvider}
		llmProvider = interpret.NewSafeProvider(bridged, interpret.DefaultProviderConfig())
	}

	// Bridge analyzer plugins
	var plugins []internalEngine.PluginAnalyzer
	for _, p := range e.config.plugins {
		p := p // capture
		plugins = append(plugins, internalEngine.PluginAnalyzer{
			PluginName: p.Name(),
			Langs:      p.Languages(),
			Exts:       p.Extensions(),
			AnalyzeFn:  p.Analyze,
		})
	}

	result := internalEngine.Run(internalEngine.Config{
		Ctx:          ctx,
		RepoPath:     input.RepoPath,
		Ref:          ref,
		Profile:      profile,
		ClaimSet:     input.ClaimSet,
		OutputDir:    input.OutputDir,
		Format:       format,
		Strict:       input.Strict,
		Interpret:    e.config.interpret,
		LLMProvider:  llmProvider,
		Progress:     e.config.progress,
		Hooks:        hooks,
		Plugins:      plugins,
		Mode:         input.Mode,
		SkillProfile: input.SkillProfile,
	})

	// Convert internal scan report to typed public output
	scanOut := ScanOutput{
		ScanSchemaVersion: result.Scan.ScanSchemaVersion,
		RepoPath:          result.Scan.RepoPath,
		RepoName:          result.Scan.RepoName,
		Ref:               result.Scan.Ref,
		CommitSHA:         result.Scan.CommitSHA,
		ScannedAt:         result.Scan.ScannedAt,
		Languages:         result.Scan.Languages,
		FileCount:         result.Scan.FileCount,
		Partial:           result.Scan.Partial,
		Analyzers:         result.Scan.Analyzers,
		Errors:            result.Scan.Errors,
		Profile:           result.Scan.Profile,
	}

	// Convert internal findings to typed public output with trust summary
	var trustSummary TrustSummary
	findings := make([]FindingOutput, 0, len(result.Report.Findings))
	for _, f := range result.Report.Findings {
		evidence := make([]EvidenceOutput, 0, len(f.Evidence))
		for _, ev := range f.Evidence {
			evidence = append(evidence, EvidenceOutput{
				ID:        ev.ID,
				File:      ev.File,
				LineStart: ev.LineStart,
				LineEnd:   ev.LineEnd,
				Symbol:    ev.Symbol,
				Excerpt:   ev.Excerpt,
			})
		}
		fo := FindingOutput{
			RuleID:            f.RuleID,
			Status:            string(f.Status),
			Confidence:        string(f.Confidence),
			VerificationLevel: string(f.VerificationLevel),
			TrustClass:        string(f.TrustClass),
			Message:           f.Message,
			Evidence:          evidence,
			UnknownReasons:    f.UnknownReasons,
		}
		findings = append(findings, fo)

		switch f.TrustClass {
		case rules.TrustMachineTrusted:
			trustSummary.MachineTrusted++
		case rules.TrustAdvisory:
			trustSummary.Advisory++
		case rules.TrustHumanOrRuntimeRequired:
			trustSummary.HumanOrRuntimeRequired++
		}
	}

	skipped := make([]SkippedRuleOutput, 0, len(result.Report.SkippedRules))
	for _, sr := range result.Report.SkippedRules {
		skipped = append(skipped, SkippedRuleOutput{
			RuleID: sr.RuleID,
			Reason: sr.Reason,
		})
	}

	// Populate capability summary from internal report
	capSummary := CapabilitySummaryOutput{
		FullySupported: result.Report.CapabilitySummary.FullySupported,
		Partial:        result.Report.CapabilitySummary.Partial,
		Unsupported:    result.Report.CapabilitySummary.Unsupported,
		Degraded:       result.Report.CapabilitySummary.Degraded,
	}

	// Compute trust guidance
	guidance := computeTrustGuidance(findings, trustSummary, capSummary)

	sigSummary := SignalSummaryOutput{
		ActionableFail:         result.Report.SignalSummary.ActionableFail,
		AdvisoryFail:           result.Report.SignalSummary.AdvisoryFail,
		InformationalDetection: result.Report.SignalSummary.InformationalDetection,
		Unknown:                result.Report.SignalSummary.Unknown,
	}

	reportOut := ReportOutput{
		ReportSchemaVersion: result.Report.ReportSchemaVersion,
		Partial:             result.Report.Partial,
		Summary: ReportSummaryOutput{
			Pass:    result.Report.Summary.Pass,
			Fail:    result.Report.Summary.Fail,
			Unknown: result.Report.Summary.Unknown,
		},
		TrustSummary:      trustSummary,
		CapabilitySummary: capSummary,
		SignalSummary:     sigSummary,
		TrustGuidance:     guidance,
		Findings:          findings,
		SkippedRules:      skipped,
		Errors:            result.Report.Errors,
	}

	// Bridge skill report if present
	var skillOut SkillOutput
	if result.SkillReport != nil {
		skillOut = bridgeSkillReport(result.SkillReport)
	}

	return &VerifyOutput{
		ExitCode: result.ExitCode,
		Success:  result.ExitCode == 0,
		Scan:     scanOut,
		Report:   reportOut,
		Skills:   skillOut,
		Errors:   result.Errors,
	}, nil
}

func (e *defaultEngine) ListProfiles() []ProfileInfo {
	profiles := rules.AllProfiles()
	infos := make([]ProfileInfo, 0, len(profiles))
	for name, p := range profiles {
		infos = append(infos, ProfileInfo{
			Name:        name,
			Description: p.Description,
			RuleCount:   len(p.Rules),
		})
	}
	return infos
}

func (e *defaultEngine) ListClaimSets() []ClaimSetInfo {
	sets := claims.AllClaimSets()
	infos := make([]ClaimSetInfo, 0, len(sets))
	for name, cs := range sets {
		infos = append(infos, ClaimSetInfo{
			Name:        name,
			Description: cs.Description,
			ClaimCount:  len(cs.Claims),
		})
	}
	return infos
}

func (e *defaultEngine) ValidateProfile(name string) bool {
	_, ok := rules.GetProfile(name)
	return ok
}

func (e *defaultEngine) ListSkillProfiles() []SkillProfileInfo {
	profiles := skills.AllProfiles()
	infos := make([]SkillProfileInfo, 0, len(profiles))
	for _, p := range profiles {
		infos = append(infos, SkillProfileInfo{
			Name:        p.Name,
			Description: p.Description,
			SignalCount: len(p.Signals),
		})
	}
	return infos
}

func (e *defaultEngine) ValidateSkillProfile(name string) bool {
	return skills.ValidateProfileName(name)
}

func bridgeSkillReport(r *skills.Report) SkillOutput {
	signals := make([]SkillSignalOutput, 0, len(r.Signals))
	for _, s := range r.Signals {
		evidence := make([]EvidenceOutput, 0, len(s.Evidence))
		for _, ev := range s.Evidence {
			evidence = append(evidence, EvidenceOutput{
				ID:        ev.ID,
				File:      ev.File,
				LineStart: ev.LineStart,
				LineEnd:   ev.LineEnd,
				Symbol:    ev.Symbol,
				Excerpt:   ev.Excerpt,
			})
		}
		signals = append(signals, SkillSignalOutput{
			ID:               s.ID,
			SkillID:          s.SkillID,
			Category:         string(s.Category),
			Status:           string(s.Status),
			Confidence:       string(s.Confidence),
			TrustClass:       s.TrustClass,
			EvidenceStrength: string(s.EvidenceStrength),
			Message:          s.Message,
			SourceRuleIDs:    s.SourceRuleIDs,
			Evidence:         evidence,
			UnknownReasons:   s.UnknownReasons,
		})
	}
	return SkillOutput{
		SchemaVersion: r.SchemaVersion,
		Profile:       r.Profile,
		Signals:       signals,
		Summary: SkillSummaryOutput{
			Observed:    r.Summary.Observed,
			Inferred:    r.Summary.Inferred,
			Unsupported: r.Summary.Unsupported,
		},
	}
}

// computeTrustGuidance derives consumer-facing trust guidance from findings.
func computeTrustGuidance(findings []FindingOutput, ts TrustSummary, cs CapabilitySummaryOutput) TrustGuidance {
	g := TrustGuidance{
		DegradedAnalysis: cs.Degraded,
	}

	// CanAutomate: only if ALL findings are machine_trusted AND verified
	allMachineTrustedVerified := len(findings) > 0
	for _, f := range findings {
		if f.TrustClass != "machine_trusted" || f.VerificationLevel != "verified" {
			allMachineTrustedVerified = false
			break
		}
	}
	g.CanAutomate = allMachineTrustedVerified && !cs.Degraded

	// RequiresReview: true if any advisory or human_or_runtime_required findings
	g.RequiresReview = ts.Advisory > 0 || ts.HumanOrRuntimeRequired > 0

	// Build summary
	switch {
	case len(findings) == 0:
		g.Summary = "No findings to evaluate."
	case g.CanAutomate && !g.DegradedAnalysis:
		g.Summary = "All findings are machine-trusted and verified. Safe for automated consumption."
	case g.DegradedAnalysis:
		g.Summary = "Analysis was degraded. Results require manual review before use."
		g.RequiresReview = true
	case g.RequiresReview:
		g.Summary = fmt.Sprintf("%d advisory and %d human-review findings present. Manual review required.",
			ts.Advisory, ts.HumanOrRuntimeRequired)
	default:
		g.Summary = "Findings contain mixed trust levels. Review recommended."
	}

	return g
}
