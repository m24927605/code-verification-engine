package cve

import (
	"context"
	"fmt"
	"io"

	"github.com/verabase/code-verification-engine/internal/artifactsv2"
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
	var agentProvider interpret.LLMProvider
	if e.config.agentRuntime && e.config.agentProvider != nil {
		bridged := &llmProviderBridge{pub: e.config.agentProvider}
		agentProvider = interpret.NewSafeProvider(bridged, interpret.DefaultProviderConfig())
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
		Ctx:           ctx,
		RepoPath:      input.RepoPath,
		Ref:           ref,
		Profile:       profile,
		ClaimSet:      input.ClaimSet,
		OutputDir:     input.OutputDir,
		Format:        format,
		Strict:        input.Strict,
		Interpret:     e.config.interpret,
		LLMProvider:   llmProvider,
		AgentRuntime:  e.config.agentRuntime,
		AgentProvider: agentProvider,
		Progress:      e.config.progress,
		Hooks:         hooks,
		Plugins:       plugins,
		Mode:          input.Mode,
		SkillProfile:  input.SkillProfile,
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

	// Bridge skill report if present
	var skillOut SkillOutput
	if result.SkillReport != nil {
		skillOut = bridgeSkillReport(result.SkillReport)
	}

	var claimOut *ClaimReportOutput
	if result.ClaimReport != nil {
		claimOut = bridgeClaimReport(result.ClaimReport)
	}

	var claimsProjectionOut *ClaimsProjectionOutput
	if result.VerifiableClaimsArtifacts != nil {
		claimsProjectionOut = bridgeClaimsProjection(result.VerifiableClaimsArtifacts)
	}

	var verifiableOut *VerifiableOutput
	if result.VerifiableBundle != nil {
		verifiableOut = bridgeVerifiableBundle(result.VerifiableBundle)
	}

	var reportOut ReportOutput
	if result.VerifiableBundle != nil {
		reportOut = bridgeReport(result.VerifiableBundle.Report)
	}

	return &VerifyOutput{
		ExitCode:         result.ExitCode,
		Success:          result.ExitCode == 0,
		Scan:             scanOut,
		Report:           reportOut,
		Skills:           skillOut,
		Claims:           claimOut,
		ClaimsProjection: claimsProjectionOut,
		Verifiable:       verifiableOut,
		Errors:           result.Errors,
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
	technologies := make([]TechnologyOutput, 0, len(r.Technologies))
	for _, t := range r.Technologies {
		technologies = append(technologies, TechnologyOutput{
			Name: t.Name,
			Kind: t.Kind,
		})
	}
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
		Skills:        append([]string(nil), r.Skills...),
		Languages:     append([]string(nil), r.Languages...),
		Frameworks:    append([]string(nil), r.Frameworks...),
		Technologies:  technologies,
		Signals:       signals,
		Summary: SkillSummaryOutput{
			Observed:    r.Summary.Observed,
			Inferred:    r.Summary.Inferred,
			Unsupported: r.Summary.Unsupported,
		},
	}
}

func bridgeClaimReport(r *claims.ClaimReport) *ClaimReportOutput {
	if r == nil {
		return nil
	}
	verdicts := make([]ClaimVerdictOutput, 0, len(r.Claims))
	for _, v := range r.Claims {
		supportingRules := make([]ClaimRuleResultOutput, 0, len(v.SupportingRules))
		for _, sr := range v.SupportingRules {
			supportingRules = append(supportingRules, ClaimRuleResultOutput{
				RuleID:     sr.RuleID,
				Status:     sr.Status,
				Confidence: sr.Confidence,
				Message:    sr.Message,
			})
		}
		evidenceChain := make([]ClaimEvidenceLinkOutput, 0, len(v.EvidenceChain))
		for _, ev := range v.EvidenceChain {
			evidenceChain = append(evidenceChain, ClaimEvidenceLinkOutput{
				ID:        ev.ID,
				Type:      ev.Type,
				File:      ev.File,
				LineStart: ev.LineStart,
				LineEnd:   ev.LineEnd,
				Symbol:    ev.Symbol,
				Excerpt:   ev.Excerpt,
				FromRule:  ev.FromRule,
				Relation:  ev.Relation,
			})
		}
		verdicts = append(verdicts, ClaimVerdictOutput{
			ClaimID:           v.ClaimID,
			Title:             v.Title,
			Category:          v.Category,
			Status:            v.Status,
			Confidence:        v.Confidence,
			VerificationLevel: v.VerificationLevel,
			TrustBreakdown: ClaimTrustBreakdownOutput{
				MachineTrusted:         v.TrustBreakdown.MachineTrusted,
				Advisory:               v.TrustBreakdown.Advisory,
				HumanOrRuntimeRequired: v.TrustBreakdown.HumanOrRuntimeRequired,
				EffectiveTrustClass:    v.TrustBreakdown.EffectiveTrustClass,
			},
			Summary:         v.Summary,
			SupportingRules: supportingRules,
			EvidenceChain:   evidenceChain,
			UnknownReasons:  append([]string(nil), v.UnknownReasons...),
		})
	}
	return &ClaimReportOutput{
		SchemaVersion: r.SchemaVersion,
		ClaimSetName:  r.ClaimSetName,
		TotalClaims:   r.TotalClaims,
		Verdicts: ClaimVerdictSummaryOutput{
			Verified: r.Verdicts.Verified,
			Passed:   r.Verdicts.Passed,
			Failed:   r.Verdicts.Failed,
			Unknown:  r.Verdicts.Unknown,
			Partial:  r.Verdicts.Partial,
		},
		Claims: verdicts,
	}
}

func bridgeVerifiableBundle(b *artifactsv2.Bundle) *VerifiableOutput {
	if b == nil {
		return nil
	}
	out := &VerifiableOutput{
		Report:    bridgeReportV2(b.Report),
		Evidence:  bridgeEvidenceV2(b.Evidence),
		Skills:    bridgeSkillsV2(b.Skills),
		Trace:     bridgeTraceV2(b.Trace),
		SummaryMD: b.SummaryMD,
		Signature: bridgeSignatureV2(b.Signature),
	}
	return out
}

func bridgeClaimsProjection(a *artifactsv2.ClaimsProjectionArtifacts) *ClaimsProjectionOutput {
	if a == nil {
		return nil
	}
	return &ClaimsProjectionOutput{
		Claims: ClaimsArtifactOutput{
			SchemaVersion: a.Claims.SchemaVersion,
			Repository: ClaimRepositoryRef{
				Path:   a.Claims.Repository.Path,
				Commit: a.Claims.Repository.Commit,
			},
			Claims:  bridgeClaimRecords(a.Claims.Claims),
			Summary: bridgeClaimSummary(a.Claims.Summary),
		},
		Profile:     bridgeProfileArtifact(a.Profile),
		ResumeInput: bridgeResumeInputArtifact(a.ResumeInput),
	}
}

func bridgeClaimRecords(in []artifactsv2.ClaimRecord) []ClaimRecordOutput {
	out := make([]ClaimRecordOutput, 0, len(in))
	for _, claim := range in {
		var scenarioApplicability *ScenarioApplicabilityOutput
		if claim.ScenarioApplicability != nil {
			scenarioApplicability = &ScenarioApplicabilityOutput{
				Hiring:              claim.ScenarioApplicability.Hiring,
				OutsourceAcceptance: claim.ScenarioApplicability.OutsourceAcceptance,
				PMAcceptance:        claim.ScenarioApplicability.PMAcceptance,
			}
		}
		out = append(out, ClaimRecordOutput{
			ClaimID:                  claim.ClaimID,
			Title:                    claim.Title,
			Category:                 claim.Category,
			ClaimType:                claim.ClaimType,
			Status:                   claim.Status,
			SupportLevel:             claim.SupportLevel,
			Confidence:               claim.Confidence,
			VerificationClass:        string(claim.VerificationClass),
			ScenarioApplicability:    scenarioApplicability,
			SourceOrigins:            append([]string(nil), claim.SourceOrigins...),
			SupportingEvidenceIDs:    append([]string(nil), claim.SupportingEvidenceIDs...),
			ContradictoryEvidenceIDs: append([]string(nil), claim.ContradictoryEvidenceIDs...),
			Reason:                   claim.Reason,
			ProjectionEligible:       claim.ProjectionEligible,
		})
	}
	return out
}

func bridgeClaimSummary(in artifactsv2.ClaimSummary) ClaimSummaryOutput {
	return ClaimSummaryOutput{
		Verified:          in.Verified,
		StronglySupported: in.StronglySupported,
		Supported:         in.Supported,
		Weak:              in.Weak,
		Unsupported:       in.Unsupported,
		Contradicted:      in.Contradicted,
	}
}

func bridgeProfileArtifact(in artifactsv2.ProfileArtifact) ProfileArtifactOutput {
	out := ProfileArtifactOutput{
		SchemaVersion: in.SchemaVersion,
		Repository: ClaimRepositoryRef{
			Path:   in.Repository.Path,
			Commit: in.Repository.Commit,
		},
		Technologies: append([]string(nil), in.Technologies...),
		ClaimIDs:     append([]string(nil), in.ClaimIDs...),
	}
	for _, h := range in.Highlights {
		out.Highlights = append(out.Highlights, CapabilityHighlightOutput{
			HighlightID:           h.HighlightID,
			Title:                 h.Title,
			SupportLevel:          h.SupportLevel,
			ClaimIDs:              append([]string(nil), h.ClaimIDs...),
			SupportingEvidenceIDs: append([]string(nil), h.SupportingEvidenceIDs...),
		})
	}
	for _, area := range in.CapabilityAreas {
		out.CapabilityAreas = append(out.CapabilityAreas, CapabilityAreaOutput{
			AreaID:   area.AreaID,
			Title:    area.Title,
			ClaimIDs: append([]string(nil), area.ClaimIDs...),
		})
	}
	return out
}

func bridgeResumeInputArtifact(in artifactsv2.ResumeInputArtifact) ResumeInputArtifactOutput {
	out := ResumeInputArtifactOutput{
		SchemaVersion:     in.SchemaVersion,
		Profile:           bridgeProfileArtifact(in.Profile),
		TechnologySummary: append([]string(nil), in.TechnologySummary...),
		SynthesisConstraints: SynthesisConstraintsOutput{
			AllowUnsupportedClaims:        in.SynthesisConstraints.AllowUnsupportedClaims,
			AllowClaimInvention:           in.SynthesisConstraints.AllowClaimInvention,
			AllowContradictionSuppression: in.SynthesisConstraints.AllowContradictionSuppression,
		},
	}
	for _, claim := range in.VerifiedClaims {
		out.VerifiedClaims = append(out.VerifiedClaims, ResumeClaimStubOutput{
			ClaimID:               claim.ClaimID,
			Title:                 claim.Title,
			SupportLevel:          claim.SupportLevel,
			Confidence:            claim.Confidence,
			SupportingEvidenceIDs: append([]string(nil), claim.SupportingEvidenceIDs...),
		})
	}
	for _, claim := range in.StronglySupportedClaims {
		out.StronglySupportedClaims = append(out.StronglySupportedClaims, ResumeClaimStubOutput{
			ClaimID:               claim.ClaimID,
			Title:                 claim.Title,
			SupportLevel:          claim.SupportLevel,
			Confidence:            claim.Confidence,
			SupportingEvidenceIDs: append([]string(nil), claim.SupportingEvidenceIDs...),
		})
	}
	for _, ref := range in.EvidenceReferences {
		out.EvidenceReferences = append(out.EvidenceReferences, EvidenceReferenceOutput{
			EvidenceID:            ref.EvidenceID,
			ClaimIDs:              append([]string(nil), ref.ClaimIDs...),
			ContradictoryClaimIDs: append([]string(nil), ref.ContradictoryClaimIDs...),
		})
	}
	return out
}

func bridgeReport(r artifactsv2.ReportArtifact) ReportOutput {
	out := ReportOutput{
		SchemaVersion: r.SchemaVersion,
		EngineVersion: r.EngineVersion,
		Repo:          r.Repo,
		Commit:        r.Commit,
		Timestamp:     r.Timestamp,
		TraceID:       r.TraceID,
		Summary: ReportSummaryOutput{
			OverallScore: r.Summary.OverallScore,
			RiskLevel:    r.Summary.RiskLevel,
			IssueCounts: IssueCountOutput{
				Critical: r.Summary.IssueCounts.Critical,
				High:     r.Summary.IssueCounts.High,
				Medium:   r.Summary.IssueCounts.Medium,
				Low:      r.Summary.IssueCounts.Low,
			},
		},
	}
	for _, skill := range r.Skills {
		out.Skills = append(out.Skills, ReportSkillOutput{
			SkillID: skill.SkillID,
			Score:   skill.Score,
		})
	}
	for _, issue := range r.Issues {
		var breakdown *ConfidenceBreakdownOutput
		if issue.ConfidenceBreakdown != nil {
			breakdown = &ConfidenceBreakdownOutput{
				RuleReliability:      issue.ConfidenceBreakdown.RuleReliability,
				EvidenceQuality:      issue.ConfidenceBreakdown.EvidenceQuality,
				BoundaryCompleteness: issue.ConfidenceBreakdown.BoundaryCompleteness,
				ContextCompleteness:  issue.ConfidenceBreakdown.ContextCompleteness,
				SourceAgreement:      issue.ConfidenceBreakdown.SourceAgreement,
				ContradictionPenalty: issue.ConfidenceBreakdown.ContradictionPenalty,
				LLMPenalty:           issue.ConfidenceBreakdown.LLMPenalty,
				Final:                issue.ConfidenceBreakdown.Final,
			}
		}
		out.Issues = append(out.Issues, IssueOutput{
			ID:                 issue.ID,
			Fingerprint:        issue.Fingerprint,
			RuleFamily:         issue.RuleFamily,
			MergeBasis:         issue.MergeBasis,
			Category:           issue.Category,
			Title:              issue.Title,
			Severity:           issue.Severity,
			Confidence:         issue.Confidence,
			ConfidenceClass:    issue.ConfidenceClass,
			PolicyClass:        issue.PolicyClass,
			Status:             issue.Status,
			EvidenceIDs:        append([]string(nil), issue.EvidenceIDs...),
			CounterEvidenceIDs: append([]string(nil), issue.CounterEvidenceIDs...),
			SkillImpacts:       append([]string(nil), issue.SkillImpacts...),
			Sources:            append([]string(nil), issue.Sources...),
			SourceSummary: IssueSourceSummaryOutput{
				RuleCount:            issue.SourceSummary.RuleCount,
				DeterministicSources: issue.SourceSummary.DeterministicSources,
				AgentSources:         issue.SourceSummary.AgentSources,
				TotalSources:         issue.SourceSummary.TotalSources,
				MultiSource:          issue.SourceSummary.MultiSource,
			},
			ConfidenceBreakdown: breakdown,
		})
	}
	return out
}

func bridgeReportV2(r artifactsv2.ReportArtifact) ReportV2Output {
	out := ReportV2Output{
		SchemaVersion: r.SchemaVersion,
		EngineVersion: r.EngineVersion,
		Repo:          r.Repo,
		Commit:        r.Commit,
		Timestamp:     r.Timestamp,
		TraceID:       r.TraceID,
		Summary: ReportV2SummaryOutput{
			OverallScore: r.Summary.OverallScore,
			RiskLevel:    r.Summary.RiskLevel,
			IssueCounts: IssueCountV2Output{
				Critical: r.Summary.IssueCounts.Critical,
				High:     r.Summary.IssueCounts.High,
				Medium:   r.Summary.IssueCounts.Medium,
				Low:      r.Summary.IssueCounts.Low,
			},
		},
	}
	for _, skill := range r.Skills {
		out.Skills = append(out.Skills, ReportV2SkillOutput{
			SkillID: skill.SkillID,
			Score:   skill.Score,
		})
	}
	for _, issue := range r.Issues {
		var breakdown *ConfidenceBreakdownV2Output
		if issue.ConfidenceBreakdown != nil {
			breakdown = &ConfidenceBreakdownV2Output{
				RuleReliability:      issue.ConfidenceBreakdown.RuleReliability,
				EvidenceQuality:      issue.ConfidenceBreakdown.EvidenceQuality,
				BoundaryCompleteness: issue.ConfidenceBreakdown.BoundaryCompleteness,
				ContextCompleteness:  issue.ConfidenceBreakdown.ContextCompleteness,
				SourceAgreement:      issue.ConfidenceBreakdown.SourceAgreement,
				ContradictionPenalty: issue.ConfidenceBreakdown.ContradictionPenalty,
				LLMPenalty:           issue.ConfidenceBreakdown.LLMPenalty,
				Final:                issue.ConfidenceBreakdown.Final,
			}
		}
		out.Issues = append(out.Issues, IssueV2Output{
			ID:                 issue.ID,
			Fingerprint:        issue.Fingerprint,
			RuleFamily:         issue.RuleFamily,
			MergeBasis:         issue.MergeBasis,
			Category:           issue.Category,
			Title:              issue.Title,
			Severity:           issue.Severity,
			Confidence:         issue.Confidence,
			ConfidenceClass:    issue.ConfidenceClass,
			PolicyClass:        issue.PolicyClass,
			Status:             issue.Status,
			EvidenceIDs:        append([]string(nil), issue.EvidenceIDs...),
			CounterEvidenceIDs: append([]string(nil), issue.CounterEvidenceIDs...),
			SkillImpacts:       append([]string(nil), issue.SkillImpacts...),
			Sources:            append([]string(nil), issue.Sources...),
			SourceSummary: IssueSourceSummaryV2Output{
				RuleCount:            issue.SourceSummary.RuleCount,
				DeterministicSources: issue.SourceSummary.DeterministicSources,
				AgentSources:         issue.SourceSummary.AgentSources,
				TotalSources:         issue.SourceSummary.TotalSources,
				MultiSource:          issue.SourceSummary.MultiSource,
			},
			ConfidenceBreakdown: breakdown,
		})
	}
	return out
}

func bridgeEvidenceV2(a artifactsv2.EvidenceArtifact) EvidenceV2Output {
	out := EvidenceV2Output{
		SchemaVersion: a.SchemaVersion,
		EngineVersion: a.EngineVersion,
		Repo:          a.Repo,
		Commit:        a.Commit,
		Timestamp:     a.Timestamp,
	}
	for _, ev := range a.Evidence {
		locs := make([]LocationV2Output, 0, len(ev.Locations))
		for _, loc := range ev.Locations {
			locs = append(locs, LocationV2Output{
				RepoRelPath: loc.RepoRelPath,
				StartLine:   loc.StartLine,
				EndLine:     loc.EndLine,
				StartCol:    loc.StartCol,
				EndCol:      loc.EndCol,
				SymbolID:    loc.SymbolID,
			})
		}
		out.Evidence = append(out.Evidence, EvidenceV2Record{
			ID:              ev.ID,
			Kind:            ev.Kind,
			Source:          ev.Source,
			ProducerID:      ev.ProducerID,
			ProducerVersion: ev.ProducerVersion,
			Repo:            ev.Repo,
			Commit:          ev.Commit,
			BoundaryHash:    ev.BoundaryHash,
			FactQuality:     ev.FactQuality,
			EntityIDs:       append([]string(nil), ev.EntityIDs...),
			Locations:       locs,
			Claims:          append([]string(nil), ev.Claims...),
			Payload:         ev.Payload,
			Supports:        append([]string(nil), ev.Supports...),
			Contradicts:     append([]string(nil), ev.Contradicts...),
			DerivedFrom:     append([]string(nil), ev.DerivedFrom...),
			CreatedAt:       ev.CreatedAt,
		})
	}
	return out
}

func bridgeSkillsV2(a artifactsv2.SkillsArtifact) SkillsV2Output {
	out := SkillsV2Output{
		SchemaVersion: a.SchemaVersion,
		EngineVersion: a.EngineVersion,
		Repo:          a.Repo,
		Commit:        a.Commit,
		Timestamp:     a.Timestamp,
	}
	for _, skill := range a.Skills {
		var formula *SkillFormulaInputsV2Output
		if skill.FormulaInputs != nil {
			formula = &SkillFormulaInputsV2Output{}
			for _, c := range skill.FormulaInputs.Positive {
				formula.Positive = append(formula.Positive, WeightedContributionV2Output{
					IssueID: c.IssueID,
					Weight:  c.Weight,
					Value:   c.Value,
				})
			}
			for _, c := range skill.FormulaInputs.Negative {
				formula.Negative = append(formula.Negative, WeightedContributionV2Output{
					IssueID: c.IssueID,
					Weight:  c.Weight,
					Value:   c.Value,
				})
			}
		}
		out.Skills = append(out.Skills, SkillScoreV2Output{
			SkillID:                 skill.SkillID,
			Score:                   skill.Score,
			Confidence:              skill.Confidence,
			ContributingIssueIDs:    append([]string(nil), skill.ContributingIssueIDs...),
			ContributingEvidenceIDs: append([]string(nil), skill.ContributingEvidenceIDs...),
			FormulaInputs:           formula,
		})
	}
	return out
}

func bridgeTraceV2(t artifactsv2.TraceArtifact) TraceV2Output {
	out := TraceV2Output{
		SchemaVersion: t.SchemaVersion,
		EngineVersion: t.EngineVersion,
		TraceID:       t.TraceID,
		Repo:          t.Repo,
		Commit:        t.Commit,
		Timestamp:     t.Timestamp,
		Partial:       t.Partial,
		Degraded:      t.Degraded,
		Errors:        append([]string(nil), t.Errors...),
		ScanBoundary: TraceScanBoundaryV2Output{
			Mode:          t.ScanBoundary.Mode,
			IncludedFiles: t.ScanBoundary.IncludedFiles,
			ExcludedFiles: t.ScanBoundary.ExcludedFiles,
		},
	}
	if t.MigrationSummary != nil {
		ruleStates := make(map[string]string, len(t.MigrationSummary.RuleStates))
		for ruleID, state := range t.MigrationSummary.RuleStates {
			ruleStates[ruleID] = state
		}
		ruleReasons := make(map[string]string, len(t.MigrationSummary.RuleReasons))
		for ruleID, reason := range t.MigrationSummary.RuleReasons {
			ruleReasons[ruleID] = reason
		}
		out.MigrationSummary = &RuleMigrationSummaryV2Output{
			LegacyOnlyCount:     t.MigrationSummary.LegacyOnlyCount,
			FindingBridgedCount: t.MigrationSummary.FindingBridgedCount,
			SeedNativeCount:     t.MigrationSummary.SeedNativeCount,
			IssueNativeCount:    t.MigrationSummary.IssueNativeCount,
			RuleStates:          ruleStates,
			RuleReasons:         ruleReasons,
		}
	}
	if t.ConfidenceCalibration != nil {
		familyBaselines := make(map[string]float64, len(t.ConfidenceCalibration.RuleFamilyBaselines))
		for family, baseline := range t.ConfidenceCalibration.RuleFamilyBaselines {
			familyBaselines[family] = baseline
		}
		out.ConfidenceCalibration = &ConfidenceCalibrationV2Output{
			Version:                 t.ConfidenceCalibration.Version,
			MachineTrustedThreshold: t.ConfidenceCalibration.MachineTrustedThreshold,
			UnknownCap:              t.ConfidenceCalibration.UnknownCap,
			AgentOnlyCap:            t.ConfidenceCalibration.AgentOnlyCap,
			RuleFamilyBaselines:     familyBaselines,
			OrderingRules:           append([]string(nil), t.ConfidenceCalibration.OrderingRules...),
		}
	}
	for _, a := range t.Analyzers {
		out.Analyzers = append(out.Analyzers, AnalyzerRunV2Output{
			Name:     a.Name,
			Version:  a.Version,
			Language: a.Language,
			Status:   a.Status,
			Degraded: a.Degraded,
			Reason:   a.Reason,
		})
	}
	for _, r := range t.Rules {
		out.Rules = append(out.Rules, RuleRunV2Output{
			ID:                 r.ID,
			Version:            r.Version,
			MigrationState:     r.MigrationState,
			MigrationReason:    r.MigrationReason,
			TriggeredIssueIDs:  append([]string(nil), r.TriggeredIssueIDs...),
			EmittedEvidenceIDs: append([]string(nil), r.EmittedEvidenceIDs...),
		})
	}
	for _, sr := range t.SkippedRules {
		out.SkippedRules = append(out.SkippedRules, SkippedRuleV2Output{
			ID:     sr.ID,
			Reason: sr.Reason,
		})
	}
	for _, c := range t.ContextSelections {
		locs := make([]LocationV2Output, 0, len(c.SelectedSpans))
		for _, loc := range c.SelectedSpans {
			locs = append(locs, LocationV2Output{
				RepoRelPath: loc.RepoRelPath,
				StartLine:   loc.StartLine,
				EndLine:     loc.EndLine,
				StartCol:    loc.StartCol,
				EndCol:      loc.EndCol,
				SymbolID:    loc.SymbolID,
			})
		}
		out.ContextSelections = append(out.ContextSelections, ContextSelectionV2Output{
			ID:                  c.ID,
			TriggerType:         c.TriggerType,
			TriggerID:           c.TriggerID,
			SelectedEvidenceIDs: append([]string(nil), c.SelectedEvidenceIDs...),
			EntityIDs:           append([]string(nil), c.EntityIDs...),
			SelectedSpans:       locs,
			MaxFiles:            c.MaxFiles,
			MaxSpans:            c.MaxSpans,
			MaxTokens:           c.MaxTokens,
			SelectionTrace:      append([]string(nil), c.SelectionTrace...),
		})
	}
	for _, a := range t.Agents {
		out.Agents = append(out.Agents, AgentRunV2Output{
			ID:                 a.ID,
			Kind:               a.Kind,
			IssueType:          a.IssueType,
			Question:           a.Question,
			IssueID:            a.IssueID,
			ContextSelectionID: a.ContextSelectionID,
			TriggerReason:      a.TriggerReason,
			InputEvidenceIDs:   append([]string(nil), a.InputEvidenceIDs...),
			OutputEvidenceIDs:  append([]string(nil), a.OutputEvidenceIDs...),
			UnresolvedReasons:  append([]string(nil), a.UnresolvedReasons...),
			MaxFiles:           a.MaxFiles,
			MaxTokens:          a.MaxTokens,
			AllowSpeculation:   a.AllowSpeculation,
			Status:             a.Status,
		})
	}
	for _, d := range t.Derivations {
		out.Derivations = append(out.Derivations, IssueDerivationV2Output{
			IssueID:                d.IssueID,
			IssueFingerprint:       d.IssueFingerprint,
			DerivedFromEvidenceIDs: append([]string(nil), d.DerivedFromEvidenceIDs...),
		})
	}
	return out
}

func bridgeSignatureV2(s artifactsv2.SignatureArtifact) SignatureV2Output {
	return SignatureV2Output{
		Version:         s.Version,
		SignedBy:        s.SignedBy,
		Timestamp:       s.Timestamp,
		ArtifactHashes:  s.ArtifactHashes,
		BundleHash:      s.BundleHash,
		Signature:       s.Signature,
		SignatureScheme: s.SignatureScheme,
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
