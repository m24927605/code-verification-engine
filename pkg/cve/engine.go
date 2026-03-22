package cve

import (
	"context"
	"io"

	"github.com/verabase/code-verification-engine/internal/claims"
	internalEngine "github.com/verabase/code-verification-engine/internal/engine"
	"github.com/verabase/code-verification-engine/internal/interpret"
	"github.com/verabase/code-verification-engine/internal/rules"
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

	// Bridge LLM provider if interpretation is enabled
	var llmProvider interpret.LLMProvider
	if e.config.interpret && e.config.llmProvider != nil {
		llmProvider = &llmProviderBridge{pub: e.config.llmProvider}
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
		Ctx:         ctx,
		RepoPath:    input.RepoPath,
		Ref:         ref,
		Profile:     profile,
		ClaimSet:    input.ClaimSet,
		OutputDir:   input.OutputDir,
		Format:      format,
		Strict:      input.Strict,
		Interpret:   e.config.interpret,
		LLMProvider: llmProvider,
		Progress:    e.config.progress,
		Hooks:       hooks,
		Plugins:     plugins,
	})

	return &VerifyOutput{
		ExitCode: result.ExitCode,
		Success:  result.ExitCode == 0,
		Scan:     result.Scan,
		Report:   result.Report,
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
