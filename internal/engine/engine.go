package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/verabase/code-verification-engine/internal/analyzers"
	goanalyzer "github.com/verabase/code-verification-engine/internal/analyzers/go"
	jsanalyzer "github.com/verabase/code-verification-engine/internal/analyzers/js"
	pyanalyzer "github.com/verabase/code-verification-engine/internal/analyzers/python"
	tsanalyzer "github.com/verabase/code-verification-engine/internal/analyzers/ts"
	"github.com/verabase/code-verification-engine/internal/artifactsv2"
	"github.com/verabase/code-verification-engine/internal/claims"
	"github.com/verabase/code-verification-engine/internal/claimsources"
	"github.com/verabase/code-verification-engine/internal/evidencegraph"
	"github.com/verabase/code-verification-engine/internal/facts"
	"github.com/verabase/code-verification-engine/internal/git"
	"github.com/verabase/code-verification-engine/internal/interpret"
	"github.com/verabase/code-verification-engine/internal/repo"
	"github.com/verabase/code-verification-engine/internal/report"
	"github.com/verabase/code-verification-engine/internal/rules"
	"github.com/verabase/code-verification-engine/internal/schema"
	"github.com/verabase/code-verification-engine/internal/skills"
	"github.com/verabase/code-verification-engine/internal/typegraph"
)

// PluginAnalyzer adapts an external analyzer plugin to the internal pipeline.
// Plugins return JSON-encoded AnalysisResult.
type PluginAnalyzer struct {
	PluginName string
	Langs      []string
	Exts       []string // file extensions this plugin handles (e.g., ".rs", ".rb")
	AnalyzeFn  func(ctx context.Context, dir string, files []string) ([]byte, error)
}

// Config holds engine execution configuration.
type Config struct {
	Ctx                        context.Context // caller context for cancellation/timeout
	RepoPath                   string
	Ref                        string
	Profile                    string // built-in profile name
	OutputDir                  string
	Format                     string
	Strict                     bool
	Progress                   io.Writer             // stderr for progress messages
	Interpret                  bool                  // Enable LLM interpretation layer
	LLMProvider                interpret.LLMProvider // LLM provider (nil = skip interpretation)
	AgentRuntime               bool                  // Enable bounded non-deterministic agent execution
	AgentProvider              interpret.LLMProvider // Agent runtime provider (nil = skip execution)
	ClaimSet                   string                // optional claim set name (alternative/complement to Profile)
	Hooks                      *ScanHooks            // optional extension hooks
	Plugins                    []PluginAnalyzer      // optional external analyzer plugins
	Mode                       string                // execution mode: verification, skill_inference, both (default: verification)
	SkillProfile               string                // skill profile name (default: github-engineer-core)
	OutsourceAcceptanceProfile string                // optional internal scenario projection profile
	PMAcceptanceProfile        string                // optional internal scenario projection profile
}

// Result holds the engine execution result.
type Result struct {
	ExitCode                  int
	Scan                      report.ScanReport
	Report                    report.VerificationReport
	Accounting                *ScanAccounting                // per-file analysis accounting
	ClaimReport               *claims.ClaimReport            // nil if no claim set specified
	EvidenceGraph             *evidencegraph.EvidenceGraph   // evidence relationship graph
	InterpretedReport         *interpret.InterpretedReport   // nil if interpretation disabled
	SkillReport               *skills.Report                 // nil if mode does not include skill_inference
	VerifiableIssueSet        *artifactsv2.IssueCandidateSet // canonical deterministic v2 verification product
	VerifiableEvidenceStore   *artifactsv2.EvidenceStore     // intermediate evidence-first store for v2 compatibility path
	VerifiableIssueCandidates []artifactsv2.IssueCandidate   // intermediate issue candidates for v2 compatibility path
	VerifiableBundle          *artifactsv2.Bundle            // nil if verifiable bundle generation failed or is disabled
	VerifiableClaimsArtifacts *artifactsv2.ClaimsProjectionArtifacts
	Errors                    []string
}

// cancelledResult returns a Result for a cancelled/timed-out context.
func cancelledResult(ctx context.Context) Result {
	return Result{ExitCode: 7, Errors: []string{fmt.Sprintf("context cancelled: %v", ctx.Err())}}
}

// Run executes the full verification pipeline.
func Run(cfg Config) Result {
	ctx := cfg.Ctx
	if ctx == nil {
		ctx = context.Background()
	}

	progress := cfg.Progress
	if progress == nil {
		progress = os.Stderr
	}

	// 0. Validate mode early — before any pipeline work or file writes
	if cfg.Mode != "" && !skills.ValidMode(cfg.Mode) {
		return Result{ExitCode: 1, Errors: []string{fmt.Sprintf("invalid mode %q: allowed modes are verification, skill_inference, both", cfg.Mode)}}
	}

	// 1. Load profile
	p, ok := rules.GetProfile(cfg.Profile)
	if !ok {
		return Result{ExitCode: 3, Errors: []string{fmt.Sprintf("unknown profile: %s", cfg.Profile)}}
	}

	// Resolve claim set (optional)
	var claimSet *claims.ClaimSet
	if cfg.ClaimSet != "" {
		cs, csOK := claims.GetClaimSet(cfg.ClaimSet)
		if !csOK {
			return Result{ExitCode: 3, Errors: []string{fmt.Sprintf("unknown claim set: %s", cfg.ClaimSet)}}
		}
		claimSet = cs

		// Merge claim rule IDs into the profile so they are executed
		profileRuleIDs := make(map[string]bool)
		for _, r := range p.Rules {
			profileRuleIDs[r.ID] = true
		}
		// Find rules from all profiles that claims reference but profile doesn't include
		allRules := make(map[string]rules.Rule)
		for _, prof := range rules.AllProfiles() {
			for _, r := range prof.Rules {
				allRules[r.ID] = r
			}
		}
		for _, c := range claimSet.Claims {
			for _, ruleID := range c.RuleIDs {
				if !profileRuleIDs[ruleID] {
					if r, exists := allRules[ruleID]; exists {
						p.Rules = append(p.Rules, r)
						profileRuleIDs[ruleID] = true
					}
				}
			}
		}
		fmt.Fprintf(progress, "[INFO] claim set: %s (%d claims)\n", cfg.ClaimSet, len(claimSet.Claims))
	}

	ruleFile := rules.ProfileToRuleFile(p)
	if err := rules.Validate(ruleFile); err != nil {
		return Result{ExitCode: 3, Errors: []string{fmt.Sprintf("invalid profile %q: %v", cfg.Profile, err)}}
	}
	fmt.Fprintf(progress, "[INFO] profile: %s (%d rules)\n", cfg.Profile, len(ruleFile.Rules))

	// Hook: OnScanStart
	if cfg.Hooks != nil && cfg.Hooks.OnScanStart != nil {
		cfg.Hooks.OnScanStart(cfg.RepoPath, cfg.Ref, cfg.Profile)
	}

	// Check cancellation before repo load
	if ctx.Err() != nil {
		return cancelledResult(ctx)
	}

	// 2. Load repository
	ref := cfg.Ref
	if ref == "" {
		ref = "HEAD"
	}
	fmt.Fprintf(progress, "[INFO] repo: %s\n", cfg.RepoPath)
	fmt.Fprintf(progress, "[INFO] ref: %s\n", ref)
	meta, err := repo.Load(cfg.RepoPath, ref)
	if err != nil {
		return Result{ExitCode: 2, Errors: []string{fmt.Sprintf("repo error: %v", err)}}
	}

	// Check cancellation before workspace creation
	if ctx.Err() != nil {
		return cancelledResult(ctx)
	}

	// 3. Create isolated scan workspace
	fmt.Fprintf(progress, "[INFO] preparing scan workspace\n")
	tmpRoot := git.DefaultTempRoot()
	if err := git.EnsureTempRoot(tmpRoot); err != nil {
		return Result{ExitCode: 2, Errors: []string{fmt.Sprintf("workspace error: %v", err)}}
	}
	// Use meta.RepoPath (resolved to repo root) instead of cfg.RepoPath,
	// because repo.Load resolves subdirectories to the repo root.
	ws, err := git.CreateWorkspaceWithClone(meta.RepoPath, ref, tmpRoot)
	if err != nil {
		return Result{ExitCode: 2, Errors: []string{fmt.Sprintf("workspace error: %v", err)}}
	}
	defer git.CleanupWorkspace(ws)

	// Re-enumerate files from the workspace (which is checked out at the
	// target ref). The original repo.Load runs filterSafePaths against the
	// source repo's working tree, which may differ from the target ref and
	// silently drop files that don't exist on the current checkout.
	wsFiles, err := repo.ListTrackedFiles(ws.Path, "HEAD")
	if err != nil {
		return Result{ExitCode: 2, Errors: []string{fmt.Sprintf("workspace file enumeration: %v", err)}}
	}
	// CRITICAL: preserve scan boundary — filter to the same subtree as repo.Load
	wsFiles = repo.FilterFilesToSubtree(wsFiles, meta.ScanSubdir)
	wsFiles = repo.FilterSafePaths(ws.Path, wsFiles)
	meta.Files = wsFiles
	meta.FileCount = len(wsFiles)
	meta.Languages = repo.DetectLanguages(wsFiles)

	// 4. Detect languages
	if meta.ScanSubdir != "" {
		fmt.Fprintf(progress, "[INFO] scan boundary: %s (subdir of %s)\n", meta.ScanSubdir, meta.SourceRepoRoot)
	}
	fmt.Fprintf(progress, "[INFO] detected languages: %s\n", joinStrings(meta.Languages))

	// Check cancellation before analysis
	if ctx.Err() != nil {
		git.CleanupWorkspace(ws)
		return cancelledResult(ctx)
	}

	// 5. Run analyzers in parallel
	allAnalyzers := []analyzers.Analyzer{
		goanalyzer.New(),
		jsanalyzer.New(),
		tsanalyzer.New(),
		pyanalyzer.New(),
	}

	analyzerStatuses := make(map[string]string)
	var analyzerErrors []string
	var allResults []*analyzers.AnalysisResult
	resultLanguages := make(map[*analyzers.AnalysisResult]string) // track which language each result belongs to
	var mu sync.Mutex
	var wg sync.WaitGroup

	activeAnalyzers := filterAnalyzers(allAnalyzers, meta.Languages)
	sem := make(chan struct{}, 4) // max 4 concurrent

	for _, a := range activeAnalyzers {
		wg.Add(1)
		go func(az analyzers.Analyzer) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			// Skip if already cancelled
			if ctx.Err() != nil {
				return
			}

			lang := string(az.Language())
			langFiles := filterFiles(meta.Files, az.Extensions())
			fmt.Fprintf(progress, "[INFO] analyzing: %s (%d files)\n", lang, len(langFiles))

			result, err := az.Analyze(ws.Path, langFiles)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				analyzerStatuses[lang] = "error"
				analyzerErrors = append(analyzerErrors, fmt.Sprintf("%s analyzer: %v", lang, err))
			} else {
				analyzerStatuses[lang] = "ok"
				allResults = append(allResults, result)
				resultLanguages[result] = lang
			}

			// Hook: OnAnalyzerComplete
			if cfg.Hooks != nil && cfg.Hooks.OnAnalyzerComplete != nil {
				skipped := 0
				if result != nil {
					skipped = len(result.SkippedFiles)
				}
				cfg.Hooks.OnAnalyzerComplete(lang, len(langFiles), skipped)
			}
		}(a)
	}
	wg.Wait()

	// Run plugin analyzers
	for _, plugin := range cfg.Plugins {
		// Determine file extensions: use plugin-provided extensions if available,
		// otherwise fall back to built-in language extensions
		exts := plugin.Exts
		if len(exts) == 0 {
			for _, lang := range plugin.Langs {
				exts = append(exts, languageExtensions(lang)...)
			}
		}
		langFiles := filterFiles(meta.Files, exts)
		if len(langFiles) == 0 {
			continue
		}
		pluginLang := plugin.PluginName
		if len(plugin.Langs) > 0 {
			pluginLang = plugin.Langs[0]
		}
		fmt.Fprintf(progress, "[INFO] plugin %s analyzing: %d files\n", plugin.PluginName, len(langFiles))
		data, err := plugin.AnalyzeFn(ctx, ws.Path, langFiles)
		if err != nil {
			analyzerStatuses["plugin:"+plugin.PluginName] = "error"
			analyzerErrors = append(analyzerErrors, fmt.Sprintf("plugin %s: %v", plugin.PluginName, err))
			continue
		}
		var result analyzers.AnalysisResult
		if err := json.Unmarshal(data, &result); err != nil {
			analyzerStatuses["plugin:"+plugin.PluginName] = "error"
			analyzerErrors = append(analyzerErrors, fmt.Sprintf("plugin %s: invalid output: %v", plugin.PluginName, err))
			continue
		}
		analyzerStatuses["plugin:"+plugin.PluginName] = "ok"
		allResults = append(allResults, &result)
		resultLanguages[&result] = pluginLang

		// Add plugin languages to meta.Languages so rules scoped to these
		// languages will be executed
		for _, lang := range plugin.Langs {
			found := false
			for _, ml := range meta.Languages {
				if ml == lang {
					found = true
					break
				}
			}
			if !found {
				meta.Languages = append(meta.Languages, lang)
			}
		}
	}

	// Check strict mode
	hasErrors := len(analyzerErrors) > 0
	hasSuccess := len(allResults) > 0

	// Track skipped files — any skipped file makes the scan partial
	// and downgrades the corresponding analyzer status
	for _, r := range allResults {
		if len(r.SkippedFiles) > 0 {
			for _, sf := range r.SkippedFiles {
				analyzerErrors = append(analyzerErrors, fmt.Sprintf("skipped %s: %s", sf.File, sf.Reason))
			}
			// Use the tracked language for this result (works even if all files skipped)
			if lang, ok := resultLanguages[r]; ok {
				if analyzerStatuses[lang] == "ok" {
					analyzerStatuses[lang] = "partial"
				}
			}
			hasErrors = true
		}
	}
	// Compute scan accounting
	accounting := ComputeAccounting(allResults, resultLanguages, analyzerStatuses)

	if cfg.Strict && hasErrors {
		return Result{ExitCode: 4, Errors: analyzerErrors}
	}

	// Check cancellation after analysis
	if ctx.Err() != nil {
		return cancelledResult(ctx)
	}

	// 6. Build fact set
	factSet := buildFactSet(allResults)
	factSet.TypeGraph = mergeTypeGraphs(allResults)

	// Add root-level config files (lockfiles, etc.) that analyzers skip because
	// they don't match language extensions. These are needed for rules like FE-DEP-001.
	addRootConfigFiles(ws.Path, meta.Files, factSet)

	// 7. Execute rules
	ruleEngine := rules.NewEngine()

	// Degrade capability matrix for languages whose AST runtime is unavailable.
	// This ensures the matrix reflects actual analyzer strength, not theoretical.
	if !pyanalyzer.PythonASTAvailable() {
		ruleEngine.DegradeLanguageCapability("python", "python3 unavailable")
		fmt.Fprintf(progress, "[INFO] python3 not available — Python capability degraded to regex fallback\n")
	}

	execResult := ruleEngine.Execute(ruleFile, factSet, meta.Languages)

	// Emit hooks after rules-layer normalization has already finalized
	// evidence IDs, trust class, and issue seeds.
	for i := range execResult.Findings {
		if cfg.Hooks != nil && cfg.Hooks.OnFindingProduced != nil {
			cfg.Hooks.OnFindingProduced(execResult.Findings[i])
		}
	}

	// Build evidence graph
	evGraph := evidencegraph.BuildFromResults(allResults, execResult.Findings)
	fmt.Fprintf(progress, "[INFO] evidence graph: %d nodes, %d edges, %d files\n",
		evGraph.NodeCount(), evGraph.EdgeCount(), len(evGraph.UniqueFiles()))

	ruleIndex := make(map[string]rules.Rule, len(ruleFile.Rules))
	for _, rule := range ruleFile.Rules {
		ruleIndex[rule.ID] = rule
	}
	sigSummary := report.ComputeSignalSummary(execResult.Findings, ruleIndex)
	fmt.Fprintf(progress, "[INFO] findings: pass=%d fail=%d (actionable=%d advisory=%d informational=%d) unknown=%d\n",
		countStatus(execResult.Findings, rules.StatusPass),
		countStatus(execResult.Findings, rules.StatusFail),
		sigSummary.ActionableFail,
		sigSummary.AdvisoryFail,
		sigSummary.InformationalDetection,
		countStatus(execResult.Findings, rules.StatusUnknown))

	// Check cancellation before report generation
	if ctx.Err() != nil {
		return cancelledResult(ctx)
	}

	// 8. Generate reports
	partial := hasErrors && hasSuccess
	scanReport := report.GenerateScanReport(report.ScanInput{
		RepoPath:       meta.RepoPath,
		RepoName:       meta.RepoName,
		Ref:            meta.Ref,
		CommitSHA:      meta.CommitSHA,
		Languages:      meta.Languages,
		FileCount:      meta.FileCount,
		Partial:        partial,
		Analyzers:      analyzerStatuses,
		Errors:         analyzerErrors,
		Profile:        cfg.Profile,
		SourceRepoRoot: meta.SourceRepoRoot,
		RequestedPath:  meta.RequestedPath,
		ScanSubdir:     meta.ScanSubdir,
		BoundaryMode:   meta.BoundaryMode,
	})

	// Track whether any analyzer runtime was degraded (e.g., python3 unavailable).
	// This must be surfaced in the report so consumers know analysis quality.
	analysisDegraded := !pyanalyzer.PythonASTAvailable() && containsLanguage(meta.Languages, "python")
	ruleMetadata := artifactsv2.RuleMetadataFromRuleFile(ruleFile)

	verReport := report.GenerateVerificationReport(report.ReportInput{
		Partial:      partial,
		Findings:     execResult.Findings,
		RuleMetadata: ruleIndex,
		SkippedRules: execResult.SkippedRules,
		Errors:       analyzerErrors,
		Degraded:     analysisDegraded,
	})

	// Validate output contracts — fail closed on violations.
	// If the engine produces output that violates its own public contract,
	// that is a bug and must not be written as a "successful" result.
	var contractErrors []string
	if contractErrs := schema.ValidateReportContract(schema.ReportContractInput{
		ReportSchemaVersion:          verReport.ReportSchemaVersion,
		Findings:                     verReport.Findings,
		SummaryPass:                  verReport.Summary.Pass,
		SummaryFail:                  verReport.Summary.Fail,
		SummaryUnknown:               verReport.Summary.Unknown,
		SignalActionableFail:         verReport.SignalSummary.ActionableFail,
		SignalAdvisoryFail:           verReport.SignalSummary.AdvisoryFail,
		SignalInformationalDetection: verReport.SignalSummary.InformationalDetection,
		SignalUnknown:                verReport.SignalSummary.Unknown,
	}); len(contractErrs) > 0 {
		for _, e := range contractErrs {
			contractErrors = append(contractErrors, fmt.Sprintf("report contract: %v", e))
		}
	}
	if contractErrs := schema.ValidateScanContract(schema.ScanContractInput{
		ScanSchemaVersion: scanReport.ScanSchemaVersion,
		RepoPath:          scanReport.RepoPath,
		ScannedAt:         scanReport.ScannedAt,
		Analyzers:         scanReport.Analyzers,
	}); len(contractErrs) > 0 {
		for _, e := range contractErrs {
			contractErrors = append(contractErrors, fmt.Sprintf("scan contract: %v", e))
		}
	}
	if len(contractErrors) > 0 {
		for _, e := range contractErrors {
			fmt.Fprintf(progress, "[ERROR] contract violation: %v\n", e)
		}
		return Result{ExitCode: 5, Errors: contractErrors}
	}

	// Check cancellation before writing outputs
	if ctx.Err() != nil {
		return cancelledResult(ctx)
	}

	// 9. Write outputs
	if err := report.WriteOutputs(cfg.OutputDir, scanReport, verReport, cfg.Format); err != nil {
		return Result{ExitCode: 5, Errors: []string{fmt.Sprintf("report write: %v", err)}}
	}
	fmt.Fprintf(progress, "[INFO] report written to: %s\n", cfg.OutputDir)

	// Write accounting.json
	if err := writeJSONFile(filepath.Join(cfg.OutputDir, "accounting.json"), accounting); err != nil {
		return Result{ExitCode: 5, Errors: []string{fmt.Sprintf("accounting.json: %v", err)}}
	}

	// Write evidence graph
	if err := writeJSONFile(filepath.Join(cfg.OutputDir, "evidence-graph.json"), evGraph); err != nil {
		return Result{ExitCode: 5, Errors: []string{fmt.Sprintf("evidence-graph.json: %v", err)}}
	}

	// Generate claim report if claim set specified
	var claimReport *claims.ClaimReport
	if claimSet != nil {
		evaluator := claims.NewEvaluator()
		claimReport = evaluator.Evaluate(claimSet, execResult)
		if err := writeJSONFile(filepath.Join(cfg.OutputDir, "claims.json"), claimReport); err != nil {
			return Result{ExitCode: 5, Errors: []string{fmt.Sprintf("claims.json: %v", err)}}
		}
		fmt.Fprintf(progress, "[INFO] claims: verified=%d passed=%d failed=%d unknown=%d partial=%d\n",
			claimReport.Verdicts.Verified, claimReport.Verdicts.Passed,
			claimReport.Verdicts.Failed, claimReport.Verdicts.Unknown,
			claimReport.Verdicts.Partial)
	}

	// Optional: LLM interpretation layer (post-pipeline, never affects verdicts)
	var interpretedReport *interpret.InterpretedReport
	if cfg.Interpret && cfg.LLMProvider != nil {
		fmt.Fprintf(progress, "[INFO] running LLM interpretation layer\n")
		// interpret.New only fails on nil provider, which is already guarded above.
		interp, _ := interpret.New(cfg.LLMProvider)
		snippets := collectEvidenceSnippets(ws.Path, execResult.Findings)

		// Step 1: Constrained LLM review for partial/unknown findings only.
		// Machine-trusted rules remain deterministic. Advisory rules may get refined.
		// Review handles LLM errors internally (per-finding) and always returns nil error.
		reviewReport, _ := interp.Review(ctx, execResult.Findings, snippets, interpret.ReviewPolicyDefault)
		fmt.Fprintf(progress, "[INFO] LLM review: %d reviewed, %d skipped, %d errors\n",
			reviewReport.ReviewCount, reviewReport.SkipCount, reviewReport.ErrorCount)
		// Write review report
		reviewPath := filepath.Join(cfg.OutputDir, "review.json")
		if data, err := json.MarshalIndent(reviewReport, "", "  "); err == nil {
			os.WriteFile(reviewPath, append(data, '\n'), 0o644)
		}

		// Step 2: Full interpretation (explanation, triage, suggested fix)
		// Interpret handles LLM errors internally (per-finding) and always returns nil error.
		interpretedReport, _ = interp.Interpret(ctx, execResult.Findings, snippets)
	}

	if interpretedReport != nil {
		if err := writeJSONFile(filepath.Join(cfg.OutputDir, "interpreted.json"), interpretedReport); err != nil {
			return Result{ExitCode: 5, Errors: []string{fmt.Sprintf("interpreted.json: %v", err)}}
		}
	}

	// Skill inference pipeline (runs after verification if mode includes it)
	mode := skills.Mode(cfg.Mode)
	if cfg.Mode == "" {
		mode = skills.DefaultMode()
	}

	var skillReport *skills.Report
	if mode.IncludesSkillInference() {
		skillProfileName := cfg.SkillProfile
		if skillProfileName == "" {
			skillProfileName = "github-engineer-core"
		}
		sp, spOK := skills.GetProfile(skillProfileName)
		if !spOK {
			return Result{ExitCode: 3, Errors: []string{fmt.Sprintf("unknown skill profile: %s", skillProfileName)}}
		}

		skillReport = skills.Evaluate(
			execResult.Findings,
			sp,
			cfg.RepoPath,
			skills.WithFactSet(factSet),
			skills.WithLanguages(meta.Languages),
		)

		// Validate skill output contract — fail closed
		if contractErrs := skills.ValidateReport(skillReport); len(contractErrs) > 0 {
			var skillContractErrors []string
			for _, e := range contractErrs {
				skillContractErrors = append(skillContractErrors, fmt.Sprintf("skill contract: %v", e))
			}
			for _, e := range skillContractErrors {
				fmt.Fprintf(progress, "[ERROR] %s\n", e)
			}
			return Result{ExitCode: 5, Errors: skillContractErrors}
		}

		// Write skills.json
		if err := skills.WriteSkillsJSON(cfg.OutputDir, skillReport); err != nil {
			return Result{ExitCode: 5, Errors: []string{fmt.Sprintf("write skills.json: %v", err)}}
		}
		fmt.Fprintf(progress, "[INFO] skills: observed=%d inferred=%d unsupported=%d\n",
			skillReport.Summary.Observed, skillReport.Summary.Inferred, skillReport.Summary.Unsupported)
	}

	// Compatibility bridge: emit the v2 verifiable artifact bundle under a
	// dedicated subdirectory so the current public output contract remains intact
	// while the engine transitions to the new evidence-first model.
	var agentExecutor artifactsv2.AgentExecutor
	if cfg.AgentRuntime && cfg.AgentProvider != nil {
		agentExecutor = NewLLMAgentExecutor(ctx, cfg.AgentProvider, scanReport, "verabase@dev")
	}
	v2Build, err := artifactsv2.BuildCompatArtifacts(artifactsv2.CompatBuildInput{
		Scan: scanReport,
		Verification: artifactsv2.VerificationSource{
			ReportSchemaVersion: verReport.ReportSchemaVersion,
			Findings:            append([]rules.Finding(nil), execResult.Findings...),
			IssueSeeds:          artifactsv2.IssueSeedsFromRuleSeeds(execResult.IssueSeeds),
			RuleMetadata:        ruleMetadata,
			SkippedRules:        append([]rules.SkippedRule(nil), execResult.SkippedRules...),
			Partial:             partial,
			Degraded:            analysisDegraded,
			AnalyzerStatuses:    copyStringMap(analyzerStatuses),
			Errors:              append([]string(nil), analyzerErrors...),
		},
		AgentExecutor: agentExecutor,
		SkillReport:   skillReport,
		EngineVersion: "verabase@dev",
	})
	if err != nil {
		return Result{ExitCode: 5, Errors: []string{fmt.Sprintf("build verifiable bundle: %v", err)}}
	}
	v2Bundle := v2Build.Bundle
	claimArtifacts, claimSourceEvidence, err := buildClaimsProfileResumeArtifacts(meta, claimSet, execResult, ruleFile, factSet, skillReport)
	if err != nil {
		return Result{ExitCode: 5, Errors: []string{fmt.Sprintf("build claims/profile/resume artifacts: %v", err)}}
	}
	if claimArtifacts != nil {
		v2Bundle.Evidence.Evidence = appendMissingEvidenceRecords(v2Bundle.Evidence.Evidence, adaptClaimSourceEvidenceRecords(
			claimSourceEvidence,
			scanReport.RepoName,
			scanReport.CommitSHA,
			scanReport.ScannedAt,
		))
		v2Bundle.Claims = &claimArtifacts.Claims
		v2Bundle.Profile = &claimArtifacts.Profile
		v2Bundle.ResumeInput = &claimArtifacts.ResumeInput
	}
	outsourceAcceptance, pmAcceptance, err := artifactsv2.BuildScenarioAcceptanceArtifacts(artifactsv2.ScenarioAcceptanceBuildInput{
		RepoIdentity: scanReport.RepoName,
		Commit:       scanReport.CommitSHA,
		TraceID:      v2Bundle.Trace.TraceID,
		Claims:       v2Bundle.Claims,
		Options: artifactsv2.ScenarioBuildOptions{
			OutsourceAcceptanceProfile: cfg.OutsourceAcceptanceProfile,
			PMAcceptanceProfile:        cfg.PMAcceptanceProfile,
		},
	})
	if err != nil {
		return Result{ExitCode: 5, Errors: []string{fmt.Sprintf("build scenario acceptance artifacts: %v", err)}}
	}
	v2Bundle.OutsourceAcceptance = outsourceAcceptance
	v2Bundle.PMAcceptance = pmAcceptance
	v2OutputDir := filepath.Join(cfg.OutputDir, "verifiable")
	if err := artifactsv2.WriteBundle(v2OutputDir, &v2Bundle, "verabase"); err != nil {
		return Result{ExitCode: 5, Errors: []string{fmt.Sprintf("write verifiable bundle: %v", err)}}
	}
	fmt.Fprintf(progress, "[INFO] verifiable bundle written to: %s\n", v2OutputDir)

	// Preserve the historical engine contract: when a claim set is requested and
	// evaluation completed, Result.ClaimReport must be populated even if later
	// projection work does not consume it.
	if claimSet != nil && claimReport == nil {
		claimReport = claims.NewEvaluator().Evaluate(claimSet, execResult)
	}

	exitCode := 0
	if partial {
		exitCode = 6
	}

	// Hook: OnScanComplete
	if cfg.Hooks != nil && cfg.Hooks.OnScanComplete != nil {
		cfg.Hooks.OnScanComplete(exitCode, cfg.OutputDir)
	}

	return Result{
		ExitCode:                  exitCode,
		Scan:                      scanReport,
		Report:                    verReport,
		Accounting:                &accounting,
		ClaimReport:               claimReport,
		EvidenceGraph:             evGraph,
		InterpretedReport:         interpretedReport,
		SkillReport:               skillReport,
		VerifiableIssueSet:        v2Build.IssueSet,
		VerifiableEvidenceStore:   v2Build.EvidenceStore,
		VerifiableIssueCandidates: append([]artifactsv2.IssueCandidate(nil), v2Build.IssueCandidates...),
		VerifiableBundle:          &v2Bundle,
		VerifiableClaimsArtifacts: claimArtifacts,
		Errors:                    analyzerErrors,
	}
}

func filterAnalyzers(all []analyzers.Analyzer, languages []string) []analyzers.Analyzer {
	langSet := make(map[string]bool)
	for _, l := range languages {
		langSet[l] = true
	}
	var result []analyzers.Analyzer
	for _, a := range all {
		if langSet[string(a.Language())] {
			result = append(result, a)
		}
	}
	return result
}

func filterFiles(files []string, extensions []string) []string {
	extSet := make(map[string]bool)
	for _, ext := range extensions {
		extSet[ext] = true
	}
	var result []string
	for _, f := range files {
		for ext := range extSet {
			if len(f) > len(ext) && f[len(f)-len(ext):] == ext {
				result = append(result, f)
				break
			}
		}
	}
	return result
}

// addRootConfigFiles adds well-known root-level configuration files to the FactSet
// so that rules like FE-DEP-001 (lockfile detection) can find them even though
// they aren't analyzed by language-specific analyzers.
func addRootConfigFiles(wsPath string, trackedFiles []string, fs *rules.FactSet) {
	configFiles := []string{
		"package-lock.json", "yarn.lock", "pnpm-lock.yaml",
		".env", ".env.local", ".env.production", ".env.development",
	}
	configSet := make(map[string]bool)
	for _, cf := range configFiles {
		configSet[strings.ToLower(cf)] = true
	}

	// Check tracked files list for root-level config files
	for _, f := range trackedFiles {
		baseName := strings.ToLower(filepath.Base(f))
		if configSet[baseName] {
			// Check if already present in FileFacts
			alreadyPresent := false
			for _, ff := range fs.Files {
				if ff.File == f {
					alreadyPresent = true
					break
				}
			}
			if !alreadyPresent {
				// Use a generic language — these are config files
				lang := facts.LangJavaScript // lockfiles are JS ecosystem files
				if fact, err := facts.NewFileFact(lang, f, 1); err == nil {
					fs.Files = append(fs.Files, fact)
				}
			}
		}
	}
}

func buildFactSet(results []*analyzers.AnalysisResult) *rules.FactSet {
	fs := &rules.FactSet{}
	for _, r := range results {
		fs.Symbols = append(fs.Symbols, r.Symbols...)
		fs.Imports = append(fs.Imports, r.Imports...)
		fs.Middlewares = append(fs.Middlewares, r.Middlewares...)
		fs.Routes = append(fs.Routes, r.Routes...)
		fs.Tests = append(fs.Tests, r.Tests...)
		fs.DataAccess = append(fs.DataAccess, r.DataAccess...)
		fs.Secrets = append(fs.Secrets, r.Secrets...)
		fs.Files = append(fs.Files, r.Files...)
	}
	return fs
}

func countStatus(findings []rules.Finding, status rules.Status) int {
	count := 0
	for _, f := range findings {
		if f.Status == status {
			count++
		}
	}
	return count
}

func joinStrings(ss []string) string {
	result := ""
	for i, s := range ss {
		if i > 0 {
			result += ", "
		}
		result += s
	}
	return result
}

func mergeTypeGraphs(results []*analyzers.AnalysisResult) *typegraph.TypeGraph {
	merged := typegraph.New()
	for _, r := range results {
		if r.TypeGraph != nil {
			for key, node := range r.TypeGraph.Nodes {
				merged.Nodes[key] = node
			}
		}
	}
	return merged
}

func languageExtensions(lang string) []string {
	switch lang {
	case "go":
		return []string{".go"}
	case "javascript":
		return []string{".js", ".jsx"}
	case "typescript":
		return []string{".ts", ".tsx"}
	case "python":
		return []string{".py"}
	default:
		return nil
	}
}

func buildClaimsProfileResumeArtifacts(meta *repo.RepoMetadata, claimSet *claims.ClaimSet, execResult rules.ExecutionResult, ruleFile *rules.RuleFile, fs *rules.FactSet, skillReport *skills.Report) (*artifactsv2.ClaimsProjectionArtifacts, []claimsources.SourceEvidenceRecord, error) {
	if meta == nil {
		return nil, nil, nil
	}
	descriptors := claimsources.DiscoverFromRepo(meta)
	sourceEvidence := claimsources.ExtractFromRepo(meta, descriptors)
	claimEvidence := adaptClaimSourceEvidence(sourceEvidence)
	graph := claims.BuildMultiSourceClaimGraph(claimSet, claimEvidence)
	if graph == nil || len(graph.Claims) == 0 {
		graph = &claims.ClaimGraph{}
	}
	claimRecords := adaptVerifiedClaims(graph.Claims)
	claimRecords = append(claimRecords, buildRuleBackedScenarioClaims(execResult, ruleFile)...)
	claimRecords = append(claimRecords, buildConfigFactClaims(fs)...)
	if len(claimRecords) == 0 {
		return nil, sourceEvidence, nil
	}
	artifacts, err := artifactsv2.BuildClaimsProfileResumeArtifacts(artifactsv2.ClaimsProjectionInput{
		Repository: artifactsv2.ClaimRepositoryRef{
			Path:   meta.RepoPath,
			Commit: meta.CommitSHA,
		},
		Claims:       claimRecords,
		Technologies: collectClaimProjectionTechnologies(meta, skillReport, execResult),
	})
	if err != nil {
		return nil, sourceEvidence, err
	}
	return &artifacts, sourceEvidence, nil
}

type scenarioRuleClaimSpec struct {
	ClaimID               string
	Title                 string
	Category              string
	ClaimType             string
	ScenarioApplicability *artifactsv2.ScenarioApplicability
	Positive              bool
	ProjectionEligible    bool
}

func buildRuleBackedScenarioClaims(execResult rules.ExecutionResult, ruleFile *rules.RuleFile) []artifactsv2.ClaimRecord {
	if ruleFile == nil {
		return nil
	}
	ruleIndex := rules.RuleIndexFromFile(ruleFile)
	out := make([]artifactsv2.ClaimRecord, 0)
	for _, finding := range execResult.Findings {
		specs := scenarioClaimSpecsForFinding(finding.RuleID)
		if len(specs) == 0 {
			continue
		}
		rule, ok := ruleIndex[finding.RuleID]
		if !ok {
			continue
		}
		for _, spec := range specs {
			claim := buildRuleBackedScenarioClaim(rule, finding, spec)
			if len(claim.SupportingEvidenceIDs) == 0 && len(claim.ContradictoryEvidenceIDs) == 0 {
				continue
			}
			out = append(out, claim)
		}
	}
	return out
}

func scenarioClaimSpecsForFinding(ruleID string) []scenarioRuleClaimSpec {
	allScenarios := &artifactsv2.ScenarioApplicability{Hiring: true, OutsourceAcceptance: true, PMAcceptance: true}
	switch ruleID {
	case "SEC-001", "SEC-SECRET-001":
		return []scenarioRuleClaimSpec{
			{
				ClaimID:               "security.hardcoded_secret_present",
				Title:                 "Hardcoded secret literals are present in the repository",
				Category:              "security",
				ClaimType:             "implementation",
				ScenarioApplicability: &artifactsv2.ScenarioApplicability{OutsourceAcceptance: true, PMAcceptance: true},
				Positive:              false,
				ProjectionEligible:    false,
			},
			{
				ClaimID:               "security.hardcoded_secret_absent",
				Title:                 "Hardcoded secret literals are absent from the scanned repository boundary",
				Category:              "security",
				ClaimType:             "security_maturity",
				ScenarioApplicability: &artifactsv2.ScenarioApplicability{OutsourceAcceptance: true, PMAcceptance: true},
				Positive:              true,
				ProjectionEligible:    false,
			},
		}
	case "TEST-001", "TEST-AUTH-001":
		return []scenarioRuleClaimSpec{{
			ClaimID:               "testing.auth_module_tests_present",
			Title:                 "Authentication module has automated tests",
			Category:              "testing",
			ClaimType:             "testing_maturity",
			ScenarioApplicability: allScenarios,
			Positive:              true,
			ProjectionEligible:    true,
		}}
	case "AUTH-002", "SEC-AUTH-002":
		return []scenarioRuleClaimSpec{{
			ClaimID:               "security.route_auth_binding",
			Title:                 "Protected routes are bound to authentication middleware",
			Category:              "security",
			ClaimType:             "implementation",
			ScenarioApplicability: allScenarios,
			Positive:              true,
			ProjectionEligible:    true,
		}}
	case "ARCH-001", "ARCH-LAYER-001":
		return []scenarioRuleClaimSpec{
			{
				ClaimID:               "architecture.controller_direct_db_access_present",
				Title:                 "Controller-layer code directly accesses the database",
				Category:              "architecture",
				ClaimType:             "architecture",
				ScenarioApplicability: allScenarios,
				Positive:              false,
				ProjectionEligible:    false,
			},
			{
				ClaimID:               "architecture.controller_direct_db_access_absent",
				Title:                 "Controller-layer code avoids direct database access",
				Category:              "architecture",
				ClaimType:             "architecture",
				ScenarioApplicability: &artifactsv2.ScenarioApplicability{OutsourceAcceptance: true, PMAcceptance: true},
				Positive:              true,
				ProjectionEligible:    true,
			},
		}
	default:
		return nil
	}
}

func buildRuleBackedScenarioClaim(rule rules.Rule, finding rules.Finding, spec scenarioRuleClaimSpec) artifactsv2.ClaimRecord {
	status, supportLevel := scenarioClaimStatusAndSupport(finding, spec.Positive)
	verificationClass := verificationClassFromFinding(finding, rule)
	supportingEvidence := evidenceIDsFromFinding(finding)
	contradictoryEvidence := []string(nil)
	if status == "rejected" {
		supportingEvidence, contradictoryEvidence = contradictoryEvidence, supportingEvidence
	}
	if status != "accepted" && verificationClass == artifactsv2.VerificationProofGrade {
		verificationClass = artifactsv2.VerificationStructuralInference
	}

	return artifactsv2.ClaimRecord{
		ClaimID:                  spec.ClaimID,
		Title:                    spec.Title,
		Category:                 spec.Category,
		ClaimType:                spec.ClaimType,
		Status:                   status,
		SupportLevel:             supportLevel,
		Confidence:               confidenceScoreFromFinding(finding),
		VerificationClass:        verificationClass,
		ScenarioApplicability:    spec.ScenarioApplicability,
		SourceOrigins:            []string{string(claims.ClaimOriginRuleInferred)},
		SupportingEvidenceIDs:    supportingEvidence,
		ContradictoryEvidenceIDs: contradictoryEvidence,
		Reason:                   finding.Message,
		ProjectionEligible:       spec.ProjectionEligible && status == "accepted" && claimEligibleForResume(verificationClass, supportLevel),
	}
}

func scenarioClaimStatusAndSupport(finding rules.Finding, positive bool) (string, string) {
	switch finding.Status {
	case rules.StatusUnknown:
		return "unknown", "unsupported"
	case rules.StatusPass:
		if positive {
			return "accepted", supportLevelFromFinding(finding)
		}
		return "rejected", rejectionSupportLevelFromFinding(finding)
	case rules.StatusFail:
		if positive {
			return "rejected", rejectionSupportLevelFromFinding(finding)
		}
		return "accepted", supportLevelFromFinding(finding)
	default:
		return "unknown", "unsupported"
	}
}

func supportLevelFromFinding(finding rules.Finding) string {
	switch finding.VerificationLevel {
	case rules.VerificationVerified:
		return string(claims.ClaimSupportVerified)
	case rules.VerificationStrongInference:
		return string(claims.ClaimSupportStronglySupported)
	default:
		return string(claims.ClaimSupportWeak)
	}
}

func rejectionSupportLevelFromFinding(finding rules.Finding) string {
	switch finding.VerificationLevel {
	case rules.VerificationVerified, rules.VerificationStrongInference:
		return string(claims.ClaimSupportContradicted)
	default:
		return string(claims.ClaimSupportUnsupported)
	}
}

func verificationClassFromFinding(finding rules.Finding, rule rules.Rule) artifactsv2.VerificationClass {
	if finding.TrustClass == rules.TrustHumanOrRuntimeRequired || rule.MatcherClass == rules.MatcherAttestation {
		return artifactsv2.VerificationHumanOrRuntimeRequired
	}
	if finding.VerificationLevel == rules.VerificationVerified &&
		rule.MatcherClass == rules.MatcherProof &&
		finding.FactQualityFloor == string(facts.QualityProof) &&
		finding.TrustClass == rules.TrustMachineTrusted {
		return artifactsv2.VerificationProofGrade
	}
	if finding.VerificationLevel == rules.VerificationVerified || finding.VerificationLevel == rules.VerificationStrongInference {
		return artifactsv2.VerificationStructuralInference
	}
	return artifactsv2.VerificationHeuristicAdvisory
}

func confidenceScoreFromFinding(finding rules.Finding) float64 {
	switch finding.Confidence {
	case rules.ConfidenceHigh:
		return 0.95
	case rules.ConfidenceMedium:
		return 0.75
	default:
		return 0.45
	}
}

func evidenceIDsFromFinding(finding rules.Finding) []string {
	if len(finding.Evidence) == 0 {
		return nil
	}
	out := make([]string, 0, len(finding.Evidence))
	for _, ev := range finding.Evidence {
		id := strings.TrimSpace(ev.ID)
		if id == "" {
			continue
		}
		out = append(out, id)
	}
	return out
}

func claimEligibleForResume(vc artifactsv2.VerificationClass, supportLevel string) bool {
	if supportLevel != string(claims.ClaimSupportVerified) && supportLevel != string(claims.ClaimSupportStronglySupported) {
		return false
	}
	return vc == artifactsv2.VerificationProofGrade || vc == artifactsv2.VerificationStructuralInference
}

func buildConfigFactClaims(fs *rules.FactSet) []artifactsv2.ClaimRecord {
	if fs == nil || len(fs.ConfigReads) == 0 {
		return nil
	}

	var envEvidenceIDs []string
	var secretEnvEvidenceIDs []string
	var literalSecretEvidenceIDs []string

	for _, cr := range fs.ConfigReads {
		evID := artifactsv2.HashBytes([]byte("config-read:" + cr.File + ":" + cr.Key + ":" + cr.SourceKind))
		switch strings.TrimSpace(cr.SourceKind) {
		case "env":
			envEvidenceIDs = append(envEvidenceIDs, evID)
			if configKeyLooksSecret(cr.Key) {
				secretEnvEvidenceIDs = append(secretEnvEvidenceIDs, evID)
			}
		case "literal":
			if configKeyLooksSecret(cr.Key) {
				literalSecretEvidenceIDs = append(literalSecretEvidenceIDs, evID)
			}
		}
	}

	out := make([]artifactsv2.ClaimRecord, 0, 3)
	if len(envEvidenceIDs) > 0 {
		out = append(out, artifactsv2.ClaimRecord{
			ClaimID:               "config.env_read_call_exists",
			Title:                 "Configuration values are read from environment sources",
			Category:              "security",
			ClaimType:             "implementation",
			Status:                "accepted",
			SupportLevel:          string(claims.ClaimSupportStronglySupported),
			Confidence:            0.84,
			VerificationClass:     artifactsv2.VerificationStructuralInference,
			ScenarioApplicability: &artifactsv2.ScenarioApplicability{Hiring: true, OutsourceAcceptance: true, PMAcceptance: true},
			SourceOrigins:         []string{string(claims.ClaimOriginRuleInferred)},
			SupportingEvidenceIDs: dedupeStringsSorted(envEvidenceIDs),
			Reason:                "ConfigReadFact entries show environment-backed configuration reads.",
			ProjectionEligible:    true,
		})
	}
	if len(secretEnvEvidenceIDs) > 0 {
		out = append(out, artifactsv2.ClaimRecord{
			ClaimID:               "config.secret_key_sourced_from_env",
			Title:                 "Secret-like configuration keys are sourced from environment reads",
			Category:              "security",
			ClaimType:             "security_maturity",
			Status:                "accepted",
			SupportLevel:          string(claims.ClaimSupportStronglySupported),
			Confidence:            0.82,
			VerificationClass:     artifactsv2.VerificationStructuralInference,
			ScenarioApplicability: &artifactsv2.ScenarioApplicability{Hiring: true, OutsourceAcceptance: true, PMAcceptance: true},
			SourceOrigins:         []string{string(claims.ClaimOriginRuleInferred)},
			SupportingEvidenceIDs: dedupeStringsSorted(secretEnvEvidenceIDs),
			Reason:                "Secret-like config keys were observed with SourceKind=env.",
			ProjectionEligible:    true,
		})
	}
	if len(literalSecretEvidenceIDs) > 0 {
		out = append(out, artifactsv2.ClaimRecord{
			ClaimID:                  "config.secret_key_not_literal",
			Title:                    "Secret-like configuration keys are not assigned from literals",
			Category:                 "security",
			ClaimType:                "security_maturity",
			Status:                   "rejected",
			SupportLevel:             string(claims.ClaimSupportContradicted),
			Confidence:               0.90,
			VerificationClass:        artifactsv2.VerificationStructuralInference,
			ScenarioApplicability:    &artifactsv2.ScenarioApplicability{OutsourceAcceptance: true, PMAcceptance: true},
			SourceOrigins:            []string{string(claims.ClaimOriginRuleInferred)},
			ContradictoryEvidenceIDs: dedupeStringsSorted(literalSecretEvidenceIDs),
			Reason:                   "Secret-like config keys were observed with SourceKind=literal.",
			ProjectionEligible:       false,
		})
	} else if len(secretEnvEvidenceIDs) > 0 {
		out = append(out, artifactsv2.ClaimRecord{
			ClaimID:               "config.secret_key_not_literal",
			Title:                 "Secret-like configuration keys are not assigned from literals",
			Category:              "security",
			ClaimType:             "security_maturity",
			Status:                "accepted",
			SupportLevel:          string(claims.ClaimSupportStronglySupported),
			Confidence:            0.78,
			VerificationClass:     artifactsv2.VerificationStructuralInference,
			ScenarioApplicability: &artifactsv2.ScenarioApplicability{OutsourceAcceptance: true, PMAcceptance: true},
			SourceOrigins:         []string{string(claims.ClaimOriginRuleInferred)},
			SupportingEvidenceIDs: dedupeStringsSorted(secretEnvEvidenceIDs),
			Reason:                "Secret-like keys were observed from env-backed reads and no literal-backed secret reads were found.",
			ProjectionEligible:    false,
		})
	}
	return out
}

func configKeyLooksSecret(key string) bool {
	key = strings.ToLower(strings.TrimSpace(key))
	return strings.Contains(key, "secret") || strings.Contains(key, "token") ||
		strings.Contains(key, "api_key") || strings.Contains(key, "apikey") ||
		strings.Contains(key, "password") || strings.Contains(key, "private_key")
}

func adaptClaimSourceEvidence(records []claimsources.SourceEvidenceRecord) []claims.SourceEvidenceRecord {
	out := make([]claims.SourceEvidenceRecord, 0, len(records))
	for _, record := range records {
		spans := make([]claims.SourceSpan, 0, len(record.Spans))
		for _, span := range record.Spans {
			spans = append(spans, claims.SourceSpan{
				File:      record.Path,
				LineStart: span.StartLine,
				LineEnd:   span.EndLine,
			})
		}
		out = append(out, claims.SourceEvidenceRecord{
			EvidenceID: record.EvidenceID,
			SourceType: string(record.SourceType),
			Origin:     claimOriginForSourceType(record.SourceType),
			Producer:   record.Producer,
			Path:       record.Path,
			Kind:       record.Kind,
			Summary:    record.Summary,
			Spans:      spans,
			EntityIDs:  append([]string(nil), record.EntityIDs...),
			Metadata:   copyStringMap(record.Metadata),
		})
	}
	return out
}

func adaptClaimSourceEvidenceRecords(records []claimsources.SourceEvidenceRecord, repoName, commitSHA, scannedAt string) []artifactsv2.EvidenceRecord {
	out := make([]artifactsv2.EvidenceRecord, 0, len(records))
	for _, record := range records {
		locations := make([]artifactsv2.LocationRef, 0, len(record.Spans))
		for _, span := range record.Spans {
			locations = append(locations, artifactsv2.LocationRef{
				RepoRelPath: record.Path,
				StartLine:   span.StartLine,
				EndLine:     span.EndLine,
			})
		}

		factQuality := "heuristic"
		switch record.SourceType {
		case claimsources.SourceTypeCode, claimsources.SourceTypeTest, claimsources.SourceTypeEval:
			factQuality = "structural"
		}

		out = append(out, artifactsv2.EvidenceRecord{
			ID:              record.EvidenceID,
			Kind:            "source_evidence",
			Source:          "analyzer",
			ProducerID:      "claimsources:" + record.Producer,
			ProducerVersion: "1.0.0",
			Repo:            repoName,
			Commit:          commitSHA,
			BoundaryHash:    artifactsv2.HashBytes([]byte(commitSHA + ":" + record.Path)),
			FactQuality:     factQuality,
			EntityIDs:       append([]string(nil), record.EntityIDs...),
			Locations:       locations,
			Claims:          nil,
			Payload: map[string]any{
				"source_type": string(record.SourceType),
				"kind":        record.Kind,
				"summary":     record.Summary,
				"metadata":    record.Metadata,
			},
			Supports:    nil,
			Contradicts: nil,
			DerivedFrom: nil,
			CreatedAt:   scannedAt,
		})
	}
	return out
}

func appendMissingEvidenceRecords(base []artifactsv2.EvidenceRecord, extra []artifactsv2.EvidenceRecord) []artifactsv2.EvidenceRecord {
	if len(extra) == 0 {
		return base
	}
	seen := make(map[string]struct{}, len(base))
	for _, record := range base {
		seen[record.ID] = struct{}{}
	}
	out := append([]artifactsv2.EvidenceRecord(nil), base...)
	for _, record := range extra {
		if _, ok := seen[record.ID]; ok {
			continue
		}
		seen[record.ID] = struct{}{}
		out = append(out, record)
	}
	return out
}

func claimOriginForSourceType(sourceType claimsources.SourceType) string {
	switch sourceType {
	case claimsources.SourceTypeReadme:
		return string(claims.ClaimOriginReadmeExtracted)
	case claimsources.SourceTypeDoc:
		return string(claims.ClaimOriginDocExtracted)
	case claimsources.SourceTypeCode:
		return string(claims.ClaimOriginCodeInferred)
	case claimsources.SourceTypeTest:
		return string(claims.ClaimOriginTestInferred)
	case claimsources.SourceTypeEval:
		return string(claims.ClaimOriginEvalInferred)
	default:
		return string(claims.ClaimOriginRuleInferred)
	}
}

func adaptVerifiedClaims(in []claims.VerifiedClaim) []artifactsv2.ClaimRecord {
	out := make([]artifactsv2.ClaimRecord, 0, len(in))
	for _, claim := range in {
		out = append(out, artifactsv2.ClaimRecord{
			ClaimID:                  claim.ClaimID,
			Title:                    claim.Title,
			Category:                 claim.Category,
			ClaimType:                claim.ClaimType,
			Status:                   claim.Status,
			SupportLevel:             claim.SupportLevel,
			Confidence:               claim.Confidence,
			VerificationClass:        inferClaimVerificationClass(claim),
			ScenarioApplicability:    inferClaimScenarioApplicability(claim),
			SourceOrigins:            append([]string(nil), claim.SourceOrigins...),
			SupportingEvidenceIDs:    append([]string(nil), claim.SupportingEvidenceIDs...),
			ContradictoryEvidenceIDs: append([]string(nil), claim.ContradictoryEvidenceIDs...),
			Reason:                   claim.Reason,
			ProjectionEligible:       claim.SupportLevel == string(claims.ClaimSupportVerified) || claim.SupportLevel == string(claims.ClaimSupportStronglySupported),
		})
	}
	return out
}

func inferClaimVerificationClass(claim claims.VerifiedClaim) artifactsv2.VerificationClass {
	switch claim.SupportLevel {
	case string(claims.ClaimSupportVerified), string(claims.ClaimSupportStronglySupported):
		return artifactsv2.VerificationStructuralInference
	case string(claims.ClaimSupportSupported), string(claims.ClaimSupportWeak):
		return artifactsv2.VerificationHeuristicAdvisory
	case string(claims.ClaimSupportUnsupported), string(claims.ClaimSupportContradicted):
		return artifactsv2.VerificationHumanOrRuntimeRequired
	default:
		return ""
	}
}

func inferClaimScenarioApplicability(claim claims.VerifiedClaim) *artifactsv2.ScenarioApplicability {
	switch strings.TrimSpace(claim.ClaimType) {
	case "implementation", "architecture", "security_maturity", "testing_maturity":
		return &artifactsv2.ScenarioApplicability{
			Hiring:              true,
			OutsourceAcceptance: true,
			PMAcceptance:        true,
		}
	case "evaluation_maturity", "operational_maturity":
		return &artifactsv2.ScenarioApplicability{Hiring: true}
	default:
		return &artifactsv2.ScenarioApplicability{Hiring: true}
	}
}

func collectClaimProjectionTechnologies(meta *repo.RepoMetadata, skillReport *skills.Report, execResult rules.ExecutionResult) []string {
	seen := make(map[string]struct{})
	var out []string
	add := func(v string) {
		v = strings.TrimSpace(strings.ToLower(v))
		if v == "" {
			return
		}
		if _, ok := seen[v]; ok {
			return
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	if meta != nil {
		for _, lang := range meta.Languages {
			add(lang)
		}
	}
	if skillReport != nil {
		for _, framework := range skillReport.Frameworks {
			add(framework)
		}
		for _, technology := range skillReport.Technologies {
			add(technology.Name)
		}
	}
	for _, finding := range execResult.Findings {
		add(finding.RuleID)
	}
	return out
}

func collectEvidenceSnippets(scanDir string, findings []rules.Finding) map[string]string {
	snippets := make(map[string]string)
	seen := make(map[string]bool)
	for _, f := range findings {
		for _, ev := range f.Evidence {
			if seen[ev.File] || ev.File == "" {
				continue
			}
			seen[ev.File] = true
			path := scanDir + "/" + ev.File
			data, err := os.ReadFile(path)
			if err != nil {
				continue
			}
			lines := strings.Split(string(data), "\n")
			// Extract bounded snippet around evidence (max 20 lines)
			start := ev.LineStart - 3
			if start < 0 {
				start = 0
			}
			end := ev.LineEnd + 3
			if end > len(lines) {
				end = len(lines)
			}
			if start < len(lines) {
				snippets[ev.File] = strings.Join(lines[start:end], "\n")
			}
		}
	}
	return snippets
}

func containsLanguage(languages []string, lang string) bool {
	for _, l := range languages {
		if l == lang {
			return true
		}
	}
	return false
}

// writeJSONFile marshals v as indented JSON and writes it to path.
func writeJSONFile(path string, v interface{}) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}

func copyStringMap(in map[string]string) map[string]string {
	if in == nil {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func dedupeStringsSorted(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}
