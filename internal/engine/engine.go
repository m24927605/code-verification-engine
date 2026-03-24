package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/verabase/code-verification-engine/internal/analyzers"
	"github.com/verabase/code-verification-engine/internal/claims"
	"github.com/verabase/code-verification-engine/internal/evidencegraph"
	"github.com/verabase/code-verification-engine/internal/facts"
	goanalyzer "github.com/verabase/code-verification-engine/internal/analyzers/go"
	jsanalyzer "github.com/verabase/code-verification-engine/internal/analyzers/js"
	pyanalyzer "github.com/verabase/code-verification-engine/internal/analyzers/python"
	tsanalyzer "github.com/verabase/code-verification-engine/internal/analyzers/ts"
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
	Ctx          context.Context       // caller context for cancellation/timeout
	RepoPath     string
	Ref          string
	Profile      string // built-in profile name
	OutputDir    string
	Format       string
	Strict       bool
	Progress     io.Writer             // stderr for progress messages
	Interpret    bool                  // Enable LLM interpretation layer
	LLMProvider  interpret.LLMProvider // LLM provider (nil = skip interpretation)
	ClaimSet     string                // optional claim set name (alternative/complement to Profile)
	Hooks        *ScanHooks            // optional extension hooks
	Plugins      []PluginAnalyzer      // optional external analyzer plugins
	Mode         string                // execution mode: verification, skill_inference, both (default: verification)
	SkillProfile string                // skill profile name (default: github-engineer-core)
}

// Result holds the engine execution result.
type Result struct {
	ExitCode          int
	Scan              report.ScanReport
	Report            report.VerificationReport
	Accounting        *ScanAccounting              // per-file analysis accounting
	ClaimReport       *claims.ClaimReport              // nil if no claim set specified
	EvidenceGraph     *evidencegraph.EvidenceGraph    // evidence relationship graph
	InterpretedReport *interpret.InterpretedReport    // nil if interpretation disabled
	SkillReport       *skills.Report                   // nil if mode does not include skill_inference
	Errors            []string
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

	// Populate stable evidence IDs, assign trust class, and fire finding hooks
	for i := range execResult.Findings {
		for j := range execResult.Findings[i].Evidence {
			execResult.Findings[i].Evidence[j].ID = rules.EvidenceID(execResult.Findings[i].Evidence[j])
		}
		// Assign trust class and enforce trust boundary invariants
		rules.NormalizeTrust(&execResult.Findings[i])
		// Hook: OnFindingProduced
		if cfg.Hooks != nil && cfg.Hooks.OnFindingProduced != nil {
			cfg.Hooks.OnFindingProduced(execResult.Findings[i])
		}
	}

	// Build evidence graph
	evGraph := evidencegraph.BuildFromResults(allResults, execResult.Findings)
	fmt.Fprintf(progress, "[INFO] evidence graph: %d nodes, %d edges, %d files\n",
		evGraph.NodeCount(), evGraph.EdgeCount(), len(evGraph.UniqueFiles()))

	sigSummary := report.ComputeSignalSummary(execResult.Findings)
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

	verReport := report.GenerateVerificationReport(report.ReportInput{
		Partial:      partial,
		Findings:     execResult.Findings,
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

		skillReport = skills.Evaluate(execResult.Findings, sp, cfg.RepoPath, skills.WithFactSet(factSet))

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

	exitCode := 0
	if partial {
		exitCode = 6
	}

	// Hook: OnScanComplete
	if cfg.Hooks != nil && cfg.Hooks.OnScanComplete != nil {
		cfg.Hooks.OnScanComplete(exitCode, cfg.OutputDir)
	}

	return Result{
		ExitCode:          exitCode,
		Scan:              scanReport,
		Report:            verReport,
		Accounting:        &accounting,
		ClaimReport:       claimReport,
		EvidenceGraph:     evGraph,
		InterpretedReport: interpretedReport,
		SkillReport:       skillReport,
		Errors:            analyzerErrors,
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
