package engine

// ScanHooks provides extension points for external systems to integrate
// with the verification pipeline. All hooks are optional.
//
// Hooks are called at specific points in the pipeline but never affect
// the deterministic verification result.
type ScanHooks struct {
	// OnScanStart is called before analysis begins.
	OnScanStart func(repoPath, ref, profile string)

	// OnAnalyzerComplete is called when each language analyzer finishes.
	OnAnalyzerComplete func(language string, fileCount int, skippedCount int)

	// OnFindingProduced is called for each finding as it's produced.
	OnFindingProduced func(finding interface{})

	// OnScanComplete is called after all reports are written.
	OnScanComplete func(exitCode int, outputDir string)
}
