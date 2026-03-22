package engine

import "github.com/verabase/code-verification-engine/internal/analyzers"

// PartialGrade represents the severity of a partial scan.
type PartialGrade string

const (
	PartialNone     PartialGrade = "none"     // Full scan, no issues
	PartialMinor    PartialGrade = "minor"    // Few files skipped, core scope intact
	PartialModerate PartialGrade = "moderate" // Significant files skipped, some rules affected
	PartialSevere   PartialGrade = "severe"   // Major scope gaps, many rules unreliable
)

// ScanAccounting tracks per-file analysis status.
type ScanAccounting struct {
	TotalFiles    int                           `json:"total_files"`
	AnalyzedFiles int                           `json:"analyzed_files"`
	SkippedFiles  int                           `json:"skipped_files"`
	FailedFiles   int                           `json:"failed_files"`
	PartialGrade  PartialGrade                  `json:"partial_grade"`
	PerLanguage   map[string]LanguageAccounting `json:"per_language"`
	AffectedRules []string                      `json:"affected_rules,omitempty"` // Rules whose verdict may be degraded
}

// LanguageAccounting tracks analysis status per language.
type LanguageAccounting struct {
	Status        string   `json:"status"` // ok, partial, error
	TotalFiles    int      `json:"total_files"`
	AnalyzedFiles int      `json:"analyzed_files"`
	SkippedFiles  int      `json:"skipped_files"`
	SkippedPaths  []string `json:"skipped_paths,omitempty"`
}

// ComputeAccounting builds scan accounting from analyzer results.
func ComputeAccounting(results []*analyzers.AnalysisResult, resultLanguages map[*analyzers.AnalysisResult]string, analyzerStatuses map[string]string) ScanAccounting {
	acc := ScanAccounting{
		PerLanguage: make(map[string]LanguageAccounting),
	}

	for _, r := range results {
		lang := resultLanguages[r]
		la := acc.PerLanguage[lang]
		la.Status = analyzerStatuses[lang]
		la.TotalFiles += len(r.Files) + len(r.SkippedFiles)
		la.AnalyzedFiles += len(r.Files)
		la.SkippedFiles += len(r.SkippedFiles)
		for _, sf := range r.SkippedFiles {
			la.SkippedPaths = append(la.SkippedPaths, sf.File)
		}
		acc.PerLanguage[lang] = la
	}

	for _, la := range acc.PerLanguage {
		acc.TotalFiles += la.TotalFiles
		acc.AnalyzedFiles += la.AnalyzedFiles
		acc.SkippedFiles += la.SkippedFiles
	}

	// Compute partial grade
	if acc.SkippedFiles == 0 {
		acc.PartialGrade = PartialNone
	} else {
		ratio := float64(acc.SkippedFiles) / float64(max(acc.TotalFiles, 1))
		switch {
		case ratio <= 0.05:
			acc.PartialGrade = PartialMinor
		case ratio <= 0.20:
			acc.PartialGrade = PartialModerate
		default:
			acc.PartialGrade = PartialSevere
		}
	}

	return acc
}
