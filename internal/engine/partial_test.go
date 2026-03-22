package engine

import (
	"testing"

	"github.com/verabase/code-verification-engine/internal/analyzers"
	"github.com/verabase/code-verification-engine/internal/facts"
)

func TestComputeAccounting_NoSkips(t *testing.T) {
	r := &analyzers.AnalysisResult{
		Files: []facts.FileFact{
			{File: "a.go", Language: facts.LangGo},
			{File: "b.go", Language: facts.LangGo},
		},
	}
	results := []*analyzers.AnalysisResult{r}
	langs := map[*analyzers.AnalysisResult]string{r: "go"}
	statuses := map[string]string{"go": "ok"}

	acc := ComputeAccounting(results, langs, statuses)

	if acc.PartialGrade != PartialNone {
		t.Errorf("expected PartialNone, got %s", acc.PartialGrade)
	}
	if acc.TotalFiles != 2 {
		t.Errorf("expected 2 total files, got %d", acc.TotalFiles)
	}
	if acc.AnalyzedFiles != 2 {
		t.Errorf("expected 2 analyzed files, got %d", acc.AnalyzedFiles)
	}
	if acc.SkippedFiles != 0 {
		t.Errorf("expected 0 skipped files, got %d", acc.SkippedFiles)
	}
}

func TestComputeAccounting_Minor(t *testing.T) {
	// 1 skipped out of 100 = 1% → minor
	files := make([]facts.FileFact, 99)
	for i := range files {
		files[i] = facts.FileFact{File: "f.go", Language: facts.LangGo}
	}
	r := &analyzers.AnalysisResult{
		Files:        files,
		SkippedFiles: []analyzers.SkippedFile{{File: "bad.go", Reason: "parse error"}},
	}
	results := []*analyzers.AnalysisResult{r}
	langs := map[*analyzers.AnalysisResult]string{r: "go"}
	statuses := map[string]string{"go": "partial"}

	acc := ComputeAccounting(results, langs, statuses)

	if acc.PartialGrade != PartialMinor {
		t.Errorf("expected PartialMinor, got %s", acc.PartialGrade)
	}
	if acc.SkippedFiles != 1 {
		t.Errorf("expected 1 skipped, got %d", acc.SkippedFiles)
	}
}

func TestComputeAccounting_Moderate(t *testing.T) {
	// 15 skipped out of 100 = 15% → moderate
	files := make([]facts.FileFact, 85)
	for i := range files {
		files[i] = facts.FileFact{File: "f.go", Language: facts.LangGo}
	}
	skipped := make([]analyzers.SkippedFile, 15)
	for i := range skipped {
		skipped[i] = analyzers.SkippedFile{File: "s.go", Reason: "error"}
	}
	r := &analyzers.AnalysisResult{
		Files:        files,
		SkippedFiles: skipped,
	}
	results := []*analyzers.AnalysisResult{r}
	langs := map[*analyzers.AnalysisResult]string{r: "go"}
	statuses := map[string]string{"go": "partial"}

	acc := ComputeAccounting(results, langs, statuses)

	if acc.PartialGrade != PartialModerate {
		t.Errorf("expected PartialModerate, got %s", acc.PartialGrade)
	}
}

func TestComputeAccounting_Severe(t *testing.T) {
	// 50 skipped out of 100 = 50% → severe
	files := make([]facts.FileFact, 50)
	for i := range files {
		files[i] = facts.FileFact{File: "f.go", Language: facts.LangGo}
	}
	skipped := make([]analyzers.SkippedFile, 50)
	for i := range skipped {
		skipped[i] = analyzers.SkippedFile{File: "s.go", Reason: "error"}
	}
	r := &analyzers.AnalysisResult{
		Files:        files,
		SkippedFiles: skipped,
	}
	results := []*analyzers.AnalysisResult{r}
	langs := map[*analyzers.AnalysisResult]string{r: "go"}
	statuses := map[string]string{"go": "partial"}

	acc := ComputeAccounting(results, langs, statuses)

	if acc.PartialGrade != PartialSevere {
		t.Errorf("expected PartialSevere, got %s", acc.PartialGrade)
	}
}

func TestComputeAccounting_PerLanguage(t *testing.T) {
	goResult := &analyzers.AnalysisResult{
		Files: []facts.FileFact{
			{File: "a.go", Language: facts.LangGo},
		},
	}
	jsResult := &analyzers.AnalysisResult{
		Files: []facts.FileFact{
			{File: "a.js", Language: facts.LangJavaScript},
		},
		SkippedFiles: []analyzers.SkippedFile{
			{File: "b.js", Reason: "too large"},
		},
	}
	results := []*analyzers.AnalysisResult{goResult, jsResult}
	langs := map[*analyzers.AnalysisResult]string{
		goResult: "go",
		jsResult: "javascript",
	}
	statuses := map[string]string{"go": "ok", "javascript": "partial"}

	acc := ComputeAccounting(results, langs, statuses)

	goLang := acc.PerLanguage["go"]
	if goLang.Status != "ok" {
		t.Errorf("expected go status ok, got %s", goLang.Status)
	}
	if goLang.TotalFiles != 1 {
		t.Errorf("expected go total 1, got %d", goLang.TotalFiles)
	}

	jsLang := acc.PerLanguage["javascript"]
	if jsLang.Status != "partial" {
		t.Errorf("expected js status partial, got %s", jsLang.Status)
	}
	if jsLang.TotalFiles != 2 {
		t.Errorf("expected js total 2, got %d", jsLang.TotalFiles)
	}
	if jsLang.SkippedFiles != 1 {
		t.Errorf("expected js skipped 1, got %d", jsLang.SkippedFiles)
	}
	if len(jsLang.SkippedPaths) != 1 || jsLang.SkippedPaths[0] != "b.js" {
		t.Errorf("expected skipped path b.js, got %v", jsLang.SkippedPaths)
	}

	if acc.TotalFiles != 3 {
		t.Errorf("expected total 3, got %d", acc.TotalFiles)
	}
}

func TestComputeAccounting_EmptyResults(t *testing.T) {
	acc := ComputeAccounting(nil, nil, nil)

	if acc.PartialGrade != PartialNone {
		t.Errorf("expected PartialNone for empty, got %s", acc.PartialGrade)
	}
	if acc.TotalFiles != 0 {
		t.Errorf("expected 0 total files, got %d", acc.TotalFiles)
	}
}
