package facts

import (
	"fmt"
	"time"
)

// ScanContext holds metadata about a scan execution.
type ScanContext struct {
	RepoPath  string     `json:"repo_path"`
	RepoName  string     `json:"repo_name"`
	Ref       string     `json:"ref"`
	CommitSHA string     `json:"commit_sha"`
	Languages []Language `json:"languages"`
	FileCount int        `json:"file_count"`
	ScannedAt time.Time  `json:"scanned_at"`
}

// NewScanContext creates a validated ScanContext.
func NewScanContext(repoPath, repoName, ref, commitSHA string, languages []Language, fileCount int) (ScanContext, error) {
	if repoPath == "" {
		return ScanContext{}, fmt.Errorf("repo path is required")
	}
	if repoName == "" {
		return ScanContext{}, fmt.Errorf("repo name is required")
	}
	if len(languages) == 0 {
		return ScanContext{}, fmt.Errorf("at least one language is required")
	}
	for _, l := range languages {
		if !l.IsValid() {
			return ScanContext{}, fmt.Errorf("unsupported language: %q", l)
		}
	}
	return ScanContext{
		RepoPath:  repoPath,
		RepoName:  repoName,
		Ref:       ref,
		CommitSHA: commitSHA,
		Languages: languages,
		FileCount: fileCount,
		ScannedAt: time.Now(),
	}, nil
}
