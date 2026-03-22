package repo

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/verabase/code-verification-engine/internal/git"
)

// RepoMetadata contains information about a loaded repository.
type RepoMetadata struct {
	RepoPath  string
	RepoName  string
	Ref       string
	CommitSHA string
	FileCount int
	Files     []string // relative paths of tracked files
	Languages []string
}

// Load validates the repository at repoDir, resolves the given ref,
// and collects metadata including tracked files and detected languages.
func Load(repoDir, ref string) (*RepoMetadata, error) {
	info, err := os.Stat(repoDir)
	if err != nil {
		return nil, fmt.Errorf("invalid repo path: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("repo path is not a directory: %s", repoDir)
	}

	ok, err := git.IsGitRepo(repoDir)
	if err != nil {
		return nil, fmt.Errorf("git check failed: %w", err)
	}
	if !ok {
		return nil, fmt.Errorf("not a git repository: %s", repoDir)
	}

	root, err := git.ResolveRepoRoot(repoDir)
	if err != nil {
		return nil, err
	}

	sha, err := git.ResolveRef(root, ref)
	if err != nil {
		return nil, err
	}

	rawFiles, err := ListTrackedFiles(root, ref)
	if err != nil {
		return nil, fmt.Errorf("enumerate files: %w", err)
	}

	// Filter out symlinks and paths that escape the workspace.
	// This prevents a malicious repo from reading host files via symlinks.
	files := FilterSafePaths(root, rawFiles)

	repoName := filepath.Base(root)
	languages := DetectLanguages(files)

	return &RepoMetadata{
		RepoPath:  root,
		RepoName:  repoName,
		Ref:       ref,
		CommitSHA: sha,
		FileCount: len(files),
		Files:     files,
		Languages: languages,
	}, nil
}

// FilterSafePaths removes symlinks and paths that escape the repo root.
// This is critical for scanning untrusted repos (e.g., candidate submissions,
// third-party code) where a malicious symlink could read host files.
func FilterSafePaths(root string, files []string) []string {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return nil
	}
	// Resolve symlinks in root itself (e.g., macOS /var → /private/var)
	// so the prefix check matches EvalSymlinks results below.
	if resolved, err := filepath.EvalSymlinks(absRoot); err == nil {
		absRoot = resolved
	}
	absRoot = filepath.Clean(absRoot) + string(filepath.Separator)

	var safe []string
	for _, relPath := range files {
		// Reject paths with .. traversal
		if strings.Contains(relPath, "..") {
			continue
		}

		absPath := filepath.Join(root, relPath)

		// Lstat (not Stat) to detect symlinks without following them
		info, err := os.Lstat(absPath)
		if err != nil {
			continue
		}

		// Reject symlinks entirely
		if info.Mode()&os.ModeSymlink != 0 {
			continue
		}

		// Resolve the real path and verify it stays within root
		realPath, err := filepath.EvalSymlinks(filepath.Dir(absPath))
		if err != nil {
			continue
		}
		realPath = filepath.Join(realPath, filepath.Base(absPath))
		if !strings.HasPrefix(filepath.Clean(realPath)+string(filepath.Separator), absRoot) &&
			filepath.Clean(realPath) != filepath.Clean(absRoot[:len(absRoot)-1]) {
			// Allow the file itself to be exactly at root
			if !strings.HasPrefix(filepath.Clean(realPath), filepath.Clean(absRoot)) {
				continue
			}
		}

		safe = append(safe, relPath)
	}
	return safe
}

// ListTrackedFiles returns files tracked by git at the given ref.
func ListTrackedFiles(repoDir, ref string) ([]string, error) {
	cmd := exec.Command("git", "-C", repoDir, "ls-tree", "-r", "--name-only", ref)
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("git ls-tree failed: %w", err)
	}

	raw := strings.TrimSpace(string(out))
	if raw == "" {
		return nil, nil
	}
	return strings.Split(raw, "\n"), nil
}
