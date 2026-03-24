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
	// RepoPath is the git top-level root (SourceRepoRoot).
	RepoPath string
	RepoName string
	Ref      string
	CommitSHA string
	FileCount int
	Files     []string // relative paths of tracked files (filtered to scan boundary)
	Languages []string

	// Scan boundary fields
	SourceRepoRoot string // git top-level root
	RequestedPath  string // original user input after cleaning/abs
	ScanRoot       string // absolute path of requested directory in source repo
	ScanSubdir     string // relative path from repo root to scan root, "" for full repo
	BoundaryMode   string // "repo" (full) or "subdir" (subtree)
}

// Load validates the repository at repoDir, resolves the given ref,
// and collects metadata including tracked files and detected languages.
//
// If repoDir is a subdirectory inside a git repository, only files within
// that subtree are included. This is the scan boundary.
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

	// Step 1: Resolve scan boundary
	sourceRoot, requestedAbs, scanSubdir, err := ResolveScanBoundary(repoDir)
	if err != nil {
		return nil, err
	}

	sha, err := git.ResolveRef(sourceRoot, ref)
	if err != nil {
		return nil, err
	}

	// Step 2: Enumerate all tracked files from repo root
	rawFiles, err := ListTrackedFiles(sourceRoot, ref)
	if err != nil {
		return nil, fmt.Errorf("enumerate files: %w", err)
	}

	// Step 3: Filter to requested subtree FIRST
	rawFiles = FilterFilesToSubtree(rawFiles, scanSubdir)

	// Step 4: Filter out symlinks and paths that escape the workspace
	files := FilterSafePaths(sourceRoot, rawFiles)

	// Step 5: Language detection only on filtered set
	repoName := filepath.Base(requestedAbs)
	languages := DetectLanguages(files)

	boundaryMode := "repo"
	if scanSubdir != "" {
		boundaryMode = "subdir"
	}

	return &RepoMetadata{
		RepoPath:       sourceRoot,
		RepoName:       repoName,
		Ref:            ref,
		CommitSHA:      sha,
		FileCount:      len(files),
		Files:          files,
		Languages:      languages,
		SourceRepoRoot: sourceRoot,
		RequestedPath:  requestedAbs,
		ScanRoot:       requestedAbs,
		ScanSubdir:     scanSubdir,
		BoundaryMode:   boundaryMode,
	}, nil
}

// ResolveScanBoundary computes the scan boundary from a user-supplied path.
// It returns:
//   - sourceRoot: the git top-level root
//   - requestedAbs: cleaned absolute path of the user request
//   - scanSubdir: relative path from sourceRoot to requestedAbs ("" for full repo)
//   - err: if the path is invalid or escapes the repo
func ResolveScanBoundary(requestedPath string) (sourceRoot, requestedAbs, scanSubdir string, err error) {
	requestedAbs, err = filepath.Abs(requestedPath)
	if err != nil {
		return "", "", "", fmt.Errorf("resolve requested path: %w", err)
	}
	// Resolve symlinks for consistent comparison
	if resolved, e := filepath.EvalSymlinks(requestedAbs); e == nil {
		requestedAbs = resolved
	}
	requestedAbs = filepath.Clean(requestedAbs)

	sourceRoot, err = git.ResolveRepoRoot(requestedAbs)
	if err != nil {
		return "", "", "", err
	}
	sourceRoot = filepath.Clean(sourceRoot)
	// Resolve symlinks on sourceRoot too (macOS /var → /private/var)
	if resolved, e := filepath.EvalSymlinks(sourceRoot); e == nil {
		sourceRoot = resolved
	}

	// Verify requested path is inside (or equal to) repo root
	if requestedAbs == sourceRoot {
		return sourceRoot, requestedAbs, "", nil
	}

	rel, err := filepath.Rel(sourceRoot, requestedAbs)
	if err != nil {
		return "", "", "", fmt.Errorf("compute scan subdir: %w", err)
	}
	// Safety: reject if rel escapes upward
	if strings.HasPrefix(rel, "..") {
		return "", "", "", fmt.Errorf("requested path %q escapes repo root %q", requestedAbs, sourceRoot)
	}

	return sourceRoot, requestedAbs, filepath.ToSlash(rel), nil
}

// FilterFilesToSubtree filters a list of repo-root-relative file paths to
// only those within the given subdirectory. If scanSubdir is empty, all files
// are returned (full-repo scan).
//
// File paths and scanSubdir use forward slashes (git convention).
func FilterFilesToSubtree(files []string, scanSubdir string) []string {
	if scanSubdir == "" || scanSubdir == "." {
		return files
	}
	// Normalize: ensure no trailing slash, use forward slashes
	scanSubdir = strings.TrimSuffix(filepath.ToSlash(filepath.Clean(scanSubdir)), "/")
	prefix := scanSubdir + "/"

	var filtered []string
	for _, f := range files {
		if strings.HasPrefix(f, prefix) {
			filtered = append(filtered, f)
		}
	}
	return filtered
}

// FilterSafePaths removes symlinks and paths that escape the repo root.
// This is critical for scanning untrusted repos (e.g., candidate submissions,
// third-party code) where a malicious symlink could read host files.
func FilterSafePaths(root string, files []string) []string {
	// Resolve symlinks in root itself (e.g., macOS /var → /private/var)
	// so the prefix check matches EvalSymlinks results below.
	// EvalSymlinks returns an absolute, resolved path. If root does not
	// exist (e.g., race condition), fall back to filepath.Abs.
	absRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		// EvalSymlinks fails if root doesn't exist; fall back to Abs
		// which always succeeds for absolute paths.
		absRoot, _ = filepath.Abs(root)
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
