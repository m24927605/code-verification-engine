package repo_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/verabase/code-verification-engine/internal/repo"
)

func initTestRepo(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	run(t, dir, "git", "init")
	run(t, dir, "git", "config", "user.email", "test@test.com")
	run(t, dir, "git", "config", "user.name", "Test")

	for path, content := range files {
		full := filepath.Join(dir, path)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	run(t, dir, "git", "add", ".")
	run(t, dir, "git", "commit", "-m", "init")
	return dir
}

func run(t *testing.T, dir, name string, args ...string) {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v failed: %v\n%s", name, args, err, out)
	}
}

func TestLoadRepo(t *testing.T) {
	repoDir := initTestRepo(t, map[string]string{
		"main.go":     "package main\nfunc main() {}\n",
		"lib/util.go": "package lib\nfunc Util() {}\n",
		"README.md":   "# test",
	})

	meta, err := repo.Load(repoDir, "HEAD")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if meta.RepoName == "" {
		t.Fatal("repo name should not be empty")
	}
	if meta.CommitSHA == "" {
		t.Fatal("commit SHA should not be empty")
	}
	if meta.Ref != "HEAD" {
		t.Fatalf("expected ref HEAD, got %q", meta.Ref)
	}
	if meta.FileCount < 2 {
		t.Fatalf("expected at least 2 files, got %d", meta.FileCount)
	}
	if len(meta.Files) < 2 {
		t.Fatalf("expected at least 2 files, got %d", len(meta.Files))
	}
}

func TestLoadRepoInvalidPath(t *testing.T) {
	_, err := repo.Load("/nonexistent/path", "HEAD")
	if err == nil {
		t.Fatal("expected error for invalid path")
	}
}

func TestLoadRepoNotGit(t *testing.T) {
	dir := t.TempDir()
	_, err := repo.Load(dir, "HEAD")
	if err == nil {
		t.Fatal("expected error for non-git directory")
	}
}

func TestLoadRepoInvalidRef(t *testing.T) {
	repoDir := initTestRepo(t, map[string]string{
		"main.go": "package main\n",
	})

	_, err := repo.Load(repoDir, "nonexistent-branch")
	if err == nil {
		t.Fatal("expected error for invalid ref")
	}
}

func TestLoadRepoRespectsGitTracking(t *testing.T) {
	repoDir := initTestRepo(t, map[string]string{
		"main.go":    "package main\n",
		".gitignore": "ignored/\n",
	})
	// Create an untracked ignored file
	ignoredDir := filepath.Join(repoDir, "ignored")
	os.MkdirAll(ignoredDir, 0o755)
	os.WriteFile(filepath.Join(ignoredDir, "secret.go"), []byte("package secret\n"), 0o644)

	meta, err := repo.Load(repoDir, "HEAD")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, f := range meta.Files {
		if filepath.Dir(f) == "ignored" {
			t.Fatalf("ignored file should not appear: %s", f)
		}
	}
}

func TestLoadRepoFromSubdir(t *testing.T) {
	repoDir := initTestRepo(t, map[string]string{
		"main.go":     "package main\n",
		"sub/util.go": "package sub\n",
	})

	subdir := filepath.Join(repoDir, "sub")
	meta, err := repo.Load(subdir, "HEAD")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should resolve to repo root, not subdir
	expected, _ := filepath.EvalSymlinks(repoDir)
	got, _ := filepath.EvalSymlinks(meta.RepoPath)
	if got != expected {
		t.Fatalf("expected repo path %q, got %q", expected, got)
	}
}

func TestLoadRepoNotADirectory(t *testing.T) {
	// Create a file (not a directory)
	dir := t.TempDir()
	filePath := filepath.Join(dir, "not-a-dir")
	os.WriteFile(filePath, []byte("data"), 0o644)
	_, err := repo.Load(filePath, "HEAD")
	if err == nil {
		t.Fatal("expected error for file path (not a directory)")
	}
}

func TestFilterSafePathsNormalFiles(t *testing.T) {
	repoDir := initTestRepo(t, map[string]string{
		"main.go":      "package main\n",
		"lib/util.go":  "package lib\n",
		"deep/a/b.go":  "package b\n",
	})

	files := []string{"main.go", "lib/util.go", "deep/a/b.go"}
	safe := repo.FilterSafePaths(repoDir, files)

	if len(safe) != 3 {
		t.Fatalf("expected 3 safe paths, got %d: %v", len(safe), safe)
	}
}

func TestFilterSafePathsRejectsDotDot(t *testing.T) {
	repoDir := initTestRepo(t, map[string]string{
		"main.go": "package main\n",
	})

	files := []string{"main.go", "../../../etc/passwd", "sub/../../../escape"}
	safe := repo.FilterSafePaths(repoDir, files)

	for _, f := range safe {
		if filepath.Base(f) == "passwd" || filepath.Base(f) == "escape" {
			t.Fatalf("path traversal should be filtered: %s", f)
		}
	}
	// Only main.go should survive
	if len(safe) != 1 {
		t.Fatalf("expected 1 safe path, got %d: %v", len(safe), safe)
	}
}

func TestFilterSafePathsRejectsSymlinks(t *testing.T) {
	repoDir := initTestRepo(t, map[string]string{
		"main.go": "package main\n",
	})

	// Create a symlink inside the repo
	symlinkPath := filepath.Join(repoDir, "link.go")
	os.Symlink(filepath.Join(repoDir, "main.go"), symlinkPath)

	files := []string{"main.go", "link.go"}
	safe := repo.FilterSafePaths(repoDir, files)

	for _, f := range safe {
		if f == "link.go" {
			t.Fatal("symlink should be filtered out")
		}
	}
}

func TestFilterSafePathsNonexistentFile(t *testing.T) {
	repoDir := initTestRepo(t, map[string]string{
		"main.go": "package main\n",
	})

	files := []string{"main.go", "does-not-exist.go"}
	safe := repo.FilterSafePaths(repoDir, files)

	if len(safe) != 1 {
		t.Fatalf("expected 1 safe path (nonexistent filtered), got %d: %v", len(safe), safe)
	}
	if safe[0] != "main.go" {
		t.Fatalf("expected main.go, got %s", safe[0])
	}
}

func TestFilterSafePathsEmptyInput(t *testing.T) {
	repoDir := initTestRepo(t, map[string]string{
		"main.go": "package main\n",
	})

	safe := repo.FilterSafePaths(repoDir, nil)
	if len(safe) != 0 {
		t.Fatalf("expected 0 safe paths for nil input, got %d", len(safe))
	}

	safe = repo.FilterSafePaths(repoDir, []string{})
	if len(safe) != 0 {
		t.Fatalf("expected 0 safe paths for empty input, got %d", len(safe))
	}
}

func TestListTrackedFiles(t *testing.T) {
	repoDir := initTestRepo(t, map[string]string{
		"main.go":     "package main\n",
		"lib/util.go": "package lib\n",
		"README.md":   "# readme",
	})

	files, err := repo.ListTrackedFiles(repoDir, "HEAD")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(files) != 3 {
		t.Fatalf("expected 3 tracked files, got %d: %v", len(files), files)
	}
}

func TestListTrackedFilesInvalidRef(t *testing.T) {
	repoDir := initTestRepo(t, map[string]string{
		"main.go": "package main\n",
	})

	_, err := repo.ListTrackedFiles(repoDir, "nonexistent-ref")
	if err == nil {
		t.Fatal("expected error for invalid ref")
	}
}

func TestFilterSafePathsSymlinkDirectory(t *testing.T) {
	// Create a repo with a symlinked directory that escapes the repo root
	repoDir := initTestRepo(t, map[string]string{
		"main.go": "package main\n",
	})

	// Create an outside directory with a file
	outsideDir := t.TempDir()
	os.WriteFile(filepath.Join(outsideDir, "secret.txt"), []byte("secret"), 0o644)

	// Create a symlinked directory inside the repo pointing outside
	symlinkDir := filepath.Join(repoDir, "escape-dir")
	os.Symlink(outsideDir, symlinkDir)

	files := []string{"main.go", "escape-dir/secret.txt"}
	safe := repo.FilterSafePaths(repoDir, files)

	// The escape-dir/secret.txt should be filtered because escape-dir is a symlink
	for _, f := range safe {
		if f == "escape-dir/secret.txt" {
			t.Fatal("file via symlinked directory should be filtered")
		}
	}
}

func TestListTrackedFilesEmptyRepo(t *testing.T) {
	// Create a repo with no tracked files (only initial commit with no files)
	dir := t.TempDir()
	run(t, dir, "git", "init")
	run(t, dir, "git", "config", "user.email", "test@test.com")
	run(t, dir, "git", "config", "user.name", "Test")
	run(t, dir, "git", "commit", "--allow-empty", "-m", "empty init")

	files, err := repo.ListTrackedFiles(dir, "HEAD")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if files != nil {
		t.Fatalf("expected nil for empty repo, got %v", files)
	}
}

func TestLoadRepoEmptyCommit(t *testing.T) {
	// A repo with only an empty commit
	dir := t.TempDir()
	run(t, dir, "git", "init")
	run(t, dir, "git", "config", "user.email", "test@test.com")
	run(t, dir, "git", "config", "user.name", "Test")
	run(t, dir, "git", "commit", "--allow-empty", "-m", "empty init")

	meta, err := repo.Load(dir, "HEAD")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if meta.FileCount != 0 {
		t.Fatalf("expected 0 files, got %d", meta.FileCount)
	}
	if len(meta.Languages) != 0 {
		t.Fatalf("expected no languages, got %v", meta.Languages)
	}
}

func TestListTrackedFilesInvalidRepo(t *testing.T) {
	_, err := repo.ListTrackedFiles(t.TempDir(), "HEAD")
	if err == nil {
		t.Fatal("expected error for non-git directory")
	}
}

func TestLoadRepoWithLanguages(t *testing.T) {
	repoDir := initTestRepo(t, map[string]string{
		"main.go":         "package main\nfunc main() {}\n",
		"go.mod":          "module example.com/test\n",
		"web/app.ts":      "export const app = 1;\n",
		"scripts/util.py": "def util(): pass\n",
	})

	meta, err := repo.Load(repoDir, "HEAD")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(meta.Languages) != 3 {
		t.Fatalf("expected 3 languages, got %d: %v", len(meta.Languages), meta.Languages)
	}
	for _, lang := range []string{"go", "python", "typescript"} {
		found := false
		for _, l := range meta.Languages {
			if l == lang {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("expected language %q in %v", lang, meta.Languages)
		}
	}
}
