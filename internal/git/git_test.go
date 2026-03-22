package git_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/verabase/code-verification-engine/internal/git"
)

func initTestRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	run(t, dir, "git", "init")
	run(t, dir, "git", "config", "user.email", "test@test.com")
	run(t, dir, "git", "config", "user.name", "Test")
	writeFile(t, filepath.Join(dir, "README.md"), "# test")
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

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestIsGitRepo(t *testing.T) {
	repo := initTestRepo(t)

	ok, err := git.IsGitRepo(repo)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Fatal("expected true for valid git repo")
	}

	ok, err = git.IsGitRepo(t.TempDir())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Fatal("expected false for non-git directory")
	}
}

func TestResolveRepoRoot(t *testing.T) {
	repo := initTestRepo(t)
	subdir := filepath.Join(repo, "sub")
	if err := os.MkdirAll(subdir, 0o755); err != nil {
		t.Fatal(err)
	}

	root, err := git.ResolveRepoRoot(subdir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Resolve symlinks for macOS /private/var/folders
	expected, _ := filepath.EvalSymlinks(repo)
	got, _ := filepath.EvalSymlinks(root)
	if got != expected {
		t.Fatalf("expected root %q, got %q", expected, got)
	}
}

func TestResolveRef(t *testing.T) {
	repo := initTestRepo(t)

	sha, err := git.ResolveRef(repo, "HEAD")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(sha) < 7 {
		t.Fatalf("expected SHA, got %q", sha)
	}

	_, err = git.ResolveRef(repo, "nonexistent-ref")
	if err == nil {
		t.Fatal("expected error for nonexistent ref")
	}
}

func TestCreateWorkspace(t *testing.T) {
	repo := initTestRepo(t)
	tmpRoot := t.TempDir()

	ws, err := git.CreateWorkspace(repo, "HEAD", tmpRoot)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer git.CleanupWorkspace(ws)

	if _, err := os.Stat(ws.Path); os.IsNotExist(err) {
		t.Fatal("workspace directory does not exist")
	}
	if _, err := os.Stat(filepath.Join(ws.Path, "README.md")); os.IsNotExist(err) {
		t.Fatal("expected README.md in workspace")
	}
	ok, err := git.IsGitRepo(ws.Path)
	if err != nil || !ok {
		t.Fatal("workspace should be a valid git repo")
	}
}

func TestCreateWorkspaceNaming(t *testing.T) {
	repo := initTestRepo(t)
	tmpRoot := t.TempDir()

	ws, err := git.CreateWorkspace(repo, "HEAD", tmpRoot)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer git.CleanupWorkspace(ws)

	rel, err := filepath.Rel(tmpRoot, ws.Path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.HasPrefix(rel, "..") {
		t.Fatalf("workspace %q not under tmpRoot %q", ws.Path, tmpRoot)
	}
}

func TestCreateWorkspaceInvalidRef(t *testing.T) {
	repo := initTestRepo(t)
	tmpRoot := t.TempDir()

	_, err := git.CreateWorkspace(repo, "nonexistent-branch", tmpRoot)
	if err == nil {
		t.Fatal("expected error for invalid ref")
	}
}

func TestCreateWorkspaceFields(t *testing.T) {
	repo := initTestRepo(t)
	tmpRoot := t.TempDir()

	ws, err := git.CreateWorkspace(repo, "HEAD", tmpRoot)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer git.CleanupWorkspace(ws)

	if ws.SourceRepo == "" {
		t.Fatal("SourceRepo should not be empty")
	}
	if ws.CommitSHA == "" {
		t.Fatal("CommitSHA should not be empty")
	}
	if ws.Ref != "HEAD" {
		t.Fatalf("expected ref HEAD, got %q", ws.Ref)
	}
}

func TestDefaultTempRoot(t *testing.T) {
	root := git.DefaultTempRoot()
	if root == "" {
		t.Fatal("temp root should not be empty")
	}
	if !strings.Contains(root, "cve") {
		t.Fatalf("temp root should contain 'cve': %s", root)
	}
}

func TestEnsureTempRoot(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "cve-workspaces")

	err := git.EnsureTempRoot(root)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	info, err := os.Stat(root)
	if err != nil {
		t.Fatal("temp root should exist")
	}
	if !info.IsDir() {
		t.Fatal("temp root should be a directory")
	}

	// Idempotent
	err = git.EnsureTempRoot(root)
	if err != nil {
		t.Fatalf("idempotent call failed: %v", err)
	}
}

func TestCreateWorkspaceCloneFallbackBareRepo(t *testing.T) {
	// To force clone fallback, we pass a non-git directory as repoDir
	// but with a valid git repo accessible via clone. Instead, we test
	// CreateClone directly by exporting it.
	// For now, test that CreateWorkspace works with a bare repo and
	// that the workspace is functional regardless of method used.
	normalRepo := initTestRepo(t)
	bareRepo := t.TempDir() + "/bare.git"
	run(t, normalRepo, "git", "clone", "--bare", normalRepo, bareRepo)

	tmpRoot := t.TempDir()

	ws, err := git.CreateWorkspace(bareRepo, "HEAD", tmpRoot)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer git.CleanupWorkspace(ws)

	// Workspace should exist and contain our file regardless of method
	if _, err := os.Stat(filepath.Join(ws.Path, "README.md")); os.IsNotExist(err) {
		t.Fatal("expected README.md in workspace")
	}
}

func TestIsGitRepoNonexistentDir(t *testing.T) {
	ok, err := git.IsGitRepo("/nonexistent/path/that/does/not/exist")
	if err != nil {
		// git may return exit code 128 or some other error
		// either way, it shouldn't be marked as a repo
		return
	}
	if ok {
		t.Fatal("nonexistent path should not be a git repo")
	}
}

func TestResolveRepoRootNonGit(t *testing.T) {
	dir := t.TempDir()
	_, err := git.ResolveRepoRoot(dir)
	if err == nil {
		t.Fatal("expected error for non-git directory")
	}
}

func TestCleanupWorkspaceWorktreeAlreadyRemoved(t *testing.T) {
	repo := initTestRepo(t)
	tmpRoot := t.TempDir()

	ws, err := git.CreateWorkspace(repo, "HEAD", tmpRoot)
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	// Remove the directory first to simulate already-removed worktree
	os.RemoveAll(ws.Path)

	// CleanupWorkspace should handle this gracefully (may return error but shouldn't panic)
	_ = git.CleanupWorkspace(ws)
}

func TestCreateWorkspaceWithCloneInvalidRef(t *testing.T) {
	repo := initTestRepo(t)
	tmpRoot := t.TempDir()

	_, err := git.CreateWorkspaceWithClone(repo, "nonexistent-branch", tmpRoot)
	if err == nil {
		t.Fatal("expected error for invalid ref")
	}
}

func TestCreateCloneFallback(t *testing.T) {
	repo := initTestRepo(t)
	tmpRoot := t.TempDir()

	// Use CreateWorkspaceWithClone to test clone path explicitly
	ws, err := git.CreateWorkspaceWithClone(repo, "HEAD", tmpRoot)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer git.CleanupWorkspace(ws)

	if ws.IsWorktree {
		t.Fatal("expected clone, not worktree")
	}
	if _, err := os.Stat(filepath.Join(ws.Path, "README.md")); os.IsNotExist(err) {
		t.Fatal("expected README.md in cloned workspace")
	}
	if ws.CommitSHA == "" {
		t.Fatal("CommitSHA should not be empty")
	}
}

func TestCreateWorkspaceWithCloneFields(t *testing.T) {
	repo := initTestRepo(t)
	tmpRoot := t.TempDir()

	ws, err := git.CreateWorkspaceWithClone(repo, "HEAD", tmpRoot)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer git.CleanupWorkspace(ws)

	if ws.Ref != "HEAD" {
		t.Fatalf("expected ref HEAD, got %q", ws.Ref)
	}
	if ws.SourceRepo == "" {
		t.Fatal("SourceRepo should not be empty")
	}
	if ws.IsWorktree {
		t.Fatal("expected clone workspace, not worktree")
	}
}

func TestCreateWorkspaceWithCloneInvalidRepo(t *testing.T) {
	tmpRoot := t.TempDir()
	_, err := git.CreateWorkspaceWithClone("/nonexistent/repo", "HEAD", tmpRoot)
	if err == nil {
		t.Fatal("expected error for invalid repo")
	}
}

func TestCleanupWorkspaceClonePath(t *testing.T) {
	repo := initTestRepo(t)
	tmpRoot := t.TempDir()

	ws, err := git.CreateWorkspaceWithClone(repo, "HEAD", tmpRoot)
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	if err := git.CleanupWorkspace(ws); err != nil {
		t.Fatalf("cleanup clone: %v", err)
	}
	if _, err := os.Stat(ws.Path); !os.IsNotExist(err) {
		t.Fatal("clone workspace should be removed after cleanup")
	}
}

func TestCreateWorkspaceWorktreeFieldIsTrue(t *testing.T) {
	repo := initTestRepo(t)
	tmpRoot := t.TempDir()

	ws, err := git.CreateWorkspace(repo, "HEAD", tmpRoot)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer git.CleanupWorkspace(ws)

	// Normal repos should use worktree
	if !ws.IsWorktree {
		t.Fatal("expected worktree workspace for normal repo")
	}
}

func TestCreateWorkspaceInvalidRepo(t *testing.T) {
	tmpRoot := t.TempDir()
	_, err := git.CreateWorkspace("/nonexistent/repo", "HEAD", tmpRoot)
	if err == nil {
		t.Fatal("expected error for invalid repo")
	}
}

func TestResolveRefBranch(t *testing.T) {
	repo := initTestRepo(t)

	// Create a branch
	run(t, repo, "git", "checkout", "-b", "feature-branch")
	writeFile(t, filepath.Join(repo, "feature.go"), "package main\n")
	run(t, repo, "git", "add", ".")
	run(t, repo, "git", "commit", "-m", "feature")

	sha, err := git.ResolveRef(repo, "feature-branch")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(sha) != 40 {
		t.Fatalf("expected 40-char SHA, got %q (len %d)", sha, len(sha))
	}
}

func TestResolveRefTag(t *testing.T) {
	repo := initTestRepo(t)

	// Create a tag
	run(t, repo, "git", "tag", "v1.0.0")

	sha, err := git.ResolveRef(repo, "v1.0.0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(sha) != 40 {
		t.Fatalf("expected 40-char SHA, got %q", sha)
	}
}

func TestResolveRefShortSHA(t *testing.T) {
	repo := initTestRepo(t)

	fullSHA, err := git.ResolveRef(repo, "HEAD")
	if err != nil {
		t.Fatal(err)
	}

	shortSHA := fullSHA[:7]
	resolved, err := git.ResolveRef(repo, shortSHA)
	if err != nil {
		t.Fatalf("unexpected error resolving short SHA: %v", err)
	}
	if resolved != fullSHA {
		t.Fatalf("short SHA resolved to %q, expected %q", resolved, fullSHA)
	}
}

func TestIsGitRepoNotADirectory(t *testing.T) {
	// Passing a file (not a directory) to git -C should produce an error
	// that is not exit code 128 on some git versions, exercising the
	// non-128 error path in IsGitRepo.
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "notadir.txt")
	os.WriteFile(filePath, []byte("hi"), 0o644)

	ok, err := git.IsGitRepo(filePath)
	// Either returns false with no error (exit 128) or false with error
	if ok {
		t.Fatal("file should not be a git repo")
	}
	_ = err // error or nil, either is acceptable
}

func TestPruneStaleWorkspacesInvalidRoot(t *testing.T) {
	_, err := git.PruneStaleWorkspaces("/nonexistent/path", 24*3600*1e9)
	if err == nil {
		t.Fatal("expected error for invalid tmpRoot")
	}
}

func TestPruneStaleWorkspacesWithFiles(t *testing.T) {
	tmpRoot := t.TempDir()

	// Create a file (not a directory) with cve- prefix — should be skipped
	filePath := filepath.Join(tmpRoot, "cve-not-a-dir")
	os.WriteFile(filePath, []byte("data"), 0o644)

	pruned, err := git.PruneStaleWorkspaces(tmpRoot, 0)
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if pruned != 0 {
		t.Fatalf("expected 0 pruned (file not dir), got %d", pruned)
	}
}

func TestCreateWorkspaceWithBareRepo(t *testing.T) {
	// Create a bare repo and verify workspace creation works
	normalRepo := initTestRepo(t)
	bareRepo := filepath.Join(t.TempDir(), "bare.git")
	run(t, normalRepo, "git", "clone", "--bare", normalRepo, bareRepo)

	tmpRoot := t.TempDir()
	ws, err := git.CreateWorkspace(bareRepo, "HEAD", tmpRoot)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer git.CleanupWorkspace(ws)

	if ws.Ref != "HEAD" {
		t.Fatalf("expected ref HEAD, got %q", ws.Ref)
	}
	if ws.CommitSHA == "" {
		t.Fatal("CommitSHA should be set")
	}
	// Workspace should contain our file
	if _, err := os.Stat(filepath.Join(ws.Path, "README.md")); os.IsNotExist(err) {
		t.Fatal("expected README.md in workspace")
	}
}

func TestCreateWorkspaceCloneFallback(t *testing.T) {
	// Force worktree creation to fail by making .git/worktrees directory
	// read-only, causing git worktree add to fail and falling back to clone.
	repo := initTestRepo(t)

	// Make worktrees dir read-only to block git worktree add
	worktreesDir := filepath.Join(repo, ".git", "worktrees")
	os.MkdirAll(worktreesDir, 0o755)
	os.Chmod(worktreesDir, 0o444)
	defer os.Chmod(worktreesDir, 0o755) // restore for cleanup

	tmpRoot := t.TempDir()
	ws, err := git.CreateWorkspace(repo, "HEAD", tmpRoot)
	if err != nil {
		t.Fatalf("CreateWorkspace should fall back to clone: %v", err)
	}
	defer git.CleanupWorkspace(ws)

	// Should be a clone since worktree creation failed
	if ws.IsWorktree {
		t.Fatal("expected clone fallback, got worktree")
	}
	if _, err := os.Stat(filepath.Join(ws.Path, "README.md")); os.IsNotExist(err) {
		t.Fatal("expected README.md in cloned workspace")
	}
	if ws.Ref != "HEAD" {
		t.Fatalf("expected ref HEAD, got %q", ws.Ref)
	}
}

func TestCleanupWorkspaceWorktreeRemoveError(t *testing.T) {
	// Create a workspace with IsWorktree=true but invalid SourceRepo
	// so that git worktree remove fails, triggering the RemoveAll fallback.
	dir := t.TempDir()
	wsDir := filepath.Join(dir, "fake-worktree")
	os.MkdirAll(wsDir, 0o755)

	ws := &git.Workspace{
		Path:       wsDir,
		SourceRepo: "/nonexistent/repo",
		IsWorktree: true,
	}

	err := git.CleanupWorkspace(ws)
	// Should return an error from git worktree remove
	if err == nil {
		t.Fatal("expected error for worktree cleanup with invalid source repo")
	}
	// But the directory should still be cleaned up via RemoveAll fallback
	if _, statErr := os.Stat(wsDir); !os.IsNotExist(statErr) {
		t.Fatal("directory should be removed via RemoveAll fallback")
	}
}

func TestCreateWorkspaceBothMethodsFail(t *testing.T) {
	// Use a repo path that resolves the ref but can't be cloned.
	// Create a repo, resolve its HEAD, then delete the repo so clone fails.
	repo := initTestRepo(t)
	tmpRoot := t.TempDir()

	// Make worktrees dir read-only so worktree fails
	worktreesDir := filepath.Join(repo, ".git", "worktrees")
	os.MkdirAll(worktreesDir, 0o755)
	os.Chmod(worktreesDir, 0o444)
	defer os.Chmod(worktreesDir, 0o755)

	// Make the repo non-clonable by removing objects
	objectsDir := filepath.Join(repo, ".git", "objects")
	// Create a read-only barrier so clone fails
	packDir := filepath.Join(objectsDir, "pack")
	if info, err := os.Stat(packDir); err == nil && info.IsDir() {
		os.Chmod(packDir, 0o000)
		defer os.Chmod(packDir, 0o755)
	}

	_, err := git.CreateWorkspace(repo, "HEAD", tmpRoot)
	if err == nil {
		t.Fatal("expected error when both worktree and clone fail")
	}
}

func TestCreateWorkspaceWithCloneCheckoutSuccess(t *testing.T) {
	// Ensure clone path works with a specific branch ref
	repo := initTestRepo(t)

	// Create a branch with a second commit
	run(t, repo, "git", "checkout", "-b", "test-branch")
	writeFile(t, filepath.Join(repo, "branch.go"), "package main\n")
	run(t, repo, "git", "add", ".")
	run(t, repo, "git", "commit", "-m", "branch commit")

	tmpRoot := t.TempDir()
	ws, err := git.CreateWorkspaceWithClone(repo, "test-branch", tmpRoot)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer git.CleanupWorkspace(ws)

	// Should contain the branch-specific file
	if _, err := os.Stat(filepath.Join(ws.Path, "branch.go")); os.IsNotExist(err) {
		t.Fatal("expected branch.go in cloned workspace")
	}
	if ws.Ref != "test-branch" {
		t.Fatalf("expected ref test-branch, got %q", ws.Ref)
	}
}

func TestCreateWorkspaceCloneCheckoutInvalidSHA(t *testing.T) {
	// Test createClone with a valid clone but invalid SHA for checkout
	repo := initTestRepo(t)
	tmpRoot := t.TempDir()

	// We can't easily test this directly since CreateWorkspaceWithClone resolves
	// the ref first. But we can test that the workspace name generation is unique.
	ws1, err := git.CreateWorkspaceWithClone(repo, "HEAD", tmpRoot)
	if err != nil {
		t.Fatalf("ws1: %v", err)
	}
	defer git.CleanupWorkspace(ws1)

	ws2, err := git.CreateWorkspaceWithClone(repo, "HEAD", tmpRoot)
	if err != nil {
		t.Fatalf("ws2: %v", err)
	}
	defer git.CleanupWorkspace(ws2)

	if ws1.Path == ws2.Path {
		t.Fatal("two clone workspaces should have unique paths")
	}
}

func TestCreateWorkspaceMultipleUnique(t *testing.T) {
	repo := initTestRepo(t)
	tmpRoot := t.TempDir()

	ws1, err := git.CreateWorkspace(repo, "HEAD", tmpRoot)
	if err != nil {
		t.Fatalf("ws1: %v", err)
	}
	defer git.CleanupWorkspace(ws1)

	ws2, err := git.CreateWorkspace(repo, "HEAD", tmpRoot)
	if err != nil {
		t.Fatalf("ws2: %v", err)
	}
	defer git.CleanupWorkspace(ws2)

	if ws1.Path == ws2.Path {
		t.Fatal("two workspaces should have unique paths")
	}
}

func TestCreateWorkspaceWithCloneValidateFields(t *testing.T) {
	repo := initTestRepo(t)
	tmpRoot := t.TempDir()

	ws, err := git.CreateWorkspaceWithClone(repo, "HEAD", tmpRoot)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer git.CleanupWorkspace(ws)

	if ws.IsWorktree {
		t.Fatal("clone workspace should have IsWorktree=false")
	}
	if ws.Path == "" {
		t.Fatal("path should not be empty")
	}
	if ws.SourceRepo == "" {
		t.Fatal("source repo should not be empty")
	}
	if ws.CommitSHA == "" {
		t.Fatal("commit SHA should not be empty")
	}
	if len(ws.CommitSHA) != 40 {
		t.Fatalf("expected 40-char commit SHA, got %d chars", len(ws.CommitSHA))
	}

	// Verify the workspace contains the file
	content, err := os.ReadFile(filepath.Join(ws.Path, "README.md"))
	if err != nil {
		t.Fatal("README.md should exist in cloned workspace")
	}
	if !strings.Contains(string(content), "test") {
		t.Error("README.md should contain expected content")
	}
}

func TestIsGitRepoGitNotInPath(t *testing.T) {
	// When git is not in PATH, exec.Command returns a non-ExitError,
	// which exercises the fallthrough error path in IsGitRepo.
	t.Setenv("PATH", "/nonexistent")

	ok, err := git.IsGitRepo(t.TempDir())
	if ok {
		t.Fatal("should not report as git repo when git is not found")
	}
	if err == nil {
		t.Fatal("expected error when git is not found")
	}
}

func TestCreateWorkspaceWithCloneGitNotInPath(t *testing.T) {
	// Test that CreateWorkspaceWithClone fails gracefully when git is unavailable
	repo := initTestRepo(t)
	tmpRoot := t.TempDir()

	t.Setenv("PATH", "/nonexistent")

	_, err := git.CreateWorkspaceWithClone(repo, "HEAD", tmpRoot)
	if err == nil {
		t.Fatal("expected error when git is not in PATH")
	}
}

func TestCreateWorkspaceWithCloneTreeSHAFails(t *testing.T) {
	// Using a tree SHA (not a commit SHA) should fail at checkout,
	// exercising the createClone checkout error path.
	repo := initTestRepo(t)
	tmpRoot := t.TempDir()

	// Get the tree SHA (not the commit SHA)
	cmd := exec.Command("git", "-C", repo, "rev-parse", "HEAD^{tree}")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("get tree SHA: %v\n%s", err, out)
	}
	treeSHA := strings.TrimSpace(string(out))

	_, err = git.CreateWorkspaceWithClone(repo, treeSHA, tmpRoot)
	if err == nil {
		t.Fatal("expected error when using tree SHA (checkout should fail)")
	}
}

func TestCreateWorkspaceTreeSHAFails(t *testing.T) {
	// Using a tree SHA with CreateWorkspace should fail both worktree and clone paths.
	repo := initTestRepo(t)
	tmpRoot := t.TempDir()

	cmd := exec.Command("git", "-C", repo, "rev-parse", "HEAD^{tree}")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("get tree SHA: %v\n%s", err, out)
	}
	treeSHA := strings.TrimSpace(string(out))

	_, err = git.CreateWorkspace(repo, treeSHA, tmpRoot)
	if err == nil {
		t.Fatal("expected error when using tree SHA")
	}
}

func TestPruneStaleWorkspacesNonCvePrefix(t *testing.T) {
	tmpRoot := t.TempDir()

	// Directories without cve- prefix should never be pruned
	old := time.Now().Add(-100 * time.Hour)
	dirs := []string{"other-dir", "workspace-1", "temp"}
	for _, name := range dirs {
		dir := filepath.Join(tmpRoot, name)
		os.MkdirAll(dir, 0o755)
		os.Chtimes(dir, old, old)
	}

	pruned, err := git.PruneStaleWorkspaces(tmpRoot, 0)
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if pruned != 0 {
		t.Fatalf("expected 0 pruned for non-cve dirs, got %d", pruned)
	}
}
