package git_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/verabase/code-verification-engine/internal/git"
)

func TestCleanupWorkspaceWorktree(t *testing.T) {
	repo := initTestRepo(t)
	tmpRoot := t.TempDir()

	ws, err := git.CreateWorkspace(repo, "HEAD", tmpRoot)
	if err != nil {
		t.Fatalf("create workspace: %v", err)
	}

	if err := git.CleanupWorkspace(ws); err != nil {
		t.Fatalf("cleanup: %v", err)
	}

	if _, err := os.Stat(ws.Path); !os.IsNotExist(err) {
		t.Fatal("workspace directory should not exist after cleanup")
	}
}

func TestCleanupWorkspaceClone(t *testing.T) {
	tmpRoot := t.TempDir()
	cloneDir := filepath.Join(tmpRoot, "cve-test-clone")
	if err := os.MkdirAll(cloneDir, 0o755); err != nil {
		t.Fatal(err)
	}

	ws := &git.Workspace{
		Path:       cloneDir,
		IsWorktree: false,
	}

	if err := git.CleanupWorkspace(ws); err != nil {
		t.Fatalf("cleanup: %v", err)
	}

	if _, err := os.Stat(cloneDir); !os.IsNotExist(err) {
		t.Fatal("clone directory should not exist after cleanup")
	}
}

func TestCleanupWorkspaceNil(t *testing.T) {
	if err := git.CleanupWorkspace(nil); err != nil {
		t.Fatalf("cleanup nil should not error: %v", err)
	}
}

func TestPruneStaleWorkspaces(t *testing.T) {
	tmpRoot := t.TempDir()

	// Create a fake stale workspace (>24h old)
	staleDir := filepath.Join(tmpRoot, "cve-repo-abc12345-1234-aabb")
	if err := os.MkdirAll(staleDir, 0o755); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-25 * time.Hour)
	os.Chtimes(staleDir, old, old)

	// Create a fresh workspace (should not be pruned)
	freshDir := filepath.Join(tmpRoot, "cve-repo-def56789-5678-ccdd")
	if err := os.MkdirAll(freshDir, 0o755); err != nil {
		t.Fatal(err)
	}

	// Create a non-engine directory (should not be touched)
	userDir := filepath.Join(tmpRoot, "user-worktree")
	if err := os.MkdirAll(userDir, 0o755); err != nil {
		t.Fatal(err)
	}
	os.Chtimes(userDir, old, old)

	pruned, err := git.PruneStaleWorkspaces(tmpRoot, 24*time.Hour)
	if err != nil {
		t.Fatalf("prune: %v", err)
	}

	if pruned != 1 {
		t.Fatalf("expected 1 pruned, got %d", pruned)
	}

	if _, err := os.Stat(staleDir); !os.IsNotExist(err) {
		t.Fatal("stale workspace should be removed")
	}
	if _, err := os.Stat(freshDir); os.IsNotExist(err) {
		t.Fatal("fresh workspace should be kept")
	}
	if _, err := os.Stat(userDir); os.IsNotExist(err) {
		t.Fatal("non-engine directory should not be touched")
	}
}

func TestPruneStaleWorkspacesMultiple(t *testing.T) {
	tmpRoot := t.TempDir()

	// Create multiple stale workspaces
	old := time.Now().Add(-25 * time.Hour)
	for _, name := range []string{"cve-repo1-aaa-1-xx", "cve-repo2-bbb-2-yy"} {
		dir := filepath.Join(tmpRoot, name)
		os.MkdirAll(dir, 0o755)
		os.Chtimes(dir, old, old)
	}

	pruned, err := git.PruneStaleWorkspaces(tmpRoot, 24*time.Hour)
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if pruned != 2 {
		t.Fatalf("expected 2 pruned, got %d", pruned)
	}
}

func TestPruneStaleWorkspacesZeroRetention(t *testing.T) {
	tmpRoot := t.TempDir()

	// Create a fresh workspace - with 0 retention, all should be pruned
	dir := filepath.Join(tmpRoot, "cve-test-fresh-1-aa")
	os.MkdirAll(dir, 0o755)

	pruned, err := git.PruneStaleWorkspaces(tmpRoot, 0)
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if pruned != 1 {
		t.Fatalf("expected 1 pruned with 0 retention, got %d", pruned)
	}
}

func TestPruneStaleWorkspacesRemoveAllError(t *testing.T) {
	tmpRoot := t.TempDir()

	// Create a stale cve- directory
	staleDir := filepath.Join(tmpRoot, "cve-stale-unremovable-1-aa")
	os.MkdirAll(staleDir, 0o755)
	old := time.Now().Add(-25 * time.Hour)
	os.Chtimes(staleDir, old, old)

	// Make the parent directory read-only so os.RemoveAll fails
	os.Chmod(tmpRoot, 0o555)
	defer os.Chmod(tmpRoot, 0o755)

	pruned, err := git.PruneStaleWorkspaces(tmpRoot, 24*time.Hour)
	if err != nil {
		t.Fatalf("prune should not return error (best-effort): %v", err)
	}
	// RemoveAll should fail, so nothing is actually pruned
	if pruned != 0 {
		t.Fatalf("expected 0 pruned when parent is read-only, got %d", pruned)
	}
}

func TestPruneStaleWorkspacesEmptyDir(t *testing.T) {
	tmpRoot := t.TempDir()
	pruned, err := git.PruneStaleWorkspaces(tmpRoot, 24*time.Hour)
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if pruned != 0 {
		t.Fatalf("expected 0 pruned, got %d", pruned)
	}
}
