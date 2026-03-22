package git

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// IsGitRepo checks whether dir is inside a git repository.
func IsGitRepo(dir string) (bool, error) {
	cmd := exec.Command("git", "-C", dir, "rev-parse", "--is-inside-work-tree")
	out, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 128 {
			return false, nil
		}
		return false, fmt.Errorf("git check failed: %w", err)
	}
	return strings.TrimSpace(string(out)) == "true", nil
}

// ResolveRepoRoot returns the top-level directory of the git repository containing dir.
func ResolveRepoRoot(dir string) (string, error) {
	cmd := exec.Command("git", "-C", dir, "rev-parse", "--show-toplevel")
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("not a git repository: %w", err)
	}
	return strings.TrimSpace(string(out)), nil
}

// ResolveRef resolves a branch, tag, or commit SHA to its full commit hash.
func ResolveRef(repoDir, ref string) (string, error) {
	cmd := exec.Command("git", "-C", repoDir, "rev-parse", "--verify", ref)
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("ref %q not found: %w", ref, err)
	}
	return strings.TrimSpace(string(out)), nil
}

// Workspace represents an isolated scan workspace.
type Workspace struct {
	Path       string
	SourceRepo string
	Ref        string
	CommitSHA  string
	IsWorktree bool
}

// CreateWorkspace creates an isolated scan workspace for the given ref.
// It prefers git worktree, falling back to a temporary clone.
func CreateWorkspace(repoDir, ref, tmpRoot string) (*Workspace, error) {
	sha, err := ResolveRef(repoDir, ref)
	if err != nil {
		return nil, err
	}

	wsName, err := workspaceName(repoDir, sha)
	if err != nil {
		return nil, err
	}
	wsPath := filepath.Join(tmpRoot, wsName)

	// Try worktree first
	ws, err := createWorktree(repoDir, sha, wsPath)
	if err == nil {
		ws.Ref = ref
		return ws, nil
	}

	// Fallback to clone
	ws, err = createClone(repoDir, sha, wsPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create workspace: %w", err)
	}
	ws.Ref = ref
	return ws, nil
}

// CreateWorkspaceWithClone creates a workspace using git clone only (no worktree).
// This is useful when worktrees are not safe or available.
func CreateWorkspaceWithClone(repoDir, ref, tmpRoot string) (*Workspace, error) {
	sha, err := ResolveRef(repoDir, ref)
	if err != nil {
		return nil, err
	}

	wsName, err := workspaceName(repoDir, sha)
	if err != nil {
		return nil, err
	}
	wsPath := filepath.Join(tmpRoot, wsName)

	ws, err := createClone(repoDir, sha, wsPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create clone workspace: %w", err)
	}
	ws.Ref = ref
	return ws, nil
}

func createWorktree(repoDir, sha, wsPath string) (*Workspace, error) {
	cmd := exec.Command("git", "-C", repoDir, "worktree", "add", "--detach", wsPath, sha)
	if out, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("worktree add failed: %s: %w", out, err)
	}
	return &Workspace{
		Path:       wsPath,
		SourceRepo: repoDir,
		CommitSHA:  sha,
		IsWorktree: true,
	}, nil
}

func createClone(repoDir, sha, wsPath string) (*Workspace, error) {
	cmd := exec.Command("git", "clone", "--no-checkout", repoDir, wsPath)
	if out, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("clone failed: %s: %w", out, err)
	}

	cmd = exec.Command("git", "-C", wsPath, "checkout", sha)
	if out, err := cmd.CombinedOutput(); err != nil {
		os.RemoveAll(wsPath)
		return nil, fmt.Errorf("checkout failed: %s: %w", out, err)
	}

	return &Workspace{
		Path:       wsPath,
		SourceRepo: repoDir,
		CommitSHA:  sha,
		IsWorktree: false,
	}, nil
}

func workspaceName(repoDir, sha string) (string, error) {
	repoName := filepath.Base(repoDir)
	shortSHA := sha
	if len(shortSHA) > 8 {
		shortSHA = shortSHA[:8]
	}
	pid := os.Getpid()
	suffix, err := randomSuffix(4)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("cve-%s-%s-%d-%s", repoName, shortSHA, pid, suffix), nil
}

func randomSuffix(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// CleanupWorkspace removes the workspace. For worktrees, it removes and prunes.
func CleanupWorkspace(ws *Workspace) error {
	if ws == nil {
		return nil
	}
	if ws.IsWorktree {
		cmd := exec.Command("git", "-C", ws.SourceRepo, "worktree", "remove", "--force", ws.Path)
		if out, err := cmd.CombinedOutput(); err != nil {
			os.RemoveAll(ws.Path)
			return fmt.Errorf("worktree remove failed: %s: %w", out, err)
		}
		return nil
	}
	return os.RemoveAll(ws.Path)
}

// DefaultTempRoot returns the default engine-managed temporary workspace root.
func DefaultTempRoot() string {
	return filepath.Join(os.TempDir(), "cve-workspaces")
}

// EnsureTempRoot creates the temporary workspace root directory if it doesn't exist.
func EnsureTempRoot(root string) error {
	return os.MkdirAll(root, 0o755)
}
