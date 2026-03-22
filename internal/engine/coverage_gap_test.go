package engine

// coverage_gap_test.go — targeted tests to push the engine package above 95%.
// Covers: containsLanguage (0%), and remaining Run branches.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// --- containsLanguage (0% covered) ---

func TestContainsLanguage_Found(t *testing.T) {
	langs := []string{"go", "python", "javascript"}
	if !containsLanguage(langs, "python") {
		t.Error("expected containsLanguage to find 'python'")
	}
}

func TestContainsLanguage_NotFound(t *testing.T) {
	langs := []string{"go", "python", "javascript"}
	if containsLanguage(langs, "rust") {
		t.Error("expected containsLanguage to NOT find 'rust'")
	}
}

func TestContainsLanguage_Empty(t *testing.T) {
	if containsLanguage(nil, "go") {
		t.Error("expected containsLanguage to return false for nil slice")
	}
	if containsLanguage([]string{}, "go") {
		t.Error("expected containsLanguage to return false for empty slice")
	}
}

func TestContainsLanguage_SingleElement(t *testing.T) {
	if !containsLanguage([]string{"go"}, "go") {
		t.Error("expected to find 'go' in single-element slice")
	}
}

// --- Run: unknown claim set (exit code 3) ---

func TestRunUnknownClaimSet(t *testing.T) {
	result := Run(Config{
		RepoPath:  "/tmp",
		Profile:   "backend-api",
		ClaimSet:  "nonexistent-claim-set",
		OutputDir: t.TempDir(),
		Format:    "json",
	})
	if result.ExitCode != 3 {
		t.Errorf("expected exit code 3 for unknown claim set, got %d (errors: %v)", result.ExitCode, result.Errors)
	}
}

// --- Run: nil context defaults to context.Background ---

func TestRunNilContextDefaultsToBackground(t *testing.T) {
	// With nil Ctx, Run should use context.Background() — this exercises the nil ctx branch.
	// Use a nonexistent repo so it fails fast (at repo load) without doing heavy work.
	result := Run(Config{
		Ctx:       nil,
		RepoPath:  "/nonexistent/path/that/does/not/exist",
		Profile:   "backend-api",
		OutputDir: t.TempDir(),
		Format:    "json",
	})
	// Should fail at repo load (exit code 2), not panic
	if result.ExitCode == 0 {
		t.Error("expected non-zero exit code for nonexistent repo")
	}
	if result.ExitCode == 7 {
		t.Error("expected non-7 exit code (7 = cancelled context), got 7")
	}
}

// --- Run: nil progress defaults to os.Stderr ---

func TestRunNilProgressDefaultsToStderr(t *testing.T) {
	// With nil Progress, Run should use os.Stderr — exercises the nil progress branch.
	result := Run(Config{
		Progress:  nil,
		RepoPath:  "/nonexistent/path/for/testing",
		Profile:   "backend-api",
		OutputDir: t.TempDir(),
		Format:    "json",
	})
	// Just verify it didn't panic
	if result.ExitCode == 0 {
		t.Error("expected non-zero exit for nonexistent repo")
	}
}

// --- languageExtensions: ensure all branches covered ---

func TestLanguageExtensions_AllBranches(t *testing.T) {
	cases := []struct {
		lang string
		want []string
	}{
		{"go", []string{".go"}},
		{"javascript", []string{".js", ".jsx"}},
		{"typescript", []string{".ts", ".tsx"}},
		{"python", []string{".py"}},
		{"rust", nil},
		{"unknown", nil},
	}
	for _, tc := range cases {
		got := languageExtensions(tc.lang)
		if len(got) != len(tc.want) {
			t.Errorf("languageExtensions(%q) = %v, want %v", tc.lang, got, tc.want)
			continue
		}
		for i, ext := range got {
			if ext != tc.want[i] {
				t.Errorf("languageExtensions(%q)[%d] = %q, want %q", tc.lang, i, ext, tc.want[i])
			}
		}
	}
}

// --- joinStrings edge cases ---

func TestJoinStrings_Empty(t *testing.T) {
	result := joinStrings(nil)
	if result != "" {
		t.Errorf("expected empty string for nil input, got %q", result)
	}
}

func TestJoinStrings_Single(t *testing.T) {
	result := joinStrings([]string{"go"})
	if result != "go" {
		t.Errorf("expected 'go', got %q", result)
	}
}

func TestJoinStrings_Multiple(t *testing.T) {
	result := joinStrings([]string{"go", "python", "javascript"})
	if result != "go, python, javascript" {
		t.Errorf("got %q, want 'go, python, javascript'", result)
	}
}

// --- Run: EnsureTempRoot failure (line 157-159) ---

func TestRunEnsureTempRootFailure(t *testing.T) {
	// Create test fixtures before changing TMPDIR
	repoPath := createTestRepo(t, goRouterFiles())
	outDir := t.TempDir()

	// Point TMPDIR to a path inside /dev/null (a device file, not a directory).
	// DefaultTempRoot() returns filepath.Join(os.TempDir(), "cve-workspaces"),
	// so os.MkdirAll on /dev/null/impossible/cve-workspaces will fail.
	t.Setenv("TMPDIR", "/dev/null/impossible")

	result := Run(Config{
		RepoPath:  repoPath,
		Profile:   "backend-api",
		OutputDir: outDir,
		Format:    "json",
	})
	if result.ExitCode != 2 {
		t.Errorf("expected exit code 2 for workspace error, got %d; errors: %v", result.ExitCode, result.Errors)
	}
	found := false
	for _, e := range result.Errors {
		if strings.Contains(e, "workspace error") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected 'workspace error' in errors, got %v", result.Errors)
	}
}

// --- Run: CreateWorkspaceWithClone failure (line 163-165) ---

func TestRunWorkspaceCloneFailure(t *testing.T) {
	// Create test fixtures before changing TMPDIR
	repoPath := createTestRepo(t, goRouterFiles())
	outDir := t.TempDir()

	// Create a temp root where cve-workspaces exists but is read-only.
	// EnsureTempRoot (os.MkdirAll) succeeds on an existing directory,
	// but CreateWorkspaceWithClone fails because it can't write inside it.
	tmpBase := t.TempDir()
	cwDir := filepath.Join(tmpBase, "cve-workspaces")
	if err := os.MkdirAll(cwDir, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(cwDir, 0o755) }) // restore for cleanup
	t.Setenv("TMPDIR", tmpBase)

	result := Run(Config{
		RepoPath:  repoPath,
		Profile:   "backend-api",
		OutputDir: outDir,
		Format:    "json",
	})
	if result.ExitCode != 2 {
		t.Errorf("expected exit code 2 for workspace clone failure, got %d; errors: %v", result.ExitCode, result.Errors)
	}
	found := false
	for _, e := range result.Errors {
		if strings.Contains(e, "workspace error") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected 'workspace error' in errors, got %v", result.Errors)
	}
}
