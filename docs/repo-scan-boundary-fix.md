# Repo Scan Boundary Fix

## Goal

Fix the most severe correctness bug in the current engine: scanning the wrong repository scope.

This document defines:

- the root cause
- required behavior
- implementation changes
- test plan
- rollout risks

## Problem Summary

The current engine accepts a user-supplied repository path, but `repo.Load()` resolves that path to the git top-level root and then enumerates tracked files from the entire parent repository.

Current code:

- `internal/repo/loader.go`
- `internal/engine/engine.go`

Current behavior:

1. User passes `./testdata/repos/go-secure-api`
2. `git.ResolveRepoRoot()` resolves to the enclosing repo root
3. `ListTrackedFiles(root, ref)` enumerates the whole parent repository
4. language detection, analyzer dispatch, and evidence generation now run against the wrong file set
5. report evidence points at engine source files instead of the requested fixture

This is a correctness failure, not a cosmetic issue.

Any verification result produced from the wrong scan boundary is invalid.

## Root Cause

In `internal/repo/loader.go`, the engine currently treats "git repository root" and "requested scan root" as the same concept.

That is the core design bug.

The existing implementation stores:

- `RepoPath = root`
- `Files = ListTrackedFiles(root, ref)`

So a subdirectory inside a larger git repository is silently widened into a whole-repo scan.

## Correct Semantics

The engine needs two separate path concepts:

- `SourceRepoRoot`
  - the real git top-level root used for ref resolution and workspace creation
- `ScanRoot`
  - the user-requested directory within that repository that defines the file inclusion boundary

Correct behavior:

1. Validate that the requested path exists.
2. Resolve the enclosing git root for safe checkout and ref resolution.
3. Compute the requested path relative to the repo root.
4. Enumerate tracked files from the target ref.
5. Filter tracked files to the requested relative subtree.
6. Run language detection and analyzers only on that filtered file set.
7. Keep evidence file paths relative to the scan workspace repo root, but only from the filtered set.

## Required Data Model Changes

### `RepoMetadata`

Add fields:

- `SourceRepoRoot string`
- `RequestedPath string`
- `ScanRoot string`
- `ScanSubdir string`
- `BoundaryMode string`
- `IncludedFileCount int`
- `ExcludedFileCount int`

Recommended meaning:

- `SourceRepoRoot`: git top-level root
- `RequestedPath`: original user input after cleaning
- `ScanRoot`: absolute path of requested directory in source repo
- `ScanSubdir`: relative path from repo root to scan root, `""` for full repo
- `BoundaryMode`: `repo` or `subdir`

Keep existing fields if needed for backward compatibility, but do not overload them.

## Loader Fix Design

### Step 1: Preserve Requested Path

`repo.Load(repoDir, ref)` should:

- clean and absolutize `repoDir`
- keep it as `requestedAbs`
- separately resolve `sourceRoot := git.ResolveRepoRoot(requestedAbs)`

### Step 2: Verify Requested Path Is Inside Repo Root

Reject if:

- requested path escapes repo root after symlink resolution
- requested path is not a directory

This is both correctness and safety.

### Step 3: Enumerate Tracked Files from Repo Root

Still run:

- `ListTrackedFiles(sourceRoot, ref)`

This is correct because git ref resolution belongs to the full repository.

### Step 4: Filter Files to Requested Subtree

Compute:

- `scanSubdir := rel(sourceRoot, requestedAbs)`

Then filter tracked files:

- if `scanSubdir == "."` or empty: include all tracked files
- otherwise include only files where:
  - `relPath == scanSubdir/<file>`
  - or `strings.HasPrefix(relPath, scanSubdir + "/")`

This filter must run before:

- `FilterSafePaths`
- `DetectLanguages`
- analyzer file routing

Recommended order:

1. enumerate tracked files from repo root
2. subtree filter
3. safe-path filter against repo root
4. language detection on filtered set

### Step 5: Workspace Re-enumeration Must Preserve Boundary

`internal/engine/engine.go` currently re-enumerates files from the workspace after clone.

That behavior is correct in principle, but it must repeat the same subtree filtering logic against the workspace path.

Otherwise the loader fix will be undone later in the pipeline.

Required change:

- carry `ScanSubdir` from `repo.Load()` into engine runtime
- after workspace clone, enumerate tracked files from `ws.Path`
- filter those files by `ScanSubdir`
- then update `meta.Files`, `meta.FileCount`, `meta.Languages`

## Recommended Helper Functions

Add to `internal/repo`:

- `ResolveScanBoundary(requestedPath string) (sourceRoot, requestedAbs, scanSubdir string, err error)`
- `FilterFilesToSubtree(files []string, scanSubdir string) []string`

Behavior:

- `scanSubdir == ""` means full repo
- returned file paths remain repo-root-relative

This keeps the logic reusable in both loader and engine workspace re-enumeration.

## Report Contract Changes

Add to scan report:

- `source_repo_root`
- `requested_path`
- `scan_root`
- `scan_subdir`
- `boundary_mode`

This is important because boundary bugs should be visible in output, not hidden.

## CLI Semantics

`cve verify --repo <path>` should mean:

- scan exactly the repository subtree rooted at `<path>`

Not:

- scan the enclosing git top-level root

If full-repo scan is desired, the caller should pass the repo root explicitly.

Optional future addition:

- `--repo-root-only`
  - forces exact top-level root requirement

But this is not required for the fix.

## Test Plan

### Unit Tests

Add tests for `internal/repo`:

1. `FilterFilesToSubtree("", files)` returns all files.
2. `FilterFilesToSubtree("testdata/repos/go-secure-api", files)` returns only that subtree.
3. sibling paths are not included by prefix accident.
4. nested subdir scans work.
5. cleaned paths like `a/b/../c` normalize correctly.

### Loader Tests

Add a fixture repo layout like:

- `fixtures/mono-root/service-a/*.go`
- `fixtures/mono-root/service-b/*.ts`
- `fixtures/mono-root/shared/*.go`

Assertions:

1. loading `service-a` only detects Go and only `service-a` files.
2. loading `service-b` only detects TypeScript and only `service-b` files.
3. loading repo root detects both languages.

### Engine Integration Tests

Add an end-to-end regression test:

1. use a real git repo with multiple fixture subtrees
2. run `engine.Run` on each subtree path
3. assert every finding evidence path starts inside the expected subtree
4. assert no evidence references engine source files outside the subtree

This test should specifically guard against the bug observed in:

- `/tmp/cve-eval-go/report.json`
- `/tmp/cve-eval-ts/report.json`

### CLI Regression Tests

Add tests for:

- `cve verify --repo ./testdata/repos/go-secure-api`
- `cve verify --repo ./testdata/repos/ts-express-auth`

Assertions:

- language detection matches fixture language
- scan report boundary fields are correct
- evidence paths stay within requested subtree

## Acceptance Criteria

The fix is complete only when all of the following are true:

1. A subdirectory path scans only that subdirectory's tracked files.
2. Workspace clone re-enumeration preserves the same boundary.
3. Language detection is derived only from included files.
4. Evidence paths never reference files outside the requested subtree.
5. Reports expose scan boundary metadata.
6. Regression tests fail if boundary widening reappears.

## Risks And Edge Cases

### Monorepo Shared Code

If a service subtree imports shared code from sibling directories, subtree-only scanning may miss proof context.

The engine should handle this explicitly by:

- staying boundary-correct
- reporting partial coverage or unknown when required facts are outside boundary

It must not silently widen scope to "help".

### Symlinks

Symlink handling must remain conservative.

The boundary fix should not weaken existing safe-path filtering.

### Git Submodules

Submodules should remain a separate policy decision.

The fix should not implicitly traverse them unless they are already part of tracked file enumeration semantics for the chosen ref.

## Implementation Sequence

1. Add subtree filter helper functions in `internal/repo`.
2. Extend `RepoMetadata` with explicit boundary fields.
3. Update `repo.Load()` to preserve requested path and filter tracked files.
4. Update `engine.Run()` workspace re-enumeration to apply the same subtree filter.
5. Extend scan report schema with boundary metadata.
6. Add loader, engine, and CLI regression tests.
7. Re-run benchmark and fixture scans to confirm evidence locality.

## Practical Bottom Line

This fix should be treated as a release blocker.

Before it is fixed, the engine cannot make trustworthy claims about any subdirectory scan inside a larger git repository.

After it is fixed, the engine still will not automatically become a strong verification engine, but it will recover the minimum correctness required for any downstream trust model.
