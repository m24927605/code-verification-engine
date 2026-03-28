# Code Verification Engine Claim Catalog Pruning and Canonicalization Implementation Plan

## 1. Scope

Implement deterministic pruning and canonicalization in the multi-source claims
subsystem.

Primary code area:

- `internal/claims/multisource.go`

Secondary impact:

- `internal/claims/*_test.go`
- acceptance or integration tests if artifact behavior changes

## 2. Required Changes

### Workstream A: Canonical claim normalization

Add a canonicalization layer that:

- maps known aliases to canonical claim IDs
- runs before candidate construction
- runs before source-evidence-to-claim matching

Required behavior:

- alias forms collapse to one canonical ID
- matching and projection use canonical IDs consistently

### Workstream B: Claim pruning filters

Add deterministic claim pruning rules covering:

- `general.*`
- file-extension-derived IDs
- path-derived IDs
- `chunk_*`
- `task_*`
- section-title noise not matched by the canonical lexicon

Required behavior:

- pruned claims are not added as candidates
- pruned claims do not enter the claim graph
- pruned claims do not affect profile/resume projection

### Workstream C: README/docs allowlist-first extraction

Change documentation extraction behavior so that:

- README/docs only emit curated high-value canonical claims
- README/docs no longer fall back to arbitrary title-to-claim conversion

### Workstream D: Tests

Add or update tests for:

- alias canonicalization
- `general.*` pruning
- file/chunk/task/path-derived pruning
- README/docs unmatched fragment suppression
- evidence matching still works after canonicalization
- canonical high-value claims remain extractable

## 3. Non-Goals

This change does not broaden the claim catalog. It narrows and stabilizes it.

This change does not redesign:

- `profile.json` contract
- `resume_input.json` contract
- downstream LLM synthesis

## 4. Done Criteria

Implementation is complete when:

- pruning rules are in code
- canonical alias mapping is in code
- tests pass
- Vulcan-style real output shows materially fewer weak claims
- canonical high-value claims remain in `profile.json` and `resume_input.json`
