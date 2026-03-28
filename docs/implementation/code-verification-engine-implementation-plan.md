# Code Verification Engine Implementation Specification

## 1. Purpose

This document is the controlling implementation plan for completing the single-path engine.

Its primary objective is total removal of the historical finding-first execution model while keeping deterministic verification stable throughout the cutover.

## 2. Required End State

The implementation is complete only when all of the following are true:

1. rules emit issue-native seeds
2. `IssueCandidateSet` is the only semantic source for downstream artifacts
3. `report.json` derives from canonical issue and evidence data
4. finding-first bridge code is removed from runtime-critical paths
5. release gates, tests, fixtures, and docs use single-path terminology only

## 3. Workstreams

### 3.1 Rule Semantics Completion

Tasks:

- add missing rule metadata required for direct issue emission
- ensure release-blocking rules emit canonical title/category/severity/status
- remove late semantic reinterpretation from builder paths

### 3.2 Canonical Evidence and Issue Flow

Tasks:

- normalize seed evidence before clustering
- require every issue candidate to carry canonical evidence IDs
- eliminate normal-path fallback from findings to seeds

### 3.3 Report Contract Cutover

Tasks:

- redefine report projection to consume `IssueCandidateSet`
- remove public dependence on raw finding semantics
- keep only raw accounting fields that remain useful for audit

### 3.4 Skills and Claims Alignment

Tasks:

- derive skills strictly from issue/evidence contributors
- bind claims/profile/resume projections to canonical evidence
- remove dependence on historical summary or bridged semantics

### 3.5 Release and Documentation Cleanup

Tasks:

- update release gate steps
- rename docs to canonical naming
- remove wording that suggests parallel architecture generations

## 4. Implementation Order

1. Complete rule-native seed coverage for release-blocking families.
2. Make canonical seed/evidence flow sufficient for report generation without finding reconstruction.
3. Switch report, trace, and skills builders to canonical issue/evidence inputs only.
4. Remove runtime bridge logic and finding-first fallback branches.
5. Update fixtures, tests, contracts, and release gates to reject regressions.
6. Delete dead code and audit the repository for removed terminology.

## 5. Required Code Changes

Expected touch points:

- `internal/rules`
- `internal/engine`
- `internal/artifactsv2`
- `internal/report`
- `pkg/cve`
- acceptance and benchmark fixtures

Expected deletions:

- finding-derived semantic reconstruction in the normal path
- bridge-only migration states where no longer needed for audit
- duplicate artifact writing paths

## 6. Testing Requirements

### 6.1 Unit

- rule-native seed emission
- evidence normalization
- issue clustering
- confidence penalties
- report projection from canonical issue data

### 6.2 Integration

- repo scan to canonical artifact bundle
- degraded analyzer handling
- contradiction retention
- agent evidence overlay

### 6.3 Acceptance

- release-blocking fixture corpus
- benchmark corpus ordering and stability
- reproducibility under repeated runs
- contract validation for all canonical artifacts

## 7. Merge Policy

No implementation phase is complete unless:

1. deterministic tests remain green
2. canonical artifacts validate
3. no new code introduces finding-first semantics
4. documentation remains consistent with the single-path design

## 8. Closeout Checklist

- runtime path no longer requires finding-derived seed fallback
- report contract no longer centers on findings
- release gate verifies only canonical artifacts
- docs and README contain no staged-generation wording
- repository audit confirms removal is complete
