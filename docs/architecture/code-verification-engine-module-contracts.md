# Code Verification Engine Module Contract Specification

## 1. Purpose

This document defines the executable module contracts for the steady-state engine.

The contracts assume a single canonical path and forbid semantic dependence on historical finding-first outputs.

## 2. Canonical Modules

### 2.1 `repo`

Owns:

- repo resolution
- ref and commit identity
- scan boundary
- workspace preparation

Must output deterministic snapshot metadata.

### 2.2 `analyzers`

Owns:

- language parsing
- fact extraction
- degraded/partial status reporting

Must not emit final issue semantics.

### 2.3 `rules`

Owns:

- deterministic rule metadata
- issue seed emission
- unknown and skip policy

Every release-blocking rule must be able to emit:

- `rule_id`
- `title`
- `category`
- `severity`
- `status`
- `confidence floor`
- `evidence_ids`

### 2.4 `artifactsv2`

Owns:

- evidence normalization
- issue clustering
- confidence scoring
- trace derivation
- report and skills projection

Module constraint:

- this package is the canonical artifact pipeline despite its package name
- no sibling package may define a second semantic report path

### 2.5 `claimsources` and `claims`

Own:

- multi-source claim extraction
- claim evaluation
- profile and resume projections

They must consume canonical evidence and issue data rather than historical report summaries.

### 2.6 `engine`

Owns:

- orchestration
- phase ordering
- artifact writing
- release-gate integration

It must not reintroduce a second projection path.

## 3. Allowed Dependencies

- `engine` -> `repo`, `analyzers`, `rules`, `artifactsv2`, `claims`, `skills`
- `artifactsv2` -> `rules`, `report` input types only where required for scan metadata
- `claims` -> `artifactsv2` canonical outputs

Disallowed:

- deriving issue meaning from `report.findings`
- rebuilding issue seeds from non-canonical report projections in the normal path
- publishing two public artifacts with different semantic centers

## 4. Contract Rules

1. `IssueCandidateSet` is the canonical semantic product.
2. `EvidenceStore` is the canonical factual product.
3. `report.json`, `trace.json`, `skills.json`, and claims/profile projections are downstream views only.
4. Any field needed by downstream consumers must exist in canonical data before projection.
5. Migration states may exist for audit, but they may not affect normal semantics after cutover.

## 5. Completion Condition

Module contracts are complete when:

1. every release-blocking rule family emits rule-native seeds
2. no engine path depends on `rules.Finding` as the primary semantic payload
3. no public document or release gate requires an alternate artifact projection
