# Code Verification Engine v2 Native Issue Candidate Pipeline Specification

## 1. Purpose

This document defines the target implementation for the native issue candidate pipeline in Code Verification Engine v2.

The purpose of this pipeline is to eliminate the remaining finding-first dependency in the v2 verification path and establish a single deterministic flow:

`rules -> issue seeds -> evidence store -> issue candidates -> confidence -> artifacts`

This document is intentionally narrower than the full architecture specification. It focuses only on the core verification path that must be completed before broader v2 claims can be considered production-grade.

## 2. Scope

This specification covers:

1. native issue seed production in the deterministic rules path
2. seed normalization and evidence synthesis
3. issue candidate formation and aggregation
4. projection boundaries into `report.json`, `trace.json`, and `skills.json`
5. migration sequencing away from legacy finding-first coupling

This specification does not cover:

1. LLM agent orchestration details
2. context selection algorithm details beyond required interfaces
3. UI or presentation work
4. non-core report formatting changes

## 3. Problem Statement

The current system has already introduced a v2 compatibility path, but the execution model still has transitional characteristics:

1. the primary deterministic engine still produces legacy `rules.Finding`
2. the v2 path derives issue semantics from findings after rule execution
3. issue formation exists, but issue candidates are not yet the canonical first-class output of deterministic verification
4. some evidence synthesis remains adapter-driven rather than source-native

This is acceptable as an intermediate state, but not as the terminal v2 design.

The target state is:

1. deterministic rule execution emits native issue-oriented signals
2. evidence creation is explicit and stable
3. issue candidate formation is a formal engine stage
4. report artifacts are projections of issue candidates, not alternative sources of truth

## 4. Target Pipeline

The required pipeline is:

```text
Repo Snapshot
-> Analyzer / Fact Extraction
-> Rule Evaluation
-> Native Issue Seed Production
-> Seed Normalization
-> Evidence Store Construction
-> Issue Candidate Aggregation
-> Confidence Scoring
-> Artifact Projection
```

The architectural rule is:

**Issue candidates become the canonical deterministic verification output.**

Legacy findings may remain temporarily for compatibility, but they must no longer be the semantic center of the v2 path.

## 5. Design Principles

### 5.1 Deterministic First

The native issue candidate pipeline must produce identical outputs for identical inputs:

- same repo snapshot
- same scan boundary
- same analyzer outputs
- same ruleset
- same engine version

### 5.2 Evidence Before Conclusion

No issue candidate may exist without one or more evidence references.

### 5.3 Conservative Aggregation

The pipeline must prefer under-merging to over-merging. A duplicated issue is cheaper than collapsing unrelated defects into a single issue.

### 5.4 Explicit Unknowns

If a rule can detect suspicion but cannot support a strong issue candidate, it must emit:

- a low-confidence seed, or
- an unknown-compatible seed, or
- no issue seed and only evidence/assertion output

The system must not manufacture precision by hiding uncertainty.

## 6. Core Data Contracts

### 6.1 Rules-Layer Issue Seed

The rules layer must expose a native issue seed model that is stable and serialization-safe.

Required fields:

```text
rule_id
title
source
category
severity
status
confidence
quality
file
symbol
start_line
end_line
evidence_ids
```

Semantics:

- `rule_id`: deterministic rule producer identity
- `title`: canonical issue title from rule metadata, not arbitrary finding prose
- `source`: `rule`, `agent`, or future producer class
- `category`: canonical issue family
- `severity`: rule-defined or downgraded severity
- `status`: `open`, `resolved`, or `unknown`
- `confidence`: deterministic seed confidence before issue-level recomputation
- `quality`: quality of underlying evidence support
- `evidence_ids`: explicit evidence references when available

### 6.2 Evidence Store

The evidence store remains the source-of-truth backing structure for all downstream issue candidates.

Requirements:

1. deterministic `Upsert()`
2. stable `All()` ordering
3. indexed lookup by evidence ID
4. indexed lookup by producer, claim, file, and entity when available

### 6.3 Issue Candidate

Issue candidates are the first deterministic, issue-oriented output of the verification path.

Required semantics:

1. represent one logical issue cluster
2. retain all supporting evidence IDs
3. retain source producers
4. retain contributing rule IDs
5. retain confidence breakdown when available

Issue candidates are not report DTOs. They are internal verification objects.

## 7. Required Pipeline Stages

### 7.1 Native Seed Production

The deterministic rules path must produce native issue seeds directly from rule execution results.

Current acceptable transitional pattern:

`finding -> seed`

Target pattern:

`rule evaluation -> seed + evidence assertions`

Implementation requirements:

1. seed title must prefer rule metadata
2. seed category must prefer rule metadata
3. seed severity must prefer rule metadata
4. seed source must reflect trust/runtime semantics
5. seed evidence IDs must be stable if evidence exists

### 7.2 Seed Normalization

Every seed entering the v2 path must be normalized before further processing.

Normalization rules:

1. empty file becomes `unknown`
2. missing start line becomes `1`
3. end line less than start line is clamped to start line
4. missing source defaults to `rule`
5. missing category defaults conservatively to `bug`
6. missing severity defaults conservatively to `medium`
7. missing confidence defaults conservatively to low-confidence baseline
8. missing quality defaults conservatively to heuristic baseline
9. missing evidence IDs must be synthesized deterministically

### 7.3 Evidence Synthesis from Seeds

If a seed arrives without explicit evidence records, the pipeline must create deterministic synthetic evidence records before aggregation.

This is required to guarantee:

1. issue candidates never reference nonexistent evidence
2. seed-only paths still produce valid `evidence.json`
3. trace/report/skills artifacts reference the same evidence IDs

Synthetic evidence rules:

1. use deterministic evidence ID derivation from seed identity
2. mark payload as synthetic
3. preserve rule ID, source, title, status, and location
4. use conservative fact quality mapped from seed quality

### 7.4 Issue Candidate Aggregation

Aggregation must cluster seeds into issue candidates using deterministic rules.

Minimum clustering dimensions:

1. issue status
2. repo-relative file path
3. symbol identity when present
4. line overlap or bounded line-neighborhood when symbol is absent

Aggregation behavior:

1. merge evidence IDs
2. merge rule IDs
3. merge source producers
4. keep highest severity
5. keep highest quality
6. keep highest confidence
7. choose canonical title deterministically

### 7.5 Projection Boundary

Only after issue candidates exist may the system project:

1. `report.json`
2. `trace.json`
3. `skills.json`
4. `summary.md`

Projection rules:

1. no new semantic information may be invented during projection
2. projection may reorder or summarize, but may not alter issue meaning
3. `trace.json` must preserve rule-to-issue and issue-to-evidence lineage

## 8. Migration Strategy

### Phase A: Rules-Layer Seed Presence

Exit goal:

- `rules.ExecutionResult` always includes `IssueSeeds`

### Phase B: Engine Uses Native Seeds

Exit goal:

- engine bridges native `IssueSeeds` into `VerificationSource`
- v2 path no longer needs to derive seeds from findings in the normal path

### Phase C: Seed-Native Evidence Construction

Exit goal:

- v2 builder constructs or normalizes evidence from seeds before aggregation

### Phase D: Issue Candidate as Canonical Internal Product

Exit goal:

- downstream `report` and `skills` logic consume issue candidates as primary structured input

### Phase E: Legacy Finding Dependency Reduction

Exit goal:

- compatibility path still exists
- semantic dependence on `rules.Finding` is minimized

## 9. Non-Goals

The following are explicitly out of scope for this document:

1. replacing all legacy report types immediately
2. removing findings from public compatibility output
3. introducing agent-assisted issue seeding into the deterministic path
4. solving semantic deduplication across all possible rule families in a single release

## 10. Implementation Tasks

The following work items are required to complete this pipeline:

1. finalize native `rules.IssueSeed` semantics
2. ensure rule metadata is authoritative for seed title/category/severity
3. centralize seed normalization
4. centralize seed evidence synthesis
5. harden issue clustering rules
6. formalize issue candidate contract boundaries
7. remove duplicated fallback logic across builder, aggregation, and projection
8. add deterministic fixture coverage for seed-only, finding-derived, and mixed paths

## 11. Acceptance Requirements

This pipeline is complete only when all of the following are true:

1. native deterministic execution always emits issue seeds
2. every non-pass issue candidate references valid evidence IDs
3. `evidence.json`, `report.json`, and `trace.json` agree on evidence identity
4. the same snapshot produces identical issue candidates across repeated runs
5. the compatibility path no longer contains materially different issue semantics from the native seed path

## 12. Success Criteria

The native issue candidate pipeline is considered successful when:

1. issue semantics are no longer reconstructed late in the pipeline
2. evidence lineage is explicit before aggregation
3. deterministic issue formation is stable under regression testing
4. v2 artifacts can be trusted as projections of canonical issue candidates

