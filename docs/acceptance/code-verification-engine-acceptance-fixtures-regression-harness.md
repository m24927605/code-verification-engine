# Code Verification Engine Acceptance Fixtures and Regression Harness Specification

## 1. Purpose

This document defines the acceptance fixture system and regression harness required to validate Code Verification Engine.

The goal is to make verification quality measurable, reproducible, and auditable. The harness is not optional infrastructure. It is part of the product quality boundary.

## 2. Problem Statement

A verification engine cannot be accepted based only on green unit tests or successful artifact generation.

Without a formal fixture and regression harness, the system cannot reliably answer:

1. whether issue aggregation is stable
2. whether confidence behaves correctly under degraded conditions
3. whether false positives are increasing
4. whether deterministic outputs remain reproducible
5. whether changes to rules or aggregation semantics silently regress trusted outputs

## 3. Objectives

The acceptance fixture and regression harness must:

1. validate deterministic correctness on representative repositories and micro-fixtures
2. validate evidence lineage and artifact contracts
3. validate aggregation behavior
4. validate confidence ordering and penalties
5. detect false positive regressions early
6. support CI and release gating

## 4. Fixture Categories

The harness must include the following fixture classes.

### 4.1 Micro Rule Fixtures

Small repos or single-purpose code snippets that isolate one rule or one matcher behavior.

Use cases:

1. proof matcher behavior
2. structural matcher behavior
3. heuristic matcher behavior
4. pass / fail / unknown transitions

### 4.2 Aggregation Fixtures

Fixtures designed to validate:

1. duplicate issue clustering
2. overlap merge
3. same-symbol merge
4. nearby-line merge
5. non-merge across files
6. contradiction retention

### 4.3 Evidence Fixtures

Fixtures designed to validate:

1. evidence ID stability
2. synthetic evidence generation
3. evidence location correctness
4. evidence derivation preservation

### 4.4 Confidence Fixtures

Fixtures designed to validate:

1. proof-backed issue scores higher than heuristic-only issue
2. degraded analyzer conditions lower score
3. contradiction lowers score
4. agent-heavy support incurs penalty
5. partial scan lowers score

### 4.5 False Positive Guard Fixtures

Fixtures designed to prove that previously known false positives remain suppressed.

These must be treated as release-blocking for trusted output classes.

### 4.6 Reproducibility Fixtures

Fixtures designed to confirm:

1. repeated runs produce identical deterministic artifacts
2. canonical hashes remain stable
3. issue IDs and evidence IDs remain stable

### 4.7 Realistic Repository Fixtures

Representative, medium-sized test repositories that exercise cross-file and multi-language behavior.

These fixtures validate:

1. realistic clustering
2. realistic scan boundary behavior
3. realistic analyzer degradation behavior
4. realistic artifact bundle output

## 5. Harness Outputs

The regression harness must validate at least the following outputs:

1. issue candidates
2. confidence breakdowns
3. `report.json`
4. `evidence.json`
5. `skills.json`
6. `trace.json`
7. `signature.json`

Optional human-friendly outputs such as markdown may be validated secondarily, but JSON artifacts are the authoritative target.

## 6. Required Assertions

### 6.1 Contract Assertions

For each fixture run:

1. artifact schemas validate
2. cross references are complete
3. no orphan issue references exist
4. no orphan evidence references exist

### 6.2 Determinism Assertions

For deterministic mode:

1. issue IDs are stable
2. evidence IDs are stable
3. bundle hash is stable except for explicitly allowed timestamp/signature fields
4. issue ordering is stable

### 6.3 Aggregation Assertions

For aggregation fixtures:

1. duplicate seeds merge when expected
2. unrelated seeds do not merge
3. merged issue contains unioned evidence IDs
4. merged issue preserves strongest severity and quality

### 6.4 Confidence Assertions

For confidence fixtures:

1. expected relative ordering holds
2. contradiction reduces score
3. degradation reduces score
4. unsupported paths do not produce inflated scores

### 6.5 Trust Policy Assertions

For trusted output classes:

1. machine-trusted issues only appear when confidence and evidence conditions are satisfied
2. advisory issues do not escalate without rule/evidence support
3. runtime-required cases remain downgraded or unknown when static proof is absent

## 7. Fixture Data Model

Each fixture should define:

```text
fixture_id
fixture_type
repo_path_or_snapshot
scan_mode
expected_issue_count
expected_issue_ids
expected_evidence_ids
expected_confidence_constraints
expected_hash_stability
expected_rule_triggers
```

Recommended optional fields:

```text
expected_skipped_rules
expected_partial
expected_degraded
expected_non_merge_pairs
expected_merge_groups
expected_false_positive_absence
```

## 8. Recommended Repository Layout

Recommended test structure:

```text
testdata/
  v2_acceptance/
    micro/
    aggregation/
    confidence/
    false_positive_guards/
    reproducibility/
    realistic/
```

Recommended harness structure:

```text
internal/
  acceptance/
    fixtures/
    runner/
    assertions/
    golden/
```

## 9. Golden Strategy

The harness must use a selective golden strategy.

Allowed goldens:

1. issue candidate IDs
2. artifact excerpts
3. contract-validated JSON fragments
4. stable bundle hashes for fixed fixtures

Avoid:

1. fragile full-file goldens for large artifacts when smaller assertions suffice
2. goldens that encode timestamp noise
3. goldens that overfit ordering where ordering is not semantically meaningful

## 10. Required Regression Suites

The following suites must exist:

### 10.1 Deterministic Core Suite

Purpose:

- validate that the primary verification path is stable

### 10.2 Aggregation Suite

Purpose:

- validate merge and non-merge behavior

### 10.3 Confidence Suite

Purpose:

- validate score ordering and penalties

### 10.4 False Positive Guard Suite

Purpose:

- prevent known regressions from re-entering the trusted output surface

### 10.5 Artifact Contract Suite

Purpose:

- validate all artifact bundle contracts and cross references

### 10.6 Reproducibility Suite

Purpose:

- validate hash stability and deterministic reruns

## 11. CI and Release Gate Integration

The harness must be runnable:

1. in local development
2. in CI pull request validation
3. in release candidate gating

Recommended release gate policy:

1. all deterministic core fixtures must pass
2. all false positive guard fixtures must pass
3. all artifact contract fixtures must pass
4. reproducibility suite must pass
5. confidence ordering suite must pass

Any failure in these suites blocks release.

## 12. Cost and Runtime Strategy

The harness must be practical enough to run regularly.

Recommended tiering:

### Tier 1: Fast PR Suite

Includes:

1. micro rule fixtures
2. aggregation fixtures
3. artifact contract fixtures

### Tier 2: Extended Validation Suite

Includes:

1. confidence fixtures
2. false positive guards
3. reproducibility fixtures

### Tier 3: Release Candidate Suite

Includes:

1. realistic repository fixtures
2. full artifact validation
3. hash stability checks
4. broader calibration checks

## 13. Implementation Tasks

Required work items:

1. define fixture manifest format
2. implement fixture runner
3. implement artifact assertion helpers
4. implement confidence assertion helpers
5. implement reproducibility assertion helpers
6. add false positive guard fixtures
7. add CI entrypoints for tiered execution

## 14. Acceptance Requirements

The acceptance fixture and regression harness is complete only when:

1. all required fixture classes exist
2. deterministic rerun stability is validated
3. aggregation semantics are locked by tests
4. confidence ordering and penalties are locked by tests
5. false positive guard coverage exists for trusted rule classes
6. bundle contracts are validated automatically

## 15. Success Criteria

The harness is successful when:

1. regressions are detected before release
2. confidence and aggregation changes are measurable
3. trusted output classes are protected by explicit fixture coverage
4. the system can justify quality claims with repeatable evidence

