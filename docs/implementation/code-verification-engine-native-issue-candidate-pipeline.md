# Code Verification Engine Native Issue Candidate Pipeline Specification

## 1. Purpose

This document defines the canonical issue pipeline.

Its goal is simple: rule execution must emit issue-native seeds directly, and all downstream artifacts must derive from those seeds after evidence normalization and clustering.

## 2. Canonical Flow

1. rule evaluates indexed facts
2. rule emits `IssueSeed`
3. seed evidence is normalized into `EvidenceStore`
4. seeds are clustered into `IssueCandidateSet`
5. confidence is computed
6. report, trace, skills, and claims projections are generated

## 3. Required Invariants

1. every non-pass rule outcome emits either a canonical seed or an explicit skip/unknown outcome
2. issue semantics are complete at seed time
3. seeds are normalized before aggregation
4. clustering never needs to infer title/category/severity from generic findings
5. report generation consumes issue candidates, not intermediate findings

## 4. Seed Contract

Every canonical seed must carry:

- `rule_id`
- `title`
- `category`
- `severity`
- `status`
- `confidence`
- `quality`
- `file`
- `symbol`
- `start_line`
- `end_line`
- `evidence_ids`

## 5. Normalization Rules

- missing evidence references must be repaired through deterministic synthetic seed evidence
- evidence IDs must be deduplicated and stable
- file and span defaults must be explicit, never implicit
- source labels must identify whether support came from rule, analyzer, or agent input

## 6. Aggregation Rules

- cluster by deterministic fingerprint and merge family
- preserve counter-evidence
- preserve source summary
- compute candidate confidence from canonical inputs only

## 7. Completion Condition

The pipeline is complete only when:

1. no normal-path code derives seeds from findings
2. no public artifact depends on finding-only semantics
3. every release-blocking rule family enters aggregation through canonical seeds
