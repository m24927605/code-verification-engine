# Code Verification Engine Acceptance and Quality Gate Specification

## 1. Purpose

This document defines the formal acceptance criteria for the steady-state engine.

Acceptance requires complete convergence on the canonical evidence-first path and full removal of finding-first runtime semantics from release decisions.

## 2. Acceptance Conditions

The engine is accepted only when it demonstrates:

1. evidence-backed outputs
2. deterministic primary execution
3. canonical issue-based report generation
4. bounded and auditable agent participation
5. reproducible artifact generation
6. contract-valid release artifacts

## 3. Functional Acceptance

### 3.1 Canonical Issue Flow

Pass only if:

- every report issue maps to canonical issue IDs and evidence IDs
- issue meaning comes from rule-native seed metadata
- no release-blocking path depends on `rules.Finding` reinterpretation

### 3.2 Evidence Acceptance

Pass only if:

- every issue references one or more evidence records
- evidence IDs resolve to deterministic source locations or synthetic seed evidence
- support and contradiction links remain intact after clustering

### 3.3 Trace Acceptance

Pass only if:

- `trace.json` can explain issue derivation from seed to final artifact
- agent participation, when present, is bounded and explicit
- report and trace are derived from the same canonical data

## 4. Quality Acceptance

Pass only if:

- release-blocking rule families meet or exceed baseline correctness
- confidence ordering is stable and explainable
- degraded analyzers reduce confidence or certainty appropriately
- the engine does not overclaim under incomplete support

## 5. Contract Acceptance

The following artifacts must validate:

- `report.json`
- `evidence.json`
- `trace.json`
- `skills.json`
- `signature.json`

Optional projections must also validate when emitted.

## 6. Reproducibility Acceptance

Pass only if repeated runs on the same snapshot produce the same deterministic artifacts except for allowed timestamp and signature envelope fields.

## 7. Removal Acceptance

Removal of finding-first execution is accepted only when:

1. no release gate reads alternate projection artifacts
2. no canonical artifact is derived from historical finding semantics
3. no test requires bridge behavior to pass in the normal execution path
4. repository documentation uses single-path terminology consistently

## 8. Release Decision

Release is blocked if any of the following are true:

- canonical artifacts fail validation
- deterministic outputs are unstable under repeat execution
- release-blocking rules still require finding-first reinterpretation
- documentation, tests, and code disagree on the semantic source of truth
