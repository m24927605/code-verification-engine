# Code Verification Engine Proof-Grade Facts Tail Completion Acceptance Specification

## 1. Purpose

This document defines acceptance criteria for the remaining proof-grade facts tail work after the core scenario implementation is already functional.

## 2. Acceptance Goal

Tail completion is accepted only if the system becomes release-grade in the following areas:

1. scenario fixture completeness
2. golden artifact completeness
3. benchmark depth
4. config family coverage
5. migration traceability
6. final acceptance harness readiness

## 3. Golden Acceptance

### 3.1 Hiring Goldens

Required acceptance:

- hiring fixtures have assertions for:
  - `claims.json`
  - `profile.json`
  - `resume_input.json`
- README-only or heuristic overclaim does not appear in verified resume pools

### 3.2 Outsource Goldens

Required acceptance:

- outsource fixtures assert:
  - row status
  - verification class
  - trust class
  - claim references
  - evidence references
  - summary reconciliation

### 3.3 PM Goldens

Required acceptance:

- PM fixtures assert:
  - implemented, partial, blocked, unknown, or runtime-required semantics
  - engineering-only scope
  - claim and evidence references

Pass condition:

- all mandatory scenario fixtures compare successfully against normalized artifact expectations

## 4. Scenario Fixture Acceptance

### 4.1 Hiring Proof-Backed

Pass condition:

- proof-backed claims remain eligible for hiring-safe projection

### 4.2 Hiring Overclaim Downgrade

Pass condition:

- downgraded or heuristic-only claims do not appear in default verified hiring outputs

### 4.3 Outsource Pass

Pass condition:

- outsource pass fixtures show trusted proof-safe behavior only when required semantics are met

### 4.4 Outsource Fail

Pass condition:

- violating evidence is preserved and failure remains machine-auditable

### 4.5 Outsource Unknown Incomplete

Pass condition:

- incomplete negative coverage produces `unknown`, not proof-grade pass

### 4.6 PM Implemented

Pass condition:

- engineering implementation state is represented without implying business acceptance

### 4.7 PM Runtime Required

Pass condition:

- runtime-required cases preserve `human_or_runtime_required` semantics

### 4.8 Contradiction

Pass condition:

- contradiction evidence remains visible and resolvable

### 4.9 Analyzer Degradation

Pass condition:

- degraded analyzers trigger downgrade or unknown behavior

### 4.10 Unsupported Framework

Pass condition:

- unsupported stacks do not emit false proof-grade outcomes

## 5. Config Family Acceptance

The following config families must be accepted conservatively:

- `config.env_read_call_exists`
- `config.secret_key_sourced_from_env`
- `config.secret_key_not_literal`

Acceptance criteria:

1. env-read evidence may support structural inference
2. env-sourced secret evidence may support structural inference
3. literal-bound contradiction must remain visible
4. absent stronger completeness semantics, config outputs must not be upgraded to proof-grade

Pass condition:

- config claim families are covered by deterministic tests and scenario-safe projection behavior

## 6. Benchmark Acceptance

Each first-wave family must satisfy benchmark acceptance for:

1. true positive
2. opposite outcome
3. false-positive guard
4. degradation or incomplete boundary
5. unsupported case where relevant

Pass condition:

- no first-wave family remains covered only by skeleton directories

## 7. Traceability Acceptance

The system must preserve:

1. migration state
2. migration reason
3. historical rule to migrated claim family mapping
4. scenario row to claim mapping
5. claim to evidence mapping

Pass condition:

- spot-audit traversal succeeds through `trace.json`, scenario artifacts, `claims.json`, and `evidence.json`

## 8. Release Acceptance

Tail completion is accepted for release only if:

1. `go test ./...` is green
2. proof-grade scenario fixtures have semantic assertions
3. benchmark depth is present for first-wave families
4. trace migration metadata is contract-tested
5. release-gate documentation reflects the completed proof-grade scenario checks

## 9. Definition of Tail Acceptance

The proof-grade tail is accepted only when:

1. the implementation is not merely functional, but audit-complete
2. scenario outputs are protected by meaningful fixture and golden coverage
3. migrated rule families are benchmarked beyond happy-path cases
4. trace and trace outputs are sufficient for release review
