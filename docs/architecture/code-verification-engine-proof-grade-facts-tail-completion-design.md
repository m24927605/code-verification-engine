# Code Verification Engine Proof-Grade Facts Tail Completion Design

## 1. Purpose

This document defines the design for the remaining proof-grade facts tail work after the core scenario implementation is already functional.

The purpose of this tail-completion design is to finish the product to a release-grade state without reopening trust-boundary decisions that are already implemented.

This document covers:

1. full golden corpus completion
2. acceptance-fixture assertion hardening
3. config claim family completion
4. benchmark corpus expansion
5. trace and compatibility polish
6. final scenario acceptance harness integration

## 2. Design Constraints

The following are already settled and must not be reopened during tail work:

1. `proof_grade`, `structural_inference`, `heuristic_advisory`, and `human_or_runtime_required` remain the canonical verification classes
2. scenario projections may filter or downgrade, but may not upgrade trust
3. outsource and PM machine-safe pass semantics require `proof_grade + machine_trusted`
4. hiring projection remains resume-safe and must exclude weak claim classes from default verified pools
5. traceability must remain claim and evidence reference based, not free-text based

Tail work must therefore improve coverage and auditability, not redesign semantics.

## 3. Problem Statement

The current implementation is functional and test-green, but it still has three classes of incompleteness:

1. some fixture and benchmark corpora are present only as minimal deterministic skeletons
2. some migrated families are present as conservative groundwork rather than saturated proof-grade families
3. trace and compatibility metadata are sufficient for current use, but not yet rich enough for final release-grade audits

This creates a release risk:

- regressions could re-enter through incomplete fixture coverage
- migrated families may appear complete in code while still lacking benchmark depth
- scenario outputs may remain correct but insufficiently proven against a representative corpus

## 4. Tail Completion Architecture

The tail completion architecture is:

```text
Implemented Core
-> Fixture Corpus Completion
-> Golden Artifact Assertions
-> Family-Specific Benchmark Expansion
-> Trace / Compatibility Audit Hardening
-> Final Release Harness
```

The architecture principle is:

- do not widen product scope
- do not add new semantic classes
- do not add non-deterministic acceptance logic
- deepen the proof surface only where existing contracts already define the intended semantics

## 5. Design Areas

### 5.1 Golden Corpus Design

Each proof-grade scenario fixture must have artifact assertions at the scenario layer, not just directory existence.

Required golden targets:

- hiring:
  - `claims.json`
  - `profile.json`
  - `resume_input.json`
- outsource:
  - `claims.json`
  - `outsource_acceptance.json`
  - normalized `trace.json` excerpt
- PM:
  - `claims.json`
  - `pm_acceptance.json`
  - normalized `trace.json` excerpt

Golden assertions must prioritize:

1. row status
2. verification class
3. trust class
4. claim references
5. evidence references
6. contradiction references
7. summary reconciliation

Golden assertions must explicitly ignore:

- timestamps
- signature envelopes
- formatting-only differences

### 5.2 Acceptance Fixture Hardening Design

Acceptance fixtures must evolve from layout checks into behavior checks.

Each mandatory scenario fixture must prove one primary behavior:

- `hiring-proof-backed`
  - proof-backed claims survive into hiring-safe projections
- `hiring-overclaim-downgrade`
  - README-only or heuristic overclaim does not enter verified resume pools
- `outsource-pass-auth-binding`
  - proof-capable outsource requirement can pass only with strong trust
- `outsource-fail-secret`
  - proof-backed violation yields failure with evidence references
- `outsource-unknown-incomplete-negative`
  - incomplete negative cannot produce proof-grade pass
- `pm-engineering-implemented`
  - engineering-ready state is clearly separated from product acceptance
- `pm-runtime-required-feature-behavior`
  - runtime-required state is preserved and not downgraded into implemented
- `contradiction`
  - contradiction evidence remains visible
- `analyzer-degradation`
  - degraded analyzers cause downgrade or unknown
- `unsupported-framework`
  - unsupported stacks do not silently produce proof-grade outcomes

### 5.3 Config Claim Family Completion Design

Config families must remain conservative.

The completed family set is:

- `config.env_read_call_exists`
- `config.secret_key_sourced_from_env`
- `config.secret_key_not_literal`

Target design:

- environment-read existence may produce `structural_inference`
- secret-key env sourcing may produce `structural_inference`
- secret-key non-literal absence semantics remain conservative until stronger literal-assignment and completeness modeling exists

Explicit non-goal:

- do not relabel config families as proof-grade unless decisive literal and completeness facts exist

### 5.4 Benchmark Expansion Design

Each first-wave family must have a benchmark matrix, not just a happy-path fixture.

Required classes per family:

1. true positive
2. opposite outcome
3. false-positive guard
4. analyzer degradation or incomplete boundary
5. unsupported language or framework where relevant

This applies to:

- `SEC-001`
- `TEST-001`
- `AUTH-002`
- `ARCH-001`
- config families

### 5.5 Trace and Compatibility Polish Design

`trace.json` must remain the audit spine for migration.

The tail design requires:

- rule migration state
- rule migration reason
- rule to claim family mapping
- stable references from scenario outcomes back to claims and evidence

Compatibility outputs should remain intact, but they must not hide migration semantics.

### 5.6 Final Acceptance Harness Design

The final acceptance harness must test proof-grade scenario behavior as a product capability, not merely package correctness.

The harness should:

1. run scenario fixtures through the engine
2. normalize unstable fields
3. compare required artifact subsets
4. fail on trust-boundary regressions

The final harness should be wired into release-gate expectations, even if some checks remain documented manual confirmations.

## 6. Non-Goals

This tail completion work must not:

1. introduce runtime evidence systems
2. change public semantics of already-shipped artifacts
3. introduce new scenario types
4. claim proof-grade for families whose decisive facts are still incomplete

## 7. Definition of Design Completion

This design is complete when:

1. every remaining tail task is mapped to a bounded implementation unit
2. no tail task requires reopening core trust-boundary design
3. release-grade completion is reduced to coverage, corpus depth, and audit polish
