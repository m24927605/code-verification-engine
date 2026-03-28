# Code Verification Engine Proof-Grade Facts Fixture Specification

## 1. Purpose

This document defines the fixture and golden-output specification for the proof-grade facts scenario upgrade.

It exists to remove ambiguity for Claude Code when building:

- acceptance fixtures
- benchmark fixtures
- contract test inputs
- golden output files

The fixture strategy must validate both correctness and conservative trust behavior.

## 2. Fixture Design Principles

Fixtures must:

1. be deterministic
2. isolate one primary rule family or scenario behavior at a time
3. include enough code structure to support proof-path testing
4. include explicit false-positive-guard structure where relevant
5. include golden artifacts for only the fields required to validate contract and trust behavior

Fixtures must not:

- rely on ambiguous naming alone
- mix too many independent behaviors in one minimal fixture
- hide scan-boundary or analyzer degradation assumptions

## 3. Fixture Classes

The following fixture classes are mandatory.

### 3.1 Hiring Proof-Backed Claim Fixture

Purpose:

- prove that hiring-safe profile and resume outputs include proof-backed claims only

Required contents:

- repo with explicit auth middleware binding
- repo with scoped auth tests
- deterministic technologies and route structure

Required golden assertions:

- `claims.json` includes proof-backed implementation claims
- `profile.json` includes eligible highlights only
- `resume_input.json` includes verified or strongly supported hiring-safe claim stubs

### 3.2 Hiring Overclaim Downgrade Fixture

Purpose:

- prove that README or weak structural hints do not become verified resume claims

Required contents:

- README claiming strong auth or architecture behavior
- code lacking decisive proof facts for that claim

Required golden assertions:

- claim is downgraded to `weak`, `unsupported`, or `structural_inference`
- no unsafe highlight appears in `profile.json`
- `resume_input.json` excludes the overclaim from default verified claims

### 3.3 Outsource Pass Fixture

Purpose:

- prove proof-grade contractual pass behavior

Required contents:

- protected routes wired through auth middleware
- no hardcoded secret literals
- auth module tests present

Required golden assertions:

- `outsource_acceptance.json` contains `passed` proof-grade rows
- rows reference valid claim and evidence IDs
- summary counts reconcile

### 3.4 Outsource Fail Fixture

Purpose:

- prove proof-grade or sufficiently supported fail behavior on violating evidence

Required contents:

- hardcoded secret literal
- direct controller DB access or missing route auth binding

Required golden assertions:

- `outsource_acceptance.json` contains `failed` rows
- contradictory or violating evidence is preserved

### 3.5 Outsource Unknown Due to Boundary Incompleteness Fixture

Purpose:

- prove negative proof does not overclaim when completeness is insufficient

Required contents:

- repository structure where relevant subdir scan or excluded files prevent exhaustive search

Required golden assertions:

- negative acceptance row is `unknown`
- unknown reason cites boundary incompleteness or analyzer incompleteness

### 3.6 PM Engineering Acceptance Fixture

Purpose:

- prove engineering-ready implementation status without claiming product acceptance

Required contents:

- wired engineering requirement such as route auth binding or layered architecture conformance

Required golden assertions:

- `pm_acceptance.json` row status is `implemented`
- row wording stays within engineering scope
- evidence references resolve

### 3.7 PM Runtime-Required Fixture

Purpose:

- prove the system emits runtime-required instead of overclaiming business or runtime correctness

Required contents:

- requirement descriptor that cannot be statically proven, such as runtime feature correctness

Required golden assertions:

- `pm_acceptance.json` row status is `runtime_required`
- no proof-grade label is emitted for that row

### 3.8 Contradiction Fixture

Purpose:

- prove contradictory evidence is retained through claims and scenario projections

Required contents:

- docs or README claiming a capability
- code contradicting or failing to support it

Required golden assertions:

- contradictory evidence IDs are present
- scenario outputs do not silently hide contradiction

### 3.9 Analyzer Degradation Fixture

Purpose:

- prove degraded analyzers force downgrade or unknown instead of unjustified proof-grade output

Required contents:

- language or file form that triggers partial extraction or degraded analyzer path

Required golden assertions:

- `trace.json` records degradation
- affected claims or acceptance rows downgrade appropriately

### 3.10 Unsupported Framework Fixture

Purpose:

- prove unsupported frameworks do not receive false proof-grade results

Required contents:

- framework wiring not yet modeled by the analyzers

Required golden assertions:

- affected rows are `unknown` or `human_or_runtime_required`
- trace or reason fields cite unsupported framework scope

## 4. Recommended Fixture Layout

Recommended location patterns:

- acceptance scenario fixtures under `testdata/acceptance/proof_grade_scenarios/`
- benchmark rule-family fixtures under `testdata/benchmark/proof-grade/`
- optional skill-oriented fixtures under `testdata/skills/` only if they validate hiring projection behavior

Recommended directory shape:

```text
testdata/
  acceptance/
    proof_grade_scenarios/
      hiring-proof-backed/
      hiring-overclaim-downgrade/
      outsource-pass/
      outsource-fail/
      outsource-unknown-incomplete/
      pm-engineering-implemented/
      pm-runtime-required/
      contradiction/
      analyzer-degradation/
      unsupported-framework/
```

## 5. Minimal Repository Contents per Fixture

Each fixture repository should include only the files needed to prove the scenario.

Recommended minimal files:

- application entrypoint
- one or two route files
- one or two middleware files
- service and repository files where layering is required
- focused test files
- optional README or docs file when contradiction or overclaim behavior is under test

## 6. Golden Output Strategy

Golden files should validate:

- stable identifiers where deterministically defined
- required schema sections
- trust-boundary-critical fields
- scenario summary counts

Golden files should avoid:

- asserting irrelevant timestamps
- asserting signature envelopes
- asserting unstable formatting differences

## 7. Mandatory Golden Artifacts per Fixture

### 7.1 Hiring Fixtures

Required goldens:

- `claims.json`
- `profile.json`
- `resume_input.json`

### 7.2 Outsource Fixtures

Required goldens:

- `claims.json`
- `outsource_acceptance.json`
- relevant `trace.json` excerpt or normalized comparison target

### 7.3 PM Fixtures

Required goldens:

- `claims.json`
- `pm_acceptance.json`
- relevant `trace.json` excerpt or normalized comparison target

### 7.4 Contradiction and Degradation Fixtures

Required goldens:

- `claims.json`
- scenario artifact under test
- relevant `trace.json` excerpt

## 8. Golden Assertion Priorities

Claude Code should assert fields in this priority order:

1. `status`
2. `verification_class`
3. `trust_class`
4. `claim_ids`
5. evidence references
6. contradiction references
7. `unknown_reasons` or `follow_up_action`
8. summary reconciliation

## 9. Example Expected Assertions

### 9.1 Hiring Overclaim Downgrade

Expected assertions:

- no `proof_grade` highlight for README-only architecture claim
- `resume_input.json.verified_claims` excludes the downgraded claim
- contradiction or downgrade reason is present

### 9.2 Outsource Unknown Incomplete

Expected assertions:

- requirement row status equals `unknown`
- `verification_class` is not `proof_grade`
- `unknown_reasons` contains boundary or analyzer completeness explanation

### 9.3 PM Runtime Required

Expected assertions:

- row status equals `runtime_required`
- `trust_class` equals `human_or_runtime_required`
- reason states static verification is insufficient

## 10. Fixture Naming Rules

Fixture names should:

- be short and behavioral
- encode the primary outcome
- avoid implementation-noise terminology

Good examples:

- `outsource-pass-auth-binding`
- `outsource-unknown-incomplete-negative`
- `hiring-overclaim-readme-only`
- `pm-runtime-required-feature-behavior`

## 11. Claude Code Fixture Implementation Rules

Claude Code should:

1. create fixture repos with the smallest code surface that still exercises the target behavior
2. create goldens only after the target contract is stable
3. normalize away timestamp or signature noise in comparisons
4. keep one primary failure reason per fixture when possible
5. add false-positive-guard structure where naming alone might otherwise trigger a weak heuristic

## 12. Definition of Fixture Completeness

The fixture corpus is complete only when:

1. all ten mandatory fixture classes exist
2. each first-wave migrated rule family has pass, fail or opposite, and false-positive-guard coverage
3. negative proof families include incomplete-boundary coverage
4. hiring, outsource, and PM scenario projections are all exercised end-to-end
