# Code Verification Engine Proof-Grade Facts Tail Completion Implementation Plan

## 1. Purpose

This document defines the implementation plan for finishing the remaining proof-grade facts tail work after the main scenario implementation is already in place.

## 2. Implementation Goal

The goal is to move the implementation from "functional and test-green" to "release-grade and audit-complete" without expanding product scope.

## 3. Workstreams

Tail completion is divided into six workstreams:

1. golden corpus completion
2. scenario fixture assertion hardening
3. config family completion
4. benchmark expansion
5. trace and compatibility polish
6. final acceptance harness integration

## 4. Workstream 1: Golden Corpus Completion

### Objective

Add stable artifact-level goldens for the existing proof-grade scenario fixtures.

### Required Work

1. create normalized golden files under deterministic fixture directories
2. add assertion helpers that ignore:
   - timestamps
   - signatures
   - formatting-only changes
3. assert only trust-critical fields for scenario artifacts

### Required Artifact Coverage

- hiring fixtures:
  - `claims.json`
  - `profile.json`
  - `resume_input.json`
- outsource fixtures:
  - `claims.json`
  - `outsource_acceptance.json`
  - trace excerpt
- PM fixtures:
  - `claims.json`
  - `pm_acceptance.json`
  - trace excerpt

### Exit Criteria

- every mandatory proof-grade scenario fixture has normalized golden assertions

## 5. Workstream 2: Scenario Fixture Assertion Hardening

### Objective

Upgrade scenario fixture tests from layout checks to semantic checks.

### Required Work

1. add fixture-specific assertions for:
   - hiring proof-backed
   - hiring overclaim downgrade
   - outsource pass
   - outsource fail
   - outsource unknown incomplete
   - PM implemented
   - PM runtime required
   - contradiction
   - analyzer degradation
   - unsupported framework
2. assert:
   - status
   - verification class
   - trust class
   - claim references
   - evidence references
   - contradiction references where applicable

### Exit Criteria

- fixture tests fail on any trust-boundary regression, not merely missing directories

## 6. Workstream 3: Config Family Completion

### Objective

Complete the conservative migration of config claim families.

### Required Work

1. harden deterministic config claim derivation
2. add coverage for:
   - env-read positive
   - env-read fail
   - secret env source positive
   - literal-bound contradiction
   - incomplete or degraded downgrade
3. keep config families structural unless stronger proof prerequisites are implemented

### Files Likely Involved

- `internal/engine/*`
- `internal/rules/*`
- `internal/facts/*`
- scenario projection tests

### Exit Criteria

- config claim families are covered by deterministic tests and scenario-safe projections

## 7. Workstream 4: Benchmark Expansion

### Objective

Expand proof-grade benchmark depth for first-wave families.

### Required Work

For each family:

- `SEC-001`
- `TEST-001`
- `AUTH-002`
- `ARCH-001`
- config families

add:

1. true positive
2. opposite outcome
3. false-positive guard
4. degradation or incomplete boundary case
5. unsupported language or framework case where relevant

### Exit Criteria

- each first-wave family has a representative benchmark matrix instead of skeleton-only coverage

## 8. Workstream 5: Trace and Compatibility Polish

### Objective

Make migration and projection lineage auditable enough for final release review.

### Required Work

1. ensure `trace.json` preserves:
   - migration state
   - migration reason
   - rule to claim family mapping
2. add tests preventing silent loss of migration metadata
3. ensure scenario artifact references remain resolvable against bundle claims and evidence

### Exit Criteria

- migration lineage survives refactors and is contract-tested

## 9. Workstream 6: Final Acceptance Harness Integration

### Objective

Turn proof-grade scenario behavior into an explicit release artifact.

### Required Work

1. create or extend a harness that:
   - runs scenario fixtures end-to-end
   - normalizes unstable fields
   - compares required artifact subsets
2. integrate harness expectations into release-gate documentation and local checks where practical

### Exit Criteria

- proof-grade scenario outputs are validated as a product-level capability

## 10. Execution Order

Implementation order must be:

1. golden corpus completion
2. scenario fixture assertion hardening
3. config family completion
4. benchmark expansion
5. trace and compatibility polish
6. final acceptance harness integration

This order is mandatory because:

- goldens and fixture assertions define the target shape
- config and benchmark work should be measured against that shape
- trace polish should stabilize after migration outputs are already covered

## 11. Anti-Patterns

Do not:

1. expand runtime scope
2. relabel structural config families as proof-grade without stronger prerequisites
3. add fixture volume without meaningful assertions
4. replace claim/evidence references with free-text explanations
5. weaken release-gate semantics to make tests easier to pass

## 12. Definition of Implementation Completion

This implementation plan is complete when:

1. all mandatory scenario fixtures have semantic assertions
2. all first-wave families have representative benchmark depth
3. config claim families are conservatively covered
4. trace migration metadata is contract-tested
5. proof-grade scenario behavior is enforceable in the acceptance harness
