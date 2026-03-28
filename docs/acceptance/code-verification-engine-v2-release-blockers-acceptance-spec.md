# Code Verification Engine v2 Release-Blocking Acceptance Specification

## 1. Purpose

This document defines the acceptance criteria for the work that must be complete before v2 closeout.

It is narrower than the full v2 acceptance specification and exists to answer one question:

**Can v2 be closed without violating the deterministic verification contract?**
**Can v2 be closed without violating the deterministic verification contract or the required bounded non-deterministic execution contract?**

## 2. Release-Blocking Acceptance Areas

The following areas are mandatory:

1. native rule-to-issue migration progress
2. benchmark-backed confidence ordering and threshold behavior
3. aggregation family boundaries and issue lineage integrity
4. bounded non-deterministic agent execution behavior
5. local release gate coverage of the deterministic core

## 3. Acceptance Criteria

### 3.1 Native Rule-to-Issue

The system passes this area only if:

1. release-blocking priority rule families have explicit migration state
2. promoted `issue_native` families are validated by tests
3. deferred `seed_native` families are validated by tests and audited reasons
4. no release-blocking rule family is left in an implicit or untested state

### 3.2 Confidence Calibration

The system passes this area only if:

1. confidence ordering is fixture-protected for:
   - `issue_native > seed_native > finding_bridged`
   - proof > structural > heuristic
   - deterministic > agent-only
2. machine-trusted policy remains conservative and explicit
3. unknown, contradiction, partial, degraded, and agent-only penalties remain fixture-protected
4. confidence regressions are release-blocking

### 3.3 Aggregation Hardening

The system passes this area only if:

1. same-family merge cases merge deterministically
2. cross-family boundary cases do not merge
3. fingerprints remain stable across reruns
4. counter-evidence remains visible
5. completed agent evidence, when present, appears in:
   - evidence artifact
   - issue evidence IDs
   - trace derivation lineage

### 3.4 Release Gate

The system passes this area only if:

1. executed agent paths are fixture-protected
2. completed agent evidence appears in evidence, issue, derivation, and trace layers
3. insufficient-context and failed agent executions remain explicit
4. agent execution does not bypass aggregation or confidence

### 3.5 Release Gate

The system passes this area only if:

1. the local release gate command list matches the authoritative closeout scope
2. all gate steps pass
3. acceptance fixtures for release-blocking scope pass
4. build remains green

## 4. Required Test Coverage

At minimum, the release-blocking suite must cover:

1. migration matrix and audited reasons
2. calibrated confidence ordering
3. calibrated policy-class boundaries
4. aggregation family-sensitive merge and non-merge
5. completed agent result overlay into issue lineage
6. insufficient-context and failed agent execution visibility
7. deterministic artifact and derivation stability

## 5. Required Commands

The following commands must pass:

1. `go test ./internal/rules`
2. `go test ./internal/artifactsv2`
3. `go test ./internal/acceptance`
4. `go test ./internal/engine`
5. `go test ./pkg/cve`
6. `go test ./internal/releasegate ./internal/cli ./cmd/cve`
7. `go build ./cmd/cve`
8. `./cve release-gate`

## 6. Failure Conditions

V2 closeout must be blocked if any of the following are true:

1. a release-blocking rule family changes migration state without matching regression coverage
2. a confidence threshold or ordering regression is detected
3. a merge boundary regression is detected
4. completed agent evidence bypasses aggregation or derivation lineage
5. executed agent paths are not covered by acceptance fixtures
6. local release gate no longer reflects release-blocking scope

## 7. Acceptance Decision

V2 may be considered ready for closeout only when:

1. all release-blocking tests pass
2. all release-blocking gate commands pass
3. remaining incomplete items are explicitly non-blocking and documented as post-v2 work
