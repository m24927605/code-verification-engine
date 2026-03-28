# Code Verification Engine v2 Release-Blocking Implementation Plan

## 1. Purpose

This document defines the implementation plan for the work that must be completed before v2 closeout.

It is intentionally limited to release-blocking work:

1. native rule-to-issue completion for priority rule families
2. benchmark-driven confidence calibration
3. rule-family-sensitive aggregation hardening
4. bounded non-deterministic agent execution runtime

## 2. Implementation Order

Work must proceed in this order:

1. native rule-to-issue completion
2. aggregation hardening
3. confidence calibration
4. bounded non-deterministic agent runtime
5. acceptance and release-gate expansion

Reason:

1. confidence calibration depends on stable issue semantics
2. aggregation policy depends on stable rule-family semantics
3. non-deterministic runtime must execute against a stable deterministic core
4. acceptance should lock the final calibrated and executed behavior rather than an intermediate one

## 3. Workstream A: Native Rule-to-Issue Completion

### 3.1 Required Tasks

1. audit remaining explicit `seed_native` rule families
2. promote only those families with deterministic evidence and false-positive guards
3. keep other rule families explicitly `seed_native` with audited reasons
4. strengthen rule-level regression coverage for both promoted and deferred families

### 3.2 Required Deliverables

1. updated migration matrix
2. updated audited reasons
3. rule-level tests proving promotion or conservative deferral

### 3.3 Exit Criteria

1. all release-blocking priority rule families are either:
   - `issue_native`, or
   - explicitly deferred with audited release rationale
2. no release-blocking rule family remains ambiguous

## 4. Workstream B: Aggregation Hardening

### 4.1 Required Tasks

1. formalize family-sensitive merge policy
2. lock fingerprint stability under ordering changes
3. ensure agent-contributed evidence enters issue evidence and derivation lineage
4. ensure source summaries and merge basis remain deterministic

### 4.2 Required Deliverables

1. explicit merge-family policy implementation
2. aggregation tests for:
   - merge
   - non-merge
   - family-sensitive non-merge
   - completed agent evidence overlay
3. acceptance fixtures for aggregation boundaries

### 4.3 Exit Criteria

1. no known over-merge or under-merge case remains in release-blocking rule families
2. issue fingerprints remain stable across reruns
3. completed agent evidence is visible in evidence, issue, and derivation layers

## 5. Workstream C: Confidence Calibration

### 5.1 Required Tasks

1. define the release-blocking rule-family reliability table
2. calibrate machine-trusted thresholds conservatively
3. lock ordering rules for:
   - issue_native > seed_native > finding_bridged
   - proof > structural > heuristic
   - deterministic > agent-only
4. ensure contradiction and degraded scan penalties remain release-blocking

### 5.2 Required Deliverables

1. calibrated reliability baselines
2. explicit threshold policy
3. regression fixtures for calibrated score ordering

### 5.3 Exit Criteria

1. calibrated outcomes are no longer baseline-only
2. machine-trusted eligibility is explicitly fixture-protected
3. confidence regressions fail acceptance/release gate

## 6. Workstream D: Non-Deterministic Agent Runtime

### 6.1 Required Tasks

1. implement policy-defined lazy agent execution beyond trace-only planning
2. ensure every execution uses bounded context selection output
3. normalize every agent result into evidence records
4. feed completed agent evidence back into aggregation, derivation, and confidence
5. preserve failed and insufficient-context executions explicitly in trace

### 6.2 Required Deliverables

1. bounded agent execution path
2. typed task and result contracts
3. evidence normalization for executed agents
4. executed-agent regression tests

### 6.3 Exit Criteria

1. executed agents are no longer represented only as planned contracts
2. completed agent evidence enters the normal evidence-first path
3. insufficient-context and failed executions remain explicit and non-silent

## 7. Workstream E: Acceptance and Release Gate

### 7.1 Required Tasks

1. add fixtures that directly cover release-blocking rule-family migrations
2. add fixtures that directly cover calibrated confidence ordering
3. add fixtures that directly cover aggregation family boundaries
4. add fixtures that directly cover executed agent paths
5. keep release gate aligned with these checks

### 7.2 Required Deliverables

1. expanded acceptance fixture corpus
2. release gate command coverage
3. release-blocking fixture documentation in test names and assertions

### 7.3 Exit Criteria

1. every release-blocking behavior has at least one regression fixture
2. local release gate remains authoritative and green

## 8. Explicit Non-Goals

This plan does not require, before v2 closeout:

1. expanded speculative agent families beyond the bounded release-blocking runtime
2. broader LLM-assisted review modes outside the documented trigger policy
3. UI or presentation changes

These may proceed later only after the deterministic core is closed.
