# Code Verification Engine v2 Release-Blocking Design Specification

## 1. Purpose

This document defines the architecture-level scope that **must** be complete before Code Verification Engine v2 can be considered ready for version closeout.

It is intentionally narrower than the full v2 architecture. Its purpose is to separate:

1. capabilities that are required for a production-grade deterministic verification core
2. capabilities that are required to make bounded non-deterministic execution safe enough for v2 closeout

## 2. Release-Blocking Scope

The following work is mandatory before v2 closeout:

1. more priority rule families must move from `seed_native` to `issue_native`
2. confidence calibration must move from baseline policy to benchmark-driven policy
3. aggregation hardening must reach rule-family-sensitive, regression-protected behavior
4. non-deterministic agent execution runtime must exist as a bounded, policy-driven, evidence-normalized runtime rather than a trace-only contract

## 3. Architectural Rule

The v2 release boundary is defined by this rule:

**The deterministic verification core and the bounded non-deterministic agent runtime must both be complete, self-consistent, and release-gated before v2 closeout.**

## 4. Mandatory Design Outcomes

### 4.1 Native Rule-to-Issue Semantics

Before v2 closeout:

1. all priority deterministic rule families must have explicit migration audit state
2. issue-native promotion may only occur when issue semantics are supported by deterministic evidence and false-positive guards
3. `IssueCandidate` semantics must come from rule-native issue semantics, not legacy finding reinterpretation, for all release-blocking rule families

### 4.2 Confidence as a Release Contract

Before v2 closeout:

1. rule reliability must be grounded in an explicit rule-family calibration table
2. machine-trusted eligibility must be conservative and explicit
3. confidence ordering must be validated by fixtures
4. confidence classes and policy classes must be stable under reruns

### 4.3 Aggregation as a Policy Layer

Before v2 closeout:

1. merge decisions must be explicit and explainable
2. family-sensitive merge boundaries must exist
3. conflicting evidence must remain visible
4. agent-contributed evidence, when present, must flow through normal aggregation rather than bypassing it

### 4.4 Non-Deterministic Agent Runtime as a Bounded Subsystem

Before v2 closeout:

1. agent execution must exist beyond trace-only planning
2. agent invocation must remain lazy and policy-defined
3. every executed agent task must consume bounded context
4. every agent result must normalize back into evidence records
5. agent execution status, output evidence, and unresolved reasons must be visible in trace
6. agent contribution must affect evidence, aggregation, derivation, and confidence through normal deterministic stages

## 5. Release-Blocking Subsystems

The following subsystem contracts are release-blocking:

### 5.1 `rules`

Required properties:

1. migration matrix is explicit and audited
2. issue-native rule families are stable and regression-tested
3. conservative seed-native families remain explicitly justified

### 5.2 `artifactsv2/aggregation`

Required properties:

1. fingerprints are stable
2. merge basis is explicit
3. family-sensitive non-merge boundaries are enforced
4. issue source summary reflects deterministic and agent contributions consistently

### 5.3 `artifactsv2/confidence`

Required properties:

1. reliability baselines are family-aware
2. policy caps remain conservative
3. confidence output is explainable and reproducible

### 5.4 `acceptance`

Required properties:

1. regression fixtures cover release-blocking behaviors
2. regressions fail fast
3. release gate reflects release-blocking scope

### 5.5 `agents/orchestrator`

Required properties:

1. trigger policy is explicit and conservative
2. execution uses bounded context only
3. task and result contracts are typed and reproducible
4. completed agent evidence is normalized into the main pipeline
5. failed or insufficient agent runs remain explicit in trace

## 6. Non-Blocking Deferred Scope

The following can remain post-v2:

1. expanded agent family breadth beyond bug/design/security
2. richer dependency expansion for context selection beyond the current bounded runtime
3. advanced benchmark corpus automation beyond the minimum calibrated fixture wall
4. more speculative agent-assisted review modes

These may be deferred only if:

1. the deterministic core remains complete
2. the bounded non-deterministic runtime remains complete
3. the release gate remains green
4. no deferred feature is required to justify a machine-trusted output

## 7. Closeout Criteria

V2 design is sufficiently complete for closeout only when:

1. release-blocking rule families are explicitly classified and justified
2. confidence policy is benchmark-backed rather than baseline-only
3. aggregation behavior is policy-driven and fixture-protected
4. non-deterministic agent execution is bounded, typed, evidence-normalized, and fixture-protected
5. agent execution does not weaken evidence-first invariants
