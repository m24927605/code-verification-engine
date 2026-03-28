# Code Verification Engine v2 Confidence Engine Specification

## 1. Purpose

This document defines the v2 confidence engine for Code Verification Engine.

The confidence engine is responsible for assigning a deterministic, explainable confidence score to each issue candidate. Its purpose is not to inflate certainty, but to express how strongly the system can support a conclusion from available evidence, execution quality, and source agreement.

## 2. Problem Statement

The current system contains trust classes and qualitative confidence values, but v2 requires a stronger mechanism:

1. issue-level confidence must be numeric
2. confidence must be explainable
3. confidence must respond to degraded analysis conditions
4. confidence must distinguish deterministic proof from advisory inference
5. confidence must penalize contradiction and weak support

Without a formal confidence engine, the verification system can produce outputs that look precise but are not auditable.

## 3. Objectives

The confidence engine must:

1. compute a `0..1` confidence score for every issue candidate
2. produce a breakdown that is stable and explainable
3. reward strong evidence, rule reliability, and source agreement
4. penalize contradiction, partial coverage, and weak evidence quality
5. support conservative calibration for machine-trusted output classes

## 4. Design Principles

### 4.1 Confidence Is Evidence Support, Not Likelihood Theater

The score represents how strongly the engine can justify an issue, not how persuasive the prose looks.

### 4.2 Deterministic Inputs Only

The engine must use deterministic inputs:

- issue candidate structure
- evidence quality
- scan boundary state
- analyzer status
- contradiction state
- source agreement
- calibrated rule metadata

### 4.3 Conservative Defaults

Missing or ambiguous information must reduce confidence, not increase it.

### 4.4 Breakdown Required

No issue may have a final confidence score without a retained breakdown.

## 5. Confidence Inputs

Each issue candidate confidence score must be computed from the following inputs.

### 5.1 Rule Reliability

Definition:

- empirical or policy-defined reliability of the contributing rule set

Range:

- `0..1`

Initial policy:

1. machine-trusted proof-grade rules may score high
2. advisory or heuristic-heavy rules must score lower
3. unknown/runtime-required rules must not inherit high reliability

### 5.2 Evidence Quality

Definition:

- aggregated quality of evidence supporting the issue

Recommended mapping:

- `proof = 1.0`
- `structural = 0.7`
- `heuristic = 0.4`

Aggregation policy:

- use strongest-supporting and weakest-required signals conservatively
- do not allow one proof-grade evidence record to erase multiple weak supporting records without explicit rule

### 5.3 Boundary Completeness

Definition:

- how complete the scan boundary is for the issue being judged

Examples:

1. full repo boundary with successful analyzers yields higher completeness
2. subdir-only boundary for cross-layer issue types yields lower completeness
3. explicit partial scan lowers completeness

### 5.4 Context Completeness

Definition:

- how complete the local semantic context is for the issue cluster

Signals may include:

1. presence of symbol definition and call sites
2. presence of route binding or config sources when rule family requires them
3. evidence coverage density around the issue location

### 5.5 Source Agreement

Definition:

- how many independent sources support the issue

Examples:

1. multiple deterministic rules
2. analyzer + rule
3. rule + agent

Important:

- agreement must not double-count multiple outputs from the same producer class as independent certainty

### 5.6 Contradiction Penalty

Definition:

- strength of counter-evidence or unresolved contradiction associated with the issue

Requirements:

1. contradiction must decrease confidence
2. contradiction must never be silently dropped

### 5.7 LLM Penalty

Definition:

- penalty applied when support depends materially on agent or non-deterministic inference

Policy:

1. deterministic-only issues receive no penalty
2. agent-confirmed issues may receive small penalty depending on source mix
3. LLM-only or agent-only support must receive strong penalty and may be ineligible for high-confidence classes

## 6. Required Output Contract

Each issue candidate must produce:

```text
rule_reliability
evidence_quality
boundary_completeness
context_completeness
source_agreement
contradiction_penalty
llm_penalty
final
```

All values must be `0..1`.

The `final` score must be reproducible from the stored inputs.

## 7. Baseline Formula

The baseline deterministic formula is:

```text
confidence =
  0.30 * rule_reliability
+ 0.20 * evidence_quality
+ 0.15 * boundary_completeness
+ 0.15 * context_completeness
+ 0.20 * source_agreement
- 0.20 * contradiction_penalty
- 0.10 * llm_penalty
```

Then:

```text
final = clamp(confidence, 0, 1)
```

This is the baseline production formula unless explicitly superseded by a calibration ADR.

## 8. Input Derivation Rules

### 8.1 Rule Reliability Derivation

Priority order:

1. calibrated rule benchmark score
2. trust-class-based fallback
3. conservative default

Recommended fallback baseline:

- proof/machine-trusted rule family: `0.85`
- structural/advisory rule family: `0.65`
- heuristic rule family: `0.45`
- runtime-required or unresolved unknown path: `0.30`

### 8.2 Evidence Quality Derivation

Policy:

1. map each evidence record to numeric quality
2. aggregate per issue candidate conservatively
3. synthetic evidence must inherit conservative quality from seed quality

Recommended aggregate:

- `max_quality * 0.6 + median_quality * 0.4`

This avoids letting one proof record completely dominate a mixed weak cluster.

### 8.3 Boundary Completeness Derivation

Recommended baseline:

- full repo + no partial flag: `1.0`
- full repo + partial analyzer degradation: `0.75`
- subdir boundary for local issue type: `0.80`
- subdir boundary for cross-cutting issue type: `0.55`
- capability unsupported or severe degradation: `<= 0.40`

### 8.4 Context Completeness Derivation

Recommended inputs:

1. location presence
2. symbol presence
3. dependency edge coverage
4. required relation coverage for the rule family

Recommended baseline:

- complete local graph: `0.90 - 1.0`
- partial structural context: `0.60 - 0.80`
- location-only support: `0.35 - 0.50`

### 8.5 Source Agreement Derivation

Recommended policy:

- one producer class: `0.45`
- two independent producer classes: `0.70`
- three independent producer classes: `0.90`

Do not count:

1. multiple findings from the same rule as multiple independent sources
2. multiple seeds from the same producer as independent agreement

### 8.6 Contradiction Penalty Derivation

Recommended policy:

- no contradiction: `0.0`
- weak unresolved contradiction: `0.20`
- material contradiction: `0.45`
- strong counter-evidence: `0.70+`

### 8.7 LLM Penalty Derivation

Recommended policy:

- deterministic-only support: `0.0`
- rule + bounded agent confirmation: `0.05`
- agent-majority support: `0.20`
- agent-only support: `0.40+`

## 9. Confidence Classes

The numeric score may optionally be rendered into buckets for policy use:

- `0.85 - 1.00`: high-confidence
- `0.65 - 0.84`: moderate-confidence
- `0.40 - 0.64`: low-confidence
- `< 0.40`: weak-confidence

These buckets are presentation or policy aids only. The stored source-of-truth remains the numeric value plus breakdown.

## 10. Policy Constraints

The confidence engine must enforce the following:

1. unsupported/runtime-required outputs must not reach high-confidence by default
2. strong contradiction prevents machine-trusted presentation
3. partial scan state must lower issue confidence
4. low-quality heuristic evidence must not be rendered as proof-strength confidence
5. confidence may be conservative, but not optimistic without evidence

## 11. Calibration Strategy

The engine must be calibrated using benchmark fixtures.

Calibration phases:

### Phase 1: Static Baseline

- use baseline formula and fallback constants

### Phase 2: Rule Family Calibration

- calibrate reliability by rule family on fixture corpus

### Phase 3: Threshold Policy

- set acceptance thresholds for:
  - machine-trusted eligibility
  - advisory publication
  - unknown retention

Calibration must not directly fit to maximize score aesthetics. It must minimize unsafe confidence inflation.

## 12. Implementation Tasks

Required work items:

1. define confidence input model
2. implement deterministic confidence calculator
3. attach confidence breakdown to `IssueCandidate`
4. ensure projected `report.json` uses candidate confidence, not ad hoc score substitution
5. add degradation and contradiction input plumbing
6. add calibration fixture set
7. add score-ordering tests

## 13. Acceptance Requirements

The confidence engine is complete only when all of the following are true:

1. every issue candidate has a numeric confidence score
2. every issue candidate has a stored breakdown
3. degraded scans lower score on controlled fixtures
4. contradictory evidence lowers score on controlled fixtures
5. deterministic reruns produce identical scores
6. high-confidence output is limited to acceptable rule/evidence classes

## 14. Success Criteria

The confidence engine is successful when:

1. it is explainable
2. it is reproducible
3. it is conservative under uncertainty
4. it provides a practical basis for trust policy and acceptance gating

