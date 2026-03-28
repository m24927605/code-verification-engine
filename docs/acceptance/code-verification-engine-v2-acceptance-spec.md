# Code Verification Engine v2 Acceptance and Quality Gate Specification

## 1. Purpose

This document defines the formal acceptance criteria for Code Verification Engine v2. The intent is to ensure the system is not merely functional, but trustworthy, reproducible, cost-controlled, and suitable for production use as a verification engine.

Acceptance is based on evidence quality, deterministic behavior, traceability, reproducibility, and operational cost discipline.

## 2. Acceptance Objectives

The v2 system is accepted only if it demonstrates:

1. evidence-backed outputs
2. deterministic primary execution
3. bounded and auditable non-deterministic paths
4. reproducible artifact generation
5. explainable confidence and skill scoring
6. low-cost default execution
7. quality at or above the current baseline for trusted output classes

## 3. Acceptance Categories

Acceptance is divided into:

- functional acceptance
- quality acceptance
- reproducibility acceptance
- traceability acceptance
- cost acceptance
- test and contract acceptance
- release gate approval

## 4. Functional Acceptance

### 4.1 Evidence-First Acceptance

The system must satisfy all of the following:

1. Every final issue in `report.json` references one or more evidence IDs.
2. Every skill score in `skills.json` references contributing issue IDs and evidence IDs.
3. No final issue may exist without traceable supporting evidence.
4. Agent-generated contributions must appear as normalized evidence records.

Pass condition:

- artifact audit confirms there are no orphan conclusions

### 4.2 Deterministic Rule Path Acceptance

The system must satisfy all of the following:

1. The primary verification path completes without LLM access.
2. Rule outputs are deterministic under identical inputs.
3. Rule execution emits structured evidence or unknown results rather than unbacked narrative conclusions.

Pass condition:

- repeated execution on the same snapshot yields identical deterministic outputs

### 4.3 Context Selection Acceptance

The system must satisfy all of the following:

1. Every agent invocation uses a `ContextBundle`.
2. No agent invocation uses unrestricted repo-wide input by default.
3. Context selection decisions are recorded in `trace.json`.
4. Context selection results are reproducible under the same trigger and budgets.

Pass condition:

- trace audit confirms bounded context enforcement

### 4.4 Agent Orchestration Acceptance

The system must satisfy all of the following:

1. Agents are not executed eagerly for every scan.
2. Agents are triggered only by explicit policy conditions.
3. Agent failure does not corrupt or replace the deterministic primary path.
4. Agent outputs re-enter the system through evidence normalization and aggregation.

Pass condition:

- execution logs and trace data confirm lazy policy-driven agent use

### 4.5 Aggregation Acceptance

The system must satisfy all of the following:

1. Duplicate issue reports arising from overlapping evidence are clustered.
2. Counter-evidence is retained rather than discarded.
3. Multi-source agreement is represented in issue-level data.
4. Aggregation results are deterministic.

Pass condition:

- controlled duplicate and contradiction fixtures produce stable expected issue clustering

### 4.6 Confidence Acceptance

The system must satisfy all of the following:

1. Every issue has a confidence score in the range `0..1`.
2. Every issue has an explainable confidence breakdown.
3. Partial scans, analyzer degradation, or strong contradiction reduce confidence.
4. High confidence is not assigned to unsupported or LLM-only conclusions.

Pass condition:

- scoring audit on calibration fixtures confirms expected score ordering and penalties

### 4.7 Skill Scoring Acceptance

The system must satisfy all of the following:

1. Every skill score is evidence-derived.
2. Every skill score exposes its contributing issues and evidence.
3. Unsupported skills are not emitted as meaningful scores without backing data.
4. Negative issue evidence can reduce the resulting score.

Pass condition:

- skill scoring audit confirms every score is attributable

### 4.8 Artifact Acceptance

The system must generate the following artifacts:

- `report.json`
- `evidence.json`
- `skills.json`
- `trace.json`
- `summary.md`
- `signature.json`

Pass condition:

- all artifacts are emitted and validate against their contracts

## 5. Quality Acceptance

### 5.1 Correctness

Acceptance criteria:

- benchmark precision and recall must be at or above the current deterministic baseline for comparable rule families
- machine-trusted issue classes must meet stricter false-positive thresholds than advisory classes

### 5.2 Conservative Trust

Acceptance criteria:

- the system downgrades or marks unknown when proof conditions are not met
- partial coverage does not produce overconfident verified pass claims
- heuristic evidence does not silently escalate into proof-grade output

### 5.3 Output Coherence

Acceptance criteria:

- issue severity, confidence, evidence references, and skill impacts are internally consistent
- `summary.md` does not contain claims absent from the JSON artifacts

## 6. Reproducibility Acceptance

The system must satisfy all of the following:

1. Same repo snapshot, same scan boundary, same engine version, same analyzer versions, and same rule versions produce the same deterministic artifacts.
2. Recomputed artifact hashes match the emitted hashes in `signature.json`.
3. `trace.json` contains sufficient metadata to reproduce the run.

Pass condition:

- reproducibility test suite confirms stable artifact output except for allowed timestamp or signature fields

## 7. Traceability Acceptance

The system must satisfy all of the following:

1. Any issue in `report.json` can be traced to its evidence IDs.
2. Any evidence record can be traced to source producer identity and exact file locations.
3. Any agent contribution can be traced to its task trigger and input context.
4. Any skill score can be traced to issues and evidence.

Pass condition:

- spot audits can traverse issue -> evidence -> trace without missing links

## 8. Cost Acceptance

The system must prove that high-quality verification is achieved under a low-cost default operating model.

Required controls:

1. The default path does not require agent or LLM execution.
2. Agent invocation rate is policy-bound and observable.
3. Context bundle size is bounded and measured.
4. Per-repo execution time and cost are measured.

Recommended metrics:

- `deterministic_path_ratio`
- `agent_trigger_rate`
- `avg_context_files`
- `avg_context_spans`
- `avg_context_tokens`
- `cost_per_repo`
- `time_per_repo`

Pass condition:

- operational metrics remain within predefined limits for the target deployment profile

## 9. Test Acceptance

### 9.1 Unit Test Requirements

The following must be covered by unit tests:

- evidence schema validation
- deterministic evidence ID generation
- rule output normalization
- issue fingerprinting
- aggregation merge rules
- confidence scoring formula
- skill scoring formula
- artifact hash generation

### 9.2 Integration Test Requirements

The following must be covered by integration tests:

- repo ingestion to final artifact generation
- analyzer degradation handling
- partial scan handling
- issue aggregation with duplicate evidence
- contradiction handling
- agent trigger and normalization flow

### 9.3 Contract Test Requirements

The following artifacts must have contract tests:

- `report.json`
- `evidence.json`
- `skills.json`
- `trace.json`
- `signature.json`

### 9.4 Regression Test Requirements

The following must be included:

- existing benchmark fixtures
- false-positive guard fixtures
- negative-pass trust fixtures
- cross-language representative fixtures

Pass condition:

- all required test categories are implemented and passing

## 10. Audit Requirements

Before production promotion, the team must perform:

- evidence audit
- reproducibility audit
- confidence audit
- traceability spot audit
- cost audit

The audit must verify:

- no orphan findings
- no untracked agent influence
- no unstable hashing behavior
- no high-confidence outputs lacking sufficient backing

## 11. Release Gates

The system may be promoted to production only when all of the following are true:

1. Functional acceptance criteria are satisfied.
2. Quality acceptance criteria are satisfied.
3. Reproducibility acceptance criteria are satisfied.
4. Traceability acceptance criteria are satisfied.
5. Cost acceptance criteria are satisfied.
6. All required tests are passing.
7. Audit checks are complete and approved.

## 12. Recommended Quantitative Gates

The exact values may be tuned by the team, but the following gates should exist:

- machine-trusted false-positive rate threshold
- advisory false-positive rate threshold
- minimum benchmark precision per promoted rule family
- maximum default agent trigger rate
- maximum average context size
- maximum default cost per repo
- maximum artifact reproducibility variance

These thresholds must be documented before production rollout.

## 13. Failure Conditions

The system must be considered non-accepted if any of the following occurs:

- final issues exist without evidence references
- artifacts fail contract validation
- identical deterministic runs produce divergent outputs
- agent outputs bypass normalization or aggregation
- confidence values are emitted without breakdown
- skill scores are emitted without contributors
- bundle hashes cannot be recomputed successfully
- default execution depends on LLM availability

## 14. Acceptance Sign-Off Inputs

Approval should require sign-off from at least:

- architecture or platform owner
- verification engine implementation owner
- quality or calibration owner

Sign-off materials should include:

- benchmark comparison report
- reproducibility report
- artifact contract validation report
- cost profile summary
- audit checklist results

## 15. Summary

Code Verification Engine v2 is accepted only when it demonstrates that its outputs are evidence-backed, deterministic by default, traceable, reproducible, and economically viable for production use.

Functional completeness alone is not sufficient. Acceptance requires the system to prove that it can be trusted.
