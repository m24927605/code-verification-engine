# Code Verification Engine Proof-Grade Facts Scenario Acceptance Specification

## 1. Purpose

This document defines the acceptance criteria for the proof-grade facts scenario upgrade spanning:

1. interview and hiring, with code-to-resume generation
2. outsourced delivery acceptance assistance
3. software engineering PM acceptance

Acceptance focuses on correctness, determinism, traceability, conservative trust, scenario safety, and release-grade completeness.

## 2. Acceptance Objectives

The upgrade is accepted only if it demonstrates:

1. explicit separation of proof-grade, structural, heuristic, and runtime-required outcomes
2. scenario-safe projection that never upgrades weak evidence
3. proof-grade claim generation only when fact quality and completeness prerequisites are satisfied
4. correct outsource and PM acceptance semantics
5. conservative hiring and resume projection behavior
6. reproducible and auditable outputs across repeated runs

## 3. Functional Acceptance

### 3.1 Claim Verification Class Acceptance

The system must:

1. emit an explicit verification class for claim outputs
2. distinguish `proof_grade`, `structural_inference`, `heuristic_advisory`, and `human_or_runtime_required`
3. avoid collapsing structural or heuristic outcomes into proof-grade labels

Pass condition:

- repeated fixtures show stable verification class assignments and correct downgrade behavior

### 3.2 Fact Quality Enforcement Acceptance

The system must:

1. prevent proof-grade claim emission when decisive facts are below required quality
2. downgrade proof-capable rules to structural or unknown when proof prerequisites are not satisfied
3. preserve explicit reasons for downgrade

Pass condition:

- fixtures confirm the same matcher produces proof-grade only when required fact quality is present

### 3.3 Negative Completeness Acceptance

The system must:

1. require explicit completeness conditions for proof-grade negative pass
2. downgrade absence-based checks to `unknown` when scan or analyzer completeness is insufficient
3. preserve boundary and analyzer status in traceable form

Pass condition:

- incomplete-boundary fixtures produce `unknown` instead of incorrect proof-grade pass

### 3.4 Hiring Projection Acceptance

The system must:

1. generate hiring-safe profile output from verified claims
2. exclude heuristic-only claims from default top-level highlights
3. exclude unsupported or contradicted claims from `resume_input.json` default verified sets
4. retain contradiction visibility in hiring-related artifacts

Pass condition:

- hiring fixtures prove that proof-backed claims survive while overclaiming heuristics are filtered or downgraded

### 3.5 Outsource Acceptance Projection Acceptance

The system must:

1. generate `outsource_acceptance.json`
2. express requirement rows with `passed`, `failed`, `unknown`, or `runtime_required`
3. allow proof-grade checks to drive pass/fail
4. prevent structural or heuristic-only checks from silently driving contractual pass
5. preserve evidence references for every requirement row

Pass condition:

- outsource fixtures demonstrate proof-grade pass, proof-grade fail, and unknown due to insufficient completeness

### 3.6 PM Acceptance Projection Acceptance

The system must:

1. generate `pm_acceptance.json`
2. label output as engineering acceptance, not general product acceptance
3. distinguish implemented, partial, blocked, unknown, and runtime-required states where applicable
4. preserve requirement-to-evidence traceability

Pass condition:

- PM fixtures demonstrate engineering-ready, partial, and runtime-required outcomes without overclaim

### 3.7 Traceability Acceptance

The system must:

1. allow traversal from scenario row to claim
2. allow traversal from claim to evidence IDs
3. allow traversal from evidence to file path and location
4. preserve contradiction links where present

Pass condition:

- spot-audit traversal succeeds for representative hiring, outsource, and PM outputs

## 4. Scenario-Specific Acceptance

### 4.1 Hiring and Resume Safety

Acceptance criteria:

- documentation-only or heuristic-only claims must not become proof-grade resume highlights
- proof-backed implementation claims may appear in hiring profile and resume input
- structural claims may appear only when explicitly labeled and policy-allowed
- contradictory evidence must remain visible to downstream synthesis

### 4.2 Outsourced Delivery Acceptance Safety

Acceptance criteria:

- contractual pass/fail must not rely on heuristic-only signals
- structural-only evidence may produce advisory notes or `unknown`, not silent pass
- negative proof-grade pass requires explicit completeness support
- unsupported languages or degraded analyzers must not yield false contractual pass

### 4.3 PM Acceptance Safety

Acceptance criteria:

- PM projection must stay within engineering acceptance scope
- business correctness and runtime behavior must not be presented as statically verified unless future runtime evidence exists
- implementation presence must not be misrepresented as end-user acceptance

## 5. Quality Acceptance

### 5.1 Conservative Trust

Acceptance criteria:

- proof-grade labels appear only when decisive proof facts and completeness are available
- heuristic-only claims remain advisory
- runtime-required claims remain outside proof-grade automation scope

### 5.2 Output Coherence

Acceptance criteria:

- verification class, support level, trust class, and reason fields must be internally coherent
- scenario projections must not strengthen underlying claim semantics
- summaries must agree with row-level data

### 5.3 Compatibility Discipline

Acceptance criteria:

- existing evidence and report generation must remain coherent
- current public artifacts must not silently change semantics without contract updates

## 6. Reproducibility Acceptance

The upgrade must satisfy:

1. same snapshot and same engine version produce the same verification classes
2. same snapshot and same engine version produce the same scenario outputs
3. same snapshot and same engine version produce the same evidence references and claim references

Pass condition:

- reproducibility suite confirms stable outputs apart from allowed timestamp or signature fields

## 7. Test Acceptance

### 7.1 Unit Tests

Mandatory unit coverage:

- claim verification class derivation
- fact-quality downgrade logic
- completeness gating for negative proof
- scenario applicability filtering
- hiring projection filters
- outsource summary and requirement row generation
- PM summary and engineering-scope labeling

### 7.2 Integration Tests

Mandatory integration coverage:

- first-wave auth protection proof path
- first-wave config and secret sourcing proof path
- first-wave direct DB access negative proof path
- first-wave hardcoded secret fail path
- first-wave scoped test-presence proof path
- hiring projection end-to-end
- outsource acceptance end-to-end
- PM acceptance end-to-end

### 7.3 Contract Tests

Mandatory contract coverage:

- `claims.json`
- `profile.json`
- `resume_input.json`
- `outsource_acceptance.json`
- `pm_acceptance.json`
- relevant `trace.json` additions

### 7.4 Acceptance Fixtures

The following fixture classes are mandatory:

1. hiring proof-backed claim fixture
2. hiring overclaim downgrade fixture
3. outsource pass fixture
4. outsource fail fixture
5. outsource unknown due to boundary incompleteness fixture
6. PM engineering acceptance fixture
7. PM runtime-required fixture
8. contradiction fixture
9. analyzer degradation fixture
10. unsupported framework fixture

## 8. Release Gate Requirements

The local release gate must include checks for:

1. proof-grade claim contract validity
2. scenario projection integrity
3. completeness gating correctness for negative proof
4. hiring resume-safety constraints
5. evidence and claim reference integrity
6. reproducibility of scenario artifacts

The upgrade is not complete until these checks are green in the release gate.

## 9. Failure Conditions

The upgrade fails acceptance if any of the following occur:

- heuristic-only claims are emitted as proof-grade
- incomplete negative checks are emitted as proof-grade pass
- hiring highlights include unsupported or contradiction-hidden claims
- outsource acceptance rows silently pass on structural or heuristic evidence alone
- PM acceptance is framed as product acceptance rather than engineering acceptance
- claim or evidence references do not resolve
- repeated runs produce inconsistent scenario artifacts
- degraded analyzers still produce unjustified proof-grade outputs

## 10. Definition of Acceptance

This upgrade is accepted only when:

1. proof-grade semantics are explicit and enforced
2. first-wave rule families satisfy quality and completeness constraints
3. hiring outputs are resume-safe
4. outsource acceptance is contract-safe
5. PM acceptance stays within engineering scope
6. unit, integration, contract, acceptance, and release-gate checks are green
