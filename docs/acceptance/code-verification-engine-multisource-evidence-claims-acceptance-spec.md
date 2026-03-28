# Code Verification Engine Multi-Source Evidence Claims Acceptance Specification

## 1. Purpose

This document defines the acceptance criteria for the multi-source evidence claims subsystem used to support high-value, evidence-backed capability profile and resume generation.

Acceptance focuses on correctness, traceability, determinism, conservative trust, and bounded synthesis.

## 2. Acceptance Objectives

The subsystem is accepted only if it demonstrates:

1. typed ingestion of `README`, `docs`, `code`, `tests`, and `eval`
2. deterministic claim candidate extraction
3. conservative claim verification against stronger evidence
4. contradiction-aware claim output
5. auditable capability profile projection
6. bounded resume synthesis inputs

## 3. Functional Acceptance

### 3.1 Source Ingestion Acceptance

The system must:

1. identify README sources when present
2. identify docs and ADR sources when present
3. identify tests and eval assets when present
4. classify discovered files into valid source types
5. operate correctly when one or more optional source classes are absent

Pass condition:

- source discovery fixtures confirm correct source typing and graceful degradation

### 3.2 Source Evidence Acceptance

The system must:

1. normalize extracted source records into deterministic evidence-like records
2. preserve source type, file path, and section/span metadata
3. emit stable IDs on repeated runs

Pass condition:

- repeated extraction on the same snapshot yields identical source evidence IDs

### 3.3 Claim Candidate Acceptance

The system must:

1. extract claim candidates from README/docs without treating them as verified
2. extract structural claim candidates from code/tests/evals where possible
3. preserve claim origin metadata
4. deduplicate semantically identical candidate claims conservatively

Pass condition:

- fixtures show identical claim candidates under repeated runs and preserved origin metadata

### 3.4 Claim Verification Acceptance

The system must:

1. verify documentation claims against stronger evidence
2. downgrade documentation-only claims when support is insufficient
3. retain contradictory evidence instead of collapsing it away
4. expose support level and confidence for every verified claim

Pass condition:

- acceptance fixtures demonstrate `verified`, `strongly_supported`, `supported`, `weak`, and `unsupported` outcomes

### 3.5 Claim Graph Acceptance

The system must:

1. preserve edges from claims to supporting evidence
2. preserve contradictory evidence links
3. preserve origin links from README/docs/test/eval/code candidates

Pass condition:

- spot-audit traversal from claim -> evidence -> source file succeeds without missing links

### 3.6 Capability Profile Acceptance

The system must:

1. generate machine-readable profile output
2. restrict default highlights to `verified` and `strongly_supported` claims
3. expose supporting claim and evidence references
4. avoid projecting `weak` or `unsupported` claims into top-level highlights

Pass condition:

- profile fixtures confirm projection rules and contributor integrity

### 3.7 Resume Synthesis Input Acceptance

The system must:

1. generate bounded synthesis input
2. include only allowed claim classes in default high-value synthesis
3. preserve contradiction visibility
4. include explicit synthesis constraints

Pass condition:

- synthesis-input fixtures confirm unsupported claims are excluded from default highlight prompts

## 4. Quality Acceptance

### 4.1 Conservative Trust

Acceptance criteria:

- README-only claims must not become `verified`
- tests and evals may strengthen implementation claims but may not overwrite contradictory code evidence
- contradictory evidence must lower support level or reject the claim

### 4.2 Output Coherence

Acceptance criteria:

- claim support level, confidence, and supporting evidence must be internally consistent
- projected profile highlights must not exceed the strength of their source claims

### 4.3 High-Value Narrative Discipline

Acceptance criteria:

- high-level architecture statements must be backed by multi-source support
- marketing-style documentation text alone must not produce strong profile claims

## 5. Reproducibility Acceptance

The subsystem must satisfy:

1. same snapshot and same extraction versions produce the same discovered sources
2. same snapshot and same extraction versions produce the same claim graph
3. same snapshot and same extraction versions produce the same profile projection

Pass condition:

- reproducibility suite confirms stable outputs apart from allowed timestamp/signature fields

## 6. Traceability Acceptance

The subsystem must satisfy:

1. every projected profile highlight can be traced to claim IDs
2. every claim can be traced to supporting or contradictory evidence IDs
3. every source evidence record can be traced to file paths and spans

Pass condition:

- traceability spot audits succeed for representative verified and downgraded claims

## 7. Test Acceptance

### 7.1 Unit Tests

The following require unit coverage:

- source discovery classification
- README/docs/test/eval extraction
- deterministic source evidence ID generation
- claim candidate deduplication
- support-level scoring
- contradiction handling
- profile projection filters
- bounded synthesis input filters

### 7.2 Integration Tests

The following require integration coverage:

- repo ingestion to claims/profile artifact generation
- mixed-source claim verification
- documentation claim downgrade path
- contradiction path
- missing-source graceful degradation

### 7.3 Contract Tests

The following require contract coverage:

- `claims.json`
- `profile.json`
- `resume_input.json`
- source evidence integration with `trace.json` and `evidence.json`

### 7.4 Acceptance Fixtures

The following fixture classes are mandatory:

1. README over-claim fixture
2. code-backed architecture claim fixture
3. test-strengthened security maturity fixture
4. eval-backed AI quality maturity fixture
5. contradiction fixture where docs and code disagree
6. no-README fixture proving the system still works

## 8. Release Gate Requirements

The local release gate must include checks for:

1. source discovery determinism
2. claim graph integrity
3. profile projection integrity
4. synthesis input boundedness

The subsystem must not be considered complete until these checks are green in the local release gate.

## 9. Failure Conditions

The subsystem fails acceptance if any of the following occur:

- README-only claims are emitted as verified
- profile highlights contain unsupported claims
- contradictions are dropped
- claim IDs or evidence references do not resolve
- outputs vary nondeterministically across repeated runs
- synthesis input includes unrestricted raw repository context

## 10. Definition of Acceptance

This subsystem is accepted only when:

1. all five source classes are supported
2. claim verification is deterministic and conservative
3. claim graph output is traceable and auditable
4. profile output is evidence-backed
5. bounded synthesis input is safe by contract
6. unit, integration, contract, and acceptance fixtures are green
