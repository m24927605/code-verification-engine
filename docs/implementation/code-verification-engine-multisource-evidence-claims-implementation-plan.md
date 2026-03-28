# Code Verification Engine Multi-Source Evidence Claims Implementation Plan

## 1. Purpose

This document defines the implementation plan for adding multi-source evidence claims and evidence-backed capability profile generation on top of the current v2 core.

The implementation must preserve the existing v2 release guarantees while adding a new, stricter path for high-value profile extraction.

## 2. Implementation Objectives

The implementation must:

1. model `README`, `docs`, `code`, `tests`, and `eval` as evidence sources
2. extend the current claim subsystem rather than bypass it
3. keep the claim verification path deterministic by default
4. preserve current v2 evidence/report/trace/skills artifacts
5. create bounded inputs for later LLM narrative synthesis

## 3. Baseline Context

The repo already contains:

- deterministic issue and evidence pipeline
- `internal/claims` claim-centric output
- evidence-backed v2 artifacts
- acceptance harness
- release gate

The current gaps are:

- claims are still primarily rule-result-centric
- README and docs are not first-class evidence sources
- tests and evals are not modeled as claim-strengthening evidence
- there is no claim graph or profile projection artifact

## 4. Delivery Strategy

This work should be implemented incrementally in six phases.

Rules:

- preserve current v2 behavior while adding new capability
- add contracts before broad extraction logic
- keep resume synthesis as a final projection, not a core evaluator
- do not introduce non-deterministic repo-wide reasoning

## 5. Phase 1: Source Discovery and Typing

Objective:

- discover and type non-code sources needed for claim verification

Work items:

- add source discovery for README files
- add source discovery for docs and ADRs
- add source discovery for tests
- add source discovery for eval assets
- classify discovered files into typed `SourceDescriptor` records

Target modules:

- new `internal/profile` or `internal/claimsources` package
- optional reuse of current repo loader metadata

Exit criteria:

- repository snapshot can enumerate source descriptors across all five source classes
- discovery is deterministic

## 6. Phase 2: Multi-Source Evidence Extraction

Objective:

- convert discovered sources into normalized evidence records

Work items:

- implement README section extraction
- implement docs section extraction
- implement test intent extraction
- implement eval asset extraction
- normalize extracted records into evidence-style source records

Design constraints:

- preserve path and location
- preserve source type
- preserve extractor identity
- generate deterministic IDs

Exit criteria:

- each source class can produce source evidence records
- extracted source evidence can be traced back to a file and span

## 7. Phase 3: Claim Candidate Extraction

Objective:

- produce claim candidates from multi-source evidence

Work items:

- add claim candidate extraction from README/docs text
- add claim candidate extraction from code structure patterns
- add claim candidate extraction from tests and eval assets
- deduplicate semantically equivalent candidates
- attach claim origin metadata

Design constraints:

- extracted claim text must remain bounded and typed
- identical claim semantics from multiple origins must merge conservatively

Exit criteria:

- candidate claims can be built without LLM access
- candidate extraction preserves origin and source evidence references

## 8. Phase 4: Claim Verification and Claim Graph

Objective:

- verify claim candidates against stronger evidence and build claim graph output

Work items:

- extend `internal/claims` from rule-result-centric evaluation into multi-source verification
- add support-level computation
- add contradiction handling
- add verified claim output
- add claim graph serialization

Design constraints:

- code and tests outweigh README marketing language
- contradictions are retained, not discarded
- weak documentation-only claims must be downgraded

Exit criteria:

- claim verification output can distinguish `verified`, `strongly_supported`, `supported`, `weak`, and `unsupported`
- every verified claim can be traversed to supporting evidence

## 9. Phase 5: Capability Profile Projection

Objective:

- turn verified claims into structured capability profile output

Work items:

- add `profile.json`
- add projection rules for highlights, capability areas, and technology summary
- restrict default highlights to `verified` and `strongly_supported`
- expose contributor evidence IDs for profile highlights

Design constraints:

- profile projection must not invent new claims
- profile output must remain machine-readable and auditable

Exit criteria:

- machine-readable capability profile can be generated deterministically
- highlights are fully traceable

## 10. Phase 6: Bounded Resume Synthesis

Objective:

- produce safe LLM synthesis inputs from verified claims

Work items:

- add `resume_input.json`
- emit synthesis constraints
- bound the claim set available for prose generation
- ensure contradiction visibility reaches synthesis input

Design constraints:

- synthesis is projection only
- unsupported claims may not be silently promoted
- raw repository content must not be sent by default

Exit criteria:

- bounded synthesis input can generate high-value prose while staying evidence-backed

## 11. Module-Level Plan

### 11.1 `internal/claims`

Refactor goals:

- preserve existing claim report support
- add multi-source claim candidate and verified claim support
- add claim graph output

### 11.2 `internal/artifactsv2`

Refactor goals:

- allow source evidence records to flow through current evidence/trace contracts where appropriate
- add projections for `claims.json`, `profile.json`, and `resume_input.json`

### 11.3 `pkg/cve`

Refactor goals:

- expose profile and claims artifacts through the public API
- preserve backward compatibility for current verification output

### 11.4 `internal/acceptance`

Refactor goals:

- add deterministic fixtures for source extraction, claim verification, contradiction handling, and profile projection

## 12. Example Implementation Sequence

Recommended execution order:

1. source discovery contracts
2. README/docs/test/eval extraction
3. source evidence normalization
4. claim candidate extraction
5. claim verification
6. claim graph artifact
7. capability profile artifact
8. bounded resume synthesis input

## 13. Risk Controls

Primary risks:

- README over-trust
- over-abstracting weak structural signals into high-value claims
- drifting into narrative generation before verification is solid
- adding too many source heuristics without strong tests

Mitigations:

- prioritize code/test/eval over README
- retain contradictions
- expose support level explicitly
- gate new projection artifacts behind contract and acceptance tests

## 14. Deliverables

The implementation should deliver:

- deterministic source discovery
- multi-source evidence extraction
- verified claims artifact
- capability profile artifact
- bounded resume synthesis input artifact
- acceptance fixtures and release-gate coverage

## 15. Definition of Done

The implementation is complete when:

1. all five source types are supported
2. claim verification is deterministic
3. verified claims are evidence-backed and contradiction-aware
4. profile output is auditable
5. bounded synthesis input is available
6. all new contracts are covered by tests and release gate
