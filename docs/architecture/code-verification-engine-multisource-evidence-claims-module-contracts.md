# Code Verification Engine Multi-Source Evidence Claims Module Contracts

## 1. Purpose

This document defines the module contracts for introducing `README`, `docs`, `code`, `tests`, and `eval` as first-class evidence sources for high-value claim verification and capability profile generation.

It complements the architecture document by specifying typed boundaries and responsibilities.

## 2. Contract Goals

The contracts must ensure:

1. every source type is explicit
2. every claim is evidence-backed
3. documentation claims are distinguishable from verified implementation claims
4. profile output remains traceable
5. synthesis inputs remain bounded and auditable

## 3. Source Discovery Contract

### 3.1 `SourceDescriptor`

Required fields:

- `source_id`
- `source_type`
- `path`
- `language`
- `role`
- `included_in_boundary`

Allowed `source_type` values:

- `code`
- `test`
- `eval`
- `doc`
- `readme`

Allowed `role` examples:

- `agent_module`
- `pipeline`
- `service`
- `route`
- `unit_test`
- `integration_test`
- `security_test`
- `eval_dataset`
- `architecture_doc`
- `adr`
- `overview_readme`

## 4. Multi-Source Evidence Contract

### 4.1 `SourceEvidenceRecord`

This extends the v2 evidence concept with source-class metadata.

Required fields:

- `evidence_id`
- `source_type`
- `producer`
- `path`
- `kind`
- `summary`
- `spans`
- `entity_ids`
- `metadata`

Recommended metadata by source type:

- `code`
  - module kind
  - exported symbol
  - route or service class
- `test`
  - test kind
  - target module
  - assertion intent
- `eval`
  - dataset id
  - benchmark purpose
  - adversarial flag
- `doc`
  - section title
  - claim fragments
- `readme`
  - heading
  - claim fragments

## 5. Claim Candidate Contract

### 5.1 `ClaimCandidate`

Required fields:

- `claim_id`
- `title`
- `category`
- `claim_type`
- `origin`
- `candidate_evidence_ids`
- `scope`

Allowed `origin` values:

- `readme_extracted`
- `doc_extracted`
- `code_inferred`
- `test_inferred`
- `eval_inferred`
- `rule_inferred`

Allowed `claim_type` values:

- `implementation`
- `architecture`
- `security_maturity`
- `testing_maturity`
- `evaluation_maturity`
- `operational_maturity`

## 6. Claim Verification Contract

### 6.1 `VerifiedClaim`

Required fields:

- `claim_id`
- `title`
- `category`
- `claim_type`
- `status`
- `support_level`
- `confidence`
- `supporting_evidence_ids`
- `contradictory_evidence_ids`
- `source_origins`
- `reason`

Allowed `status` values:

- `accepted`
- `downgraded`
- `rejected`
- `unknown`

Allowed `support_level` values:

- `verified`
- `strongly_supported`
- `supported`
- `weak`
- `unsupported`
- `contradicted`

Required semantics:

- `verified` requires direct implementation evidence and no unresolved contradiction
- `strongly_supported` requires strong structural support from code plus at least one reinforcing non-code source
- `supported` allows partial multi-source support but not enough for strong architectural wording
- `weak` means plausible but not safe for strong resume projection
- `unsupported` means extracted claim lacks sufficient evidence
- `contradicted` means stronger evidence conflicts with the claim

## 7. Claim Graph Contract

### 7.1 `ClaimGraph`

Required fields:

- `schema_version`
- `claims`
- `edges`

### 7.2 Edge Types

Allowed edge types:

- `supported_by`
- `contradicted_by`
- `derived_from`
- `validated_by`
- `documented_by`
- `projected_to`

Required semantics:

- every projected profile statement must trace back to a claim node
- every claim node must trace back to one or more evidence records

## 8. Profile Projection Contract

### 8.1 `CapabilityProfile`

Required fields:

- `profile_schema_version`
- `repository`
- `highlights`
- `capability_areas`
- `technologies`
- `claim_ids`

### 8.2 `CapabilityHighlight`

Required fields:

- `highlight_id`
- `title`
- `support_level`
- `claim_ids`
- `supporting_evidence_ids`

Projection rules:

- default highlights may only use `verified` and `strongly_supported` claims
- `supported` claims may be used only in lower-strength sections
- `weak` and `unsupported` claims must not appear in default profile highlights

## 9. Resume Synthesis Input Contract

### 9.1 `ResumeInput`

Required fields:

- `profile`
- `verified_claims`
- `strongly_supported_claims`
- `technology_summary`
- `evidence_references`
- `synthesis_constraints`

Required synthesis constraints:

- no unsupported claim invention
- no contradiction suppression
- no upgrade of `supported` to `verified`
- no repository-wide raw code dump

## 10. Artifact Integration Contract

The new contracts must integrate with existing v2 artifacts as follows:

- `evidence.json`
  - must include multi-source evidence records or references
- `trace.json`
  - must include source discovery and claim verification trace
- `skills.json`
  - may remain narrower than profile output
- `claims.json`
  - should become the main machine-readable output for this subsystem

## 11. API Surface Contract

Any public API exposure must preserve:

- source type
- claim support level
- claim confidence
- contributor evidence IDs
- contradiction visibility

The API must not flatten all claims into unqualified marketing statements.

## 12. Backward Compatibility Rules

The new claim subsystem must not:

- break current v2 report, evidence, trace, or skills output
- require README or docs to exist
- require LLM execution to produce machine-readable claims

If README and docs are absent, the engine must still operate on code/tests/evals alone.
