# Code Verification Engine Proof-Grade Facts Scenario Implementation Plan

## 1. Purpose

This document defines the implementation plan for productizing proof-grade facts across the three primary scenarios:

1. interview and hiring, with code-to-resume generation
2. outsourced delivery acceptance assistance
3. software engineering PM acceptance

The implementation must produce a system that Claude Code can deliver incrementally without weakening current guarantees.

## 2. Implementation Objectives

The implementation must:

1. preserve the existing evidence-first and deterministic-first core
2. upgrade proof-capable checks away from heuristic-heavy rule semantics
3. introduce scenario-aware claim projection without forking the engine
4. make proof eligibility, completeness, and downgrade paths explicit in code and artifacts
5. add acceptance-grade outputs for outsource and PM use cases
6. keep hiring outputs conservative and resume-safe

## 3. Baseline Context

The repository already contains:

- deterministic rule execution
- evidence-backed canonical artifacts
- fact quality classes: `proof`, `structural`, `heuristic`
- claim/profile/resume projection contracts
- trust class semantics
- acceptance harness and release gate infrastructure

The implementation gaps are:

- fact quality is not yet enforced strongly enough as rule policy
- claim outputs lack scenario-specific verification class semantics
- acceptance-oriented scenario projections do not yet exist
- proof-capable rule families are not yet split sufficiently from artifact heuristics
- absence-based proof semantics are not yet explicit enough for contract gating

## 4. Delivery Strategy

This work should be delivered in eight phases.

Rules:

- no parallel unverifiable path
- contracts before broad implementation
- rule migration before mass scenario projection
- acceptance fixtures introduced alongside capability, not after
- each phase must preserve current output continuity unless the contract explicitly changes

## 5. Phase 1: Contract and Metadata Expansion

### Objective

Introduce the metadata required to distinguish proof-grade claims from weaker signals and to support scenario-aware projection.

### Work Items

- extend claim contracts with `verification_class`
- add `scenario_applicability`
- add `projection_policies`
- define scenario artifact contracts for outsource and PM acceptance
- define requirement row schema for acceptance artifacts
- define completeness metadata required for negative proof

### Target Modules

- `internal/artifactsv2`
- `pkg/cve/schema.go`
- `docs/contracts/*`

### Exit Criteria

- artifact contracts are explicit and versioned
- claim records can express proof-grade versus weaker classes
- scenario outputs have a typed schema before implementation begins

## 6. Phase 2: Rule Metadata Hardening

### Objective

Make rule reliability and proof prerequisites machine-enforceable rather than descriptive only.

### Work Items

- extend rule metadata to declare:
  - minimum fact quality for proof-grade verdicts
  - minimum fact quality for structural inference
  - whether the rule is exhaustive for negative pass
  - scenario applicability
  - acceptance intent
- add helper functions for verdict downgrade based on fact quality and completeness
- add shared policy utilities so matchers cannot accidentally emit proof-grade claims without satisfying prerequisites

### Target Modules

- `internal/rules/*`
- `rules.yaml`
- `internal/artifactsv2/confidence.go`
- `internal/report/*`

### Exit Criteria

- no rule may emit a proof-grade claim without declared prerequisites
- negative passes must explicitly state whether completeness was sufficient

## 7. Phase 3: Fact and Analyzer Upgrade

### Objective

Increase the supply of proof-capable facts needed by migrated rules.

### Work Items

- complete and harden extraction for:
  - `CallFact`
  - `RouteBindingFact`
  - `AppBindingFact`
  - `ConfigReadFact`
  - caller-enriched `DataAccessFact`
  - `FileRoleFact`
- ensure per-fact provenance and stable IDs
- record partial extraction and analyzer degradation in a way rule policy can consume directly
- verify that JS/TS and Python analyzers meet the current precision-upgrade design intent, not just Go

### Target Modules

- `internal/analyzers/go/*`
- `internal/analyzers/js/*`
- `internal/analyzers/jsts/*`
- `internal/analyzers/python/*`
- `internal/facts/*`

### Exit Criteria

- migrated rule families have the proof facts they need
- degraded extraction is explicit and testable

## 8. Phase 4: Rule Family Migration

### Objective

Replace broad heuristic rules with narrower proof-capable claim slices.

### Work Items

- audit existing rules and classify them into:
  - proof-capable now
  - proof-capable after analyzer upgrade
  - structural-only
  - runtime-or-human-only
- split broad rules into smaller rule families
- preserve audit mapping from historical rule IDs to new claim families where necessary
- update matcher logic to use fact quality, completeness, and binding facts rather than names or file paths where possible

### Mandatory First-Wave Rule Families

1. auth and route protection
2. config and secret sourcing
3. direct DB access and layering
4. hardcoded secret detection
5. test presence on scoped modules

### Target Modules

- `internal/rules/*`
- `rules.yaml`
- `internal/engine/*`
- benchmark fixtures under `testdata/benchmark/*`

### Exit Criteria

- first-wave rule families can emit proof-grade, structural, or unknown outcomes deterministically
- heuristic-only historical finding semantics are no longer presented as equivalent to proof

## 9. Phase 5: Claim Verification Class Integration

### Objective

Push rule and evidence outcomes into claim records that downstream scenario projections can consume safely.

### Work Items

- extend claim generation to compute `verification_class`
- derive claim support level without upgrading underlying fact quality
- propagate contradiction evidence and completeness reasons
- ensure claim reasoning explains why a claim is proof-grade versus structural versus runtime-required

### Target Modules

- `internal/claims/*`
- `internal/artifactsv2/claims_profile_resume.go`
- `internal/artifactsv2/types.go`

### Exit Criteria

- claim artifacts can distinguish proof-grade from structural and advisory claims
- hiring, outsource, and PM projections can rely on the same canonical claim set

## 10. Phase 6: Scenario Projection Outputs

### Objective

Add scenario-aware projection artifacts without changing the underlying truth model.

### Work Items

- harden hiring profile projection:
  - exclude heuristic-only top highlights
  - restrict default resume inputs to allowed claim classes
  - expose verification class per projected highlight
- implement `outsource_acceptance.json`
  - requirement rows
  - pass/fail/unknown states
  - blocking reasons
  - evidence references
- implement `pm_acceptance.json`
  - engineering acceptance rows
  - runtime-required or unknown distinction
  - requirement-to-evidence traceability

### Suggested Output Shape for `outsource_acceptance.json`

- `schema_version`
- `repository`
- `acceptance_profile`
- `requirements[]`
  - `requirement_id`
  - `title`
  - `status`: `passed | failed | unknown | runtime_required`
  - `verification_class`
  - `trust_class`
  - `supporting_evidence_ids`
  - `contradictory_evidence_ids`
  - `reason`
- `summary`

### Suggested Output Shape for `pm_acceptance.json`

- `schema_version`
- `repository`
- `acceptance_profile`
- `engineering_requirements[]`
  - `requirement_id`
  - `title`
  - `status`
  - `verification_class`
  - `delivery_scope`: `implemented | partial | blocked | unknown`
  - `supporting_evidence_ids`
  - `reason`
- `summary`

### Target Modules

- `internal/artifactsv2/*`
- `pkg/cve/api.go`
- `pkg/cve/schema.go`

### Exit Criteria

- three scenario projections can be generated from one canonical claim and evidence set
- scenario projection never upgrades trust

## 11. Phase 7: Fixture Corpus and Benchmark Expansion

### Objective

Create the benchmark and fixture coverage required to justify proof-grade expansion.

### Work Items

- add fixture sets for all three scenarios
- add true-positive, true-negative, and false-positive-guard fixtures for each first-wave rule family
- add contradiction fixtures
- add incomplete-boundary fixtures
- add partial-analyzer fixtures
- add hiring overclaim fixtures proving heuristic-only claims are filtered out

### Mandatory Fixture Classes

1. hiring proof-safe resume claim fixture
2. hiring overclaim downgrade fixture
3. outsource contract pass fixture
4. outsource contract unknown fixture due to incomplete completeness
5. outsource contract fail fixture
6. PM engineering-implemented fixture
7. PM runtime-required fixture
8. contradiction fixture where docs and code disagree
9. partial-analyzer fixture
10. unsupported-language or unsupported-framework fixture

### Exit Criteria

- benchmark corpus is sufficient to justify proof-grade labels on the migrated rule families

## 12. Phase 8: Release Gate and Migration Completion

### Objective

Make the new proof-grade scenario path release-blocking where appropriate.

### Work Items

- extend release gate with:
  - fact quality enforcement checks
  - scenario projection integrity checks
  - negative-proof completeness checks
  - hiring resume-safety checks
- add migration summary to trace output
- document historical rule-to-new-claim mappings

### Exit Criteria

- the local release gate fails if scenario projections violate trust boundaries
- migrated rule families are observable through trace and trace outputs

## 13. Recommended File-Level Work Breakdown

### 13.1 Contracts and Schemas

- update:
  - `docs/contracts/multisource-claims-profile-resume-contract.md`
  - `docs/contracts/trace-json-contract.md`
  - `pkg/cve/schema.go`

- add:
  - `docs/contracts/outsource-acceptance-json-contract.md`
  - `docs/contracts/pm-acceptance-json-contract.md`

### 13.2 Rule Metadata and Matchers

- update:
  - `rules.yaml`
  - `internal/rules/matchers.go`
  - rule-family-specific matcher files

### 13.3 Artifact Builders

- update:
  - `internal/artifactsv2/types.go`
  - `internal/artifactsv2/claims_profile_resume.go`
  - `internal/artifactsv2/trace*`
  - `internal/artifactsv2/write.go`

- add:
  - acceptance projection builders under `internal/artifactsv2/`

### 13.4 Public API

- update:
  - `pkg/cve/api.go`
  - `pkg/cve/schema.go`

## 14. Scenario-Specific Implementation Rules

### 14.1 Hiring

Implementation rules:

- resume-safe projection may include only `proof_grade` and explicitly allowed `structural_inference` claims
- structural claims included in profile output must be labeled as such
- `resume_input.json` must not contain heuristic-only verified claims
- contradiction references must remain available to downstream synthesis

### 14.2 Outsource Acceptance

Implementation rules:

- proof-grade checks may drive `passed` and `failed`
- proof-grade negative passes require completeness proof
- structural or heuristic outputs may only drive advisory notes or `unknown`
- each acceptance row must resolve to evidence IDs

### 14.3 PM Acceptance

Implementation rules:

- output must be named and described as engineering acceptance
- product, business, or runtime acceptance must map to `runtime_required` or `unknown` unless a future runtime evidence subsystem exists
- wiring-complete and policy-complete checks may be proof-grade if fact prerequisites are met

## 15. Testing Strategy

### 15.1 Unit Coverage

Required:

- rule metadata enforcement helpers
- proof downgrade helpers
- scenario applicability filters
- projection policy filters
- completeness gating
- acceptance summary computation

### 15.2 Integration Coverage

Required:

- end-to-end proof-grade hiring projection
- end-to-end outsource acceptance with mixed pass/fail/unknown
- end-to-end PM acceptance with runtime-required rows
- contradiction retention through scenario outputs

### 15.3 Contract Coverage

Required:

- `claims.json`
- `profile.json`
- `resume_input.json`
- `outsource_acceptance.json`
- `pm_acceptance.json`

### 15.4 Regression Coverage

Required:

- existing canonical outputs remain coherent
- heuristic-only findings do not regress into stronger classes accidentally

## 16. Migration Rules for Claude Code

Claude Code should follow these sequencing constraints:

1. implement contracts first
2. add failing tests before broad matcher changes
3. migrate first-wave rule families one family at a time
4. keep old trace outputs until new artifacts are stable
5. do not mark proof-grade on any rule family until benchmark fixtures are green
6. prefer explicit downgrade to `unknown` over fallback heuristics

## 17. Definition of Implementation Completion

This work is complete only when:

1. proof-grade claim semantics are explicit in artifacts
2. first-wave rule families are migrated and benchmarked
3. hiring outputs are resume-safe by contract
4. outsource and PM acceptance artifacts exist and are machine-readable
5. release gate checks enforce the new trust boundaries
6. existing evidence-first guarantees remain intact
