# Code Verification Engine Proof-Grade Facts Execution Checklist

## 1. Purpose

This document is the implementation execution checklist for Claude Code.

It translates the architecture, contracts, migration matrix, and acceptance specs into a concrete execution order with explicit stop conditions.

Claude Code should treat this checklist as the default implementation sequence unless repository realities require a narrowly justified deviation.

## 2. Execution Rules

Claude Code must follow these rules throughout implementation:

1. do not start broad matcher rewrites before contracts and schemas are in place
2. do not mark any rule family as `proof_grade` until the required fixtures for that family are green
3. prefer downgrade to `unknown` over fallback heuristic overclaim
4. preserve current outputs unless a contract change explicitly requires a new field or artifact
5. make changes in small, reviewable slices and keep tests green after each slice
6. do not silently merge `structural_inference` into proof-grade scenario outputs

## 3. Pre-Flight Checks

Before editing code, Claude Code should:

1. read:
   - `docs/architecture/code-verification-engine-proof-grade-facts-scenario-architecture.md`
   - `docs/implementation/code-verification-engine-proof-grade-facts-scenario-implementation-plan.md`
   - `docs/implementation/code-verification-engine-proof-grade-facts-rule-migration-matrix.md`
   - `docs/contracts/outsource-acceptance-json-contract.md`
   - `docs/contracts/pm-acceptance-json-contract.md`
   - `docs/acceptance/code-verification-engine-proof-grade-facts-scenario-acceptance-spec.md`
   - `docs/acceptance/code-verification-engine-proof-grade-facts-fixture-spec.md`
2. inspect current schema and artifact builder code:
   - `pkg/cve/schema.go`
   - `internal/artifactsv2/types.go`
   - `internal/artifactsv2/claims_profile_resume.go`
   - `internal/artifactsv2/write.go`
   - `internal/artifactsv2/trace*`
3. inspect current rule metadata and matcher code:
   - `rules.yaml`
   - `internal/rules/*`
4. inspect current analyzer fact support:
   - `internal/facts/*`
   - `internal/analyzers/go/*`
   - `internal/analyzers/js/*`
   - `internal/analyzers/jsts/*`
   - `internal/analyzers/python/*`

Stop condition:

- Claude Code can name the exact structs, builders, and matchers that will be changed in phase 1 and phase 2

## 4. Phase 1: Add Artifact Schema Types

### Goal

Introduce new public and internal types without changing rule behavior yet.

### Required Work

1. add or extend internal artifact types for:
   - claim `verification_class`
   - claim `scenario_applicability`
   - claim `projection_policies`
   - `outsource_acceptance.json`
   - `pm_acceptance.json`
2. update public API schema types in `pkg/cve/schema.go`
3. add validation helpers for the new artifact types

### Suggested Files

- `internal/artifactsv2/types.go`
- `internal/artifactsv2/validate.go`
- `pkg/cve/schema.go`

### Tests Required

- schema validation unit tests
- JSON serialization or bridge tests for new output types

### Stop Condition

- code compiles
- new types exist
- validation tests for the new artifacts are green
- no scenario artifact is written yet

## 5. Phase 2: Add Builder Skeletons for Scenario Artifacts

### Goal

Add artifact builders and writer plumbing while returning empty or placeholder-safe outputs derived from existing claims.

### Required Work

1. add builder skeletons for:
   - outsource acceptance artifact
   - PM acceptance artifact
2. wire artifact writing into the canonical artifact path
3. extend trace generation with projection metadata if required
4. keep all row derivation conservative while rule migration is incomplete

### Suggested Files

- `internal/artifactsv2/builder.go`
- `internal/artifactsv2/write.go`
- new scenario-specific builder files under `internal/artifactsv2/`
- trace builder files under `internal/artifactsv2/`

### Tests Required

- artifact write tests
- contract-shape tests
- empty-state or minimal-state scenario artifact tests

### Stop Condition

- scenario artifacts can be emitted in valid empty or low-information form
- no contract fields are missing
- existing artifact generation remains green

## 6. Phase 3: Add Claim Metadata Plumbing

### Goal

Ensure claim records can carry the metadata needed by scenario builders.

### Required Work

1. add `verification_class` derivation
2. add `scenario_applicability`
3. add claim-level projection policy metadata
4. preserve contradiction and completeness reasoning in claim records

### Suggested Files

- `internal/claims/*`
- `internal/artifactsv2/claims_profile_resume.go`
- `internal/artifactsv2/types.go`

### Tests Required

- claim derivation unit tests
- claim projection integrity tests
- contradiction propagation tests

### Stop Condition

- `claims.json` can express the new metadata deterministically
- builders can consume claim metadata without ad hoc inference

## 7. Phase 4: Add Rule Metadata Enforcement

### Goal

Make proof eligibility machine-enforceable before changing specific rule families.

### Required Work

1. extend rule metadata model to include:
   - minimum fact quality for proof-grade
   - minimum fact quality for structural inference
   - exhaustive-negative flag
   - scenario applicability
   - acceptance intent
2. add shared downgrade helpers
3. update matcher plumbing so rule outputs are checked against metadata before projection

### Suggested Files

- `rules.yaml`
- `internal/rules/*`
- `internal/report/*`
- `internal/artifactsv2/confidence.go`

### Tests Required

- metadata parsing tests
- downgrade logic tests
- negative completeness gating tests

### Stop Condition

- a matcher cannot emit proof-grade classification unless metadata and prerequisites allow it

## 8. Phase 5: Verify Fact Supply for First-Wave Families

### Goal

Confirm analyzer and fact readiness before migrating each first-wave family.

### Required Work

For each family in the migration matrix:

1. inspect whether decisive facts already exist
2. if missing, implement or harden the required fact extraction
3. add or update analyzer tests proving:
   - success path
   - degraded path
   - unsupported path where relevant

### Priority Order

1. `security.hardcoded_secret_present`
2. `testing.auth_module_tests_present`
3. `security.route_auth_binding`
4. `architecture.controller_direct_db_access_present`
5. config-related families

### Suggested Files

- `internal/facts/*`
- analyzer packages under `internal/analyzers/*`

### Tests Required

- analyzer fact extraction tests
- fact-quality tests
- degradation-path tests

### Stop Condition

- decisive proof facts for the target family are available and tested before matcher migration begins

## 9. Phase 6: Build Fixture Repositories Before Rule Migration

### Goal

Create the fixture corpus needed to safely migrate rule families.

### Required Work

1. create acceptance scenario fixtures under the layout defined in the fixture spec
2. create benchmark fixtures for first-wave rule families
3. create false-positive-guard fixtures
4. create incomplete-boundary and degraded-analyzer fixtures

### Suggested Files

- `testdata/acceptance/proof_grade_scenarios/*`
- `testdata/benchmark/proof-grade/*`

### Tests Required

- fixture loader or integration harness tests
- baseline golden generation only after artifact outputs stabilize

### Stop Condition

- all mandatory fixture directories exist
- fixture repos are minimal and deterministic

## 10. Phase 7: Migrate `SEC-001` Fail Path First

### Goal

Deliver the first proof-grade family using the lowest-risk path.

### Required Work

1. split secret-present versus secret-absent claims
2. implement proof-grade fail path for hardcoded secret presence
3. keep pass path conservative until completeness logic is ready
4. project this family into outsource and PM artifacts

### Why First

- violating evidence is easier to justify than absence proof
- existing facts and benchmarks are already closest to proof readiness

### Tests Required

- fail-path unit tests
- outsource fail fixture
- PM blocked fixture if applicable
- false-positive-guard fixture

### Stop Condition

- secret-presence fail path emits proof-grade where supported
- no strong absence pass has been enabled yet

## 11. Phase 8: Migrate `TEST-001`

### Goal

Enable proof-grade module test-presence claims.

### Required Work

1. split current test rule into explicit claim family
2. enforce module scoping and module-role detection quality
3. wire hiring projection to allow this claim when policy permits

### Tests Required

- pass and fail fixture tests
- hiring proof-backed claim fixture assertions

### Stop Condition

- test-presence claims can appear as proof-backed hiring-safe support

## 12. Phase 9: Migrate `AUTH-002`

### Goal

Upgrade route-auth binding into the primary proof-grade auth acceptance family.

### Required Work

1. confirm `RouteBindingFact` and `AppBindingFact` readiness
2. split artifact-existence from binding proof
3. implement proof-grade binding checks
4. downgrade to structural or unknown when bindings are incomplete or framework support is missing

### Tests Required

- pass fixture
- fail fixture
- unknown-incomplete fixture
- unsupported-framework fixture

### Stop Condition

- route-auth binding can produce proof-grade acceptance rows where facts are complete
- auth artifact existence no longer masquerades as proof of protection

## 13. Phase 10: Migrate `ARCH-001`

### Goal

Upgrade direct controller DB access fail detection first, then absence logic only after completeness support is solid.

### Required Work

1. split present versus absent claims
2. implement fail-path correctness using `FileRoleFact` and caller-enriched `DataAccessFact`
3. add strong absence logic only when completeness gating is implemented

### Tests Required

- fail fixture
- false-positive-guard fixture
- unknown-incomplete fixture for absence path

### Stop Condition

- present-path detection is correct and stable
- absence path is still conservative unless exhaustive conditions are met

## 14. Phase 11: Add Config Claim Families

### Goal

Introduce config proof families only after fact support is stable.

### Required Work

1. add `ConfigReadFact` and related symbol/literal linkage if incomplete
2. implement:
   - `config.env_read_call_exists`
   - `config.secret_key_sourced_from_env`
   - `config.secret_key_not_literal`
3. apply strong downgrade behavior on partial binding

### Tests Required

- pass fixture
- fail fixture
- partial-binding fixture
- unsupported-framework fixture

### Stop Condition

- config claim families produce deterministic outputs with correct downgrade behavior

## 15. Phase 12: Harden Hiring Projection

### Goal

Make hiring outputs strictly resume-safe.

### Required Work

1. filter out heuristic-only highlights
2. restrict default `resume_input.json` claim inclusion to allowed classes
3. preserve contradiction references for synthesis constraints
4. expose verification class in profile projection where appropriate

### Suggested Files

- `internal/artifactsv2/claims_profile_resume.go`
- related validation and tests

### Tests Required

- hiring proof-backed fixture
- hiring overclaim downgrade fixture
- contradiction fixture

### Stop Condition

- no README-only or heuristic-only overclaim can enter default verified resume inputs

## 16. Phase 13: Harden Outsource and PM Projections

### Goal

Make scenario outputs fully compliant with their new contracts.

### Required Work

1. populate summary counters correctly
2. enforce machine-safe pass semantics only for proof-grade rows
3. ensure PM wording and semantics stay within engineering scope
4. surface `unknown_reasons` and `follow_up_action` where required

### Tests Required

- contract tests for both artifacts
- summary reconciliation tests
- scope wording or semantics tests for PM outputs

### Stop Condition

- scenario artifacts are fully traceable and semantically compliant

## 17. Phase 14: Add Release-Gate Coverage

### Goal

Make the new trust boundaries enforceable in CI and local release checks.

### Required Work

1. extend release gate checks for:
   - proof-grade contract validity
   - scenario summary reconciliation
   - negative completeness gating
   - hiring resume-safety constraints
   - claim and evidence reference integrity
2. ensure reproducibility checks cover the new artifacts

### Suggested Files

- `internal/releasegate/*`
- release-gate documentation and tests

### Tests Required

- release gate unit tests
- end-to-end local release gate tests if present in this repo

### Stop Condition

- release gate fails on trust-boundary violations in new artifacts

## 18. Phase 15: Backfill Compatibility and Trace Metadata

### Goal

Document and expose the migration relationship between old rule IDs and new claim families.

### Required Work

1. add migration metadata to trace or verifiable artifacts
2. preserve historical identifiers where useful for audits
3. update docs if any contract names or enum values shifted during implementation

### Tests Required

- trace reference integrity tests
- bridge-removal regression tests if applicable

### Stop Condition

- migration is explainable and auditable from artifact outputs

## 19. Final Verification Checklist

Claude Code should not declare completion until all of the following are true:

1. all new contracts are implemented in code
2. first-wave rule families are migrated according to the migration matrix
3. all mandatory fixture classes exist
4. all scenario artifacts are generated and validated
5. hiring outputs are resume-safe
6. outsource outputs do not overclaim contractual pass
7. PM outputs do not overclaim product acceptance
8. release gate checks are green
9. reproducibility and reference integrity tests are green

## 20. Anti-Patterns to Avoid

Claude Code must avoid:

- enabling proof-grade labels before fact support is complete
- using file-name or path heuristics as hidden proof substitutes
- implementing strong absence passes before completeness gating exists
- merging scenario policy logic directly into analyzers
- emitting scenario artifacts that are not traceable back to claims and evidence
- treating README text as verified implementation evidence
