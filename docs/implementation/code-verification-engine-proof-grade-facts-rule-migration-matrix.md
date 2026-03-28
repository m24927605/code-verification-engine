# Code Verification Engine Proof-Grade Facts Rule Migration Matrix

## 1. Purpose

This document maps current or near-term rule families into their target proof-grade migration state.

It exists to remove ambiguity for implementation work. Claude Code should use this matrix as the authoritative migration guide when deciding:

- which rule families are eligible for proof-grade migration now
- which rule families must remain structural or heuristic
- which new claim slices replace current broad rules
- which fixtures and benchmark cases are mandatory before enabling proof-grade outputs

## 2. Migration Classes

The following migration classes are used in this matrix:

- `proof_now`
  - can be upgraded in the current architecture with existing or near-complete fact support
- `proof_after_fact_upgrade`
  - target is proof-grade, but required analyzer or fact work is not yet complete
- `structural_only`
  - may produce strong structural inference but should not be labeled proof-grade
- `runtime_or_human_only`
  - must not be statically upgraded to proof-grade in the current product scope

## 3. Rule Family Columns

Each row below defines:

- historical rule or target
- target claim family
- migration class
- decisive proof facts
- allowed fallback class
- scenario applicability
- required benchmark fixtures

## 4. First-Wave Migration Matrix

| Legacy ID / Target | Target Claim Family | Migration Class | Decisive Proof Facts | Allowed Fallback | Scenario Applicability | Required Fixtures |
|---|---|---|---|---|---|---|
| `AUTH-001` / `auth.jwt_middleware` | `security.auth_middleware_artifact_exists` | `structural_only` | middleware symbol extraction, import resolution | `heuristic_advisory` | hiring, outsource_acceptance, pm_acceptance | pass, false-positive-guard |
| `AUTH-002` / `route.protected_uses_auth_middleware` | `security.route_auth_binding` | `proof_after_fact_upgrade` | `RouteBindingFact`, `AppBindingFact`, protected-route classification, boundary completeness | `structural_inference` | hiring, outsource_acceptance, pm_acceptance | pass, fail, unknown-incomplete, false-positive-guard |
| `SEC-001` / `secret.hardcoded_credential` fail path | `security.hardcoded_secret_present` | `proof_now` | secret literal fact with replayable span | `structural_inference` only when parser degraded | outsource_acceptance, pm_acceptance | fail, false-positive-guard, parser-degraded |
| `SEC-001` / `secret.hardcoded_credential` pass path | `security.hardcoded_secret_absent` | `proof_after_fact_upgrade` | exhaustive search completeness, analyzer success, scan boundary completeness | `unknown` | outsource_acceptance, pm_acceptance | pass-complete, unknown-incomplete, unsupported-language |
| `ARCH-001` / `db.direct_access_from_controller` fail path | `architecture.controller_direct_db_access_present` | `proof_after_fact_upgrade` | caller-enriched `DataAccessFact`, `FileRoleFact`, call path evidence | `structural_inference` | hiring, outsource_acceptance, pm_acceptance | fail, false-positive-guard |
| `ARCH-001` / `db.direct_access_from_controller` pass path | `architecture.controller_direct_db_access_absent` | `proof_after_fact_upgrade` | exhaustive search completeness, `FileRoleFact`, caller-enriched `DataAccessFact` | `unknown` | outsource_acceptance, pm_acceptance | pass-complete, unknown-incomplete |
| `TEST-001` / `module.auth_service` | `testing.auth_module_tests_present` | `proof_now` | normalized test fact linked to scoped module | `structural_inference` when module-role detection is weak | hiring, outsource_acceptance, pm_acceptance | pass, fail, false-positive-guard |
| `config.env_read_call_exists` future split | `config.env_read_call_exists` | `proof_after_fact_upgrade` | `ConfigReadFact` | `structural_inference` | hiring, outsource_acceptance, pm_acceptance | pass, fail, unsupported-framework |
| `config.secret_key_sourced_from_env` future split | `config.secret_key_sourced_from_env` | `proof_after_fact_upgrade` | `ConfigReadFact`, symbol binding, literal-assignment exclusion | `structural_inference` | hiring, outsource_acceptance, pm_acceptance | pass, fail, partial-binding |
| `config.secret_key_not_literal` future split | `config.secret_key_not_literal` | `proof_after_fact_upgrade` | `ConfigReadFact`, `LiteralAssignmentFact` | `unknown` | outsource_acceptance, pm_acceptance | pass-complete, fail, unknown-incomplete |

## 5. Scenario Handling Rules per Migration Class

### 5.1 `proof_now`

Implementation rule:

- may emit `verification_class=proof_grade` once fixtures and benchmark gates are green

### 5.2 `proof_after_fact_upgrade`

Implementation rule:

- must not emit `proof_grade` until required decisive proof facts are fully available and acceptance fixtures are green

### 5.3 `structural_only`

Implementation rule:

- may emit `structural_inference`
- must not be relabeled as proof-grade in any scenario projection

### 5.4 `runtime_or_human_only`

Implementation rule:

- must emit `human_or_runtime_required`
- may appear as explanatory scope rows but not as proof-grade acceptance rows

## 6. Legacy Rule Splitting Map

### 6.1 `AUTH-001`

Current meaning is too broad.

Split into:

- `security.auth_middleware_artifact_exists`
- `security.route_auth_binding`
- `security.token_validation_call_exists`

Policy:

- artifact existence alone is not proof of route protection

### 6.2 `AUTH-002`

Current meaning is the real high-value engineering rule.

Target:

- make this the primary proof-grade auth acceptance rule once route binding facts are complete

### 6.3 `SEC-001`

Current negative rule should become two claims:

- `security.hardcoded_secret_present`
- `security.hardcoded_secret_absent`

Policy:

- fail path can be proof-grade earlier than pass path

### 6.4 `ARCH-001`

Current negative architecture rule should become:

- `architecture.controller_direct_db_access_present`
- `architecture.controller_direct_db_access_absent`
- optional supporting structural claim:
  - `architecture.service_repository_layering_present`

Policy:

- architecture-negative fail path is easier to justify than a strong absence pass

### 6.5 `TEST-001`

Current rule should become:

- `testing.auth_module_tests_present`
- optional future refinement:
  - `testing.auth_module_coverage_target_present`

Policy:

- existence of relevant tests is proofable
- adequacy of test quality is not yet proof-grade

## 7. Current Non-Migratable or Deferred Families

The following families must not be upgraded to proof-grade in the current scope:

- team ownership or authorship claims
- business impact claims
- production reliability claims
- deployment correctness claims without runtime evidence
- broad engineering maturity summaries without concrete proof facts

These map to:

- `runtime_or_human_only`
- or, if useful, `structural_only`

## 8. Benchmark Requirements per Family

Before a family can emit `proof_grade`, the following benchmark classes must exist:

1. true-positive pass or fail case
2. true-negative or opposite-outcome case
3. false-positive-guard case
4. incomplete-boundary or degraded-analyzer case where applicable
5. unsupported-language or unsupported-framework case where applicable

## 9. Claude Code Implementation Rules

Claude Code should apply this matrix as follows:

1. do not upgrade a family to proof-grade unless this matrix says `proof_now` or the prerequisite fact upgrade has been completed and corresponding tests are green
2. if a rule family is ambiguous, prefer splitting into narrower claims over keeping a broad heuristic rule
3. when migrating a negative rule, implement fail-path correctness before strong absence-pass correctness
4. preserve audit mapping from historical rule ID to new claim family in trace or migration metadata

## 10. Definition of Migration Readiness

A rule family is ready for proof-grade enablement only when:

1. decisive proof facts exist and are stable
2. minimum quality requirements are enforced in matcher policy
3. benchmark fixtures for that family are green
4. scenario projections do not upgrade weaker fallback classes
