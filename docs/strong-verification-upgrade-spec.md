# Strong Verification Upgrade Spec

## Purpose

Provide one execution-oriented specification that Claude Code can follow to upgrade `code-verification-engine` toward a stronger verification engine.

This document intentionally excludes the scan-boundary bug fix covered in:

- `docs/repo-scan-boundary-fix.md`

This spec covers the remaining major problems:

- heuristic-heavy rule semantics
- insufficient proof-grade facts
- weak trust/verification enforcement
- incomplete negative-rule pass semantics
- limited benchmark and calibration coverage
- report contract gaps that hide why a verdict is strong or weak

## Operating Rule

Claude Code should treat this document as an implementation spec, not a brainstorming note.

Expected behavior:

1. Make changes in small, testable phases.
2. Preserve existing working behavior unless the spec explicitly requires stricter downgrade.
3. Prefer tightening trust claims over adding new rules.
4. Do not attempt to solve scan-boundary issues in this workstream.
5. Stop if a phase reveals that a prerequisite is missing and update the spec or tests accordingly.

## Non-Goals

This upgrade does not include:

- scan-boundary fixes
- whole-program theorem proving
- runtime/deployment verification
- LLM-based trust promotion
- new product surfaces beyond current CLI/report contracts unless required by this spec

## Current Problems To Solve

### Problem 1: Too many findings are based on artifact existence

Examples:

- package import exists
- symbol name looks relevant
- middleware-like name exists somewhere

This is useful for advisory signal, but not for verification.

### Problem 2: The engine lacks enough proof-grade facts

Current analyzers emit:

- files
- imports
- symbols
- routes
- middleware
- tests
- data access
- secrets

But stronger verification needs:

- caller-to-callee facts
- route-to-middleware binding facts
- app/global middleware binding facts
- config-read source facts
- file-role facts

### Problem 3: Trust policy is not enforced strongly enough by matcher class

The system has `verification_level` and `trust_class`, but the codebase still allows too much rule ambiguity.

### Problem 4: Negative-rule `pass` can overstate certainty

A missing violation is not proof unless the search space is exhaustive enough for that rule.

### Problem 5: Benchmarks are too small for trusted expansion

Current benchmark coverage is useful, but not enough to justify many more machine-trusted findings.

## Target State

At the end of this upgrade:

- advisory findings remain useful but are less over-claimed
- machine-trusted findings are fewer, narrower, and more defensible
- rule contracts explain which facts and fact quality are required
- analyzers emit enough new facts to support stronger matcher semantics
- reports expose why a verdict is trusted or downgraded
- benchmark/autocal gates prevent accidental trust inflation

## Mandatory Deliverables

Claude Code should produce these outputs across the implementation:

1. Code changes in analyzers, rules, engine, report, and tests.
2. Updated capability and trust enforcement.
3. Expanded benchmark/autocal fixtures.
4. Updated documentation where runtime behavior changes.

## Phase Plan

### Phase 1: Trust Hardening

#### Goal

Prevent over-claiming without requiring major analyzer expansion first.

#### Required changes

1. Introduce explicit matcher classes:
   - `proof_matcher`
   - `structural_matcher`
   - `heuristic_matcher`
   - `attestation_matcher`
2. Enforce verification ceilings:
   - `proof_matcher` may emit `verified`
   - `structural_matcher` may emit at most `strong_inference`
   - `heuristic_matcher` may emit at most `strong_inference`
   - `attestation_matcher` should remain `unknown` without external evidence
3. Add rule metadata fields:
   - `matcher_class`
   - `required_fact_types`
   - `minimum_fact_quality`
   - `trusted_pass_allowed`
   - `trusted_fail_allowed`
4. Tighten trust normalization so any mismatch between matcher class and verification level is downgraded automatically.

#### Acceptance criteria

- No advisory or heuristic finding can survive as `verified`.
- Existing tests still pass after expected trust-level downgrades are updated.
- New tests cover downgrade behavior for every matcher class.

### Phase 2: Fact Quality Model

#### Goal

Make fact provenance materially affect trust and matcher eligibility.

#### Required changes

1. Add fact quality classes:
   - `proof`
   - `structural`
   - `heuristic`
2. Map current extraction paths to quality:
   - AST/native parser fact -> `proof`
   - structurally parsed or filtered fact -> `structural`
   - regex/raw pattern-only fact -> `heuristic`
3. Ensure matchers can inspect minimum acceptable fact quality before producing a trusted verdict.

#### Acceptance criteria

- Facts carry machine-usable quality metadata.
- Rule evaluation can reject low-quality facts for strong verdicts.
- Tests demonstrate that the same logical finding downgrades when only heuristic facts are available.

### Phase 3: Add Missing Proof-Grade Facts

#### Goal

Support stronger rule semantics with new extracted facts.

#### Required fact types

1. `CallFact`
   - caller symbol
   - callee target
   - file/span
2. `RouteBindingFact`
   - route handler
   - middleware/guard/interceptor chain
   - scope
3. `AppBindingFact`
   - app/global middleware or guard registration
4. `ConfigReadFact`
   - config key
   - source kind: env/file/default/literal/unknown
5. `LiteralAssignmentFact`
   - symbol
   - literal class
6. `FileRoleFact`
   - controller/service/repository/middleware/test/config

#### Language priorities

1. Go first
2. TypeScript / JavaScript second
3. Python third

Reason:

- Go already has the strongest AST base.
- TS/JS has the highest benefit from moving away from regex-heavy semantics.
- Python AST path exists but needs narrower framework-focused upgrades.

#### Acceptance criteria

- At least one production rule family is upgraded to use each new fact type where relevant.
- New fact extraction has unit tests and cross-language fixtures.
- Capability matrix reflects the new fact availability conservatively.

### Phase 4: Replace Artifact Rules with Binding-Oriented Semantics

#### Goal

Move important checks from "something relevant exists" to "the enforcement/binding relation exists".

#### Required changes

1. Split broad existence targets logically in matcher behavior, even if DSL changes are deferred.
2. Upgrade key rule families:
   - auth
   - route protection
   - config/env sourcing
   - direct controller DB access
3. Keep artifact-only checks advisory.
4. Reserve trusted promotion for binding or call-backed checks.

#### Initial target families

1. `auth.jwt_middleware`
   - artifact presence remains advisory
   - bound auth protection becomes stronger
2. `route.protected_uses_auth_middleware`
   - require binding facts
   - downgrade to `unknown` if binding is incomplete
3. `secret` and `config` rules
   - distinguish env-based reads from imports or config-library presence
4. architecture rules
   - use caller + role + data-access facts rather than name/path heuristics only

#### Acceptance criteria

- Auth and route-protection rules no longer rely only on symbol/import presence for their strongest verdicts.
- Config-related checks distinguish actual config source from package presence.
- Architecture checks are tied to caller context and file roles where available.

### Phase 5: Coverage-Aware Negative Rules

#### Goal

Stop overstating `pass` on `not_exists` rules.

#### Required changes

1. Add rule-level pass trust gates:
   - relevant analyzers succeeded
   - no blocking skipped files in the search space
   - search procedure is exhaustive enough for that rule/language
2. If any gate fails:
   - downgrade `pass` from `verified` to `strong_inference` or `unknown`
3. Keep `fail` trusted when direct violating evidence exists.

#### Candidate rule families

- hardcoded secrets
- direct DB access from controller
- frontend dangerous sink rules
- frontend token/localStorage rules

#### Acceptance criteria

- `fail` and `pass` semantics are tested separately for each negative-rule family.
- Negative-rule `pass` no longer becomes trusted simply because no evidence was found.

### Phase 6: Report Contract Upgrade

#### Goal

Expose why the engine trusts or distrusts a verdict.

#### Required report additions

Per finding:

- `verdict_basis`
  - `proof`
  - `structural_binding`
  - `heuristic_inference`
  - `runtime_required`
- `fact_quality_floor`
- `matcher_class`

Report summary:

- trusted summary
- advisory summary
- unknown summary
- fact quality summary

#### Acceptance criteria

- JSON report includes the new fields.
- Existing consumers are updated or output continuity is preserved.
- Tests assert these fields are populated correctly.

### Phase 7: Benchmark And Calibration Expansion

#### Goal

Prevent future trust inflation without evidence.

#### Required changes

1. Expand fixtures for trusted and near-trusted rules.
2. Add false-positive guards per upgraded rule family.
3. Add fixtures for degraded fact quality and partial extraction.
4. Tighten autocal gate policy:
   - no increase in machine-trusted findings without new expected fixtures
   - no verified findings backed only by heuristic facts
   - no trusted promotion on incomplete rule search space

#### Acceptance criteria

- New benchmark cases exist for upgraded rule families.
- Autocal blocks ungrounded trusted expansion.
- Fixture contracts are frozen after promotion.

## Implementation Order

Claude Code should follow this order:

1. Phase 1: trust hardening
2. Phase 2: fact quality model
3. Phase 5: coverage-aware negative rules
4. Phase 3: new fact types
5. Phase 4: binding-oriented rule upgrades
6. Phase 6: report contract
7. Phase 7: benchmark/autocal expansion

Rationale:

- first reduce over-claiming
- then make the engine capable of stronger claims
- then expand trust only where evidence supports it

## Required File Areas

Likely touch points:

- `internal/rules/*`
- `internal/facts/*`
- `internal/analyzers/go/*`
- `internal/analyzers/ts/*`
- `internal/analyzers/js/*`
- `internal/analyzers/python/*`
- `internal/engine/*`
- `internal/report/*`
- `internal/autobench/*`
- `testdata/benchmark/*`
- `testdata/autobench/*`

## Required Test Strategy

For each major phase, Claude Code should add:

1. unit tests
2. integration tests
3. at least one fixture-driven regression test

Specific test expectations:

- matcher class downgrade tests
- fact quality downgrade tests
- negative-rule pass/fail asymmetry tests
- route-binding completeness tests
- config-source proof tests
- benchmark fixtures for upgraded trusted claims

## Stop Conditions

Claude Code should stop and report if any of the following happen:

1. A planned trusted upgrade still depends only on naming/import heuristics.
2. A new fact type cannot be extracted with bounded complexity in the current analyzer architecture.
3. Report contract changes would silently break public API consumers without a historical bridge path.
4. Benchmark additions are too weak to justify the trust upgrade.

## Definition Of Done

This upgrade is done only when all of the following are true:

1. Trust ceilings are enforced by matcher class in code.
2. Facts have quality levels that affect rule outcomes.
3. Key security and architecture rule families use proof-grade or structural-binding facts rather than artifact presence alone.
4. Negative-rule `pass` semantics are coverage-aware.
5. Reports explain the basis of trust.
6. Benchmark/autocal coverage is expanded enough to defend any new trusted verdicts.

## Practical Bottom Line

Yes, the remaining non-boundary problems can be unified into one file for Claude Code.

That file should not be a broad design essay. It should be a constrained upgrade spec with:

- explicit scope
- ordered phases
- required files
- acceptance criteria
- stop conditions

This document is that spec.
