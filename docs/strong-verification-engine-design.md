# Strong Verification Engine Design

## Goal

Define the concrete product and architecture changes required to move `code-verification-engine` from a trust-aware static rule engine into a stronger verification engine.

This document is based on the current implementation, especially:

- `internal/engine/*`
- `internal/repo/*`
- `internal/rules/*`
- `internal/analyzers/*`
- `internal/autobench/*`

The target is not "perfect proof for every claim". The target is narrower and stricter:

- only emit strong verdicts for claims whose proof surface is mechanically defined
- reduce the share of heuristic `pass`
- turn more important checks from name/import inference into binding/call/config proof
- make scan scope, evidence scope, and trust scope explicit and testable

## Current State

The engine already has several good foundations:

- isolated workspace scanning
- normalized fact extraction
- capability matrix
- `verification_level`
- `trust_class`
- `unknown_reasons`
- benchmark/autocal infrastructure

But it is still not a strong verification engine for four reasons:

1. Too many rules are still artifact-existence or naming heuristics.
2. Scan scope is not modeled explicitly enough, so coverage claims are fragile.
3. Most analyzers do not yet produce proof-grade binding and call facts.
4. The benchmark corpus is too small to justify machine-trusted expansion.

## Product Reframe

The engine should stop treating "verification" as a generic label for all findings.

It should separate outputs into three classes:

- Proof verdicts
  Meaning: mechanically justified from complete-enough source evidence.
- Structural inferences
  Meaning: strong static signal, but not proof of enforcement.
- Unverifiable claims
  Meaning: runtime, deployment, policy intent, or incomplete extraction.

This separation already exists partially via `trust_class`, but it needs to drive rule design, analyzer contracts, gating, and report UX.

## Strong Verification Definition

A finding is eligible for strong verification only if all of the following hold:

1. The scan boundary is exact and explicit.
2. The search space for the rule is exhaustively defined.
3. Required analyzers for that search space completed successfully.
4. The matcher depends on proof facts, not merely names/imports/keywords.
5. Evidence is replayable to concrete code locations.
6. The benchmark corpus contains true-positive, true-negative, and false-positive-guard cases for the rule.

If any condition fails, the finding must downgrade to `strong_inference`, `weak_inference`, or `unknown`.

## Architectural Changes

### 1. Add Scan Boundary as a First-Class Contract

Current weakness:

- the engine reasons about repo root and file set, but does not model user-requested scan scope as a typed contract

Required additions:

- `ScanBoundary`
  - `SourceRepoRoot`
  - `RequestedPath`
  - `ScanRoot`
  - `Mode`: `repo`, `subdir`, `snapshot`
  - `TrackedFiles`
  - `IncludedFiles`
  - `ExcludedFiles`
- report fields for boundary and coverage
- rule runtime access to boundary completeness

Impact:

- negative-rule `pass` can only be trusted when boundary completeness is explicit
- subdirectory scans become mechanically safe instead of accidental

### 2. Split Facts into Proof Facts and Heuristic Facts

Current weakness:

- facts from AST extraction and facts from regex/structural fallback are mixed, with provenance present but not enforced strongly enough in rule policy

Required additions:

- fact quality classes:
  - `proof`
  - `structural`
  - `heuristic`
- matcher policies that declare the minimum fact quality they accept for each verdict level

Examples:

- `hardcoded secret literal` can use proof facts for `fail`
- `service layer exists` cannot become proof from naming facts
- `route protected by auth middleware` requires binding facts, not just middleware symbol existence

### 3. Replace Artifact Rules with Binding Rules

Current weakness:

- many `exists` rules still mean "some related code exists somewhere"

Design direction:

- decompose broad targets into narrower proofable targets

Examples:

- replace `auth.jwt_middleware` with:
  - `auth.middleware_artifact_exists`
  - `auth.middleware_bound_to_protected_routes`
  - `auth.token_validation_call_reaches_handler_boundary`
- replace `security.headers_middleware exists` with:
  - `security.headers_package_present`
  - `security.headers_registration_exists`
  - `security.headers_registration_global_or_route_scoped`
- replace `env config exists` with:
  - `config.env_read_call_exists`
  - `config.secret_key_sourced_from_env`
  - `config.secret_key_not_literal`

Rule effect:

- artifact rules remain advisory
- binding and dataflow rules become candidates for strong verification

### 4. Introduce Call, Binding, and Config Facts

Current weakness:

- analyzers extract imports, symbols, routes, middleware, tests, secrets
- they do not yet consistently extract the facts needed to prove enforcement

Required new fact types:

- `CallFact`
  - caller symbol
  - callee symbol or import-qualified target
  - file/span
- `RouteBindingFact`
  - route handler
  - attached middleware/guard/interceptor chain
  - scope
- `AppBindingFact`
  - app-wide middleware/guard registration
- `ConfigReadFact`
  - config key name
  - source kind: env/file/default/literal/unknown
- `LiteralAssignmentFact`
  - target symbol
  - literal class
- `FileRoleFact`
  - controller/service/repository/middleware/test/config
  - derivation source: AST/package path/convention

These are the minimum new facts needed to upgrade rule quality.

### 5. Add Dataflow-Lite Verification

The engine does not need full symbolic execution to become materially stronger.

It needs a bounded "dataflow-lite" layer for high-value checks:

- literal to config sink
- env-read to secret/config variable
- route entrypoint to validation call
- route entrypoint to auth middleware/guard
- controller to direct DB access

Recommended constraints:

- intra-file and intra-package first
- framework-aware edges only
- explicit downgrade when graph is incomplete

This keeps complexity bounded while still moving beyond name-based inference.

### 6. Introduce Coverage-Aware Negative Rules

Current weakness:

- a `not_exists` pass may look stronger than it really is

Required policy:

- `fail` may be `verified` when violating evidence exists
- `pass` may be `verified` only when:
  - boundary completeness is true
  - relevant analyzers completed
  - skipped files do not affect the rule's search space
  - the matcher's search procedure is exhaustive for the language/framework

Examples:

- hardcoded secrets
- direct controller DB access
- frontend dangerous sinks

Without coverage proof, `pass` must downgrade.

## Analyzer Upgrade Plan

### Go

Current state:

- best positioned for proof upgrades due to AST support

Next upgrades:

- route-to-middleware binding for common routers
- handler-to-service and handler-to-repo call edges
- config read extraction from `os.Getenv`, `LookupEnv`, common config libs
- file role inference from package and symbol graph

### TypeScript and JavaScript

Current state:

- mixed AST and regex fallback

Next upgrades:

- framework-specific route/binding extraction for Express, NestJS, Fastify, Next.js
- middleware chain extraction with order and scope
- call fact extraction for `jwt.verify`, validation libraries, dangerous frontend sinks
- lockfile and manifest facts independent of language detection

### Python

Current state:

- AST path exists, but proof coverage is still limited

Next upgrades:

- FastAPI/Flask/Django route and decorator binding facts
- dependency injection / guard facts
- env/config read extraction
- ORM access call facts and caller-role linkage

## Rule System Changes

### Matcher Classes

Add explicit matcher classes:

- `proof_matcher`
- `structural_matcher`
- `heuristic_matcher`
- `attestation_matcher`

Contract:

- `proof_matcher` may emit `verified`
- `structural_matcher` may emit at most `strong_inference`
- `heuristic_matcher` may emit at most `weak_inference` or `strong_inference`
- `attestation_matcher` requires external evidence before leaving `unknown`

### Rule Metadata Additions

Every rule should declare:

- required fact types
- minimum fact quality
- whether `pass` can ever be trusted
- whether `fail` can ever be trusted
- coverage preconditions
- framework support scope

This metadata should be enforced in code, not only documented.

## Report Contract Changes

Add fields:

- `scan_boundary`
- `coverage_summary`
- `fact_quality_summary`
- `verdict_basis`

Example `verdict_basis` values:

- `proof`
- `structural_binding`
- `name_import_inference`
- `runtime_required`

This makes downstream consumers understand why a verdict is strong or weak.

## Benchmark And Calibration Requirements

Strong verification cannot be claimed from unit tests alone.

Required benchmark expansion:

- at least 10 real or realistic fixtures per machine-trusted rule family
- per-language false-positive guards
- per-framework binding fixtures
- broken analyzer coverage fixtures
- scan-boundary regression fixtures

Autocal gate additions:

- block any promotion that increases trusted verdict count without corresponding benchmark coverage
- block trusted `pass` on partial scans unless rule explicitly supports subdir-local exhaustiveness
- block verified findings backed only by heuristic facts

## Phased Delivery

### Phase 1: Trust Hardening

Goal:

- stop over-claiming

Changes:

- boundary contract
- coverage-aware negative rule downgrade
- matcher class enforcement
- report basis fields

Success criteria:

- fewer `verified` findings
- zero verified findings backed only by heuristic facts

### Phase 2: Proof Fact Expansion

Goal:

- increase proof surface for security and architecture checks

Changes:

- `CallFact`
- `RouteBindingFact`
- `AppBindingFact`
- `ConfigReadFact`
- `FileRoleFact`

Success criteria:

- `SEC-AUTH-002` no longer defaults to unknown for supported frameworks with extracted bindings
- `SEC-SECRET-002` moves from import inference toward config-source proof

### Phase 3: Trusted-Core Expansion

Goal:

- increase machine-trusted rule set without lowering precision

Changes:

- only after benchmark and autocal evidence supports it

Success criteria:

- trusted-core precision remains above target
- new trusted rules have explicit proof contracts

## Non-Goals

These should not be claimed as part of the strong verification upgrade:

- proving runtime behavior of external infrastructure from source alone
- proving human intent
- generic whole-program theorem proving
- LLM-generated trust promotion

## Practical Bottom Line

To become a strong verification engine, this project does not primarily need more rules.

It needs:

- exact scan boundaries
- proof-grade facts
- binding and dataflow evidence
- coverage-aware verdict semantics
- stricter benchmark gating

If those are not implemented, the engine remains valuable as a structured advisory scanner, but not as a strong verification product.
