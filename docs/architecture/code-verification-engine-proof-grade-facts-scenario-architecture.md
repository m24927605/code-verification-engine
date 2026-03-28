# Code Verification Engine Proof-Grade Facts Scenario Architecture

## 1. Purpose

This document defines the product and system architecture for upgrading Code Verification Engine from heuristic-heavy rule evaluation toward proof-grade fact evaluation across three primary business scenarios:

1. interview and hiring, with code-to-resume generation
2. outsourced delivery acceptance assistance
3. software engineering PM acceptance

The target is not to eliminate every heuristic in the system.

The target is to:

- expand the set of claims that can be mechanically justified
- make trust boundaries explicit per scenario
- prevent heuristic-only signals from being presented as proof
- preserve conservative `unknown` and `human_or_runtime_required` outcomes where proof is not possible

This architecture must remain consistent with the existing v2 principles already established in the repository:

- evidence-first
- deterministic-first
- conservative trust
- bounded projection

## 2. Problem Statement

The current engine already models fact quality, trust class, evidence-backed outputs, and deterministic rules. That foundation is strong, but it is not yet sufficient for the three target scenarios because the product boundary is still too rule-centric and too generic.

Current gaps:

1. too many outputs are still derived from artifact existence, naming, or file-path heuristics
2. scenario-specific trust requirements are not modeled explicitly enough
3. proof-capable claims are not separated sharply enough from advisory or resumable claims
4. negative passes are still difficult to defend without explicit boundary and search completeness
5. resume-oriented projection can still be misunderstood as capability proof if support classes are not made stricter

## 3. Product Goal

The system must support three outcome classes across all scenarios:

1. `proof_grade`
   Meaning: claim is mechanically justified from explicit scan boundary, indexed facts, and replayable evidence.
2. `structural_inference`
   Meaning: claim is strongly indicated by code structure but is not sufficient for proof.
3. `human_or_runtime_required`
   Meaning: claim cannot be safely verified from static repository evidence alone.

These classes must not remain implicit. They must drive:

- rule authoring
- evidence aggregation
- claim projection
- scenario-specific UX and policy gating

## 4. Scenario Framing

### 4.1 Interview and Hiring

Primary user goal:

- turn repository evidence into conservative, reusable, resume-safe capability claims

Primary risk:

- overstating ownership, impact, or maturity from limited code evidence

Required posture:

- proof-grade claims may be projected into resume-safe artifacts
- structural inference may be used as supporting profile context
- heuristic-only claims must not become verified resume highlights

### 4.2 Outsourced Delivery Acceptance Assistance

Primary user goal:

- determine whether contracted engineering requirements are actually present in the delivered repository snapshot

Primary risk:

- payment or sign-off decisions based on weak indicators

Required posture:

- proof-grade claims should dominate acceptance
- structural inference may be shown as advisory
- heuristic-only acceptance must not drive automated pass decisions

### 4.3 Software Engineering PM Acceptance

Primary user goal:

- determine whether engineering delivery requirements are implemented and wired correctly

Primary risk:

- conflating engineering completion with product correctness or business acceptance

Required posture:

- proof-grade claims may drive engineering acceptance status
- structural inference may identify likely implementation gaps or incomplete work
- runtime, integration, or product-behavior questions must remain outside proof-grade scope unless runtime evidence is incorporated later

## 5. Architectural Goal

The architecture must allow the same repository snapshot to produce scenario-aware outputs without duplicating the entire engine.

The target architecture is:

```text
Repo Snapshot
-> Scan Boundary Contract
-> AST / Index Extraction
-> Proof / Structural / Heuristic Fact Layer
-> Deterministic Rule Evaluation
-> Claim Classification
-> Scenario Policy Projection
-> Verifiable Outputs
```

The key architectural change is not a new scanner. The key change is a stricter contract between extracted facts, rule outputs, claim classes, and scenario projections.

## 6. Core Principles

### 6.1 Proof Is Narrower Than Detection

The system must not assume that every detectable pattern is proofable.

Examples:

- `auth middleware symbol exists` is detection
- `auth middleware is bound to protected routes` may be proofable
- `authentication is effective in production` is not statically proofable

### 6.2 Scenario Projection Must Not Upgrade Trust

Projection layers may filter, summarize, group, or rename claims. They may not upgrade:

- fact quality
- trust class
- support level
- confidence class

Resume projection, acceptance projection, and PM projection are all derived views over the same trust boundary.

### 6.3 Unknown Is a Valid Product Outcome

If scan boundary, analyzer coverage, or proof facts are insufficient, the system must emit `unknown` or `human_or_runtime_required` rather than fallback to overconfident acceptance.

### 6.4 Negative Pass Requires Exhaustiveness

A negative claim such as "no direct controller DB access" or "no hardcoded secret literal" may be proof-grade only if:

- scan boundary is explicit and complete enough
- relevant analyzers succeeded
- the rule search space is exhaustively defined for the covered languages and frameworks

### 6.5 Resume Safety Is a First-Class Constraint

For hiring outputs, the engine must separate:

- evidence-backed implementation facts
- capability claims
- resume-safe highlights

Documentation-only or heuristic-only signals must never silently enter `resume_input.json` as proof-grade claims.

## 7. Domain Model

### 7.1 Fact Quality

The system already models:

- `proof`
- `structural`
- `heuristic`

This classification must become operationally binding, not merely descriptive.

Required semantics:

- proof-grade claims require `proof` facts for decisive edges
- structural inference may be built from `proof` and `structural` facts
- heuristic-only outputs must remain advisory

### 7.2 Claim Verification Class

Add an explicit claim verification class in downstream artifacts:

- `proof_grade`
- `structural_inference`
- `heuristic_advisory`
- `human_or_runtime_required`

This is distinct from support level. Support level describes strength inside a claim family. Verification class describes the type of trust boundary behind that claim.

### 7.3 Scenario Applicability

Each claim family should declare scenario applicability metadata:

- `hiring`
- `outsource_acceptance`
- `pm_acceptance`

This metadata determines:

- whether the claim is eligible for projection
- whether the claim may drive gating
- which explanation template should be used

### 7.4 Acceptance Intent

For outsource and PM scenarios, rules must declare whether they are:

- `existence_check`
- `binding_check`
- `boundary_check`
- `maturity_check`
- `negative_exhaustive_check`

This makes it explicit which checks can be safely automated.

## 8. Claim Taxonomy by Scenario

### 8.1 Hiring and Resume Claim Families

Safe proof-grade claim families:

- framework and technology usage grounded in indexed imports and concrete call sites
- route and middleware wiring
- test presence and targeted module coverage existence
- architecture wiring claims such as repository-service-controller layering where call and binding facts exist
- config source claims such as "secret key sourced from environment" when config-read proof exists

Structural-only claim families:

- engineering style or pattern preference
- partial module ownership signals
- broad architecture maturity claims

Human-or-runtime claim families:

- team leadership
- incident response quality
- production reliability
- scale handled
- business impact
- authorship and contribution share

### 8.2 Outsourced Delivery Claim Families

Safe proof-grade claim families:

- required middleware or guard binding
- required route registration
- required config source usage
- forbidden direct access patterns
- required tests or policy files existence when scoped in contract
- secret literal violations
- exact delivery artifacts declared in engineering acceptance scope

Structural-only claim families:

- implementation quality maturity beyond explicit contract
- maintainability posture inferred from project shape

Human-or-runtime claim families:

- actual production availability
- runtime latency and throughput
- operational resilience not represented in repo artifacts

### 8.3 PM Acceptance Claim Families

Safe proof-grade claim families:

- engineering delivery wiring
- guardrail presence
- service boundary conformance
- required test or config paths
- prohibited layering violations

Structural-only claim families:

- codebase maintainability
- likely extensibility
- generalized engineering maturity

Human-or-runtime claim families:

- user acceptance
- commercial correctness
- end-to-end behavior spanning external systems without runtime evidence

## 9. Rule Migration Model

The engine must migrate away from broad heuristic rules toward narrower proof-capable rule families.

### 9.1 Replace Artifact Rules with Proofable Claim Slices

Examples:

- replace `auth.jwt_middleware exists`
  with:
  - `auth.middleware_artifact_exists`
  - `auth.middleware_bound_to_routes`
  - `auth.token_validation_call_exists`

- replace `repository pattern exists`
  with:
  - `architecture.repository_layer_symbols_exist`
  - `architecture.service_to_repository_call_path_exists`
  - `architecture.controller_direct_db_access_absent`

- replace `env config exists`
  with:
  - `config.env_read_call_exists`
  - `config.secret_key_sourced_from_env`
  - `config.secret_key_not_literal`

### 9.2 Separate Search Completeness from Violation Evidence

For each negative or absence-based rule, the system must separately record:

- violating evidence found
- whether the search space was complete enough to justify a proof-grade pass

### 9.3 Require Minimum Fact Quality per Verdict Class

Each rule family must declare:

- minimum fact quality for `proof_grade`
- minimum fact quality for `structural_inference`
- downgrade path when proof prerequisites are missing

## 10. Analyzer and Fact Requirements

The current architecture already points toward these requirements. This scenario architecture formalizes them as mandatory for product correctness.

Required fact families:

- `CallFact`
- `RouteBindingFact`
- `AppBindingFact`
- `ConfigReadFact`
- `LiteralAssignmentFact`
- `FileRoleFact`
- `DataAccessFact` with caller context
- explicit scan-boundary completeness metadata

Required analyzer properties:

- deterministic IDs
- per-fact provenance
- downgrade behavior on partial extraction
- explicit unsupported language and unsupported framework handling

## 11. Scenario Policy Projection Layer

The engine must add a scenario policy projection layer above claim verification.

Inputs:

- verified claims
- support levels
- verification classes
- trust class
- evidence references
- scan-boundary completeness

Outputs:

- `hiring_profile.json`
- `outsource_acceptance.json`
- `pm_acceptance.json`

These outputs may be implemented as separate artifacts or scenario sections inside existing artifacts. The critical requirement is that each projection must apply scenario-specific filtering without altering the underlying evidence truth.

### 11.1 Hiring Projection Rules

Must:

- include only `proof_grade` and eligible `structural_inference` claims in default profile summaries
- exclude heuristic-only top highlights
- preserve contradiction visibility
- preserve evidence references for every projected claim

### 11.2 Outsource Acceptance Projection Rules

Must:

- elevate proof-grade contract checks into pass/fail/unknown acceptance rows
- show structural inference as advisory, not contractual proof
- expose explicit blocking reasons when acceptance cannot be safely determined

### 11.3 PM Acceptance Projection Rules

Must:

- emit engineering acceptance status rather than product acceptance status
- distinguish implemented, blocked, unknown, and runtime-required conditions
- preserve requirement-to-evidence traceability

## 12. Artifact Strategy

The architecture should extend the existing artifact bundle instead of bypassing it.

Recommended additions:

- `claims.json`
  - add `verification_class`
  - add `scenario_applicability`
  - add `projection_policies`

- `profile.json`
  - retain hiring-safe highlights only
  - add `highlight_verification_class`

- `resume_input.json`
  - include only claim stubs allowed for hiring synthesis
  - preserve contradiction and boundedness constraints

- new `outsource_acceptance.json`
  - machine-readable contract acceptance output

- new `pm_acceptance.json`
  - machine-readable engineering PM acceptance output

- `trace.json`
  - include scenario policy version and projection derivation metadata

## 13. Trust and Gating Semantics

### 13.1 Hiring

Automation policy:

- safe for evidence-backed resume drafting
- not safe for automated candidate rejection without human review

### 13.2 Outsourced Delivery

Automation policy:

- safe for automated gate decisions only on proof-grade contractual checks
- structural and heuristic findings require reviewer interpretation

### 13.3 PM Acceptance

Automation policy:

- safe for engineering readiness or engineering completion gates
- not safe as sole product or business acceptance authority

## 14. Non-Goals

This architecture does not attempt to:

- prove runtime behavior from static code alone
- determine authorship, contribution share, or developer seniority
- replace product QA or UAT
- infer business value from implementation presence
- silently reinterpret weak evidence as strong evidence

## 15. Risks and Mitigations

### 15.1 Risk: Over-Narrow Proof Surface

If proof requirements are too strict, outputs may become overly sparse.

Mitigation:

- preserve structural inference as a distinct product tier
- keep unknown explicit instead of forcing proof

### 15.2 Risk: Resume Overclaim

Hiring outputs may accidentally overstate capability.

Mitigation:

- enforce hiring-safe projection filters
- disallow heuristic-only verified highlights
- preserve contradiction visibility in resume input

### 15.3 Risk: Acceptance Over-Automation

Outsource or PM projections may be used beyond their trust scope.

Mitigation:

- label outputs as engineering acceptance
- require explicit `runtime_required` outcomes where appropriate
- expose gateability only for proof-grade checks

### 15.4 Risk: Incomplete Negative Proof

Absence-based passes may be misrepresented as proof.

Mitigation:

- make scan completeness and search completeness first-class conditions
- downgrade incomplete negatives to `unknown`

## 16. Definition of Architectural Success

This architecture is successful only if:

1. scenario outputs do not upgrade weak evidence into proof
2. outsource and PM acceptance can be driven by proof-grade checks with explicit unknown handling
3. hiring outputs remain resume-safe and contradiction-aware
4. negative proof claims are emitted only when completeness requirements are met
5. the implementation extends the current evidence-first v2 system rather than creating a parallel unverifiable path
