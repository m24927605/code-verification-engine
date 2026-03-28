# Code Verification Engine v2 Implementation Specification

## 1. Purpose

This document defines the execution strategy for implementing Code Verification Engine v2. It translates the architecture specification into phased engineering work, module changes, migration sequencing, cost controls, and delivery expectations.

The implementation strategy is intentionally incremental. The current system already contains useful building blocks. The goal is to refactor the system around evidence, aggregation, and reproducibility without destabilizing the existing deterministic analysis path.

## 2. Implementation Objectives

The implementation must:

1. preserve the current working deterministic pipeline wherever possible
2. introduce an evidence-first core without a big-bang rewrite
3. keep the primary verification path independent from LLM availability
4. improve verification quality without materially increasing default cost
5. provide measurable migration checkpoints with clear acceptance gates

## 3. Baseline Context

The current codebase already provides:

- repository loading and isolated scan workspace preparation
- multi-language analyzer execution
- normalized fact extraction
- deterministic rule execution
- report generation
- evidence graph generation
- optional post-hoc interpretation

The current gaps relevant to implementation are:

- evidence is still attached to findings rather than modeled as a global store
- issue aggregation is not a first-class stage
- context selection is not formalized
- confidence is not a numeric explainable engine
- agent orchestration is not formalized
- verifiable artifact boundaries are incomplete

## 4. Delivery Strategy

The implementation must be performed in phases. Each phase should leave the system in a releasable or at least regression-safe state.

Guiding rules:

- no big-bang rewrite
- preserve compatibility where practical
- add adapters before removing old code paths
- introduce contracts before broad refactors
- keep deterministic path green throughout migration

## 5. Phased Implementation Plan

### Phase 0: Baseline Assessment and Inventory

Objective:

- establish the current-state inventory required for safe refactoring

Work items:

- map existing analyzers and fact outputs
- map current rule families, matcher classes, and trust semantics
- inventory current report contract and evidence usage
- classify which current findings can be converted directly into evidence-backed issue candidates
- identify existing benchmark and calibration coverage

Deliverables:

- analyzer-to-fact matrix
- rule quality inventory
- current trust boundary inventory
- migration risk register

Exit criteria:

- current architecture map is documented
- existing contracts are identified and versioned for migration planning

### Phase 1: Unified Evidence Schema

Objective:

- create the v2 evidence contract as a stable shared system primitive

Work items:

- define `EvidenceRecord`
- define evidence schema versioning
- implement deterministic evidence ID generation
- implement evidence normalization pipeline
- map current analyzer facts into normalized evidence records
- map current rule evidence into normalized evidence records

Design constraints:

- evidence must support provenance, derivation, contradiction, and location references
- evidence IDs must be stable under repeated execution

Deliverables:

- evidence schema
- evidence normalizer
- evidence store abstraction
- compatibility adapter from current outputs

Exit criteria:

- current deterministic pipeline outputs can be losslessly represented in the new evidence model
- evidence IDs are stable across repeated runs on the same snapshot

### Phase 2: Index Layer Hardening

Objective:

- formalize the AST/index layer as the canonical ground truth surface

Work items:

- define `CodeIndex` contract
- introduce stable entity IDs
- consolidate existing extracted relations into index structures
- add call edges, route bindings, config reads, and file roles as canonical indexed entities where available
- ensure partial extraction is explicitly represented

Design constraints:

- downstream rules and agents must prefer index access over raw fact slices
- multi-language support must remain conservative

Deliverables:

- canonical index data model
- serialization or in-memory store contract
- adapters from current analyzers into index structures

Exit criteria:

- rule execution can consume index-backed structures
- index is sufficient for at least one upgraded rule family per priority language

### Phase 3: Rule Engine Refactor

Objective:

- convert the rule engine from finding-first to evidence-first

Work items:

- expand rule DSL metadata
- require rules to declare minimum fact quality and required fact kinds
- add pass exhaustiveness controls
- emit structured support, contradiction, or unknown evidence outputs
- preserve current rule compatibility through adapters where needed

Design constraints:

- rule execution remains deterministic
- rules must not emit unbacked prose findings

Deliverables:

- updated DSL contract
- rule runtime refactor
- compatibility layer for existing report generation

Exit criteria:

- rule outputs are represented as normalized evidence assertions
- current rule families still function under compatibility mode

### Phase 4: Evidence Aggregator

Objective:

- introduce issue-centric aggregation as a formal system layer

Work items:

- define issue fingerprinting strategy
- implement deterministic clustering
- implement overlap merge
- retain contradictory evidence
- compute multi-source agreement
- produce `IssueCandidate` outputs

Design constraints:

- aggregation must be conservative and reproducible
- overlapping evidence may merge, but contradictory evidence may not be discarded

Deliverables:

- aggregation module
- issue candidate schema
- merge and conflict policies

Exit criteria:

- duplicate outputs for the same issue are reduced through clustering
- conflict retention is observable in issue candidates

### Phase 5: Confidence Engine

Objective:

- introduce numeric, explainable confidence scoring

Work items:

- define confidence feature inputs
- implement baseline confidence formula
- add evidence quality mapping
- add boundary and context completeness inputs
- add contradiction and agent-dependence penalties
- emit breakdown data

Design constraints:

- confidence must be numeric and deterministic
- degraded or partial analysis must reduce confidence

Deliverables:

- confidence engine
- scoring formula implementation
- breakdown schema

Exit criteria:

- every issue candidate can be scored with a confidence float and breakdown
- partial scans and degraded analyzers materially affect score outputs

### Phase 6: Skill Scoring Refactor

Objective:

- derive skill scoring from issues and evidence instead of loosely aggregated findings

Work items:

- define issue-to-skill mapping model
- support positive and negative contributors
- implement score normalization
- attach contributing issue and evidence references
- emit scoring confidence

Design constraints:

- every score must be attributable
- unsupported scores are not allowed

Deliverables:

- skill mapping contract
- scoring engine
- updated `skills.json` output path

Exit criteria:

- each skill score can be traced back to supporting issue IDs and evidence IDs

### Phase 7: Context Selection Layer

Objective:

- formalize bounded context generation for uncertain or specialist review paths

Work items:

- define `ContextBundle`
- implement seed-based context selection
- implement dependency expansion
- implement ranking and budget enforcement
- log selection trace to execution metadata

Design constraints:

- no whole-repo or whole-file default context
- context must be reproducible from the same trigger and budget

Deliverables:

- context selector
- ranking model
- trace logging integration

Exit criteria:

- downstream agent calls consume context bundles rather than free-form file sets

### Phase 8: Agent Orchestrator

Objective:

- introduce lazy specialist agents under strict policy control

Work items:

- define agent contracts
- implement orchestration trigger policy
- support bug, design, and security agent families
- normalize agent outputs back into evidence records
- enforce hard context and budget limits

Design constraints:

- agents run only when required
- agent outputs do not bypass aggregation or scoring
- agent dependence must not silently inflate confidence

Deliverables:

- orchestrator
- agent task and result contracts
- output normalization
- policy configuration

Exit criteria:

- agents are invoked only on policy-defined paths
- agent contributions enter the evidence store and flow through normal aggregation

### Phase 9: Verifiable Artifact Bundle

Objective:

- finalize the v2 output contract

Work items:

- generate `report.json`
- generate `evidence.json`
- generate `skills.json`
- generate `trace.json`
- render `summary.md`
- generate `signature.json`
- implement per-artifact and bundle hashing

Design constraints:

- `summary.md` must remain a derived view
- `signature.json` must hash all primary artifacts

Deliverables:

- artifact writers
- artifact hash generation
- bundle integrity contract

Exit criteria:

- the full artifact bundle can be generated and re-hashed deterministically

## 6. Module-Level Work Breakdown

Recommended target package layout:

```text
internal/
  ingestion/
  index/
  context/
  rules/
  evidence/
  agents/
  aggregation/
  confidence/
  skills/
  reporting/
  reproducibility/
```

Recommended implementation sequence by dependency:

1. `evidence`
2. `index`
3. `rules`
4. `aggregation`
5. `confidence`
6. `skills`
7. `context`
8. `agents`
9. `reporting`
10. `reproducibility`

## 7. Compatibility Strategy

Migration must preserve existing working behavior where possible.

Recommended compatibility approach:

- keep the current engine entrypoint and introduce v2 subcomponents behind adapters
- support dual-write or dual-projection during migration where useful
- preserve current report generation until v2 artifacts are stable
- prefer additive contracts before removing old fields

Compatibility rules:

- deterministic correctness takes priority over backward shape preservation
- if old behavior over-claims trust, downgrade behavior rather than preserve incorrect semantics

## 8. Cost Control Requirements

This implementation must be optimized for low default cost.

Required controls:

- deterministic path must not require LLM access
- agent orchestration must be opt-in by policy trigger
- context bundles must be size-limited
- high-cost paths must be observable

Recommended operational metrics:

- `deterministic_path_ratio`
- `agent_trigger_rate`
- `avg_context_files`
- `avg_context_spans`
- `avg_context_tokens`
- `cost_per_repo`
- `time_per_repo`

## 9. Language and Rule Investment Priority

Implementation priority should follow expected verification ROI:

1. Go
2. TypeScript / JavaScript
3. Python

Reasoning:

- Go already has a stronger AST base
- TypeScript and JavaScript benefit significantly from explicit binding upgrades
- Python support should remain conservative until index quality is sufficient

Rule family investment priority:

1. auth and route protection
2. config and secret sourcing
3. direct controller-to-database access
4. validation and dangerous sink checks
5. design and architecture pattern verification

## 10. Testing Strategy During Implementation

Every phase must include contract and regression coverage.

Required test categories:

- unit tests for new schema and scoring logic
- integration tests for end-to-end evidence flow
- regression tests against existing golden fixtures
- contract tests for artifacts
- repeatability tests to confirm deterministic outputs

Testing rule:

- no phase is considered complete until its primary contract is covered by tests

## 11. Risk Register

### Risk 1: Evidence Schema Churn

Description:

- the evidence schema may need revision as aggregation and agent integration mature

Mitigation:

- version the schema early
- keep adapters explicit
- write schema contract tests

### Risk 2: Aggregation Complexity Growth

Description:

- issue clustering may become hard to reason about if over-designed early

Mitigation:

- start with deterministic conservative fingerprinting
- delay advanced graph clustering until justified by failure cases

### Risk 3: Agent Cost Expansion

Description:

- permissive agent triggers can materially increase cost

Mitigation:

- strict trigger policy
- hard budgets
- metrics and guardrails
- no agents on green deterministic path

### Risk 4: Confidence Miscalibration

Description:

- confidence may appear precise without being calibrated

Mitigation:

- keep formula explicit
- tie rule reliability to benchmark data
- expose confidence breakdown and not just scalar outputs

### Risk 5: Migration Instability

Description:

- the current engine may become unstable during multi-layer refactor

Mitigation:

- phase the rollout
- preserve adapters
- maintain deterministic regression suite

## 12. Rollout Plan

Recommended rollout path:

1. internal development behind feature flags
2. shadow artifact generation in CI
3. compare v1 and v2 outputs on benchmark corpus
4. validate reproducibility and confidence behavior
5. enable v2 artifact bundle for non-blocking production runs
6. promote v2 deterministic report as primary
7. enable agent path selectively for policy-defined cases

## 13. Implementation Exit Criteria

The implementation is complete only when:

1. evidence-first contracts are live in the primary path
2. issue aggregation replaces naive finding emission for final reporting
3. confidence is numeric and explainable
4. skills are evidence-derived
5. context selection is enforced for agent use
6. the six-artifact bundle is generated deterministically
7. cost guardrails are observable and enforced

## 14. Summary

The correct implementation strategy for v2 is not a full rewrite of analysis features. It is a restructuring of the engine around evidence, aggregation, confidence, and traceability while preserving a low-cost deterministic path as the product backbone.

This implementation plan should be treated as the controlling engineering sequence for v2 delivery.
