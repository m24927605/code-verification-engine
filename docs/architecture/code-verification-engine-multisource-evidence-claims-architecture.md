# Code Verification Engine Multi-Source Evidence Claims Architecture

## 1. Purpose

This document defines the architecture for extending Code Verification Engine from rule-centric verification into multi-source claim verification suitable for high-value skill resume generation.

The target is not to let README text drive output. The target is to let `README`, `docs`, `code`, `tests`, and `eval` all act as typed evidence sources, then verify high-value claims against those sources before any narrative synthesis is allowed.

This architecture is intended to preserve the existing architecture principles:

- evidence-first
- deterministic-first
- conservative trust
- machine-verifiable outputs

## 2. Problem Statement

The current engine is good at:

- deterministic rule execution
- issue generation
- evidence-backed artifact production
- conservative skill scoring

The current engine is not sufficient for high-value engineering profile extraction because it under-represents:

- system-level architecture decisions
- design intent
- testing maturity
- evaluation maturity
- product-quality guardrail design
- cross-module engineering patterns

These signals often exist across multiple sources rather than in one rule or one file.

Examples:

- multi-agent architecture
- shared secure answer pipeline
- adversarial evaluation maturity
- structured tracing across agent calls
- deterministic pre-check before LLM routing

## 3. Architectural Goal

The system must be able to produce evidence-backed capability claims from multiple repository sources without trusting documentation text by default.

The target architecture is:

```text
Repo Snapshot
-> Source Discovery
-> Multi-Source Evidence Extraction
-> Evidence Normalization
-> Claim Candidate Extraction
-> Claim Verification
-> Claim Graph
-> Capability Profile Projection
-> Bounded LLM Resume Synthesis
```

## 4. Core Principles

### 4.1 README Is a Candidate Source, Not Ground Truth

`README` and documentation may propose high-value claims. They may not directly create verified capability output.

They can:

- suggest claims
- prioritize what should be verified
- provide design vocabulary

They cannot:

- bypass code evidence
- create verified claims without support
- override contradictory code, test, or eval evidence

### 4.2 Code Remains the Primary Ground Truth

Code remains the strongest source for implementation existence and structural wiring.

Documentation-derived claims must be validated against:

- code modules
- routes
- services
- agents
- pipelines
- middleware
- configuration paths

### 4.3 Tests and Evals Upgrade Maturity, Not Mere Existence

Tests and evaluation artifacts should primarily influence:

- maturity
- confidence
- support level
- release readiness

A feature existing in code is weaker than the same feature being explicitly covered by tests or adversarial evaluation.

### 4.4 Claims Must Be Typed and Auditable

High-value outputs must be represented as explicit claim records with:

- source origin
- supporting evidence
- contradictory evidence
- support level
- confidence
- reasoning trace

### 4.5 LLM Is Projection Only

LLM may be used only for bounded synthesis after claim verification.

LLM may not:

- invent new claims
- upgrade weak claims to verified claims
- ignore contradictory evidence

## 5. Source Model

The system must treat the following as first-class evidence sources.

### 5.1 Code Sources

Examples:

- route handlers
- service modules
- agent modules
- pipelines
- middleware
- configuration readers
- tracing modules

Typical capability signals:

- system architecture
- wiring
- execution flow
- security controls
- integration surfaces

### 5.2 Test Sources

Examples:

- unit tests
- integration tests
- security tests
- regression tests
- architecture tests

Typical capability signals:

- implementation maturity
- regression protection
- explicit quality constraints
- security verification depth

### 5.3 Eval Sources

Examples:

- benchmark datasets
- adversarial datasets
- evaluation runners
- calibration fixtures

Typical capability signals:

- model quality governance
- prompt safety maturity
- evaluation discipline
- benchmark-backed behavior

### 5.4 Docs Sources

Examples:

- architecture docs
- ADRs
- design notes
- security docs
- operational docs

Typical capability signals:

- design intent
- architecture rationale
- tradeoff articulation
- operating constraints

### 5.5 README Sources

Examples:

- product overview
- top-level architecture claims
- security positioning
- feature summary

Typical capability signals:

- explicit high-value claims
- project self-description
- capability prioritization hints

## 6. Claim Model

The new system should extend the existing claim-centric model rather than replace it.

The current `internal/claims` package is rule-result-centric. The target model is multi-source claim-centric.

Each claim should be represented with:

- `claim_id`
- `title`
- `category`
- `claim_type`
- `source_candidates`
- `supporting_evidence_ids`
- `contradictory_evidence_ids`
- `support_level`
- `claim_confidence`
- `verification_reason`
- `projection_eligibility`

### 6.1 Claim Types

At minimum:

- `implementation`
- `architecture`
- `security_maturity`
- `testing_maturity`
- `evaluation_maturity`
- `operational_maturity`

### 6.2 Support Levels

The engine must distinguish:

- `verified`
- `strongly_supported`
- `supported`
- `weak`
- `unsupported`
- `contradicted`

Only `verified` and `strongly_supported` claims are safe default inputs for high-value resume synthesis.

## 7. Claim Graph

The canonical internal representation should be a claim graph rather than a flat skill list.

Each claim node should be connected to:

- source evidence records
- related rule findings or issues
- supporting tests
- supporting evals
- supporting docs sections
- originating README claim fragments

This allows:

- traceability
- contradiction preservation
- support-level explanation
- selective projection into profile output

## 8. Data Flow

The target flow is:

```text
README/docs/code/tests/eval
-> source-specific extractors
-> normalized evidence records
-> claim candidate extraction
-> claim verification against evidence graph
-> claim graph
-> profile projection
-> optional bounded LLM synthesis
```

### 8.1 Source Discovery

Responsibilities:

- find README files
- find docs/ and ADR content
- identify tests and eval folders
- classify code modules

### 8.2 Source-Specific Extraction

Responsibilities:

- extract candidate architecture patterns
- extract test intent and regression assertions
- extract eval suite semantics
- extract documentation claims

### 8.3 Evidence Normalization

Responsibilities:

- preserve source type
- preserve file path and location
- preserve extractor identity
- assign deterministic evidence IDs

### 8.4 Claim Candidate Extraction

Responsibilities:

- lift raw evidence into candidate claims
- deduplicate semantically identical candidates
- preserve claim origin

### 8.5 Claim Verification

Responsibilities:

- verify documentation and README claims against code/tests/evals
- downgrade unsupported claims
- preserve contradictions
- compute support level and claim confidence

### 8.6 Profile Projection

Responsibilities:

- emit capability-oriented structured output
- expose only supported claims
- preserve trace links to evidence

### 8.7 Resume Synthesis

Responsibilities:

- synthesize prose only from supported claims
- reference claim support level
- avoid inventing unsupported capability statements

## 9. Module Boundaries

The preferred architecture reuses and extends current subsystems.

### 9.1 Existing Modules to Extend

- `internal/claims`
- `internal/artifactsv2`
- `internal/acceptance`
- `internal/releasegate`
- `pkg/cve`

### 9.2 New Logical Subsystems

- source discovery for docs/README/tests/evals
- claim candidate extraction
- claim graph builder
- profile projection layer

These may be implemented as new packages or as staged extensions of current packages, but they must preserve current canonical contracts.

## 10. Output Artifacts

The system should add profile-oriented artifacts without weakening current canonical artifacts.

Recommended new outputs:

- `claims.json`
- `profile.json`
- `resume_input.json`

Recommended semantics:

- `claims.json` stores full multi-source verified claims
- `profile.json` stores structured capability profile projection
- `resume_input.json` stores bounded, evidence-backed input for LLM synthesis

## 11. Example: Vulcan

For Vulcan-like repositories, the target system should be able to verify claims such as:

- planner, executor, and verifier separated into distinct agent roles
- deterministic pre-check exists before LLM escalation
- secure answer generation is enforced through a shared pipeline
- tracing is structured and reused across agent operations
- adversarial evaluation assets exist and are part of quality governance

These claims must not be accepted solely because the README says so. They must be linked to code, tests, evals, or docs evidence.

## 12. Non-Goals

This architecture does not require:

- trusting free-form marketing language
- extracting capability claims from arbitrary prose without evidence
- letting LLMs inspect full repositories without bounded context
- replacing current issue/evidence artifacts

## 13. Completion Criteria

This capability is architecturally complete only when:

1. all five source classes are modeled as evidence sources
2. README/docs claims can be verified or downgraded against stronger evidence
3. claim graph output is traceable and deterministic
4. profile projection is evidence-backed
5. LLM synthesis, when used, is bounded to verified claim inputs only
