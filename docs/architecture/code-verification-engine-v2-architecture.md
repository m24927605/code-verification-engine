# Code Verification Engine v2 Architecture Design Specification

## 1. Purpose

This document defines the target architecture for Code Verification Engine v2. The system is intended to evolve from a trust-aware static analysis engine into a production-grade verification platform optimized for verifiability, determinism, evidence-based reasoning, and low operational cost.

The primary goal is not to produce more narrative analysis. The primary goal is to produce machine-verifiable outputs whose conclusions are traceable to normalized evidence and reproducible from a fixed repository snapshot.

## 2. Scope

This specification covers:

- system goals and architectural principles
- module boundaries and responsibilities
- canonical data flow between layers
- evidence-first data model
- deterministic rule execution model
- bounded agent orchestration model
- confidence and skill scoring requirements
- report artifact contract
- non-functional requirements for quality, cost, and extensibility

This specification does not define:

- detailed JSON Schema syntax for every artifact
- per-language analyzer implementation details
- UI or presentation surfaces beyond artifact generation
- deployment topology

## 3. Goals

The v2 system must satisfy the following product goals:

1. Transform the system from code analysis into code verification.
2. Ensure every output is backed by structured evidence.
3. Minimize LLM dependency and keep LLM usage as bounded fallback only.
4. Prefer deterministic and explainable logic over speculative reasoning.
5. Make outputs machine-verifiable, traceable, and reproducible.
6. Maintain high analysis quality under a low-cost execution model.

## 4. Architectural Principles

### 4.1 Evidence-First

Evidence is the primary system artifact. Findings, scores, summaries, and reports are derived artifacts. No final conclusion may exist without explicit evidence references.

### 4.2 Deterministic-First

The default execution path must be deterministic. Given the same repository snapshot, scan boundary, engine version, analyzer versions, and rule set, the system must produce the same deterministic outputs.

### 4.3 Ground Truth Before Reasoning

All reasoning layers must operate on indexed ground truth derived from the AST and canonical repository metadata. Free-form reasoning over raw files is not an allowed primary verification path.

### 4.4 Bounded Context

No agent or LLM may receive the entire repository or arbitrary large files by default. All contextual input must be selected through a deterministic context selection layer with explicit budgets and selection trace.

### 4.5 Report-as-Derivation

The report is not the source of truth. The report is a projection generated from evidence, issue aggregation, confidence scoring, and reproducibility metadata.

### 4.6 Conservative Trust

When boundary completeness, extraction quality, or agreement is insufficient, the system must downgrade confidence or produce unknown rather than over-claim.

## 5. System Architecture

The target architecture is:

```text
Repo
-> Ingestion Layer
-> AST / Index Layer
-> Context Selection Layer
-> Rule Engine (DSL, deterministic)
-> Evidence Layer
-> Agent Orchestrator
-> Specialized Agents
-> Evidence Aggregator
-> Confidence Engine
-> Skill Scoring
-> Verifiable Report
```

## 6. Layer Responsibilities

### 6.1 Ingestion Layer

Responsibilities:

- resolve repo path, ref, and commit
- establish deterministic scan snapshot
- define exact scan boundary
- enumerate included and excluded files
- produce file manifest and boundary hash

Inputs:

- local repo path
- requested ref or commit
- scan mode

Outputs:

- `RepoSnapshot`
- `ScanBoundary`
- `FileManifest`

Requirements:

- all later evidence must bind to the exact commit and boundary hash
- included and excluded files must be explicit
- subdirectory scans must be represented as typed boundary contracts

### 6.2 AST / Index Layer

Responsibilities:

- parse language-specific ASTs
- extract canonical entities and stable entity IDs
- build symbol tables
- build import and dependency structures
- build call edges
- build route and middleware binding edges
- build config read and source structures
- build file role and structural classification

Outputs:

- `CodeIndex`

Requirements:

- this layer is the ground truth source for downstream reasoning
- rules and agents should depend on indexed entities and edges, not raw repo scanning
- partial extraction must be represented explicitly

### 6.3 Context Selection Layer

Responsibilities:

- build minimal sufficient context for downstream rules or agents
- select function-level, binding-level, and dependency-level context
- rank contextual candidates by relevance and evidence strength
- enforce file, span, and token budgets
- record selection trace for reproducibility

Outputs:

- `ContextBundle`

Requirements:

- context must be graph-derived, not whole-repo derived
- selection must be deterministic under the same inputs and budgets

### 6.4 Rule Engine

Responsibilities:

- evaluate deterministic DSL rules against indexed data
- generate structured evidence, support assertions, contradiction assertions, or unknown outputs
- enforce required fact kinds, minimum fact quality, and pass exhaustiveness policies

Outputs:

- `RuleEvidenceOutput[]`

Requirements:

- rules do not directly author final report prose
- rules are versioned and typed
- rule reliability is first-class metadata

### 6.5 Evidence Layer

Responsibilities:

- normalize all evidence records
- maintain evidence identity
- preserve provenance, derivation, and contradiction relationships
- serve as source-of-truth backing store for all downstream layers

Outputs:

- `EvidenceStore`

Requirements:

- evidence IDs must be deterministic
- evidence must be replayable to concrete file locations and entity references
- analyzer, rule, and agent evidence must share one schema

### 6.6 Agent Orchestrator

Responsibilities:

- decide whether an agent should run
- trigger specialist agents lazily
- provide bounded context bundles
- normalize agent output back into evidence records

Trigger conditions:

- unknown rule output
- issue cluster conflict
- high-value unresolved issue requiring specialist review

Requirements:

- agents are not part of the default path
- agents may not directly emit final findings
- all agent contributions must re-enter the system as evidence

### 6.7 Specialized Agents

Agent families:

- Bug Agent
- Design Agent
- Security Agent

Responsibilities:

- inspect bounded context
- produce structured support or counter-evidence
- surface unresolved reasons when context is insufficient

Requirements:

- must be schema-constrained
- must not act as single-source proof for high-confidence conclusions

### 6.8 Evidence Aggregator

Responsibilities:

- deduplicate evidence-backed issue candidates
- merge overlapping issue clusters
- retain contradictions
- compute multi-source agreement
- form canonical issue candidates from raw evidence

Requirements:

- aggregation is not a flat merge
- counter-evidence must remain attached to the resulting issue
- the clustering algorithm must be deterministic

### 6.9 Confidence Engine

Responsibilities:

- compute numeric confidence in the range `0..1`
- produce explainable confidence breakdowns
- apply penalties for contradiction, incomplete boundary, degraded analyzers, or heavy agent dependence

Requirements:

- confidence must be derived from machine-usable inputs
- confidence must not be opaque or narrative-only

### 6.10 Skill Scoring

Responsibilities:

- map issues and evidence to skill dimensions
- compute explainable skill scores
- expose positive and negative contributors

Requirements:

- skill scoring must be evidence-derived
- no unsupported score may be emitted without contributing references

### 6.11 Verifiable Report

Responsibilities:

- project all finalized outputs into a stable artifact bundle
- preserve traceability from report to evidence to execution trace
- emit artifacts suitable for future hashing and signing

Artifact set:

- `report.json`
- `evidence.json`
- `skills.json`
- `trace.json`
- `summary.md`
- `signature.json`

## 7. Canonical Data Flow

The canonical data flow is:

```text
RepoSnapshot
-> ScanBoundary
-> FileManifest
-> CodeIndex
-> Rule Evaluation
-> Evidence Store
-> Issue Aggregation
-> Optional Agent Execution
-> Additional Evidence
-> Re-Aggregation
-> Confidence Scoring
-> Skill Scoring
-> Artifact Projection
-> Artifact Hashing
```

Key rule:

- rules produce evidence first
- issue candidates are formed by aggregation
- report artifacts are generated after aggregation and scoring

## 8. Core Data Contracts

### 8.1 RepoSnapshot

```ts
interface RepoSnapshot {
  repo: string;
  ref: string;
  commit: string;
  capturedAt: string;
  boundaryHash: string;
}
```

### 8.2 ScanBoundary

```ts
interface ScanBoundary {
  mode: "repo" | "subdir" | "snapshot";
  rootPath: string;
  includedFiles: string[];
  excludedFiles: string[];
  ignoreRules: string[];
}
```

### 8.3 LocationRef

```ts
interface LocationRef {
  repoRelPath: string;
  startLine: number;
  endLine: number;
  startCol?: number;
  endCol?: number;
  symbolId?: string;
}
```

### 8.4 CodeIndex

```ts
interface CodeIndex {
  entities: Record<string, CodeEntity>;
  callEdges: CallEdge[];
  routeBindings: RouteBinding[];
  configReads: ConfigRead[];
  fileRoles: FileRole[];
}
```

### 8.5 EvidenceRecord

```ts
interface EvidenceRecord {
  id: string;
  kind: string;
  source: "analyzer" | "rule" | "agent";
  producerId: string;
  producerVersion: string;
  repo: string;
  commit: string;
  boundaryHash: string;
  factQuality: "proof" | "structural" | "heuristic";
  entityIds: string[];
  locations: LocationRef[];
  claims: string[];
  payload: Record<string, unknown>;
  supports: string[];
  contradicts: string[];
  derivedFrom: string[];
  createdAt: string;
}
```

### 8.6 ContextBundle

```ts
interface ContextBundle {
  id: string;
  trigger: {
    type: "rule" | "issue" | "evidence";
    id: string;
  };
  evidenceIds: string[];
  entityIds: string[];
  spans: LocationRef[];
  graphFragment: Record<string, unknown>;
  selectionTrace: string[];
}
```

### 8.7 RuleDefinition

```ts
interface RuleDefinition {
  id: string;
  version: string;
  category: string;
  severity: "low" | "medium" | "high" | "critical";
  target: string;
  requires: {
    factKinds: string[];
    minQuality: "proof" | "structural" | "heuristic";
    exhaustiveForPass: boolean;
  };
  emits: {
    issueType: string;
    claim: string;
  };
  reliability: number;
}
```

### 8.8 IssueCandidate

```ts
interface IssueCandidate {
  id: string;
  canonicalType: string;
  title: string;
  severity: "low" | "medium" | "high" | "critical";
  status: "open" | "resolved" | "unknown";
  evidenceIds: string[];
  counterEvidenceIds: string[];
  sourceSummary: {
    analyzers: string[];
    rules: string[];
    agents: string[];
  };
}
```

### 8.9 ConfidenceBreakdown

```ts
interface ConfidenceBreakdown {
  ruleReliability: number;
  evidenceQuality: number;
  boundaryCompleteness: number;
  contextCompleteness: number;
  sourceAgreement: number;
  contradictionPenalty: number;
  llmPenalty: number;
  final: number;
}
```

### 8.10 SkillScore

```ts
interface SkillScore {
  skillId: string;
  score: number;
  confidence: number;
  contributingIssueIds: string[];
  contributingEvidenceIds: string[];
}
```

## 9. Context Selection Design

The context selection layer is mandatory for all non-deterministic downstream work.

Selection algorithm:

1. Start from seed evidence or triggering issue entities.
2. Add enclosing function, method, route, class, or module definitions.
3. Expand one-hop and, if needed, bounded two-hop semantic dependencies.
4. Add framework-relevant bindings such as route-to-middleware or config source-to-sink edges.
5. Rank candidates by directness, fact quality, and issue relevance.
6. Stop when marginal information gain falls below threshold or the configured budget is reached.

Selection priorities:

- direct evidence span
- defining symbol span
- bound callee or caller relationship
- route or middleware binding
- config source or sink
- same-file nearby context

Hard constraints:

- no whole-repo context
- no uncontrolled large-file context
- all selected spans must be traceable in `trace.json`

## 10. Rule Engine Design

The rule engine must be deterministic and typed.

Rules must declare:

- rule identity and version
- target category
- required fact kinds
- minimum accepted fact quality
- whether verified pass requires exhaustive search
- emitted issue type and claim
- benchmarked reliability input

Rule outputs:

- support evidence
- contradiction evidence
- unknown with unresolved reasons

Rules may not:

- emit free-form conclusions without evidence
- rely on unbounded LLM interpretation
- treat heuristic presence as proof without explicit downgrade

## 11. Evidence Aggregation Design

Aggregation is a first-class engine stage.

Required functions:

- normalize all evidence records
- compute issue fingerprints
- cluster evidence into issue candidates
- merge overlapping clusters conservatively
- preserve contradictory evidence
- compute source agreement

Fingerprint inputs should include:

- issue type
- canonical entity or normalized path
- location window
- rule family or claim family

Conflict policy:

- contradictory evidence must remain visible
- conflicts reduce confidence
- unresolved conflicts may keep an issue in `unknown`

## 12. Confidence Model

Confidence must be numeric, bounded, and explainable.

Recommended baseline formula:

```text
confidence =
  0.30 * ruleReliability
+ 0.20 * evidenceQuality
+ 0.15 * boundaryCompleteness
+ 0.15 * contextCompleteness
+ 0.20 * sourceAgreement
- 0.20 * contradictionPenalty
- 0.10 * llmPenalty
```

Definitions:

- `ruleReliability`: benchmark or calibration-derived rule trust input
- `evidenceQuality`: proof > structural > heuristic
- `boundaryCompleteness`: whether scan coverage is complete for the issue search space
- `contextCompleteness`: whether the relevant graph is complete enough for conclusion
- `sourceAgreement`: agreement across independent analyzers, rules, and agents
- `contradictionPenalty`: strength of counter-evidence
- `llmPenalty`: extra penalty when an issue materially depends on agent-generated heuristic evidence

Requirements:

- final score is clamped to `0..1`
- the system must emit the component breakdown

## 13. Skill Scoring Design

Skill scoring must be evidence-derived and explainable.

The system must:

- map issue types to skill dimensions
- support positive and negative contributors
- record contributing issue IDs and evidence IDs
- emit both score and confidence

Recommended formula:

```text
skill_score(skill) =
  normalize(
    sum(positive_issue_confidence * positive_weight * coverage)
    - sum(negative_issue_confidence * negative_weight)
  )
```

Requirements:

- every score must list contributors
- unsupported skill scores are not allowed

## 14. Artifact Contract

### 14.1 `evidence.json`

Purpose:

- source-of-truth evidence backing store

Contains:

- normalized evidence records
- source identity
- fact quality
- exact file and line references
- derivation and contradiction links

### 14.2 `report.json`

Purpose:

- issue-centric final verification output

Contains:

- repo and engine metadata
- issue summary
- issue list
- confidence per issue
- evidence references
- skill references

Rule:

- report entries reference evidence IDs; they do not embed duplicate raw evidence

### 14.3 `skills.json`

Purpose:

- evidence-derived skill scoring output

Contains:

- score per skill
- confidence per skill
- contributing issue IDs
- contributing evidence IDs
- formula inputs or explanation fields

### 14.4 `trace.json`

Purpose:

- reproducibility and execution manifest

Contains:

- trace ID
- repo and commit
- scan boundary
- analyzer versions
- rule versions
- context selection decisions
- agent executions
- derivation links from evidence to issues

### 14.5 `summary.md`

Purpose:

- human-readable projection of the report

Rule:

- must not introduce novel claims absent from the JSON artifacts

### 14.6 `signature.json`

Purpose:

- artifact bundle hash envelope for integrity and future signing

Contains:

- per-artifact hashes
- bundle hash
- signature scheme
- signer identity
- optional signature payload

## 15. Non-Functional Requirements

### 15.1 Quality

The system must be:

- deterministic
- reproducible
- traceable
- explainable

### 15.2 Cost

The system must be optimized for low cost:

- deterministic path is the default path
- agent execution is lazy, not eager
- LLM usage is exception-path only
- context bundles are budgeted

### 15.3 Scalability

The system must support:

- additional languages
- additional rule families
- additional agents
- future signing and policy-gating workflows

### 15.4 Extensibility

The following must be versioned:

- evidence schema
- rule DSL
- artifact contracts
- scoring model

## 16. Cost Control Strategy

High quality must not require uncontrolled spend.

Required strategies:

- deterministic-first execution
- strict agent trigger policy
- minimal context extraction
- hard budgets on files and tokens
- benchmark-driven trust promotion
- selective investment in high-value languages and rule families

Recommended language priority:

1. Go
2. TypeScript / JavaScript
3. Python

## 17. Architectural Decision Summary

The central architectural decision for v2 is:

All deterministic analyzers, rules, and bounded agents are evidence producers. Aggregation, confidence scoring, and report projection are downstream derivation layers. Evidence plus trace form the system core.

This decision is required to meet the product goals of verifiability, determinism, and low-cost high-quality analysis.
