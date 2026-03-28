# Code Verification Engine v2 Module Contract Specification

## 1. Purpose

This document defines the implementation-facing module contracts for Code Verification Engine v2. It exists to make the architecture executable by engineering teams without relying on implicit assumptions.

The goal of this document is to specify:

- module boundaries
- inputs and outputs
- invariants
- failure semantics
- ownership expectations

This document should be used together with:

- [code-verification-engine-v2-architecture.md](/Users/sin-chengchen/products/verabase/code-verification-engine/docs/architecture/code-verification-engine-v2-architecture.md)
- [code-verification-engine-v2-implementation-plan.md](/Users/sin-chengchen/products/verabase/code-verification-engine/docs/implementation/code-verification-engine-v2-implementation-plan.md)
- [code-verification-engine-v2-acceptance-spec.md](/Users/sin-chengchen/products/verabase/code-verification-engine/docs/acceptance/code-verification-engine-v2-acceptance-spec.md)

## 2. Global Contract Rules

All v2 modules must follow these rules:

1. Module outputs must be typed and machine-consumable.
2. Module outputs must not silently depend on global mutable state.
3. All non-deterministic work must be explicitly marked and bounded.
4. Failures must be surfaced explicitly rather than downgraded silently.
5. Every output that contributes to a final issue must be traceable to a producer ID and source version.

## 3. Repository and Boundary Contracts

### 3.1 `ingestion/snapshot`

Responsibilities:

- resolve repo and ref
- capture exact commit
- generate boundary hash inputs

Input:

```ts
interface SnapshotRequest {
  repoPath: string;
  ref?: string;
}
```

Output:

```ts
interface RepoSnapshot {
  repo: string;
  ref: string;
  commit: string;
  capturedAt: string;
  boundaryHash: string;
}
```

Invariants:

- `commit` must be a resolved immutable commit SHA
- `boundaryHash` must be derived from scan boundary inputs, not arbitrary runtime state

Failure semantics:

- if ref cannot be resolved, the module fails hard
- if repository state cannot be read safely, the module fails hard

### 3.2 `ingestion/boundary`

Responsibilities:

- determine included and excluded files
- apply scan mode
- apply safe path filtering
- generate deterministic file manifest

Input:

```ts
interface BoundaryRequest {
  repoSnapshot: RepoSnapshot;
  mode: "repo" | "subdir" | "snapshot";
  requestedPath?: string;
}
```

Output:

```ts
interface ScanBoundary {
  mode: "repo" | "subdir" | "snapshot";
  rootPath: string;
  includedFiles: string[];
  excludedFiles: string[];
  ignoreRules: string[];
}
```

Invariants:

- `includedFiles` ordering must be deterministic
- files outside the allowed boundary may not appear downstream
- exclusion reasons must be explainable in trace output

## 4. Index Layer Contracts

### 4.1 `index/entities`

Responsibilities:

- produce stable entity IDs for files, functions, methods, classes, routes, and config anchors

Input:

- boundary-scoped source files
- analyzer extraction output

Output:

```ts
interface CodeEntity {
  id: string;
  kind: "file" | "function" | "class" | "method" | "route" | "config" | "module";
  language: string;
  name: string;
  location: LocationRef;
}
```

Invariants:

- identical source structure under the same snapshot must generate stable entity IDs
- entity IDs must be unique within a scan

### 4.2 `index/graph`

Responsibilities:

- assemble canonical relations from extraction outputs

Output:

```ts
interface CodeIndex {
  entities: Record<string, CodeEntity>;
  callEdges: CallEdge[];
  routeBindings: RouteBinding[];
  configReads: ConfigRead[];
  fileRoles: FileRole[];
}
```

Invariants:

- relations must reference valid entity IDs where applicable
- partial extraction must be represented explicitly, not omitted silently

Failure semantics:

- language-specific extractor failure may degrade quality, but must be recorded
- malformed relation references are contract violations

## 5. Evidence Contracts

### 5.1 `evidence/normalize`

Responsibilities:

- normalize analyzer, rule, and agent outputs into `EvidenceRecord`
- generate deterministic evidence IDs

Input:

- raw analyzer facts
- rule evidence outputs
- agent evidence outputs

Output:

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

Invariants:

- every evidence record must have source, producer, and quality metadata
- every evidence record that references code must include at least one valid location
- evidence records may not reference files outside the scan boundary

Failure semantics:

- malformed evidence is rejected
- missing provenance fields are contract violations

### 5.2 `evidence/store`

Responsibilities:

- store normalized evidence
- support lookup by ID, claim, issue fingerprint input, producer, and location

Required behaviors:

- deterministic retrieval
- duplicate-safe insertion by ID
- explicit handling of contradictions

## 6. Rule Engine Contracts

### 6.1 `rules/dsl`

Responsibilities:

- define versioned typed rules

Required fields:

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

Invariants:

- rule identity plus version must uniquely identify behavior
- rule reliability must be an explicit input, not an implicit assumption

### 6.2 `rules/runtime`

Responsibilities:

- evaluate rules against the code index and evidence-accessible facts
- emit support, contradiction, or unknown outputs

Output:

```ts
interface RuleEvidenceOutput {
  ruleId: string;
  ruleVersion: string;
  status: "support" | "contradict" | "unknown";
  evidence: EvidenceRecord[];
  unresolvedReasons?: string[];
}
```

Invariants:

- rule outputs must be deterministic
- `unknown` outputs must include unresolved reasons
- support outputs must include evidence records

Failure semantics:

- rule runtime bugs fail the run or the rule explicitly, based on policy
- missing required fact kinds prevent verified conclusions

## 7. Context Selection Contracts

### 7.1 `context/selector`

Responsibilities:

- generate bounded `ContextBundle` inputs for agents or specialist review steps

Input:

```ts
interface ContextRequest {
  triggerType: "rule" | "issue" | "evidence";
  triggerId: string;
  maxFiles: number;
  maxSpans: number;
  maxTokens?: number;
}
```

Output:

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

Invariants:

- context selection must be reproducible
- selected spans must remain within explicit budgets
- selection trace must explain why spans were included

Failure semantics:

- insufficient context may return a small but valid bundle plus unresolved reason
- context selector may not silently expand to whole-repo scope

## 8. Agent Contracts

### 8.1 `agents/orchestrator`

Responsibilities:

- decide if an agent should run
- choose agent kind
- prepare context bundle
- normalize output

Input:

- unresolved issues
- issue conflicts
- policy configuration

Output:

```ts
interface AgentTask {
  id: string;
  kind: "bug" | "design" | "security";
  issueType: string;
  question: string;
  context: ContextBundle;
  constraints: {
    maxFiles: number;
    maxTokens: number;
    allowSpeculation: false;
  };
}
```

Invariants:

- agent execution is lazy
- orchestrator decisions must be recorded in trace output

### 8.2 `agents/<kind>`

Output:

```ts
interface AgentResult {
  taskId: string;
  status: "completed" | "insufficient_context" | "failed";
  emittedEvidence: EvidenceRecord[];
  unresolvedReasons?: string[];
}
```

Invariants:

- agent results must not bypass evidence normalization
- free-form narrative without evidence payload is insufficient
- an agent may return no new evidence if context is insufficient

## 9. Aggregation Contracts

### 9.1 `aggregation/fingerprint`

Responsibilities:

- compute deterministic issue fingerprints

Input:

- normalized evidence

Output:

- fingerprint string

Invariants:

- same evidence set must generate the same fingerprint
- equivalent issue instances should converge where conservative merge is intended

### 9.2 `aggregation/cluster`

Responsibilities:

- group evidence into issue candidates

Output:

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

Invariants:

- clusters must preserve all contributing evidence IDs
- contradictory evidence IDs must remain attached
- clustering must be deterministic

## 10. Confidence Contracts

### 10.1 `confidence/engine`

Responsibilities:

- score issue candidates
- produce breakdown data

Output:

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

Invariants:

- final confidence must be clamped to `0..1`
- component values must be machine-readable
- low-quality or contradictory support must reduce final confidence

## 11. Skill Contracts

### 11.1 `skills/scoring`

Responsibilities:

- compute skill scores from issues and evidence

Output:

```ts
interface SkillScore {
  skillId: string;
  score: number;
  confidence: number;
  contributingIssueIds: string[];
  contributingEvidenceIds: string[];
}
```

Invariants:

- every skill score must be attributable
- unsupported scores may not be emitted as meaningful output

## 12. Reporting Contracts

### 12.1 `reporting/report`

Responsibilities:

- generate `report.json`

Invariants:

- issues reference evidence IDs
- report is derived, not authoritative over evidence store

### 12.2 `reporting/evidence`

Responsibilities:

- generate `evidence.json`

Invariants:

- contains normalized evidence as emitted and accepted by the pipeline

### 12.3 `reporting/skills`

Responsibilities:

- generate `skills.json`

### 12.4 `reporting/trace`

Responsibilities:

- generate `trace.json`

Invariants:

- includes scan boundary, versions, context selection events, and agent executions

### 12.5 `reporting/signature`

Responsibilities:

- generate `signature.json`

Invariants:

- includes per-artifact hashes and bundle hash

## 13. Cross-Module Invariants

The following invariants span the full system:

1. No final issue without evidence references.
2. No evidence without producer identity.
3. No agent contribution without trace record.
4. No skill score without issue and evidence contributors.
5. No report artifact outside the declared bundle contract.

## 14. Implementation Readiness

The v2 implementation is considered sufficiently specified when engineering can:

- implement modules independently against these contracts
- write contract tests without requiring architecture reinterpretation
- connect module outputs through deterministic interfaces
- validate end-to-end behavior through artifact audits

This document is intended to define that readiness boundary.
