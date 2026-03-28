# Code Verification Engine Architecture Design Specification

## 1. Purpose

This document defines the steady-state architecture for Code Verification Engine.

The engine has a single canonical verification path:

`repo snapshot -> indexed facts -> rule-native issue seeds -> evidence store -> issue candidates -> confidence -> artifacts`

There is no finding-first bridge, no parallel projection path, and no alternate report lineage.

## 2. Goals

The architecture must guarantee:

1. evidence-backed outputs
2. deterministic default execution
3. issue semantics expressed directly by rules
4. a single artifact lineage from source evidence to final report
5. bounded optional agent participation
6. reproducible, auditable release gating

## 3. Principles

### 3.1 Evidence-First

Evidence is the source of truth. Reports, scores, summaries, and traces are derived artifacts.

### 3.2 Single-Path Execution

The engine has one canonical deterministic path. Historical finding projections, bridge adapters, and duplicate semantic paths are removed.

### 3.3 Rule-Native Semantics

Rules express issue title, category, severity, status policy, and minimum evidence requirements directly. Issue meaning is not reconstructed later from generic findings.

### 3.4 Conservative Verification

If the engine lacks sufficient support, boundary completeness, or contradiction resolution, it downgrades confidence or returns unknown. It does not guess.

### 3.5 Bounded Agents

Agents are optional. They consume bounded context and emit normalized evidence only. They never bypass evidence validation or author final issue semantics.

## 4. Canonical Data Flow

```text
Repo Snapshot
-> Scan Boundary
-> Language Analyzers
-> Code Index
-> Rule Evaluation
-> Issue Seeds
-> Evidence Store
-> Issue Candidate Set
-> Confidence Engine
-> Skills / Claims / Scenario Projections
-> report.json / evidence.json / trace.json / skills.json / signature.json
```

## 5. Core Layers

### 5.1 Snapshot and Boundary

Responsibilities:

- resolve repo path, ref, commit, and scan root
- define included files exactly
- compute deterministic boundary metadata

Outputs:

- `RepoSnapshot`
- `ScanBoundary`
- `FileManifest`

### 5.2 Analysis and Indexing

Responsibilities:

- parse supported languages
- extract facts, entities, routes, bindings, dependencies, and file roles
- build canonical indexed structures consumed by rules

Outputs:

- `FactSet`
- `CodeIndex`

### 5.3 Rule Evaluation

Responsibilities:

- evaluate deterministic rules on indexed facts
- emit rule-native `IssueSeed`
- emit normalized evidence references or synthetic seed evidence when needed
- surface unknown with explicit reasons

Outputs:

- `IssueSeed[]`
- `RuleMetadata`
- `SkippedRule[]`

### 5.4 Evidence Store

Responsibilities:

- normalize analyzer, rule, agent, and projection evidence
- assign deterministic IDs
- retain provenance, derivation, support, and contradiction links

Outputs:

- `EvidenceRecord[]`
- `EvidenceStore`

### 5.5 Issue Candidate Set

Responsibilities:

- cluster related issue seeds
- preserve counter-evidence
- produce canonical issue IDs and fingerprints
- attach supporting and contradicting evidence

Outputs:

- `IssueCandidate[]`

### 5.6 Confidence Engine

Responsibilities:

- compute numeric confidence
- apply penalties for contradiction, degraded analyzers, incomplete boundary, or weak source mix
- emit explainable breakdown

Outputs:

- `ConfidenceBreakdown`
- issue-level `confidence` and `policy_class`

### 5.7 Projection Layer

Responsibilities:

- derive report, trace, skills, claims, profile, resume, and scenario artifacts from the canonical issue/evidence set

Requirement:

- projections may not invent semantics unavailable in `IssueCandidateSet` or `EvidenceStore`

## 6. Canonical Artifacts

The architecture treats the following as first-class release artifacts:

- `report.json`
- `evidence.json`
- `trace.json`
- `skills.json`
- `summary.md`
- `signature.json`

Optional projections:

- `claims.json`
- `profile.json`
- `resume_input.json`
- scenario acceptance artifacts

## 7. Removed Architectural Elements

The following are not part of the target architecture:

- finding-first semantic flow
- post-rule issue reconstruction from generic findings
- duplicate report contracts describing the same verification result
- secondary bundles used as a second-class projection target
- release decisions based on raw finding counts instead of canonical issue data

## 8. Release Condition

The architecture is complete only when:

1. rules emit issue-native seeds for all release-blocking rule families
2. `IssueCandidateSet` is the only semantic source for downstream artifacts
3. report, trace, skills, and claims projections derive from the same evidence store
4. no removal blocker depends on historical finding semantics
