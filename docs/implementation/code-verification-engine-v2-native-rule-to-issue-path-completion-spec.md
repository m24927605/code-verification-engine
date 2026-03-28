# Code Verification Engine v2 Native Rule-to-Issue Path Completion Specification

## 1. Purpose

This document defines the remaining work required to complete the native rule-to-issue path in Code Verification Engine v2.

The specific objective is to eliminate the semantic dependency on legacy finding-first behavior in the deterministic v2 core, while preserving compatibility outputs for as long as needed.

## 2. Current State

The current implementation already provides:

1. native `rules.IssueSeed`
2. deterministic issue seed production in the rules layer
3. seed-native evidence synthesis in the v2 builder
4. `IssueCandidateSet` as the canonical deterministic v2 product

However, the system still has transitional characteristics:

1. many rule families still derive issue meaning indirectly through legacy finding semantics
2. evidence creation still assumes a compatibility bridge in some paths
3. rule family semantics are not yet uniformly encoded as first-class issue-oriented outputs

## 3. Target State

The target deterministic path is:

```text
facts / index
-> rule evaluation
-> rule-native issue semantics
-> issue seeds
-> evidence store
-> issue candidates
-> confidence
-> artifact projection
```

The architectural rule is:

**A rule should express issue semantics directly, not merely emit a legacy finding that is later reinterpreted.**

## 4. Completion Objectives

The native rule-to-issue path is complete only when all of the following are true:

1. all priority deterministic rule families emit stable issue seeds directly
2. issue title/category/severity are sourced from rule definition or rule-native semantics, not late heuristics
3. evidence IDs are stable before aggregation
4. issue candidate formation no longer depends on legacy finding shape for normal execution

## 5. Priority Rule Families

The migration should proceed in this order:

1. security proof-grade rules
2. structural architecture / design rules
3. heuristic quality rules
4. remaining unknown/runtime-required rule families

Reason:

- proof-grade security rules drive the highest trust requirements
- architecture rules stress aggregation and cross-file semantics
- heuristic quality rules are lower trust and can migrate later

## 6. Required Design Rules

### 6.1 Rule Metadata Is Authoritative

For each migrated rule family:

1. issue title comes from rule metadata or explicit rule-native issue label
2. category comes from explicit rule definition
3. severity comes from explicit rule definition or deterministic downgrade policy

### 6.2 Seed Production Must Be Deterministic

Rule-native seed generation must not depend on:

1. markdown rendering
2. post-hoc narrative formatting
3. non-deterministic agent output

### 6.3 Evidence Must Exist Before Aggregation

Issue seeds must either:

1. carry stable evidence IDs, or
2. deterministically synthesize them before aggregation

### 6.4 Unknown Is Explicit

Rules that cannot establish sufficient support must produce:

1. unknown-compatible seed, or
2. evidence without issue promotion

They must not silently convert uncertainty into confident issue output.

## 7. Required Implementation Work

### 7.1 Rule Family Audit

For each active deterministic rule family, classify:

1. current producer shape
2. current title/category/severity source
3. evidence source quality
4. migration difficulty

### 7.2 Rule-Native Issue Semantics

For migrated rule families, implement explicit issue semantics:

1. canonical issue title
2. canonical category
3. canonical severity
4. seed status logic
5. evidence quality policy

### 7.3 Direct Seed Construction

Refactor priority rule families so they produce seeds directly from rule evaluation state rather than via finding reinterpretation.

### 7.4 Compatibility Boundary Reduction

Keep legacy findings for compatibility output, but stop using them as the semantic source for the v2 primary path.

### 7.5 Migration Tracking

Maintain a rule-family migration matrix with states:

- `legacy_only`
- `finding_bridged`
- `seed_native`
- `issue_native`

## 8. Acceptance Requirements

The native rule-to-issue path is complete only when:

1. all priority rule families are at least `seed_native`
2. evidence IDs are stable across repeated runs
3. issue candidate semantics match rule definition semantics
4. compatibility output no longer defines the v2 path

## 9. Success Criteria

Success means:

1. the deterministic v2 core no longer reconstructs issue meaning late in the pipeline
2. rule semantics are explicit and auditable
3. issue candidates are the true primary deterministic verification product

