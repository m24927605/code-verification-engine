# Code Verification Engine v2 Aggregation Hardening Specification

## 1. Purpose

This document defines the remaining work required to harden issue aggregation in Code Verification Engine v2.

The goal is to move from a conservative initial clustering implementation to a stable, auditable, and policy-driven aggregation layer suitable for production verification.

## 2. Current State

The current aggregation layer already supports:

1. deterministic clustering
2. same-file merge logic
3. same-symbol merge logic
4. nearby-line merge fallback
5. severity escalation on merge

This is sufficient for a bootstrap phase, but not the full production target.

## 3. Hardening Objectives

Aggregation hardening must provide:

1. stable issue fingerprinting
2. clearer merge vs non-merge policy
3. conflict retention
4. multi-source agreement visibility
5. less reliance on incidental overlap

## 4. Required Hardening Areas

### 4.1 Fingerprint Stability

Issue fingerprints must remain stable under:

1. repeated execution
2. deterministic evidence ordering changes
3. compatibility output refactors

### 4.2 Merge Policy

Merge policy must be explicit for:

1. same symbol, same file
2. same file, overlapping lines
3. different files
4. different statuses
5. different source mixes

### 4.3 Conflict Retention

Aggregation must preserve conflicting or counter-evidence rather than flattening it away.

### 4.4 Multi-Source Agreement

Aggregation must expose whether an issue is supported by:

1. one deterministic rule
2. multiple deterministic rules
3. deterministic plus agent support

### 4.5 Rule Family Sensitivity

Different rule families may eventually need different merge policies.

The hardening goal is not to encode all possible family-specific logic now, but to prepare the aggregation layer so those policies can be introduced without redesign.

## 5. Required Work Items

1. formalize issue fingerprint contract
2. formalize merge decision contract
3. add counter-evidence fields where needed
4. add source agreement counters or normalized summaries
5. add more aggregation fixtures for boundary cases

## 6. Acceptance Requirements

Aggregation hardening is complete only when:

1. duplicate logical issues merge reliably
2. unrelated issues do not merge
3. conflicting support is preserved
4. issue fingerprints remain stable across reruns
5. merge behavior is protected by regression fixtures

