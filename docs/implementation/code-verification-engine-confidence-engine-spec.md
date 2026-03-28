# Code Verification Engine Confidence Engine Specification

## 1. Purpose

This document defines the canonical confidence model.

## 2. Inputs

Confidence is computed from:

- evidence quality
- source diversity
- contradiction presence
- boundary completeness
- analyzer degradation
- context completeness
- agent dependence

## 3. Requirements

1. confidence is numeric in `0..1`
2. confidence is deterministic for the same canonical inputs
3. contradiction and degraded support reduce confidence
4. unsupported or agent-only support cannot produce release-grade certainty

## 4. Output

Each issue must expose:

- `confidence`
- `confidence_class`
- `policy_class`
- `confidence_breakdown`

## 5. Cutover Rule

The confidence engine is complete only when it operates exclusively on canonical issue/evidence data and does not consult finding-first bridge semantics.
