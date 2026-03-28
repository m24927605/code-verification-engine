# Code Verification Engine v2 Acceptance Harness Expansion Plan

## 1. Purpose

This document defines the next expansion phase for the v2 acceptance harness.

The harness already has a minimal executable skeleton. The next goal is to grow it into a practical regression wall for the deterministic v2 core without turning it into an oversized framework.

## 2. Current State

The acceptance harness already includes:

1. fixture manifest shape
2. bundle assertions
3. deterministic hash assertions
4. executable compatibility fixture runner
5. a small set of critical regression fixtures

## 3. Expansion Objectives

The harness expansion must:

1. add fixture coverage where the deterministic core is still fragile
2. keep execution practical for local use
3. remain simple enough to eventually move into CI/CD without redesign

## 4. Immediate Expansion Areas

### 4.1 Aggregation Boundary Fixtures

Add fixtures for:

1. same symbol merge
2. nearby line merge
3. different file non-merge
4. status mismatch non-merge

### 4.2 Confidence Boundary Fixtures

Add fixtures for:

1. unknown cap
2. agent-only cap
3. degraded penalty
4. multi-rule support boost

### 4.3 Evidence Integrity Fixtures

Add fixtures for:

1. explicit evidence ID preservation
2. synthetic evidence generation
3. report/trace/evidence cross-reference agreement

### 4.4 Reproducibility Fixtures

Add fixtures for:

1. stable artifact hashes
2. stable issue IDs
3. stable evidence IDs

## 5. Expansion Constraints

The harness must not expand into:

1. a generic scenario DSL before needed
2. a large orchestration framework
3. excessive golden files that are hard to maintain

## 6. Deliverables

1. additional deterministic fixtures in `internal/acceptance`
2. repeatable local test commands
3. release gate checklist that references these fixture suites

## 7. Acceptance Requirements

Harness expansion is complete for this phase only when:

1. current deterministic weak spots are covered by fixtures
2. the harness remains fast enough for local execution
3. failures are understandable and directly actionable

