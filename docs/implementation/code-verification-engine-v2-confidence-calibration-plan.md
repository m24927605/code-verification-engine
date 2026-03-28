# Code Verification Engine v2 Confidence Calibration Plan

## 1. Purpose

This document defines how the v2 confidence engine must be calibrated after the baseline deterministic formula is in place.

The goal is not to maximize scores. The goal is to ensure that score ordering, thresholds, and policy caps reflect actual verification quality and trust boundaries.

## 2. Current State

The system already has:

1. deterministic issue-level confidence breakdown
2. degradation penalties
3. agent-only penalties
4. policy caps for `unknown` and `agent-only` cases

What is still missing:

1. empirical calibration of rule reliability
2. policy thresholds for machine-trusted eligibility
3. score validation against representative fixtures

## 3. Calibration Objectives

Calibration must answer:

1. which rule families deserve higher rule reliability
2. what final score range qualifies for machine-trusted presentation
3. how much partial scans and degraded analyzers should reduce confidence
4. how much mixed-source or agent-heavy support should be penalized

## 4. Calibration Principles

1. calibrate to reduce unsafe confidence inflation
2. prefer conservative thresholds
3. do not tune for cosmetic score distribution
4. keep the formula deterministic and auditable

## 5. Calibration Inputs

Calibration must use fixture groups covering:

1. proof-backed deterministic issues
2. structural issues
3. heuristic-only issues
4. degraded / partial scan cases
5. contradiction or weak-support cases
6. agent-only and mixed-source cases

## 6. Calibration Outputs

Calibration must produce:

1. per-rule-family reliability baselines
2. confidence thresholds for:
   - machine-trusted eligibility
   - advisory publication
   - unknown retention
3. expected score ordering rules

## 7. Required Calibration Phases

### Phase 1: Baseline Validation

Validate that current score ordering is correct on existing fixtures.

### Phase 2: Rule Family Reliability Table

Introduce a rule-family reliability table with conservative defaults.

### Phase 3: Threshold Policy

Set thresholds for:

1. machine-trusted issue eligibility
2. advisory issue eligibility
3. mandatory unknown downgrade

### Phase 4: Regression Lock

Turn calibrated expectations into regression fixtures and release gate checks.

## 8. Required Deliverables

1. rule-family reliability table
2. threshold policy document
3. calibrated fixture set
4. regression checks for score ordering

## 9. Acceptance Requirements

Calibration is complete only when:

1. rule reliability is not derived purely from ad hoc heuristics
2. machine-trusted thresholds are explicit
3. calibration outcomes are locked by fixtures
4. score regressions are release-blocking

