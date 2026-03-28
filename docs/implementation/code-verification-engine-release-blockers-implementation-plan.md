# Code Verification Engine Release-Blocking Implementation Plan

## 1. Purpose

This document defines the implementation work that must be finished before version closeout.

## 2. Mandatory Deliverables

- canonical seed emission for release-blocking rule families
- report projection from canonical issue candidates
- deterministic confidence and trace generation
- release gate coverage for canonical artifacts
- repository-wide documentation cleanup

## 3. Ordered Work

1. finish rule-native metadata and seed emission
2. remove normal-path finding-derived seed fallback
3. switch report generation to canonical issue inputs
4. align skills and claims with canonical evidence inputs
5. update tests and fixtures
6. run repository audit and delete dead bridge code

## 4. Exit Criteria

Release-blocking work is complete only when:

1. all mandatory tests pass
2. bridge-dependent tests are either removed or rewritten
3. release gate exercises canonical artifacts only
4. docs, acceptance specs, and README describe the same architecture
