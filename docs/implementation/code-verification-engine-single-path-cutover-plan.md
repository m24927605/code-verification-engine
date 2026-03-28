# Code Verification Engine Single-Path Cutover Plan

## 1. Purpose

This document is the explicit cutover plan for full removal of the historical finding-first path.

## 2. Scope

The cutover covers:

- design
- runtime implementation
- public contracts
- tests and fixtures
- release gates
- repository documentation

## 3. Required Repository Changes

### 3.1 Design

- define `IssueCandidateSet` as the only semantic source of truth
- define `EvidenceStore` as the only factual source of truth
- prohibit release decisions derived from raw finding totals

### 3.2 Runtime

- remove normal-path finding-to-seed fallback
- project `report.json` from canonical issue/evidence data
- keep raw finding data only if retained as non-semantic audit data

### 3.3 Public API

- de-emphasize or retire finding-centered public fields
- document canonical artifact expectations in README and contracts
- align CLI and release gate wording with single-path semantics

### 3.4 Tests

- rewrite bridge-era unit tests to canonical seed-first expectations
- add regression tests that fail if findings become the semantic source again
- require acceptance fixtures to validate issue/evidence lineage

### 3.5 Documentation

- remove staged-generation naming from file names and headings
- remove wording that implies multiple active architecture generations
- document historical bridge behavior only when strictly necessary for deletion tracking

## 4. Completion Checklist

- no canonical artifact depends on finding-first semantics
- no release gate references bridge-only outputs
- docs and README use canonical terminology only
- repository search confirms staged-generation terms are removed from docs
- remaining historical identifiers are either deleted or confined to code-level audit metadata
