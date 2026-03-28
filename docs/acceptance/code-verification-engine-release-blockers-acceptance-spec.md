# Code Verification Engine Release-Blocking Acceptance Specification

## 1. Purpose

This document defines the minimum acceptable state before version closeout.

## 2. Acceptance Questions

Closeout is allowed only if the answer to both questions is yes:

1. can the deterministic engine produce canonical artifacts without finding-first fallback?
2. can bounded agent participation occur without bypassing canonical evidence normalization?

## 3. Required Evidence

- release-blocking fixture corpus passes
- canonical artifact contracts validate
- repeated runs are stable
- documentation and release gate terminology are aligned

## 4. Failure Conditions

Closeout fails if:

- any blocker still depends on historical finding semantics
- `report.json` and `trace.json` disagree on issue derivation
- release gate checks duplicate or obsolete artifact paths
