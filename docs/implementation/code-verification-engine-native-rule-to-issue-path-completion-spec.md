# Code Verification Engine Native Rule-to-Issue Path Completion Specification

## 1. Purpose

This document defines the remaining work needed to make the rule-to-issue path complete and exclusive.

## 2. Problem Statement

Any runtime path that still depends on generic findings to recover issue meaning is incomplete. The engine must instead treat rule-native issue seeds as the first complete semantic object.

## 3. Required Properties

1. rules express issue semantics directly
2. unknown remains explicit and structured
3. evidence synthesis happens before aggregation
4. issue candidates are canonical before projection

## 4. Required Rule Metadata

Each release-blocking rule family must define:

- canonical title
- canonical category
- canonical severity
- status policy
- minimum support requirement
- migration/audit metadata if retained

## 5. Completion Tasks

- finish native seed emission for remaining rule families
- remove late-stage semantic reinterpretation helpers from the normal path
- make builder code reject incomplete seed semantics
- align tests around seed-first behavior

## 6. Completion Test

This path is complete only when a release-blocking run can produce canonical issue candidates, report artifacts, and trace artifacts without any semantic fallback to generic findings.
