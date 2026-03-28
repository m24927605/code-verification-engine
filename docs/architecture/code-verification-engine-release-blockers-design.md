# Code Verification Engine Release-Blocking Design Specification

## 1. Purpose

This document defines the architecture-level scope that must be complete before version closeout.

## 2. Release-Blocking Requirements

The following are mandatory:

1. canonical issue semantics for all release-blocking rule families
2. canonical evidence store and issue candidate set
3. report and trace generation from canonical data only
4. bounded agent runtime that feeds normalized evidence only
5. release gates and docs aligned with single-path terminology

## 3. Blockers

Version closeout is blocked if:

- any release-blocking rule still requires finding reinterpretation
- report semantics differ from trace semantics
- confidence depends on bridge-only metadata
- release gates still verify duplicate artifact lineages

## 4. Non-Blockers

The following may continue after version closeout if they do not weaken canonical outputs:

- additional rule family migration beyond the release-blocking set
- broader benchmark expansion
- new projection artifacts built strictly from canonical evidence and issue data
