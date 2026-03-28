# Code Verification Engine v2 Local Release Gate

## 1. Purpose

This document defines the local release gate for Code Verification Engine v2 in the absence of CI/CD.

It is the authoritative checklist for deciding whether a candidate version is acceptable for local release, milestone tagging, or manual deployment preparation.

## 2. Principle

Until CI/CD exists, the release gate is a **manually executed but strictly defined** verification process.

The rule is simple:

**If any release gate step fails, the version is not V2-ready.**

## 3. Required Commands

The following commands must all pass:

```bash
go test ./internal/rules
go test ./internal/report
go test ./internal/artifactsv2
go test ./internal/acceptance
go test ./internal/engine
go test ./pkg/cve
```

## 4. Required Manual Checks

The following conditions must be confirmed before release:

1. acceptance fixtures for deterministic path are green
2. aggregation merge / non-merge fixtures are green
3. confidence penalty and cap fixtures are green
4. verifiable bundle artifacts validate successfully
5. issue candidate set remains the deterministic primary product

## 5. Release-Blocking Conditions

Release is blocked if any of the following occur:

1. artifact contract validation fails
2. deterministic hash checks fail
3. aggregation regression fixtures fail
4. confidence boundary fixtures fail
5. unknown or agent-only caps regress
6. engine no longer produces canonical issue candidate output

## 6. Recommended Execution Order

Run in this order:

1. `go test ./internal/rules`
2. `go test ./internal/report`
3. `go test ./internal/artifactsv2`
4. `go test ./internal/acceptance`
5. `go test ./internal/engine`
6. `go test ./pkg/cve`

Reason:

- fail fast on core deterministic logic
- validate artifact core before engine integration
- validate engine before public API bridge

## 7. Exit Rule

A build may be called locally release-ready only if:

1. all required commands pass
2. no release-blocking condition is present
3. no known deterministic regression remains unresolved

