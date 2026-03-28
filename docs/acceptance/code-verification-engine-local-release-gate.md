# Code Verification Engine Local Release Gate

## 1. Purpose

This document defines the local release gate in the absence of CI/CD.

## 2. Gate Objective

The gate must prove that canonical artifacts, deterministic execution, and single-path semantics remain intact.

## 3. Minimum Commands

```bash
go test ./internal/artifactsv2
go test ./internal/acceptance
go test ./pkg/cve
go test ./...
```

## 4. Pass Conditions

Release is allowed only when:

1. canonical artifact tests pass
2. acceptance fixtures pass
3. API bridging tests do not require finding-first semantics for correctness
4. documentation audit shows no staged-generation wording in repo docs
