# Autonomous Calibration Framework

## Goal

Build a zero-human-in-the-loop calibration loop for `code-verification-engine` that:

- generates or curates repo fixtures across all supported profiles
- runs the real CLI / engine pipeline against those fixtures
- compares engine output against frozen expected truth contracts
- asks separate reviewer models to classify mismatches
- hands actionable discrepancy reports to a repair agent
- blocks promotions when frozen benchmarks regress

This is not a replacement for unit tests. It is a higher-level system for keeping analyzer, rule, and trust behavior aligned with real code.

## Core Principles

- Frozen truth beats reviewer opinion.
- Reviewer AI helps explain diffs; it does not redefine truth.
- Generated datasets may grow automatically, but promoted datasets must freeze.
- The repair agent may update engine code, but must not rewrite the frozen benchmark contract.
- Promotion is controlled by deterministic gates, not a single model verdict.

## Dataset Contract

The machine-readable contract lives in:

- `testdata/autobench/datasets/<dataset>/manifest.json`
- `testdata/autobench/datasets/<dataset>/expected/*.json`

The schema is implemented in:

- `internal/autobench/schema.go`
- `internal/autobench/loader.go`

### `manifest.json`

Defines:

- dataset mode: `frozen`, `generated`, or `shadow`
- adjudication policy
- promotion gate policy
- suites grouped by `profile`
- repo fixtures and expected outcome files per case

### `expected/*.json`

Defines:

- target rule expectations
- exact or allowed statuses
- expected trust class
- evidence floor
- blocking vs advisory priority
- rationale

This is the truth contract used for regression gating.

## Recommended Workflow

1. Generator agent creates or mutates candidate repos in a `generated` dataset.
2. `cve verify` runs against every case and stores `actual/` outputs.
3. A diff step compares `actual/report.json` against the frozen `expected/*.json`.
4. Reviewer agent A performs code review against the repo and the diff.
5. Reviewer agent B is required for protected classes such as `machine_trusted`, `trusted-core`, or critical security findings.
6. An adjudication step writes `adjudication.json` and `discrepancy.md`.
7. A repair agent edits analyzer / rule / report code.
8. The full frozen dataset reruns.
9. Promotion is accepted only if gate conditions still hold.

## Gate Policy

The initial gate policy in `autocal-v1` encodes these defaults:

- no frozen regressions
- no schema contract violations
- `trusted-core` must stay clean
- no new `unknown` findings
- minimum precision thresholds by trust class
- dataset contract paths are protected from repair-agent edits

This keeps the system from “winning” by weakening the benchmark or rewriting truth data.

## Separation Of Roles

Use distinct agents or models for:

- generator
- reviewer/adjudicator
- repair

Distinct models reduce correlated bias, but they are not sufficient on their own. Frozen truth contracts and deterministic gates remain the primary anti-drift mechanism.

## Initial Coverage

`autocal-v1` is intentionally small but multi-profile:

- backend Go
- backend Python
- frontend JavaScript
- fullstack TypeScript with claim-set coverage

The next expansion should add:

- `backend-api-strict`
- `design-patterns`
- more `trusted-core` cases
- false-positive and false-negative guards per rule family
- generated suites for NestJS, React, Next.js, and Django/FastAPI variants

## Next Implementation Step

The next code step after this scaffold is a runner that:

- loads `manifest.json`
- executes `engine.Run` or `cve verify`
- writes `actual/scan.json`, `actual/report.json`
- computes diffs against expected
- emits machine-readable adjudication input for reviewer agents

That runner should remain deterministic and should treat LLM output as evidence, not as the source of truth.
