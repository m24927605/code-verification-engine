# Fullstack Signal Calibration Plan

## Purpose

Improve `code-verification-engine` so `fullstack` scans are easier to trust and easier to act on.

This plan is driven by a real scan of `CodeVera` where:

- profile: `fullstack`
- summary: `pass=25 fail=32 unknown=0`
- most findings were `advisory`
- most findings were `capability_partial`
- `19 / 32` fails were `GOF-*` pattern detections
- architecture rules included evidence from `__tests__` and integration test files

The problem is not only precision. The larger problem is **signal calibration**:

- critical issues and informational findings share the same `fail` bucket
- test fixtures pollute architecture/security evidence
- summary counts overstate actionable risk
- profile output is technically valid but operationally misleading

## Goals

1. Reduce misleading `fail` counts in `fullstack` scans.
2. Separate actionable risk from informational pattern detection.
3. Exclude or heavily down-rank test code for architecture and security rules.
4. Add guards for test-fixture secrets.
5. Preserve deterministic behavior and auditable output.

## Non-Goals

- No rule DSL redesign in this phase.
- No LLM-only post-processing as the source of truth.
- No silent auto-suppression of findings without explicit reporting.
- No relaxation of `machine_trusted` guarantees without benchmark evidence.

## Current Failure Modes

### 1. GOF Findings Inflate `fail`

In `fullstack`, `GOF-*` findings are counted alongside security and architecture failures.

Effect:

- large `fail` totals
- low operator trust in the summary
- poor prioritization in CI and dashboards

This is a reporting and product-shaping issue, not only a matcher issue.

### 2. Test Code Pollutes Architecture Rules

Rules like:

- `ARCH-LAYER-001`
- `ARCH-PATTERN-001`

currently accept evidence from files such as:

- `__tests__/...`
- `*.spec.ts`
- `test/...`
- integration test fixtures

Effect:

- direct DB access in tests is treated like production-layer violations
- controller/repository boundaries look worse than they are
- evidence counts become inflated and hard to review

### 3. Test Fixture Secrets Pollute `SEC-SECRET-001`

The scan showed `SEC-SECRET-001` evidence from:

- a real frontend auth file
- multiple `__tests__` files

Effect:

- a true finding may be mixed with lower-value fixture hits
- reviewers cannot quickly distinguish production secrets from test placeholders
- the `machine_trusted` result remains technically valid but operationally noisy

### 4. Summary Collapses Different Kinds of Failure

The current summary exposes only:

- `pass`
- `fail`
- `unknown`

That is insufficient once the profile includes:

- critical security rules
- advisory quality rules
- pattern-detection rules
- human/runtime-required findings

## Proposed Solution

The solution has four coordinated parts.

## Part A: Introduce Finding Outcome Classes

Keep rule-level `status` as-is for consumer continuity, but add a second reporting dimension:

- `actionable_fail`
- `advisory_fail`
- `informational_detection`
- `unknown`

### Mapping Rules

Initial mapping:

- security and architecture rules with negative assertion semantics:
  - `actionable_fail` or `advisory_fail`
- quality rules:
  - usually `advisory_fail`
- GoF detection rules:
  - `informational_detection`

### Reporting Contract

Add a new summary block to `report.json` and `report.md`:

```json
"signal_summary": {
  "actionable_fail": 7,
  "advisory_fail": 6,
  "informational_detection": 19,
  "unknown": 0
}
```

This does not replace the existing summary immediately. It augments it.

### Expected Outcome

The operator still sees rule truth, but can distinguish:

- what should block release
- what needs engineering review
- what is merely descriptive/pattern-like

## Part B: Add Test-Aware Scope Filtering

Introduce centralized file-scope classification for:

- production code
- test code
- fixtures/generated/mock code

### Initial Path Heuristics

Mark as test scope if path matches:

- `**/__tests__/**`
- `**/test/**`
- `**/tests/**`
- `**/*.spec.ts`
- `**/*.spec.js`
- `**/*.test.ts`
- `**/*.test.js`
- `**/*.test.py`

Mark as generated/mock/fixture scope if path matches:

- `**/fixtures/**`
- `**/__fixtures__/**`
- `**/__mocks__/**`
- `**/mocks/**`
- `**/generated/**`

### Rule Policy

For these rules, exclude test scope evidence by default:

- `ARCH-LAYER-001`
- `ARCH-PATTERN-001`
- `ARCH-PATTERN-002`
- `ARCH-PATTERN-003`
- `ARCH-ERR-001`
- `QUAL-LOG-001`
- `QUAL-LOG-002`

For these rules, test scope should not produce a fail by itself:

- `SEC-SECRET-001`
- `SEC-INPUT-001`
- `SEC-HELMET-001`
- `SEC-RATE-001`
- `FE-TOKEN-001`

Instead:

- production evidence keeps normal behavior
- test-only evidence becomes downgraded evidence or a separate note

### Output Behavior

If a finding is triggered only by test scope:

- do not emit `machine_trusted fail`
- emit either:
  - `advisory_fail`, or
  - a dedicated note in report output such as `test_scope_only_evidence`

## Part C: Reclassify GOF Rules

`GOF-*` rules should stop behaving like normal failures in `fullstack`.

### Design

Keep detection, but mark them as:

- `status=pass` with `pattern_detected=true`, or
- retain `status=fail` internally but exclude them from actionable fail summary

Preferred option:

- preserve current matcher behavior internally
- classify all `GOF-*` findings as `informational_detection` in report aggregation

This minimizes matcher churn and avoids breaking current tests immediately.

### Report Rendering

Add a dedicated section:

```md
## Pattern Detections
- GOF-C-001 Singleton pattern detected
- GOF-B-009 Strategy pattern detected
```

Do not mix this section into primary failure counts intended for engineering action.

## Part D: Tighten Secret Rule with Fixture Guards

`SEC-SECRET-001` needs a production-aware false-positive guard.

### Policy

If all evidence is from:

- test files
- fixtures
- mocks

then the rule must not emit `machine_trusted fail`.

Allowed behaviors:

- emit `advisory_fail`
- emit `pass` with note
- emit a separate low-trust finding category such as `test_fixture_secret`

Preferred first step:

- downgrade trust when all evidence is non-production
- keep `machine_trusted` only when at least one production-scope secret exists

### Why

This preserves strong enforcement for real secrets while avoiding overclaiming on benchmark fixtures and tests.

## Architecture Changes

## 1. Add File Scope Classification

New internal package or helper:

- `internal/scope/` or `internal/report/scope.go`

Responsibilities:

- classify path into `production`, `test`, `fixture`, `generated`
- expose helper used by analyzers, matchers, and report aggregation

## 2. Annotate Evidence with Scope

Extend evidence handling in memory so report generation knows whether evidence came from:

- production code
- test code
- fixtures

This can be done either by:

- extending `rules.Evidence`, or
- enriching evidence only in report aggregation metadata

Preferred first step:

- do not change public JSON evidence schema yet
- compute scope during aggregation from file path

## 3. Add Signal Aggregation Layer

Create a reporting helper that converts raw findings into:

- raw summary
- trust summary
- capability summary
- new signal summary

This keeps matcher semantics stable while improving operator-facing output.

## 4. Centralize Rule Reclassification

Do not scatter special cases through matchers.

Add a central policy table:

- `GOF-*` => informational detection
- selected rules ignore test-only evidence
- selected rules downgrade trust on test-only evidence

Best location:

- `internal/report/`
- or a new `internal/policy/` package if the table grows

## Rollout Plan

## Phase 1: Reporting-Only Calibration

Implement:

- signal summary
- GOF reclassification in report aggregation
- pattern-detection markdown section

No matcher changes yet.

Success criteria:

- `fullstack` reports show lower actionable fail counts
- raw rule findings remain unchanged

## Phase 2: Test Scope Filtering

Implement:

- shared path classification
- exclude test evidence from architecture/quality rules
- downgrade test-only secret evidence

Success criteria:

- benchmark cases involving test fixtures stop inflating architecture/security findings
- no regression on true production-scope failures

## Phase 3: Precision Tightening

Implement:

- stronger matcher guards for JS/TS architecture rules
- better production handler vs test helper differentiation
- optional framework-aware controller/repository context tightening

Success criteria:

- fewer advisory false positives
- lower evidence noise
- improved precision on frozen dataset

## Benchmark And Gate Updates

The autonomous calibration framework already added in this repo should be extended to cover this work.

Add frozen cases for:

- `fullstack` with many GoF detections but few real security issues
- architecture violations in production code only
- identical DB access patterns in test code only
- real production secret vs fixture-only secret

Required gate conditions:

- no regression in `trusted-core`
- no increase in production-scope secret false positives
- no architecture fail triggered solely by test files
- GOF detections excluded from actionable fail summary

## Acceptance Criteria

For a scan like `CodeVera`, the report should satisfy:

1. GOF findings appear in a separate pattern-detection section.
2. The main failure summary distinguishes actionable vs informational outcomes.
3. Test files do not dominate evidence for architecture violations.
4. `SEC-SECRET-001` keeps `machine_trusted` only when production files are implicated.
5. The final report is more aligned with operator intuition without hiding real issues.

## Risks

### Risk: Over-filtering test evidence hides real issues

Mitigation:

- keep test-only evidence visible in notes
- exclude it from blocking summaries, not from existence entirely

### Risk: report consumer continuity

Mitigation:

- keep current summary fields
- add new signal summary fields alongside them

### Risk: GOF users still want raw detections

Mitigation:

- preserve detections
- only change aggregation and presentation

## Recommended First Implementation Order

1. Add signal summary to report generation.
2. Reclassify `GOF-*` into informational detection.
3. Add shared test/fixture path classifier.
4. Apply classifier to report aggregation and secret trust downgrade.
5. Apply classifier to architecture matcher evidence filtering.
6. Extend autobench frozen datasets for these cases.

## Expected Outcome

After this plan, a `fullstack` scan should stop reading like:

- “32 failures”

and start reading like:

- “7 actionable failures, 6 advisory failures, 19 pattern detections”

That is the actual product improvement needed here: not only better precision, but better calibrated truth presentation.
