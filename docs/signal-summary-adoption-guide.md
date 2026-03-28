# Signal Summary Adoption Guide

## Purpose

Standardize how humans and systems consume `code-verification-engine` results after the introduction of `signal_summary`.

This guide exists to prevent a common failure mode:

- the engine now distinguishes actionable failures from informational detections
- but downstream users continue to read only raw `summary.fail`

If that happens, the product keeps behaving as if the calibration work never happened.

## Core Rule

Consumers MUST treat `signal_summary` as the primary operational summary.

Consumers MUST treat raw `summary` as raw status accounting, not as a release decision signal.

In practice:

- use `signal_summary.actionable_fail` for blocking decisions
- use `signal_summary.advisory_fail` for review queues and engineering backlog
- use `signal_summary.informational_detection` for descriptive reporting only
- use `summary.fail` only when raw finding accounting is needed

## Definitions

### `summary`

Raw rule-status totals:

- `pass`
- `fail`
- `unknown`

This remains useful for:

- consumer continuity
- low-level debugging
- contract consistency checks

It is not the recommended product-level decision surface.

### `signal_summary`

Operationally calibrated totals:

- `actionable_fail`
- `advisory_fail`
- `informational_detection`
- `unknown`

This is the recommended product-level decision surface.

## Consumer Policy

## 1. CLI

The CLI should present calibrated numbers first.

Recommended ordering:

1. actionable failures
2. advisory failures
3. informational detections
4. unknown
5. raw totals as secondary context

Expected behavior:

- terminal progress lines may still include raw `pass/fail/unknown`
- but calibrated counts must be included in the same line or shown earlier
- markdown report first screen must prioritize `actionable_fail`

## 2. `report.json` Consumers

Consumers of `report.json` must follow this precedence:

1. `signal_summary`
2. `trust_summary`
3. `capability_summary`
4. raw `summary`

Recommended interpretation:

- `actionable_fail > 0`
  - do not auto-approve
- `advisory_fail > 0 && actionable_fail == 0`
  - allow soft-fail or manual review flow
- `informational_detection > 0` only
  - do not block

## 3. Go API Consumers

Consumers of `pkg/cve` must read:

- `VerifyOutput.Report.SignalSummary`
- not just `VerifyOutput.Report.Summary`

Recommended decision logic:

```go
if out.Report.SignalSummary.ActionableFail > 0 {
    // block or escalate
}
if out.Report.SignalSummary.AdvisoryFail > 0 {
    // create review task, but do not hard-fail by default
}
```

Go API consumers should continue to inspect:

- `TrustSummary`
- `CapabilitySummary`
- `TrustGuidance`

before treating any result as automation-safe.

## 4. CI Pipelines

CI MUST NOT gate on `summary.fail`.

CI SHOULD gate on:

- `signal_summary.actionable_fail`
- optionally `signal_summary.unknown`

Recommended baseline policy:

- fail CI if `actionable_fail > 0`
- warn but do not fail if `advisory_fail > 0`
- ignore `informational_detection` for pass/fail

Stricter environments may also fail on:

- `unknown > 0`
- degraded capability
- presence of `human_or_runtime_required` findings in sensitive workflows

## 5. Dashboards

Dashboards should visualize calibrated categories separately.

Recommended cards:

- Actionable Failures
- Advisory Failures
- Informational Detections
- Unknown

Dashboards should not collapse all of these into a single red `fail` badge.

Recommended color semantics:

- actionable: red
- advisory: amber
- informational: blue or gray
- unknown: gray or amber depending on workflow

## 6. Alerts

Alerting systems should trigger only on:

- new actionable failures
- meaningful increase in advisory failures
- regressions in trusted-core or machine-trusted rules

Alerting systems should not page on:

- pattern detections alone
- stable informational counts

## Migration Rules

## Phase 1: Dual Read

All consumers continue reading raw `summary`, but add `signal_summary`.

Use this phase to:

- update dashboards
- update CI logic
- update docs and internal examples

## Phase 2: Signal-First

All product surfaces use `signal_summary` as primary.

`summary` remains visible only as:

- raw accounting
- debugging context
- schema continuity

## Phase 3: Legacy De-Emphasis

Once downstream consumers are migrated:

- keep `summary` for consumer continuity
- document it as raw accounting
- stop using it in product copy, dashboards, and gating rules

## Recommended Decision Matrix

| Condition | Recommended Action |
|---|---|
| `actionable_fail > 0` | block, escalate, or require remediation |
| `actionable_fail == 0 && advisory_fail > 0` | allow with review |
| only `informational_detection > 0` | allow, record descriptively |
| `unknown > 0` | review capability gap or fail in strict environments |

## Trust And Capability Overlay

`signal_summary` does not replace trust and capability data.

Consumers should still interpret findings through:

- `trust_summary`
- `capability_summary`
- `trust_guidance`

Examples:

- `actionable_fail=1` with `machine_trusted`
  - strong automation candidate
- `actionable_fail=1` with only `advisory`
  - should block less aggressively or require human review
- `actionable_fail=0`, `informational_detection=19`
  - should not be treated as a failing system

## Anti-Patterns

Do not do the following:

- gate on `summary.fail`
- show only a single “fail count” badge
- treat `informational_detection` as policy violation
- ignore `trust_guidance`
- assume all `actionable_fail` findings are equally trusted

## Example

Given:

```json
"summary": {
  "pass": 25,
  "fail": 32,
  "unknown": 0
},
"signal_summary": {
  "actionable_fail": 8,
  "advisory_fail": 5,
  "informational_detection": 19,
  "unknown": 0
}
```

Correct interpretation:

- 8 issues are operationally actionable
- 5 findings need engineering review
- 19 findings are descriptive/pattern-like
- the system should not be described as “32 blocking failures”

Incorrect interpretation:

- “the repo has 32 severe failures”

## Required Documentation Updates

Every downstream integration should document:

- which field it uses for gating
- whether it respects `trust_guidance`
- whether `unknown` is blocking
- whether informational detections are displayed or suppressed

## Recommended Next Steps

1. Update CLI examples to mention `signal_summary`.
2. Update any CI scripts to gate on `actionable_fail`.
3. Update dashboards to split fail counts into calibrated categories.
4. Mark `summary.fail` as raw accounting in API docs and examples.
