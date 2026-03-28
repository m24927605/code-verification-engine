# `outsource_acceptance.json` Contract Specification

## 1. Purpose

`outsource_acceptance.json` is the machine-readable contractual engineering acceptance artifact for outsourced delivery review.

It is a derived artifact, not the source of truth. It projects claim and evidence results into requirement-oriented acceptance rows suitable for delivery sign-off assistance.

It answers:

- what contractual engineering requirements were checked
- which requirements passed, failed, or could not be safely determined
- what trust boundary applies to each requirement row
- which evidence supports or contradicts each contractual conclusion

## 2. Required Semantics

`outsource_acceptance.json` must:

- represent engineering delivery acceptance, not business or runtime acceptance
- permit automated pass/fail only when proof-grade prerequisites are satisfied
- preserve `unknown` and `runtime_required` outcomes where static verification is insufficient
- remain fully traceable to claims and evidence IDs

## 3. Top-Level Shape

```json
{
  "schema_version": "1.0.0",
  "repository": {
    "path": "/repo",
    "commit": "abc123"
  },
  "trace_id": "trace-20260328-abc123",
  "acceptance_profile": "outsource-backend-api",
  "summary": {
    "passed": 0,
    "failed": 0,
    "unknown": 0,
    "runtime_required": 0,
    "proof_grade_rows": 0,
    "blocking_failures": 0
  },
  "requirements": []
}
```

## 4. Required Fields

### 4.1 `schema_version`

- string
- identifies the version of this artifact contract

### 4.2 `repository`

Required fields:

- `path`
- `commit`

Rules:

- repository identity must match other artifacts in the same bundle

### 4.3 `trace_id`

- string
- must resolve to `trace.json.trace_id`

### 4.4 `acceptance_profile`

- string
- identifies the policy profile used to build acceptance requirements

### 4.5 `summary`

Required fields:

```json
{
  "passed": 3,
  "failed": 1,
  "unknown": 2,
  "runtime_required": 1,
  "proof_grade_rows": 4,
  "blocking_failures": 1
}
```

Rules:

- counts must reconcile with `requirements[]`
- `proof_grade_rows` counts rows where `verification_class=proof_grade`
- `blocking_failures` counts rows marked `blocking=true` and `status=failed`

### 4.6 `requirements`

Array of requirement rows:

```json
[
  {
    "requirement_id": "oa-auth-001",
    "title": "Protected routes must bind authentication middleware",
    "category": "security",
    "status": "passed",
    "verification_class": "proof_grade",
    "trust_class": "machine_trusted",
    "blocking": true,
    "acceptance_intent": "binding_check",
    "claim_ids": ["security.route_auth_binding"],
    "supporting_evidence_ids": ["ev-101", "ev-102"],
    "contradictory_evidence_ids": [],
    "reason": "All protected routes resolved to handlers with attached authentication middleware bindings.",
    "unknown_reasons": []
  }
]
```

## 5. Requirement Row Required Fields

- `requirement_id`
- `title`
- `category`
- `status`
- `verification_class`
- `trust_class`
- `blocking`
- `acceptance_intent`
- `claim_ids`
- `supporting_evidence_ids`
- `contradictory_evidence_ids`
- `reason`
- `unknown_reasons`

## 6. Allowed Values

### 6.1 `status`

- `passed`
- `failed`
- `unknown`
- `runtime_required`

### 6.2 `verification_class`

- `proof_grade`
- `structural_inference`
- `heuristic_advisory`
- `human_or_runtime_required`

### 6.3 `trust_class`

- `machine_trusted`
- `advisory`
- `human_or_runtime_required`

### 6.4 `acceptance_intent`

- `existence_check`
- `binding_check`
- `boundary_check`
- `maturity_check`
- `negative_exhaustive_check`

## 7. Required Semantics

### 7.1 Contract Safety

- a row may be `passed` by machine automation only if:
  - `verification_class=proof_grade`
  - `trust_class=machine_trusted`
  - required completeness conditions are satisfied for that rule family

- structural or heuristic rows may still appear as `passed` only if the policy profile explicitly allows advisory pass rows, but they must never be counted as machine-safe contractual pass

- if policy does not allow advisory pass rows, non-proof rows must degrade to `unknown`

### 7.2 Failure Semantics

- `failed` means violating evidence exists and is sufficient under the policy profile
- contradiction evidence must not be dropped

### 7.3 Unknown Semantics

- `unknown` means the system cannot safely determine pass or fail
- `unknown_reasons` must explain why, such as:
  - incomplete scan boundary
  - analyzer degradation
  - unsupported framework
  - insufficient proof facts

### 7.4 Runtime-Required Semantics

- `runtime_required` means the requirement is outside static proof scope without additional runtime or deployment evidence

### 7.5 Reference Integrity

- `claim_ids` must resolve to `claims.json`
- `supporting_evidence_ids` and `contradictory_evidence_ids` must resolve to `evidence.json`

## 8. Prohibited Content

`outsource_acceptance.json` must not:

- claim business or user acceptance
- silently hide contradiction evidence
- embed large raw evidence payloads instead of references
- emit machine-safe pass semantics from heuristic-only evidence

## 9. Integrity Rules

1. `trace_id` must match `trace.json.trace_id`.
2. Repository and commit must match the artifact bundle.
3. Every requirement ID must be unique.
4. Every referenced claim ID must exist in `claims.json`.
5. Every referenced evidence ID must exist in `evidence.json`.
6. Summary counts must match requirement row counts.

## 10. Use in Validation

Contract tests for `outsource_acceptance.json` must validate:

- schema shape
- enum values
- claim reference integrity
- evidence reference integrity
- summary reconciliation
- no machine-safe contractual pass derived from weak verification classes
