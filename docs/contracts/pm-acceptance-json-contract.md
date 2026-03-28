# `pm_acceptance.json` Contract Specification

## 1. Purpose

`pm_acceptance.json` is the machine-readable engineering acceptance artifact for software delivery review by PM-facing stakeholders.

It is not a product-acceptance artifact and it is not a substitute for QA, UAT, or runtime verification.

It answers:

- what engineering delivery requirements were checked
- which requirements appear implemented, partial, blocked, unknown, or runtime-required
- what trust boundary supports each engineering conclusion
- which evidence and claims justify each row

## 2. Required Semantics

`pm_acceptance.json` must:

- be explicitly framed as engineering acceptance
- separate implemented wiring from runtime or product behavior
- preserve evidence traceability
- avoid presenting static implementation presence as full end-user acceptance

## 3. Top-Level Shape

```json
{
  "schema_version": "1.0.0",
  "repository": {
    "path": "/repo",
    "commit": "abc123"
  },
  "trace_id": "trace-20260328-abc123",
  "acceptance_profile": "pm-engineering-default",
  "summary": {
    "implemented": 0,
    "partial": 0,
    "blocked": 0,
    "unknown": 0,
    "runtime_required": 0,
    "proof_grade_rows": 0
  },
  "engineering_requirements": []
}
```

## 4. Required Fields

### 4.1 `schema_version`

- string

### 4.2 `repository`

Required fields:

- `path`
- `commit`

### 4.3 `trace_id`

- string
- must resolve to `trace.json.trace_id`

### 4.4 `acceptance_profile`

- string
- identifies the PM engineering acceptance policy profile

### 4.5 `summary`

Required fields:

```json
{
  "implemented": 5,
  "partial": 1,
  "blocked": 1,
  "unknown": 2,
  "runtime_required": 1,
  "proof_grade_rows": 4
}
```

Rules:

- counts must reconcile with `engineering_requirements[]`

### 4.6 `engineering_requirements`

Array of engineering requirement rows:

```json
[
  {
    "requirement_id": "pm-eng-001",
    "title": "Protected routes are wired through authentication middleware",
    "category": "engineering_delivery",
    "status": "implemented",
    "verification_class": "proof_grade",
    "trust_class": "machine_trusted",
    "delivery_scope": "implemented",
    "claim_ids": ["security.route_auth_binding"],
    "supporting_evidence_ids": ["ev-101", "ev-102"],
    "contradictory_evidence_ids": [],
    "reason": "All protected route handlers resolve through auth middleware bindings in the indexed route graph.",
    "follow_up_action": ""
  }
]
```

## 5. Engineering Requirement Row Required Fields

- `requirement_id`
- `title`
- `category`
- `status`
- `verification_class`
- `trust_class`
- `delivery_scope`
- `claim_ids`
- `supporting_evidence_ids`
- `contradictory_evidence_ids`
- `reason`
- `follow_up_action`

## 6. Allowed Values

### 6.1 `status`

- `implemented`
- `partial`
- `blocked`
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

### 6.4 `delivery_scope`

- `implemented`
- `partial`
- `blocked`
- `unknown`

## 7. Required Semantics

### 7.1 Engineering Scope

- rows must describe engineering implementation or engineering guardrail status
- rows must not claim business acceptance or runtime correctness unless future runtime evidence is explicitly integrated

### 7.2 Implemented Semantics

- `status=implemented` is allowed when the requirement is satisfied under the policy profile
- proof-grade implemented rows are safe for engineering gate automation
- structural or heuristic implemented rows must remain clearly advisory

### 7.3 Partial Semantics

- `partial` means some required engineering structure exists but required coverage, completeness, or consistency is not yet sufficient for full implementation status

### 7.4 Blocked Semantics

- `blocked` means contradictory or violating evidence exists such that the engineering requirement is not currently met

### 7.5 Unknown and Runtime-Required

- `unknown` means the engine cannot determine the engineering status safely
- `runtime_required` means the question exceeds static proof scope and requires runtime, deployment, or product-level validation

### 7.6 Reference Integrity

- `claim_ids` must resolve to `claims.json`
- evidence references must resolve to `evidence.json`

## 8. Prohibited Content

`pm_acceptance.json` must not:

- label output as product acceptance
- imply user-facing success from static implementation presence alone
- hide contradictory evidence
- embed large raw evidence blobs instead of evidence references

## 9. Integrity Rules

1. `trace_id` must match `trace.json.trace_id`.
2. Repository and commit must match the artifact bundle.
3. Every requirement ID must be unique.
4. All referenced claim IDs and evidence IDs must resolve.
5. Summary counts must reconcile with requirement rows.

## 10. Use in Validation

Contract tests for `pm_acceptance.json` must validate:

- schema shape
- enum values
- claim and evidence reference integrity
- summary reconciliation
- absence of product-acceptance wording in generated artifact semantics
