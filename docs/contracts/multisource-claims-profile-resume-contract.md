# Multi-Source Claims, Profile, and Resume Input Contract

## 1. Purpose

This document defines the machine-readable contracts for the multi-source evidence claims subsystem.

It covers:

- `claims.json`
- `profile.json`
- `resume_input.json`

These contracts are intended to support evidence-backed capability profiling and bounded resume synthesis without weakening the existing verification artifacts.

## 2. Contract Principles

The contracts must preserve:

1. traceability to evidence
2. deterministic output shape
3. conservative trust boundaries
4. contradiction visibility
5. bounded synthesis inputs

## 3. `claims.json`

### 3.1 Purpose

`claims.json` is the primary machine-readable output for multi-source capability claims.

It answers:

- what high-value claims were considered
- which claims were verified, downgraded, or rejected
- what evidence supports or contradicts each claim
- how strong each claim is

### 3.2 Top-Level Shape

```json
{
  "claim_schema_version": "1.0.0",
  "repository": {
    "path": "/repo",
    "commit": "abc123"
  },
  "claims": [],
  "summary": {
    "verified": 0,
    "strongly_supported": 0,
    "supported": 0,
    "weak": 0,
    "unsupported": 0,
    "contradicted": 0
  }
}
```

### 3.3 Claim Record Shape

```json
{
  "claim_id": "architecture.multi_agent_pipeline",
  "title": "Multi-agent pipeline exists",
  "category": "architecture",
  "claim_type": "architecture",
  "status": "accepted",
  "support_level": "verified",
  "confidence": 0.88,
  "source_origins": ["readme_extracted", "code_inferred"],
  "supporting_evidence_ids": ["ev-1", "ev-2"],
  "contradictory_evidence_ids": [],
  "reason": "Planner, executor, and verifier modules are separately implemented and wired through shared orchestration paths.",
  "projection_eligible": true
}
```

### 3.4 Required Fields

- `claim_id`
- `title`
- `category`
- `claim_type`
- `status`
- `support_level`
- `confidence`
- `source_origins`
- `supporting_evidence_ids`
- `contradictory_evidence_ids`
- `reason`
- `projection_eligible`

### 3.5 Allowed Values

`status`:

- `accepted`
- `downgraded`
- `rejected`
- `unknown`

`support_level`:

- `verified`
- `strongly_supported`
- `supported`
- `weak`
- `unsupported`
- `contradicted`

`claim_type`:

- `implementation`
- `architecture`
- `security_maturity`
- `testing_maturity`
- `evaluation_maturity`
- `operational_maturity`

### 3.6 Required Semantics

- `confidence` must be normalized to `0..1`
- `supporting_evidence_ids` must reference evidence in `evidence.json` or source-evidence-integrated records in canonical output
- `contradictory_evidence_ids` must reference valid evidence IDs
- `projection_eligible` must be `true` only for claims safe to include in default profile output
- `README`-only claims must never be emitted as `verified`

## 4. `profile.json`

### 4.1 Purpose

`profile.json` is the structured capability profile projection derived from verified claims.

It answers:

- what capability areas are strongly supported
- what high-value highlights are safe to present
- which technologies and evidence support those highlights

### 4.2 Top-Level Shape

```json
{
  "profile_schema_version": "1.0.0",
  "repository": {
    "path": "/repo",
    "commit": "abc123"
  },
  "highlights": [],
  "capability_areas": [],
  "technologies": [],
  "claim_ids": []
}
```

### 4.3 Highlight Shape

```json
{
  "highlight_id": "hl-1",
  "title": "Built a bounded multi-agent verification pipeline",
  "support_level": "strongly_supported",
  "claim_ids": ["architecture.multi_agent_pipeline"],
  "supporting_evidence_ids": ["ev-1", "ev-2"]
}
```

### 4.4 Capability Area Shape

```json
{
  "area_id": "architecture",
  "title": "Architecture and System Design",
  "claim_ids": ["architecture.multi_agent_pipeline", "architecture.secure_answer_pipeline"]
}
```

### 4.5 Required Fields

Top-level:

- `profile_schema_version`
- `repository`
- `highlights`
- `capability_areas`
- `technologies`
- `claim_ids`

Highlight:

- `highlight_id`
- `title`
- `support_level`
- `claim_ids`
- `supporting_evidence_ids`

### 4.6 Required Semantics

- `highlights` may use only `verified` and `strongly_supported` claims by default
- `claim_ids` must resolve to `claims.json`
- `supporting_evidence_ids` must resolve to evidence
- `technologies` must be descriptive but must not imply unsupported capability claims by themselves

## 5. `resume_input.json`

### 5.1 Purpose

`resume_input.json` is the bounded synthesis input artifact for LLM-based resume generation.

It is not a human-facing artifact. It is a constrained input contract for safe narrative synthesis.

### 5.2 Top-Level Shape

```json
{
  "resume_input_schema_version": "1.0.0",
  "profile": {},
  "verified_claims": [],
  "strongly_supported_claims": [],
  "technology_summary": [],
  "evidence_references": [],
  "synthesis_constraints": {
    "allow_unsupported_claims": false,
    "allow_claim_invention": false,
    "allow_contradiction_suppression": false
  }
}
```

### 5.3 Claim Stub Shape

```json
{
  "claim_id": "architecture.multi_agent_pipeline",
  "title": "Multi-agent pipeline exists",
  "support_level": "verified",
  "confidence": 0.88,
  "supporting_evidence_ids": ["ev-1", "ev-2"]
}
```

### 5.4 Required Fields

Top-level:

- `resume_input_schema_version`
- `profile`
- `verified_claims`
- `strongly_supported_claims`
- `technology_summary`
- `evidence_references`
- `synthesis_constraints`

Synthesis constraints:

- `allow_unsupported_claims`
- `allow_claim_invention`
- `allow_contradiction_suppression`

### 5.5 Required Semantics

- default `resume_input.json` must exclude `weak`, `unsupported`, and `contradicted` claims from highlighted synthesis pools
- contradiction visibility must remain accessible through `evidence_references` or claim exclusion rationale
- the artifact must be sufficient for LLM synthesis without raw repository-wide context

## 6. Integrity Rules

The following rules apply across all three artifacts:

1. IDs must be unique within each artifact.
2. Claim references must resolve from `profile.json` and `resume_input.json` to `claims.json`.
3. Evidence references must resolve to evidence.
4. Score and confidence fields must remain in `0..1`.
5. Unsupported claims must not be silently promoted in downstream artifacts.

## 7. Prohibited Content

The subsystem must not:

- emit verified claims without supporting evidence
- project unsupported claims into default `profile.json` highlights
- include unrestricted raw repository content in `resume_input.json`
- hide contradictory evidence while presenting strong claims

## 8. Validation Requirements

Contract tests must validate:

- schema shape
- ID uniqueness
- claim reference integrity
- evidence reference integrity
- support-level constraints on profile highlights
- boundedness of resume synthesis inputs
