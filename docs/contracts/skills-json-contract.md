# `skills.json` Contract Specification

## 1. Purpose

`skills.json` is the evidence-derived skill scoring artifact. It stores explainable skill scores and their contributing issue and evidence references.

It answers:

- what skill dimensions were scored
- what the resulting scores are
- how confident the scoring is
- which issues and evidence contributed to each score

## 2. Top-Level Shape

```json
{
  "skills": []
}
```

## 3. Skill Record Shape

```json
{
  "skill_id": "system_design",
  "score": 0.88,
  "confidence": 0.84,
  "contributing_issue_ids": ["iss-021"],
  "contributing_evidence_ids": ["ev-201"],
  "formula_inputs": {
    "positive": [],
    "negative": []
  }
}
```

## 4. Required Fields

- `skill_id`
- `score`
- `confidence`
- `contributing_issue_ids`
- `contributing_evidence_ids`

Optional but recommended:

- `formula_inputs`
- `notes`

## 5. Required Semantics

### 5.1 Score

- `score` must be normalized to `0..1`
- score must be derived from evidence-backed issues

### 5.2 Confidence

- `confidence` must be normalized to `0..1`
- confidence must reflect confidence in the score, not merely the score magnitude

### 5.3 Contributors

- `contributing_issue_ids` must reference issues in `report.json`
- `contributing_evidence_ids` must reference evidence in `evidence.json`

## 6. Prohibited Content

`skills.json` must not:

- emit unsupported scores without contributors
- contain opaque score values with no traceability

## 7. Integrity Rules

1. Skill IDs must be unique.
2. All contributor references must resolve.
3. Score and confidence must be valid floats in `0..1`.

## 8. Use in Validation

Contract tests for `skills.json` must validate:

- schema shape
- contributor integrity
- score and confidence ranges
- skill ID uniqueness
