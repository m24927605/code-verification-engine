# `report.json` Contract Specification

## 1. Purpose

`report.json` is the issue-centric final verification artifact. It is not the source of truth for raw evidence. It is a derived artifact that references evidence IDs, confidence outputs, and skill impacts.

## 2. Required Semantics

`report.json` must answer:

- what repository and commit were analyzed
- what engine version produced the result
- what issues were concluded
- how severe and how confident each issue is
- which evidence records support each issue
- which skills are affected

## 3. Top-Level Shape

```json
{
  "engine_version": "verabase@2.0.0",
  "repo": "github.com/user/repo",
  "commit": "abc123",
  "timestamp": "2026-03-27T12:00:00Z",
  "trace_id": "trace-20260327-abc123",
  "summary": {},
  "skills": [],
  "issues": []
}
```

## 4. Required Fields

### 4.1 `engine_version`

- string
- must uniquely identify engine build or release identity

### 4.2 `repo`

- string
- repository identity for trace and audit use

### 4.3 `commit`

- string
- immutable commit SHA or equivalent immutable revision identifier

### 4.4 `timestamp`

- string in RFC3339 format
- generation time of this artifact

### 4.5 `trace_id`

- string
- must match `trace.json.trace_id`

### 4.6 `summary`

Required fields:

```json
{
  "overall_score": 0.82,
  "risk_level": "medium",
  "issue_counts": {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3
  }
}
```

Rules:

- `overall_score` is normalized to `0..1`
- `risk_level` must be derived from issue severity and confidence policy

### 4.7 `skills`

Array of score summaries:

```json
[
  {
    "skill_id": "backend",
    "score": 0.85
  }
]
```

Rules:

- detailed skill attribution belongs in `skills.json`
- this section is a summary projection only

### 4.8 `issues`

Required shape:

```json
[
  {
    "id": "iss-001",
    "category": "bug",
    "title": "Missing null check in user service flow",
    "severity": "high",
    "confidence": 0.91,
    "status": "open",
    "evidence_ids": ["ev-001", "ev-014"],
    "skill_impacts": ["backend", "code_quality"],
    "sources": ["rule_engine", "bug_agent"]
  }
]
```

Rules:

- `confidence` must be a float `0..1`
- `evidence_ids` must all exist in `evidence.json`
- `sources` must summarize provenance, not replace evidence references

## 5. Prohibited Content

`report.json` must not:

- embed large duplicated evidence blobs
- include findings without evidence references
- include free-form conclusions that do not map to issue objects

## 6. Integrity Rules

1. Each issue ID must be unique within the artifact.
2. Each issue must reference at least one evidence ID.
3. `trace_id` must resolve to a trace record in `trace.json`.
4. Repo and commit must match all other artifacts in the same bundle.

## 7. Use in Validation

Contract tests for `report.json` must validate:

- schema shape
- evidence reference integrity
- confidence range
- issue ID uniqueness
- repo/commit consistency
