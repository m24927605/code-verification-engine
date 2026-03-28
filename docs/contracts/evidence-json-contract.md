# `evidence.json` Contract Specification

## 1. Purpose

`evidence.json` is the source-of-truth evidence artifact for a verification run. It stores normalized evidence emitted by analyzers, rules, and agents.

It answers:

- what was observed
- who produced that observation
- where it came from in code
- what claims it supports or contradicts
- how it was derived

## 2. Top-Level Shape

```json
{
  "evidence": []
}
```

## 3. Evidence Record Shape

```json
{
  "id": "ev-001",
  "kind": "ast_fact",
  "source": "rule",
  "producer_id": "rule:missing_null_check",
  "producer_version": "1.0.0",
  "repo": "github.com/user/repo",
  "commit": "abc123",
  "boundary_hash": "sha256:...",
  "fact_quality": "proof",
  "entity_ids": ["fn-123"],
  "locations": [
    {
      "repo_rel_path": "service.ts",
      "start_line": 120,
      "end_line": 120,
      "symbol_id": "fn-123"
    }
  ],
  "claims": ["null_check_missing"],
  "payload": {},
  "supports": [],
  "contradicts": [],
  "derived_from": ["ast-node-8821"],
  "created_at": "2026-03-27T12:00:00Z"
}
```

## 4. Required Fields

- `id`
- `kind`
- `source`
- `producer_id`
- `producer_version`
- `repo`
- `commit`
- `boundary_hash`
- `fact_quality`
- `entity_ids`
- `locations`
- `claims`
- `payload`
- `supports`
- `contradicts`
- `derived_from`
- `created_at`

## 5. Required Semantics

### 5.1 Identity

- evidence IDs must be deterministic within a run
- duplicate IDs must not represent different semantic evidence

### 5.2 Provenance

- `source` must be one of `analyzer`, `rule`, or `agent`
- `producer_id` must identify the producing component
- `producer_version` must identify the producer version

### 5.3 Location

- evidence tied to source code must include one or more valid locations
- locations must remain within scan boundary

### 5.4 Quality

- `fact_quality` must be one of `proof`, `structural`, or `heuristic`

### 5.5 Relationship Fields

- `supports` lists issue, claim, or evidence targets positively supported
- `contradicts` lists issue, claim, or evidence targets contradicted
- `derived_from` lists parent evidence or extraction provenance inputs

## 6. Prohibited Content

`evidence.json` must not:

- contain final issue-level conclusions as raw evidence fields
- omit provenance fields
- contain unbounded narrative text as a substitute for structured payload

## 7. Integrity Rules

1. Evidence IDs must be unique.
2. Repo and commit must match the rest of the artifact bundle.
3. Referenced locations must be valid within the scan boundary.
4. `source=agent` evidence must correspond to an agent execution in `trace.json`.

## 8. Use in Validation

Contract tests for `evidence.json` must validate:

- schema shape
- evidence ID uniqueness
- provenance field presence
- valid quality enum values
- location integrity
