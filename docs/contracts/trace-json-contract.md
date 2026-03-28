# `trace.json` Contract Specification

## 1. Purpose

`trace.json` is the reproducibility and execution manifest for a verification run. It records how the system produced the artifact bundle.

It answers:

- what repository snapshot was scanned
- what scan boundary was applied
- what analyzer and rule versions participated
- what context selection decisions were made
- what agents ran, if any
- how issues were derived from evidence

## 2. Top-Level Shape

```json
{
  "trace_id": "trace-20260327-abc123",
  "repo": "github.com/user/repo",
  "commit": "abc123",
  "scan_boundary": {},
  "analyzers": [],
  "rules": [],
  "context_selections": [],
  "agents": [],
  "derivations": []
}
```

## 3. Required Sections

### 3.1 Identity

- `trace_id`
- `repo`
- `commit`

### 3.2 Scan Boundary

Example:

```json
{
  "mode": "repo",
  "included_files": 218,
  "excluded_files": 14
}
```

### 3.3 Analyzer Records

Each analyzer record should include:

- analyzer name
- version
- language
- status
- degradation flags if applicable

### 3.4 Rule Records

Each rule record should include:

- rule ID
- rule version
- triggered issue IDs or emitted evidence IDs

### 3.5 Context Selection Records

Each selection should include:

- trigger type and ID
- selected evidence IDs
- selected spans
- budget inputs
- selection trace

### 3.6 Agent Records

Each agent record should include:

- agent ID
- kind
- trigger reason
- input evidence IDs
- output evidence IDs
- status

### 3.7 Derivation Records

Each derivation should include:

- issue ID
- derived evidence IDs

## 4. Prohibited Content

`trace.json` must not:

- omit agent executions that influenced outputs
- omit context selection for agent-triggered decisions
- serve as a substitute for raw evidence storage

## 5. Integrity Rules

1. `trace_id` must match `report.json.trace_id`.
2. Repo and commit must match the artifact bundle.
3. Agent outputs recorded in trace must resolve in `evidence.json`.
4. Derived issue IDs must resolve in `report.json`.

## 6. Use in Validation

Contract tests for `trace.json` must validate:

- schema shape
- cross-artifact trace ID consistency
- agent/evidence linkage
- derivation reference integrity
