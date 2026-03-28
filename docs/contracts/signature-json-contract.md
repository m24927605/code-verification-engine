# `signature.json` Contract Specification

## 1. Purpose

`signature.json` is the integrity envelope for the verification artifact bundle. It is designed to support bundle hashing immediately and artifact signing in the future.

It answers:

- what hashes correspond to each artifact
- what the combined bundle hash is
- whether a signature exists
- who signed it and under what scheme

## 2. Top-Level Shape

```json
{
  "version": "1.0",
  "signed_by": "verabase",
  "timestamp": "2026-03-27T12:00:00Z",
  "artifact_hashes": {
    "report.json": "sha256:...",
    "evidence.json": "sha256:...",
    "skills.json": "sha256:...",
    "trace.json": "sha256:...",
    "summary.md": "sha256:..."
  },
  "bundle_hash": "sha256:...",
  "signature": null,
  "signature_scheme": null
}
```

## 3. Required Fields

- `version`
- `signed_by`
- `timestamp`
- `artifact_hashes`
- `bundle_hash`
- `signature`
- `signature_scheme`

## 4. Required Semantics

### 4.1 `artifact_hashes`

- must include all primary bundle artifacts
- hash algorithm must be explicit in the value or adjacent metadata

### 4.2 `bundle_hash`

- must be computed deterministically from the artifact set under a defined ordering rule

### 4.3 `signature`

- may be `null` before signing is introduced
- if non-null, must correspond to the declared scheme

### 4.4 `signature_scheme`

- may be `null` when unsigned
- if non-null, must identify the scheme used

## 5. Integrity Rules

1. All hashed artifact names must exist in the bundle.
2. Recomputed hashes must match emitted hashes.
3. Recomputed bundle hash must match emitted bundle hash.

## 6. Use in Validation

Contract tests for `signature.json` must validate:

- schema shape
- presence of required artifact hashes
- bundle hash reproducibility
