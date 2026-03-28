# ADR-001: Evidence-First Architecture

## Status

Accepted

## Context

The existing engine already extracts facts and emits findings, but the system still behaves primarily like an analysis pipeline. Findings are produced early, evidence is attached rather than centralized, and downstream interpretation is not consistently grounded in a single normalized evidence model.

The v2 system must support:

- verifiable outputs
- issue traceability
- evidence-based aggregation
- reproducibility and future signing

These requirements cannot be met reliably if findings remain the primary product artifact.

## Decision

Adopt an evidence-first architecture in which:

- analyzers, rules, and agents are evidence producers
- normalized evidence is stored in a shared evidence layer
- issue formation happens after evidence aggregation
- report, skill scoring, and summary generation are derived from evidence-backed issue candidates

## Consequences

Positive:

- explicit provenance and derivation tracking
- easier reproducibility and auditing
- consistent cross-source aggregation model
- future signing and policy-gating become feasible

Negative:

- more up-front schema work
- migration complexity from finding-first paths
- additional aggregation logic becomes mandatory

## Alternatives Considered

### Keep findings as the primary artifact

Rejected because:

- evidence remains fragmented
- traceability is weaker
- aggregation and confidence become ad hoc

### Make report.json the authoritative store

Rejected because:

- reports are derived views, not ground truth
- evidence duplication and drift risk increase

## Implementation Notes

- implement `EvidenceRecord` first
- adapt existing analyzer and rule outputs into the shared evidence layer
- delay removal of old finding projections until v2 bundle output is stable
