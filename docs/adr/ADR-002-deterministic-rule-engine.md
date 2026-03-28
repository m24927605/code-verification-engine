# ADR-002: Deterministic Rule Engine as Primary Verification Path

## Status

Accepted

## Context

The product goal is verification, not unconstrained repository interpretation. The system must be low cost, reproducible, and safe for machine consumption where supported.

This requires a primary path that:

- does not depend on LLM availability
- is reproducible under identical inputs
- can express unknown rather than speculate

## Decision

The deterministic rule engine remains the primary verification path.

Rules must:

- run on indexed ground truth
- declare required facts and minimum quality
- emit structured evidence-backed outputs
- degrade to unknown when proof conditions are not met

LLM-based agents are allowed only as bounded fallback under explicit policy.

## Consequences

Positive:

- low default cost
- stable outputs
- easier calibration and regression testing
- better machine-trust boundary

Negative:

- some complex or ambiguous cases remain unresolved without agents
- more rule and index engineering effort is required

## Alternatives Considered

### LLM-first repository analysis

Rejected because:

- cost is unpredictable
- outputs are less reproducible
- trust boundary is harder to defend

### Hybrid default path with eager agent review

Rejected because:

- unnecessary cost expansion
- more complex failure handling
- weaker deterministic guarantees

## Implementation Notes

- preserve deterministic path even when agents are enabled
- treat unknown as an acceptable product output where evidence is insufficient
