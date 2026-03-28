# ADR-003: Lazy Agent Orchestration with Bounded Context

## Status

Accepted

## Context

The system needs a way to handle ambiguity, unresolved design concerns, and specialist reasoning gaps without turning every scan into a high-cost LLM workflow.

Running all agents on every repository would conflict with core product constraints:

- low cost
- deterministic-first behavior
- bounded context

## Decision

Introduce lazy agent orchestration with the following rules:

- agents run only on explicit trigger conditions
- all agent inputs must be prepared through the context selection layer
- all agent outputs must be normalized into evidence records
- agent contributions must pass through aggregation and confidence scoring

## Consequences

Positive:

- cost remains controlled
- specialist reasoning is available where justified
- agent influence is traceable and auditable

Negative:

- orchestration policy becomes a first-class component
- context selection quality becomes critical

## Alternatives Considered

### Always run bug, design, and security agents

Rejected because:

- cost scales poorly
- adds noise on already-clear deterministic outcomes

### Let agents consume whole files or full repos

Rejected because:

- context becomes expensive and hard to reproduce
- traceability and containment degrade

## Implementation Notes

- start with unknown, conflict, and high-severity unresolved triggers
- add hard file and token budgets
- log every agent task in `trace.json`
