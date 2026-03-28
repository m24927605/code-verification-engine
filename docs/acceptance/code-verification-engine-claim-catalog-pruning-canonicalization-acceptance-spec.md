# Code Verification Engine Claim Catalog Pruning and Canonicalization Acceptance Spec

## 1. Objective

Verify that multi-source claim outputs are smaller, cleaner, and more resume-
relevant after deterministic pruning and canonicalization.

## 2. Acceptance Areas

### 2.1 Canonicalization

The system must normalize known aliases to one canonical claim ID.

Acceptance examples:

- `3-agent pipeline` -> `architecture.multi_agent_pipeline`
- `red-team evaluation` -> `evaluation_maturity.adversarial_evaluation`

### 2.2 Pruning of low-value claims

The system must reject:

- `general.*` fallback claims
- file-name-derived claims
- path-derived claims
- chunk/task-derived claims
- README/docs fallback claims not matched by the curated claim lexicon

### 2.3 High-value claim preservation

The system must continue to emit canonical high-value claims for repositories
that genuinely support them.

Minimum retained examples:

- `architecture.secure_answer_pipeline`
- `operational_maturity.structured_tracing`
- `security_maturity.auth_middleware`
- `security_maturity.defense_in_depth`
- `evaluation_maturity.adversarial_evaluation`
- `evaluation_maturity.quality_gating`

## 3. Required Tests

### Unit tests

- alias canonicalization test
- `general.*` pruning test
- file/chunk/task/path-derived pruning test
- README/docs unmatched claim suppression test
- evidence matching test for canonical aliases

### Real-output regression

Using a representative repository such as `Vulcan`, the post-change output must
show:

- a substantial reduction in `weak` claims
- no retained file/chunk/task/path-derived claims
- no retained `general.*` resume-noise claims
- preserved verified/strongly-supported high-value claims

## 4. Pass Conditions

The change passes when:

- all unit tests are green
- full project tests are green
- local release gate is green
- real output inspection confirms that the weak-claim noise floor is materially
  reduced without removing the known high-value claims
