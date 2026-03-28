# Multi-Source Evidence Claims Fixture Corpus Specification

## 1. Purpose

This document defines the fixture corpus required to implement and validate the multi-source evidence claims subsystem.

It exists to make the acceptance specification directly executable rather than purely conceptual.

## 2. Fixture Goals

The fixture corpus must:

1. exercise all five source classes
2. validate claim support-level boundaries
3. validate contradiction handling
4. validate profile projection rules
5. validate bounded resume synthesis input generation

## 3. Required Fixture Families

### 3.1 README Over-Claim Fixture

Purpose:

- prove that README text alone cannot create a verified claim

Minimum repo shape:

- `README.md` explicitly claims a high-value architecture capability
- codebase lacks the relevant modules or wiring
- no supporting tests or evals exist

Expected outputs:

- extracted claim candidate exists
- final claim is `weak`, `unsupported`, or `contradicted`
- claim is not `projection_eligible`
- no top-level profile highlight includes it

### 3.2 Code-Backed Architecture Claim Fixture

Purpose:

- prove that architecture claims can become `verified` or `strongly_supported` from code-backed evidence

Minimum repo shape:

- separate agent or pipeline modules
- clear orchestration wiring
- optional supporting doc/README mention

Expected outputs:

- claim candidate extracted from code or docs
- final claim is `verified` or `strongly_supported`
- claim is `projection_eligible`
- profile highlight is generated

### 3.3 Test-Strengthened Security Maturity Fixture

Purpose:

- prove that tests strengthen maturity claims without replacing code evidence

Minimum repo shape:

- security-sensitive implementation exists
- dedicated security or regression tests exist
- README or docs optionally claim defense-in-depth or hardening

Expected outputs:

- implementation claim supported by code
- maturity claim strengthened by test evidence
- confidence/support level is higher than code-only equivalent

### 3.4 Eval-Backed AI Quality Fixture

Purpose:

- prove that eval assets can support AI quality and safety maturity claims

Minimum repo shape:

- eval dataset or adversarial dataset
- benchmark runner or evaluator
- code path referencing eval-related behavior or quality gates

Expected outputs:

- evaluation-maturity claim extracted
- support level reflects combined eval and code evidence
- profile may include the claim if support is strong enough

### 3.5 Docs-vs-Code Contradiction Fixture

Purpose:

- prove that stronger code evidence can contradict docs claims

Minimum repo shape:

- docs or README claim a capability exists
- code demonstrates the capability is absent or differently implemented

Expected outputs:

- claim candidate extracted from docs
- contradictory evidence recorded
- final support level is `contradicted` or downgraded below projection threshold
- contradiction remains visible

### 3.6 No-README Fixture

Purpose:

- prove the subsystem works without README input

Minimum repo shape:

- code, tests, or evals are present
- no `README.md`

Expected outputs:

- source discovery succeeds
- claims still generated from code/tests/evals
- no README-specific failure occurs

## 4. Optional but Recommended Fixture Families

### 4.1 Docs-Only Rationale Fixture

Purpose:

- validate that docs may strengthen interpretation but not create verified implementation claims alone

### 4.2 Weak Structural Signal Fixture

Purpose:

- ensure weak heuristics remain below strong projection thresholds

### 4.3 Multi-Source Convergence Fixture

Purpose:

- show that README + docs + code + tests + eval together can produce a strongly supported high-value claim

## 5. Fixture Manifest Shape

Each fixture should declare:

- `fixture_id`
- `description`
- `sources_present`
- `expected_claims`
- `expected_profile_highlights`
- `expected_resume_input_claim_ids`

Recommended example:

```json
{
  "fixture_id": "readme_overclaim_multi_agent",
  "sources_present": ["readme", "code"],
  "expected_claims": [
    {
      "claim_id": "architecture.multi_agent_pipeline",
      "support_level": "unsupported",
      "projection_eligible": false
    }
  ],
  "expected_profile_highlights": [],
  "expected_resume_input_claim_ids": []
}
```

## 6. Claim-Level Assertions

For each fixture, the corpus should allow assertions on:

- presence or absence of claim candidate
- final support level
- final `projection_eligible`
- supporting evidence count
- contradictory evidence count
- origin metadata

## 7. Profile-Level Assertions

For each fixture, the corpus should allow assertions on:

- highlight count
- highlight titles or IDs
- highlight support levels
- highlight claim references
- highlight evidence references

## 8. Resume Input Assertions

For each fixture, the corpus should allow assertions on:

- included claim IDs
- excluded claim IDs
- presence of synthesis constraints
- absence of unsupported claims from default synthesis pools

## 9. Determinism Assertions

Every fixture family must support repeated-run assertions for:

- stable source discovery results
- stable evidence IDs
- stable claim IDs
- stable profile highlights
- stable resume input inclusion sets

## 10. Corpus Layout Recommendation

Recommended layout:

```text
internal/acceptance/testdata/multisource_claims/
  readme_overclaim/
  code_backed_architecture/
  test_strengthened_security/
  eval_backed_ai_quality/
  docs_code_contradiction/
  no_readme/
```

Each fixture directory should contain:

- minimal repo tree
- optional docs/README/tests/evals
- fixture manifest
- expected outputs or assertions

## 11. Release Gate Expectations

The release gate should not consider this subsystem complete unless:

1. all mandatory fixture families exist
2. all mandatory fixture families pass
3. repeated-run determinism checks pass
4. README over-claim and docs contradiction cases remain green

## 12. Definition of Corpus Completeness

The fixture corpus is complete when:

1. all mandatory fixture families exist
2. each source class participates in at least one mandatory fixture
3. each support level boundary is covered
4. contradiction and no-README behavior are both covered
5. profile and resume-input projections are both asserted
