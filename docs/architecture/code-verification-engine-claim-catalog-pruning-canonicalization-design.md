# Code Verification Engine Claim Catalog Pruning and Canonicalization Design

## 1. Purpose

This document defines the release-grade pruning and canonicalization rules for
the multi-source evidence claims subsystem.

The goal is not to increase raw claim count. The goal is to:

- reduce low-value claim noise
- preserve high-value capability claims
- keep `claims.json` machine-verifiable
- keep `profile.json` and `resume_input.json` bounded and resume-relevant

## 2. Problem Statement

Initial multi-source extraction proved the end-to-end pipeline works, but real
repository output showed excessive low-value `weak` claims. The dominant noise
classes were:

- generic fallback claims under `general.*`
- file-name-derived claims
- chunk/task/step title derived claims
- section-title restatements that do not represent capability-level claims
- duplicated aliases for the same higher-level concept

These claims dilute the value of:

- `claims.json`
- `profile.json`
- `resume_input.json`

They also increase the risk that downstream LLM synthesis produces verbose,
low-signal resumes.

## 3. Design Principles

### 3.1 High-value over high-count

The system must prefer fewer, stronger claims over many weak ones.

### 3.2 README and docs remain candidates, not truth

README/docs may suggest claim candidates, but must not produce arbitrary claim
IDs by fallback string conversion.

### 3.3 Canonical capability vocabulary

The system must normalize semantically equivalent claims into one canonical
claim ID whenever reasonable.

### 3.4 Deterministic pruning

Pruning must be explicit, deterministic, and testable. A claim must be
excluded because it matches a rule, not because of opaque ranking.

## 4. Required Pruning Rules

### 4.1 Disallow `general.*` fallback claims by default

The claim extractor must not emit claims in the `general` category unless they
come from an explicit, curated allowlist.

Rationale:

- `general.*` claims are overwhelmingly low-value
- they are rarely appropriate resume inputs
- they usually come from weak section-title or fragment fallback

### 4.2 Disallow file/chunk/task/path derived claims

Claims must be rejected if their derived identity is primarily based on:

- file names such as `*.py`, `*.ts`, `*.md`
- file path fragments
- task list item headings
- chunk/step numbering
- test file paths turned into claim IDs

Examples of claims that must be pruned:

- `architecture.app_services_chat_service.py`
- `architecture.chunk_1._types_+_data_layer`
- `architecture.task_3._create_fugleservice`
- `general.app_agents_executor.py`

### 4.3 Reject section-title restatement claims unless lexicon-matched

A section heading or fragment must not automatically become a claim merely
because it contains architecture/security/testing vocabulary.

Documentation-derived claims must only survive when they map to a curated
high-value claim lexicon or a canonical alias of that lexicon.

Examples that must usually be pruned:

- `architecture.architecture_overview`
- `architecture.core_layer`
- `architecture.ci_cd_pipeline`

## 5. Canonicalization Rules

### 5.1 Canonical claim IDs

The subsystem must maintain a deterministic canonical claim vocabulary for
high-value resume-oriented concepts. Initial canonical claims include:

- `architecture.multi_agent_pipeline`
- `architecture.secure_answer_pipeline`
- `operational_maturity.structured_tracing`
- `evaluation_maturity.adversarial_evaluation`
- `evaluation_maturity.quality_gating`
- `security_maturity.auth_middleware`
- `security_maturity.defense_in_depth`

### 5.2 Alias normalization

Known aliases must normalize to the canonical claim ID before candidate
construction and before evidence matching.

Examples:

- `architecture.3_agent_pipeline` -> `architecture.multi_agent_pipeline`
- `architecture.agent_architecture` -> `architecture.multi_agent_pipeline`
- `architecture.secure_answer` -> `architecture.secure_answer_pipeline`
- `operational_maturity.langfuse_tracing` -> `operational_maturity.structured_tracing`
- `evaluation_maturity.red_team_evaluation` -> `evaluation_maturity.adversarial_evaluation`

### 5.3 No duplicate semantic siblings in profile projection

If multiple aliases map to one canonical claim, only the canonical claim may
participate in:

- `claims.json`
- `profile.json`
- `resume_input.json`

## 6. Source-Type Policy

### 6.1 README/docs

README/docs extraction must be allowlist-first:

- lexicon match -> canonical claim
- canonical alias match -> canonical claim
- otherwise -> no claim

README/docs must not emit arbitrary fallback claims.

### 6.2 Code/tests/evals

Code/tests/evals may still emit fallback claims when they carry structured
roles, because these sources are stronger and more likely to be useful as
capability signals. However, they must still obey the global pruning rules for:

- file/path-derived IDs
- `general.*`
- chunk/task artifacts

## 7. Expected Outcome

After applying these rules:

- `claims.json` becomes materially smaller
- `weak` claims drop substantially
- high-value claims remain
- `profile.json` becomes more resume-relevant
- `resume_input.json` becomes more bounded and higher signal
