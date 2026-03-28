# Proof-Grade Scenario Fixtures

Deterministic minimal repositories for proof-grade scenario acceptance.

Canonical directories:

- `hiring-proof-backed`
- `hiring-overclaim-downgrade`
- `outsource-pass`
- `outsource-fail`
- `outsource-unknown-incomplete`
- `pm-engineering-implemented`
- `pm-runtime-required`
- `contradiction`
- `analyzer-degradation`
- `unsupported-framework`

Each canonical fixture must include a `scenario_golden.json` file and is
consumed by the scenario harness under `internal/acceptance`.

Retired fixture names are no longer authoritative and must not reappear:

- `outsource-pass-auth-binding`
- `outsource-fail-secret`
- `outsource-unknown-incomplete-negative`
- `pm-runtime-required-feature-behavior`
