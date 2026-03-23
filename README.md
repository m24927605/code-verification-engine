# Code Verification Engine

Static analysis and verification engine for code repositories. Extracts facts from source code, evaluates verification rules, and produces evidence-backed findings with explicit trust boundaries.

Supports two operating modes:

- **Verification** — policy-style rule evaluation with `pass/fail/unknown` verdicts
- **Skill Inference** — evidence-backed skill signal extraction with `observed/inferred/unsupported` semantics

## Quick Start

```bash
# Build
go build -o cve ./cmd/cve

# Run verification
cve verify --repo ~/my-api --output ./out

# Run with a specific profile
cve verify --repo ~/my-api --profile backend-api-strict --output ./out

# Run skill inference
cve verify --repo ~/my-api --mode skill_inference --output ./out

# Run both verification and skill inference
cve verify --repo ~/my-api --mode both --output ./out
```

## Requirements

- Go 1.24+
- Git (for repository scanning)
- Python 3 (optional, enables AST-based Python analysis)

## CLI Reference

### Commands

| Command              | Description                                      |
|----------------------|--------------------------------------------------|
| `verify`             | Run the verification pipeline                    |
| `list-profiles`      | List available verification profiles             |
| `list-claims`        | List available claim sets                        |
| `list-skill-profiles`| List available skill inference profiles           |
| `version`            | Print version info                               |

### `verify` Flags

| Flag              | Default              | Description                                           |
|-------------------|----------------------|-------------------------------------------------------|
| `--repo`          | (required)           | Local git repository path                             |
| `--output`        | (required)           | Output directory                                      |
| `--ref`           | `HEAD`               | Git ref (branch, tag, SHA)                            |
| `--profile`       | `backend-api`        | Verification profile                                  |
| `--format`        | `both`               | Output format: `json`, `md`, `both`                   |
| `--strict`        | `false`              | Fail on any analyzer error                            |
| `--claims`        | —                    | Claim set for claim-centric verification              |
| `--mode`          | `verification`       | Engine mode: `verification`, `skill_inference`, `both` |
| `--skill-profile` | `github-engineer-core`| Skill inference profile                              |
| `--interpret`     | `false`              | Enable LLM interpretation (requires `CVE_LLM_API_KEY`)|

### Exit Codes

| Code | Meaning                 |
|------|-------------------------|
| 0    | Success                 |
| 1    | Invalid input           |
| 2    | Repository error        |
| 3    | Profile validation error|
| 4    | Analysis failure        |
| 5    | Report write error      |
| 6    | Partial success         |
| 7    | Cancelled / timed out   |

## Verification Profiles

| Profile              | Description                                                       |
|----------------------|-------------------------------------------------------------------|
| `backend-api`        | Standard backend API — security, architecture, quality, testing    |
| `backend-api-strict` | Strict backend — adds SQL injection, data logging, DI checks       |
| `frontend`           | Frontend — XSS prevention, auth guards, token storage, CSP         |
| `fullstack`          | All backend + frontend + design pattern rules                      |
| `fullstack-strict`   | All strict backend + frontend + design pattern rules               |
| `design-patterns`    | GoF design pattern detection (23 patterns)                        |
| `trusted-core`       | Machine-trustable rules only — suitable for automated gating       |

## Claim Sets

Claim-centric verification evaluates specific claims against rule results.

| Claim Set             | Claims | Description                                          |
|-----------------------|--------|------------------------------------------------------|
| `backend-security`    | 8      | JWT auth, route protection, secrets, input validation |
| `backend-architecture`| 6      | DB layering, repository/service patterns, error handling |
| `fullstack-security`  | 12     | Backend + frontend security claims combined           |

```bash
cve verify --repo ~/my-api --claims backend-security --output ./out
```

## Skill Inference

Skill inference extracts evidence-backed skill signals from repository code. Signals use a separate contract from verification — `observed/inferred/unsupported` instead of `pass/fail/unknown`.

### Skill Profile: `github-engineer-core`

| Signal ID                                 | Category        | Description                     |
|-------------------------------------------|-----------------|---------------------------------|
| `backend_auth.jwt_middleware`             | implementation  | JWT middleware evidence          |
| `backend_routing.middleware_binding`      | implementation  | Route middleware binding         |
| `backend_security.secret_hygiene`         | hygiene         | Secret management hygiene        |
| `backend_architecture.db_layering`        | implementation  | Database access layering         |
| `backend_runtime.error_handling`          | implementation  | Global error handling            |
| `backend_runtime.graceful_shutdown`       | implementation  | Graceful shutdown                |
| `frontend_security.xss_sensitive_api_usage`| risk_exposure  | XSS-sensitive API contact        |
| `frontend_auth.route_guarding`           | implementation  | Frontend route protection        |
| `testing.auth_module_tests`              | implementation  | Auth module testing              |
| `observability.request_logging`          | implementation  | Request logging                  |

### Conservative Aggregation

- Trust floor: lowest trust class across decisive inputs
- Confidence cap: heuristic-only evidence cannot produce `high` confidence
- A single advisory signal cannot produce `high`-confidence `observed`
- `human_or_runtime_required` trust cannot produce `high` confidence

## Output Files

| File                | Mode           | Description                                    |
|---------------------|----------------|------------------------------------------------|
| `scan.json`         | verification   | Repository metadata, analyzers, languages       |
| `report.json`       | verification   | Findings, trust summary, capability summary     |
| `report.md`         | verification   | Human-readable report                          |
| `accounting.json`   | verification   | Per-file analysis accounting                    |
| `evidence-graph.json`| verification  | Evidence relationship graph                     |
| `claims.json`       | verification   | Claim verdicts (when `--claims` specified)      |
| `skills.json`       | skill_inference| Skill signals, confidence, evidence             |

## Trust Model

Every finding carries a `trust_class`:

| Trust Class                 | Meaning                                          |
|-----------------------------|--------------------------------------------------|
| `machine_trusted`           | Direct evidence, safe for automated consumption   |
| `advisory`                  | Heuristic detection, review recommended           |
| `human_or_runtime_required` | Requires human review or runtime verification     |

The report includes `trust_guidance` with:

- `can_automate` — true only if all findings are `machine_trusted` + `verified`
- `requires_review` — true if any advisory or human-required findings
- `degraded_analysis` — true if analyzer capability was limited at runtime

## Public API (Go)

```go
import "github.com/verabase/code-verification-engine/pkg/cve"

engine := cve.NewEngine()

output, err := engine.Verify(ctx, cve.VerifyInput{
    RepoPath:  "/path/to/repo",
    OutputDir: "/path/to/output",
    Profile:   "backend-api",
})

// Access typed results
for _, f := range output.Report.Findings {
    fmt.Printf("[%s] %s: %s (trust: %s)\n",
        f.RuleID, f.Status, f.Message, f.TrustClass)
}
```

### Skill Inference via API

```go
output, err := engine.Verify(ctx, cve.VerifyInput{
    RepoPath:     "/path/to/repo",
    OutputDir:    "/path/to/output",
    Mode:         "skill_inference",
    SkillProfile: "github-engineer-core",
})

for _, s := range output.Skills.Signals {
    fmt.Printf("[%s] %s (confidence: %s, trust: %s)\n",
        s.SkillID, s.Status, s.Confidence, s.TrustClass)
}
```

### Extension Points

```go
// Custom analyzer plugin
engine := cve.NewEngine(
    cve.WithAnalyzerPlugin(myPlugin),
    cve.WithProgress(os.Stderr),
)

// LLM interpretation layer
engine := cve.NewEngine(
    cve.WithInterpretation(myLLMProvider),
)
```

## Supported Languages

| Language   | Analyzer    | AST Support              |
|------------|-------------|--------------------------|
| Go         | Built-in    | Full (`go/ast`)          |
| JavaScript | Built-in    | Regex + structural       |
| TypeScript | Built-in    | Regex + structural       |
| Python     | Built-in    | AST (requires python3)   |

Custom languages can be added via the `AnalyzerPlugin` interface.

## Environment Variables

| Variable           | Description                                        |
|--------------------|----------------------------------------------------|
| `CVE_LLM_PROVIDER` | LLM provider: `ollama`                             |
| `CVE_LLM_API_URL`  | Override LLM endpoint URL                          |
| `CVE_LLM_MODEL`    | Model ID for `ollama` chat-completions provider    |

Example for local Ollama with Code Llama 8B:

```bash
export CVE_LLM_PROVIDER=ollama
export CVE_LLM_API_URL=http://localhost:11434/v1/chat/completions
export CVE_LLM_MODEL=codellama:8b

cve verify --repo . --output ./out --interpret
```

## Testing

```bash
# Run all tests
go test ./...

# Run specific package tests
go test ./internal/skills/... -v
go test ./internal/engine/... -v
go test ./pkg/cve/... -v
```

## Project Structure

```
cmd/cve/              CLI entry point
pkg/cve/              Public API (stable contract)
internal/
  analyzers/          Language-specific analyzers (go, js, ts, python)
  claims/             Claim-centric verification
  cli/                CLI command handler
  engine/             Core pipeline orchestrator
  evidence/           Evidence management
  evidencegraph/      Evidence relationship graph
  facts/              Fact types and quality model
  git/                Git repository handling
  interpret/          LLM interpretation layer
  repo/               Repository metadata and file discovery
  report/             Report generation
  rules/              Rule engine, profiles, trust normalization
  schema/             Output contract validation
  scope/              File scope classification (production/test)
  skills/             Skill inference pipeline
  typegraph/          Type relationship graph
testdata/             Test fixtures and golden files
```

## License

Proprietary. All rights reserved.
