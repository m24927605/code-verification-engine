# Precision Upgrade Design: Rule Semantic Accuracy

## Purpose

Improve rule semantic precision across JS/TS and Python analyzers so matchers rely on structurally justified evidence rather than name/path heuristics. Go is the reference — it already enriches DataAccessFact caller context and per-route middleware bindings. This upgrade brings JS/TS/Python closer to that standard.

## Scope

**In scope (this iteration):**
- JS/TS: Express, NestJS, Fastify route-binding and caller enrichment
- Python: FastAPI, Flask route-binding and caller enrichment
- Auth evidence scoring helper for all matchers
- Matcher tightening for auth, route-protection, data-access, and repository-encapsulation rules
- Conservative capability updates at framework level

**Out of scope:**
- Koa, Hapi framework support
- Django, Starlette per-route binding (stay conservative)
- New rule creation or DSL changes
- Cross-file router resolution (same-file only for all binding work)
- Re-exports, alias chains, CommonJS/ESM interop
- Dynamic or conditional router construction
- Fastify encapsulation/plugin scope semantics beyond addHook
- Python `async def` special handling (treated same as `def` for span building)
- Mounted routers imported from other files (produce `Middlewares=nil`)
- Handler name canonicalization across frameworks (use raw names from AST)

## Normative Contracts

### Middleware Binding Semantics

`RouteFact.Middlewares` has three distinct states:

| Value | Meaning | Matcher behavior |
|-------|---------|-----------------|
| `nil` | Binding unavailable — analyzer could not determine middleware | Return `unknown` for auth checks |
| `[]string{}` (empty) | Analyzer confirmed no middleware bound | Return `fail` (explicitly unprotected) |
| `[]string{"auth"}` | Analyzer found these middleware names | Evaluate via auth classification |

**Global middleware projection:** Analyzers MUST project global middleware into `RouteFact.Middlewares` for every route in scope within the same file. The `route.protected_uses_auth_middleware` matcher evaluates ONLY `RouteFact.Middlewares`.

**MiddlewareFact role:** Records middleware existence for `auth.jwt_middleware` (exists-style). NOT used by relationship matchers.

**Scope definition for projection:** "In scope" means same file. Routes in file A cannot inherit middleware declared in file B. If a route is declared in a file where the analyzer successfully ran binding analysis, that route gets explicit `Middlewares` (possibly empty). If binding analysis could not run (e.g., unrecognized framework), `Middlewares=nil`.

**Merge rules:**
- `nil` merged with `nil` → `nil`
- `nil` merged with `[]string{"x"}` → `[]string{"x"}` (known evidence wins over unknown)
- `[]string{}` merged with `[]string{"x"}` → `[]string{"x"}`
- `[]string{"a"}` merged with `[]string{"b"}` → `[]string{"a", "b"}` (union, deduplicated)
- Partial file read → routes from that file keep `Middlewares=nil`; facts are retained with nil enrichment fields

### Provenance Semantics

Provenance is per-fact, not per-field. Rule: provenance reflects the **primary extraction method** that discovered the fact's existence.
- Fact discovered via AST → `ProvenanceAST` (even if CallerName added via regex span lookup)
- Fact discovered via regex on filtered source → `ProvenanceStructural`
- Fact discovered via regex on raw source → `ProvenanceHeuristic`
- Matchers do not branch on provenance. Provenance affects capability reporting only.

### ImportsDirect Semantics

Intentionally conservative high-precision signal:
- `true`: file has direct import of a known DB package (per-language list in analyzer)
- `false`: no known DB import, or import is transitive/re-exported
- Matchers treat `false` as weaker evidence, not proof of no direct access

### Verification Level and Trust Alignment

All matchers in this upgrade remain **advisory trust class**. No matcher produces `verified`.

| Matcher | Strong evidence | Weak evidence | No evidence |
|---------|----------------|---------------|-------------|
| `auth.jwt_middleware` | pass + `strong_inference` | pass + `weak_inference` | fail |
| `route.protected_uses_auth_middleware` | pass + `strong_inference` | pass + `weak_inference` | fail or unknown |
| `db.direct_access_from_controller` | flag + `strong_inference` | flag + `weak_inference` | skip |
| `pattern.repository_encapsulation` | flag + `strong_inference` | flag + `weak_inference` | skip |

Trust normalization continues to enforce: advisory findings cannot be `verified`.

### Result States and Route-Protection Aggregation

Matchers produce: `pass`, `fail`, or `unknown`. No `partial` status.

**Route-protection aggregation for `route.protected_uses_auth_middleware`:**

A route is "protected" if ANY of its bound middleware classifies as `AuthStrong` OR `AuthWeak`.

| Scenario | Status | Verification Level |
|----------|--------|-------------------|
| All routes with binding have at least AuthStrong middleware | `pass` | `strong_inference` |
| Any route with binding has NO auth middleware (all NotDetected) | `fail` | `strong_inference` |
| Mix: some protected, some not | `fail` | `strong_inference` |
| All routes with binding have AuthWeak only (no AuthStrong) | `unknown` | n/a (insufficient evidence) |
| Any routes have `Middlewares==nil` (regardless of others) | `unknown` | n/a (incomplete binding data) |
| All routes `Middlewares==nil` | `unknown` | n/a |

**Key rule:** `route.protected_uses_auth_middleware` only passes on AuthStrong evidence. AuthWeak is insufficient for route protection claims — it produces `unknown` to avoid false security assurance. This is stricter than `auth.jwt_middleware` (which accepts AuthWeak for existence detection) because route protection is a security-critical assertion.

## Architecture

### Data Flow (unchanged)

```
source file → parser/regex → analyzer-private enrichment → normalized Facts → FactSet → matchers → findings
```

No new exported fact types. Existing `RouteFact`, `DataAccessFact`, `MiddlewareFact` fields suffice.

### Phase 1: Analyzer Enrichment

#### 1A. JS/TS CallerName Enrichment

Add `BuildFunctionSpans(result *ASTResult) []FunctionSpan` in `internal/analyzers/jsts/`:
- `FunctionSpan{Name, Kind, StartLine, EndLine}` — analyzer-private
- Include `function` and `method` kinds only; exclude `class` (too broad)
- Narrowest enclosing span wins for nested functions
- Anonymous/unnamed → `CallerName=""` (skip enrichment)
- Variable-assigned arrows: use variable name if AST captures it as a symbol

After regex DataAccessFact extraction, enrich with CallerName/CallerKind from span and ImportsDirect from import analysis.

**Known DB packages (JS/TS):** `sequelize`, `typeorm`, `prisma`, `@prisma/client`, `mongoose`, `mongodb`, `knex`, `pg`, `mysql`, `mysql2`, `better-sqlite3`, `drizzle-orm`, `mikro-orm`

#### 1B. JS/TS Route-to-Middleware Binding (same-file only)

All binding resolution is strictly same-file. Routes whose handlers or routers are imported from another file get `Middlewares=nil`.

**Express:**
- `app.use(mw)` → projected into all routes declared AFTER it in same file. Order is determined by AST source position (line number; if same line, column/offset from parser). If parser does not provide sub-line ordering, same-line calls are treated as sequential in left-to-right source order.
- `router.use(mw)` → projected into routes on that router variable in same file
- Inline: `app.get('/path', authMw, handler)` → `Middlewares` includes `authMw` plus inherited
- No `use()` and no inline → `Middlewares=[]string{}`
- `app.use('/prefix', router)` mounts: only if router is defined in same file; otherwise `nil` for child routes

**NestJS:**
- `@UseGuards(Guard)` on controller → projected into all method routes
- `@UseGuards(Guard)` on method → method-specific, merged with controller-level (union, dedup)
- No guards → `Middlewares=[]string{}`

**Fastify:**
- `addHook('onRequest'|'preHandler', hook)` → projected into routes in same scope
- Other lifecycle hooks → ignored
- Not inherently auth; classified in Phase 2

#### 1C. Python Route Binding Enrichment

**FastAPI (AST path):**
- `app.add_middleware(Cls)` → projected into all routes' Middlewares
- `Depends(fn)` at path-operation level (decorator keyword arg or function parameter default) → that route
- `Depends(fn)` at router constructor level → all routes on that router
- Nested `Depends` → NOT followed (one level only)
- Dynamic/computed `Depends()` → entire route gets `Middlewares=nil` (unknown taints route; known global middleware does not override per-route uncertainty)

**Flask (AST path):**
- `@login_required` (or similar decorator) on route function → `Middlewares=["login_required"]`
- `@app.before_request` with function name → projected into all routes' Middlewares in same file
- Blueprint `before_request` → scoped to blueprint routes if resolvable; otherwise `nil`
- `before_request` without auth-related name → still projected; auth classification happens in Phase 2

**Regex fallback (both):**
- Build function spans from `def`/`async def` lines + indentation
- Enrich DataAccessFact CallerName from enclosing def
- ImportsDirect from file-level DB imports
- Route binding NOT attempted via regex → `Middlewares=nil`

**Known DB packages (Python):** `sqlalchemy`, `django.db`, `peewee`, `tortoise`, `databases`, `motor`, `pymongo`, `psycopg2`, `asyncpg`, `aiomysql`

### Phase 2: Matcher Tightening

#### 2A. Auth Evidence Scoring

New file `internal/rules/auth_evidence.go`:

```go
type AuthEvidence struct {
    HasMiddlewareBinding bool   // name appears in RouteFact.Middlewares
    HasAuthImport        bool   // file imports known auth package
    HasAuthName          bool   // name tokens include auth keywords
    HasContradictoryName bool   // name tokens include non-auth keywords
    MiddlewareName       string // original name for reporting
}

type AuthClassification int
const (
    AuthNotDetected AuthClassification = iota
    AuthWeak
    AuthStrong
)
```

**Auth name tokens:** `auth`, `jwt`, `guard`, `verify`, `authenticate`, `passport`, `require`, `login`, `protect`

**Contradictory name tokens:** `cors`, `helmet`, `log`, `logger`, `logging`, `rate`, `limit`, `throttle`, `metrics`, `error`, `compress`, `compression`, `static`, `body`, `parse`, `json`, `cookie`, `csrf`, `csp`

**Contradiction override:** If a name contains BOTH auth and contradictory tokens (e.g., `session_auth`, `csrf_protect_auth`), auth tokens take precedence — `HasContradictoryName` is set to false. This prevents suppression of legitimate auth middleware with compound names.

**Scoring:**

| Signal | Score |
|--------|-------|
| `HasMiddlewareBinding` | +3 |
| `HasAuthImport` | +2 |
| `HasAuthName` | +1 |
| `HasContradictoryName` (without auth tokens) | -3 |

**Classification (score-based, no additional structural requirements):**
- `AuthStrong`: score >= 5 (requires binding + import)
- `AuthWeak`: score >= 1 AND NOT contradictory-only
- `AuthNotDetected`: score < 1 OR contradictory-only

This means:
- binding(3) + import(2) = 5 → AuthStrong
- binding(3) + import(2) + name(1) = 6 → AuthStrong
- binding(3) + name(1) = 4 → AuthWeak (no import confirmation)
- import(2) + name(1) = 3 → AuthWeak (no binding — exists check only)
- name(1) only = 1 → AuthWeak
- contradictory(-3) only → AuthNotDetected

**Known auth packages (authoritative list):**

| Language | Packages |
|----------|----------|
| Go | `github.com/golang-jwt/jwt`, `github.com/dgrijalva/jwt-go`, `github.com/lestrrat-go/jwx` |
| JS/TS | `jsonwebtoken`, `passport`, `passport-jwt`, `express-jwt`, `@nestjs/jwt`, `@nestjs/passport`, `jose`, `@auth0/nextjs-auth0`, `next-auth` |
| Python | `pyjwt`, `python-jose`, `fastapi.security`, `flask-jwt-extended`, `flask-login`, `django.contrib.auth` |

#### 2B. Matcher Changes

**`auth.jwt_middleware` (exists_matcher.go):**
- Build AuthEvidence for each MiddlewareFact (binding=false for exists check; use HasAuthImport + HasAuthName)
- For exists-style check: any MiddlewareFact with AuthWeak or better → pass
- AuthStrong (import + name) → `strong_inference`
- AuthWeak (name only) → `weak_inference`
- None → fail

**`route.protected_uses_auth_middleware` (relationship_matcher.go):**
- Per route: classify each Middlewares entry via ClassifyAuth (with HasMiddlewareBinding=true since they are bound)
- Aggregation per Result States table above

**`db.direct_access_from_controller` (pattern_matcher.go):**
- Handler matching: file-scoped identity — match DataAccessFact.CallerName against RouteFact.Handler only when BOTH are in the same file. This prevents false matches from common method names like `get`, `list`, `create` across files.
- With CallerName + same-file handler match + ImportsDirect=true → flag at `strong_inference`
- With CallerName + same-file handler match + ImportsDirect=false → skip (delegated)
- With CallerName + no same-file handler match → check file-path heuristic (controller/handler/endpoint tokens) at `weak_inference`
- Without CallerName → file-path fallback at `weak_inference`

**`pattern.repository_encapsulation` (pattern_matcher.go):**
- Same CallerName + ImportsDirect preference

#### 2C. Non-auth middleware exclusion

Contradictory tokens (normative, single list): `cors`, `helmet`, `log`, `logger`, `logging`, `rate`, `limit`, `throttle`, `metrics`, `error`, `compress`, `compression`, `static`, `body`, `parse`, `json`, `cookie`, `csrf`, `csp`

Overridden if auth tokens also present in same name.

### Phase 3: Capability Updates

Framework-specific updates via `CapabilityDetail.Frameworks` and `Notes`. No base language level changes. No trusted-core changes.

| Language | Target | Change |
|----------|--------|--------|
| JS/TS | `auth.jwt_middleware` | Framework notes for Express/NestJS/Fastify: "binding+import scoring" |
| JS/TS | `route.protected_uses_auth_middleware` | Framework notes: "same-file per-route binding from use()/guards" |
| JS/TS | `db.direct_access_from_controller` | Notes: "CallerName from AST function spans" |
| Python | `auth.jwt_middleware` | Framework notes for FastAPI/Flask: "dependency/decorator binding" |
| Python | `route.protected_uses_auth_middleware` | FastAPI: "Depends propagation"; Flask: "decorator+before_request" |
| Python | `db.direct_access_from_controller` | Notes: "CallerName from AST/regex function spans" |

## Edge Cases

1. JWT imports for token creation (not middleware) → `auth.jwt_middleware` requires MiddlewareFact, not just import
2. Anonymous handlers → `CallerName=""`, skip enrichment
3. Nested spans → narrowest enclosing wins
4. `nil` vs `[]string{}` preserved through all merge/dedup
5. NestJS controller+method guards → union, deduplicated
6. Fastify non-auth hooks (`onClose`, `onSend`) → ignored
7. Dynamic router construction → `Middlewares=nil`
8. Express `app.use(mw)` order-dependent by line number
9. Partial file read → routes keep `Middlewares=nil`
10. Custom auth without known imports → `AuthWeak` (advisory, not silent)
11. `session_auth` compound names → auth tokens override contradictory
12. Duplicate handler names in file → all matching handlers considered
13. DB imports used only for types → still sets `ImportsDirect=true` (conservative overshoot accepted)
14. Multiple route registrations for same handler → each route evaluated independently

## Testing Strategy

### Phase 1 (Analyzer)
- Function span construction: top-level, method, nested, anonymous, arrow
- Caller enrichment: CallerName resolution, ImportsDirect true/false
- Express binding: global use, router use, inline, order-dependent, explicit empty
- NestJS binding: controller guards, method guards, merged
- Fastify binding: onRequest/preHandler hooks, ignored hooks
- FastAPI binding: Depends at path-op/router level, add_middleware
- Flask binding: login_required decorator, before_request projection
- Regex fallback caller enrichment for Python
- nil vs empty middleware semantics

### Phase 2 (Matcher)
- Auth scoring: strong (binding+import=5), weak (binding+name=4), not detected (contradictory)
- Compound name override (session_auth → auth wins)
- Relationship matcher aggregation: all protected, one unprotected, all nil, mixed
- Data access: CallerName+handler match, CallerName+no match, no CallerName fallback
- False positive guards for each tightened matcher

### Phase 3 (Integration)
- Capability notes verification
- Go regression (unchanged behavior)
- Engine.Run() integration for improved JS/TS scenario
- Django/Starlette unchanged

## Non-Goals

- Full cross-file call graph or router resolution
- Dynamic dispatch resolution
- Runtime-dependent auth verification
- New rule creation or DSL/schema changes
- Handler name canonicalization (use raw names)
- Performance optimization beyond per-file linear
