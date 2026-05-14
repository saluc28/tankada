# Changelog

All notable changes to Tankada are documented here.

---

## [Unreleased]

### Added
- `session_block` deny category in `gateway/handler/deny_category.go`. Cross-query behavioural blocks (repeated denials, reformulation attempts, systematic pagination, repeated schema enumeration) now map to a dedicated `session_block` category instead of falling through to `unknown`. Belongs to the abort bucket. Emitted by Tankada instances that run the proprietary session-scoring extension.
- `repeated schema enumeration` reasons now map to `session_block` (previously `schema_enum`). Single schema-enumeration events stay on `schema_enum`. The split reflects the semantic difference: one-off recon vs cross-query attack pattern.
- README API reference now documents `POST /v1/explain` and `GET /health`. The explain endpoint shipped in 0.2.x but was undocumented; it returns the policy decision plus actionable suggestions without executing the query, suitable for agent self-correction loops.

### Fixed
- **PostgreSQL RLS is now actually enforced at the proxy layer.** The schema in `deploy/postgres/init.sql` already declared `tankada_app` role, `ENABLE ROW LEVEL SECURITY`, `FORCE ROW LEVEL SECURITY`, and `tenant_isolation` policies on the 5 tenant-scoped tables, but the proxy connected as the database owner (a superuser by default in the Postgres Docker image) and never switched roles, so RLS was silently bypassed at runtime. The proxy now wraps every query in a transaction that calls `SET LOCAL ROLE tankada_app` and `SELECT set_config('app.tenant_id', $1, true)` before executing. RLS now returns zero cross-tenant rows even if the OPA tenant filter is bypassed. Both settings are transaction-scoped so the connection pool stays clean. Verified: a direct call to the proxy as `tenant_1` on `SELECT id, tenant_id FROM customers` returns only `tenant_1` rows; an empty tenant_id returns zero rows (fail-safe).

### Changed
- `pii_column_guard` Rego rule reason changed from `"query accesses PII columns %v without elevated scope"` to `"query accesses PII columns %v without required scope for table '%v'"`. The category mapping is unchanged (`pii_violation`).
- `sens_score` no longer adds +3 risk on every access to a sensitive table when the agent already holds the required scope. Previously, a legitimate analyst accumulated false-positive risk on each query and approached the deny threshold (7) after a handful of valid reads. The score now fires only on unauthorised access, the same condition that already triggers `missing_scope`.
- README architecture diagram refined: rate limit step now shown explicitly, audit log fires on both deny and allow paths, proxy box now describes the actual RLS wiring (`SET LOCAL ROLE tankada_app` + `SET LOCAL app.tenant_id`).
- README audit log JSON example completed with the three fields that were always present in the event but missing from the example: `owner_user_id`, `policy_reasons`, `session_id`.
- README Quick start clarified: the dashboard is **not** part of `docker compose up -d`; it runs as a separate Python process.
- EXAMPLES.md deny-category table now lists `session_block` (16 categories total, up from 15) and the reference Python `ABORT_CATS` set was extended to match.

## [0.3.0] - 2026-05-11

### Added
- Demo dashboard `sql_database` tool (`sdk/python/dashboard/server.py`) now reads `deny_categories[]` from the gateway response and prefixes every blocked tool result with one of four behaviour-driving tags: `[ABORT]`, `[REWRITE]`, `[TRANSIENT]`, `[BLOCKED]`. The system prompt instructs the LLM to act based on the tag — so the agent stops on semantic deny (missing scope, PII guard, tenant violation) instead of attempting alternative queries. This is the reference "good citizen tool" pattern: machine-driven instructions to the LLM that work even if the system prompt is incomplete.
- New section "Handling deny categories" in [EXAMPLES.md §6](EXAMPLES.md#6-handling-deny-categories): full table of the 15 deny categories grouped into three behaviour buckets (abort / rewrite / transient), reference Python pattern (framework-agnostic), and LangChain tool wrapper pattern. Explains why this matters operationally — without it, agents return partial substituted data without the user knowing.
- README API reference now shows `deny_categories` in deny response examples and links to EXAMPLES §6 for the full handling pattern.

### Changed
- EXAMPLES.md: all four deny response examples (tautology, select_star, pii_violation, schema_enum) now include the corresponding `deny_categories` field for parity with the actual API response.
- EXAMPLES.md: PII deny reason text in scenario 4 corrected from `"query accesses PII columns: [email] (missing required scope)"` to the actual Rego-emitted `"query accesses PII columns [email] without elevated scope"`.

## [0.2.2] - 2026-05-10

### Added
- `deny_categories` field in `/v1/query` response when `decision: "deny"`. Machine-readable enum that lets client integrators decide programmatically how to react to a deny without parsing free-text `reasons[]`. Categories: `missing_scope`, `pii_violation`, `tenant_violation`, `injection`, `destructive_op`, `schema_enum`, `parse_error` (non-recoverable, agent must abort the task), `tautology`, `select_star`, `missing_where`, `high_limit` (recoverable by query reformulation), `rate_limit`, `infrastructure` (transient, retry after backoff), `risk_score`, `unknown` (composite or unmapped). Mapped from existing `reasons[]` prefixes in the gateway — zero changes to Rego policy. Solves the "agent fallback" problem where LLM agents, on a generic deny, autonomously try alternative queries with degraded data instead of stopping.
- Demo dashboard system prompt (`sdk/python/dashboard/server.py`) updated to instruct the agent to abort on semantic deny (missing scope, PII guard) instead of attempting alternative queries — paired with the new `deny_categories` API for clients who integrate programmatically.

### Fixed
- `gateway/handler/explain.go`: added nil-check on `claims` before use ([#2](https://github.com/saluc28/tankada/issues/2)). The explain handler previously assumed `claims` was always populated by upstream auth middleware; if claims were missing the handler would panic with a nil pointer dereference on `claims.AgentID`. Now returns HTTP 401 `{"error":"missing claims"}`, consistent with the query handler. Regression test added in `gateway/handler/explain_test.go`.
- `gateway/handler/query.go`: proxy failure error message changed from `"query execution failed"` to `"proxy execution failed: upstream proxy unavailable"` ([#3](https://github.com/saluc28/tankada/issues/3)). Operators debugging an HTTP 502 can now identify which upstream service failed (proxy vs analyzer vs OPA) without checking server logs. Existing `TestHandle_ProxyDown_Returns502` extended to assert the message contains "proxy".

## [0.2.1] - 2026-05-09

### Fixed
- README: quickstart, "Customize policies" section, and "JWT token structure" all updated to show the v2 `dataActions` format introduced in 0.2.0. Previously the README still showed only the legacy `scopes[]` v1 format, so users following the quickstart on 0.2.0 generated deprecated tokens from the first request. v1 tokens still work (with deprecation warning) until 0.3.0.
- README: PII keyword count corrected from "40 keywords" to "34 keywords" (the actual size of `_PII_KEYWORDS` in `analyzer/analyzer.py`, including the `account_number`, `account_num`, `balance` additions from 0.2.0).
- README: analyzer test count corrected from "63 passed" to "73 passed".
- README: Rego custom rule examples updated to use the v1 syntax `:=` (e.g. `sensitive_tables := {...}`) consistent with the actual `policies/query.rego`. The previous `=` examples were Rego v0 syntax and would have failed `opa test` if pasted as-is.

### Documentation
- README "Known limitations" section now documents two v2-specific constraints: (1) the resolver's `knownTables` and `tableSectorMap` are hardcoded to the demo fintech schema and require code edits to support a custom schema, with `templates.json`-based loading planned as the long-term fix; (2) only the `read` action is supported today — `write` and `admin` paths resolve to an empty scope list.

### Changed
- README header replaced the static `banner.svg` with a centered hero composed of the `wordmark` SVG from `brand/` rendered via `<picture>` for automatic light/dark theme adaptation, plus centered badges and quick-link navigation (Quick start · Examples · Contributing · Changelog).
- README badges expanded from 3 to 5: added Latest release (auto from GitHub releases) and Last commit (project liveness). Go Report Card was considered but doesn't apply — the repo is a polyglot monorepo with `gateway/` and `proxy/` as separate Go modules, not a single-module Go project at root.

## [0.2.0] - 2026-05-09

### Breaking Changes
- **JWT scope format**: `scopes[]` (v1) is now legacy. New JWTs should use `dataActions[]` and `notDataActions[]` with hierarchical paths in the format `{tenant_id}/{sector}/{table}/{action}`. Wildcards (`*`) are supported per segment.
- v1 tokens with `scopes[]` continue to work unchanged (no immediate action required); the gateway emits a one-shot deprecation warning per `agent_id` when it sees one. Plan to migrate before the next minor release.

  **Migration guide:**

  Old v1 token:
  ```json
  {
    "agent_id": "analyst-agent",
    "tenant_id": "tenant_1",
    "roles": ["analyst"],
    "scopes": ["accounts:read", "transactions:read"]
  }
  ```

  New v2 token:
  ```json
  {
    "agent_id": "analyst-agent",
    "tenant_id": "tenant_1",
    "roles": ["analyst"],
    "dataActions": [
      "tenant_1/financial/accounts/read",
      "tenant_1/financial/transactions/read"
    ],
    "notDataActions": []
  }
  ```

  Wildcard examples (v2-only):
  - `tenant_1/*/*/read` — all tables, read-only across the whole tenant
  - `tenant_1/financial/*/read` — every table in the `financial` sector
  - `dataActions: ["tenant_1/*/*/read"]` + `notDataActions: ["tenant_1/financial/customers/read"]` — everything except customers

  **Tenant invariant:** any path whose first segment doesn't match the JWT's `tenant_id` claim is silently dropped (and logged as `tankada.security.scope_tenant_mismatch`). Defence-in-depth on top of the HMAC signature.

  **Deprecation window:** v1 tokens remain valid until the next minor (0.3.0). Migrate before then.

### Added
- `gateway/middleware/resolver.go`: pure-function resolver that expands v2 hierarchical paths into the flat `{table}:read` scope list OPA already understands. Zero changes to Rego — all 54 OPA tests pass unchanged.
- 12 unit tests on the resolver (wildcards per segment, `notDataActions`, cross-tenant rejection, malformed entry handling) and 4 end-to-end JWT v1/v2 tests in `handler/query_test.go`.
- Demo dashboard: scenario 7 (bulk extraction, LIMIT 1000 blocked) and scenario 8 (LLM hallucination, SSN access blocked)
- Demo dashboard: redesigned UI — two-column layout, sticky header with logo, step cards with decision badge, audit trail as table, agent tab buttons instead of dropdown

### Fixed
- `policies/templates.json`: wrapped content under `templates` key — OPA was loading template rules at `data.*` root instead of `data.templates.*`, silently disabling all template-based deny rules (`pii_column_guard`, `tautology_blocker`, `select_star_block`, `row_limit_enforcer`, `destructive_query_block`)
- `analyzer/analyzer.py`: added `account_number`, `account_num`, `balance` to PII keywords — financial identifiers were not detected, allowing agents to extract account data without scope check
- Demo dashboard: pagination scenario updated from old `orders` table to `transactions` (fintech schema)
- Demo dashboard: PRESETS array and dropdown options aligned to fintech schema
- `EXAMPLES.md`: five concrete detection scenarios with curl examples and JSON responses (tautology, SELECT *, PII access, legitimate query, schema enumeration)
- `CONTRIBUTING.md`: how to run locally, how to add a policy rule, how to open a PR
- GitHub Actions CI workflow (`ci.yml`): four jobs: Analyzer (ruff lint + pytest), Gateway (go test), Proxy (go build), Policies (opa test); triggers on push and pull_request to main
- CI badge, license badge, and Docker Pulls badge in README
- Docker image published to Docker Hub: `saluc28/tankada-gateway`
- Integration tests for the gateway handler (`handler/query_test.go`): 9 tests covering the full HTTP request path: query blocked by OPA (403), query allowed with proxy result (200), rate limit exceeded (429), analyzer down fail-closed (503), OPA down fail-closed (503), proxy down (502), missing JWT claims (401), empty query (400), invalid JSON body (400)
- `policies/query_test.rego`: aligned to fintech schema: `base_input` table changed from `products` to `merchants`, sensitive table tests updated from `users` to `customers`, PII scope updated from `users:read` to `customers:read`
- `gateway/handler/explain.go`: suggestion messages now reference correct scopes (`customers:read`, `cards:read`) instead of stale `users:read`/`payments:read`
- `sdk/python/dashboard/index.html`: preset scenarios and agent dropdown updated to fintech schema (merchants, customers)
- `analyzer/test_analyzer.py`: split `import sys, os` to fix ruff E401
- `proxy/go.sum`: added missing file (caused CI build failure)

---

## [0.1.9] - 2026-05-07

### Changed
- Demo database redesigned as a fintech schema (Demobank NA / Demobank EU): 6 tables (`merchants`, `customers`, `accounts`, `transactions`, `cards`, `loans`), 280+ seed rows across two tenants; replaces the generic e-commerce schema (`products`, `orders`, `users`)
- `sensitive_tables` in `policies/query.rego` updated to `{"customers", "cards", "credentials", "secrets", "pii_data", "audit_logs"}` (was `{"users", "payments", ...}`)
- `tenant_global_tables` updated to `{"merchants"}` (was `{"products"}`)
- `agent_has_scope` scopes updated to `customers:read` and `cards:read` (was `users:read` and `payments:read`)
- Demo dashboard `AGENTS` scopes and `SYSTEM_PROMPT` updated to reflect fintech schema

---

## [0.1.8] - 2026-05-07

### Changed
- Upgraded OPA Docker image from `0.65.0` to `1.16.1` to align with local OPA CLI version; `import rego.v1` remains explicit in policy files for portability

---

## [0.1.7] - 2026-05-07

### Fixed
- OPA fails to start: added `import rego.v1` to `policies/query.rego` — required for Rego v1 syntax (`deny contains reason if`) on OPA 0.65+; without it OPA crashed with 63 `rego_parse_error` entries and the gateway went fail-closed on every query
- Demo dashboard incorrectly showed DENY for queries blocked by a 502 proxy error; error responses without a `decision` field are now shown as "error" rather than "deny"
- Demo agent added `tenant_id` filter to `products` table (which has no such column), causing proxy 502 errors; system prompt and tool docstring now explicitly state that `products` has no `tenant_id`

---

## [0.1.6] - 2026-05-07

### Added
- Policy templates: `policies/templates.json` lets operators toggle detection rules and adjust parameters (e.g. `max_limit`) without editing Rego
- `select_star_block` template: direct deny for `SELECT *`, previously only contributed to risk score
- `row_limit_enforcer` template: direct deny when LIMIT exceeds `max_limit` (default 500), previously only risk score
- `destructive_query_block`, `tautology_blocker`, `pii_column_guard` now template-controlled (same behavior when enabled, skipped when disabled)
- OPA policy unit tests extended: `default_templates` fixture, tests for each template enabled/disabled

---

## [0.1.5] - 2026-05-07

### Added
- `accesses_pii_columns` boolean field in analyzer response (shorthand for `len(pii_columns) > 0`)
- `POST /v1/explain` endpoint: returns deny reasons and actionable suggestions for a query without executing it
- OPA policy unit tests via `opa test` covering all deny rules and risk scoring

### Changed
- OPA policies migrated to Rego v1 syntax (`deny contains reason if`, `:=`, `if` keyword)
- Internal services (postgres, analyzer, OPA, proxy) no longer expose ports on the host; only gateway (8080) and dashboard (3000) are reachable from outside Docker
- Gateway now refuses to start if `JWT_SECRET` is the default dev value unless `TANKADA_ENV=development`; docker-compose sets `TANKADA_ENV=development` by default for local use
- Added "Known limitations" section in README documenting unsupported WHERE filter patterns for tenant isolation (`IN`, `$1`, `current_setting(...)`)

---

## [0.1.4] - 2026-05-06

### Fixed
- Audit logging missing on analyzer fail-closed and proxy fail-closed branches
- Rate limiter memory leak: added janitor goroutine to evict expired windows
- `has_offset` false positive for `OFFSET 0` (first page no longer flagged)

---

## [0.1.3] - 2026-05-06

### Added
- Webhook alert on policy block via `TANKADA_WEBHOOK_URL` environment variable

---

## [0.1.2] - 2026-05-05

### Added
- PostgreSQL Row-Level Security tenant isolation (wall 3): OPA enforces `tenant_id` equality filter in WHERE clause

---

## [0.1.1] - 2026-05-02

### Added
- `having_is_tautology` detection in analyzer
- PII alias bypass detection (`SELECT password AS p` correctly flagged)

### Fixed
- Parenthesized tautology `(1=1)` not detected
- `TRUE OR condition` inside parentheses not detected

---

## [0.1.0] - 2026-04-30

### Added
- Initial release
- JWT-authenticated gateway (port 8080) with OPA policy enforcement
- Python FastAPI SQL analyzer (port 8001) with sqlglot
- Transparent SQL proxy (port 8082) to PostgreSQL
- Policy walls: tautology, schema enumeration, UNION injection, multi-statement, comment stripping, PII column detection, rate limiting, high LIMIT, ORDER BY RANDOM
- `where_equality_filters` for tenant-isolation enforcement in OPA
- Dashboard UI (port 8888)
- Docker Compose deployment
- Python SDK
