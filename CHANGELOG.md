# Changelog

All notable changes to Tankada are documented here.

---

## [Unreleased]

## [0.2.1] - 2026-05-09

### Fixed
- README: quickstart, "Customize policies" section, and "JWT token structure" all updated to show the v2 `dataActions` format introduced in 0.2.0. Previously the README still showed only the legacy `scopes[]` v1 format, so users following the quickstart on 0.2.0 generated deprecated tokens from the first request. v1 tokens still work (with deprecation warning) until 0.3.0.

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
