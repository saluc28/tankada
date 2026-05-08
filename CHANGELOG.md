# Changelog

All notable changes to Tankada are documented here.

---

## [Unreleased]

### Added
- Integration tests for the gateway handler (`handler/query_test.go`): 9 table-driven tests covering the full HTTP request path -- query blocked by OPA (403), query allowed with proxy result (200), rate limit exceeded (429), analyzer down fail-closed (503), OPA down fail-closed (503), proxy down (502), missing JWT claims (401), empty query (400), invalid JSON body (400)

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
