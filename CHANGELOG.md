# Changelog

All notable changes to Tankada are documented here.

---

## [Unreleased]

### Added
- `accesses_pii_columns` boolean field in analyzer response (shorthand for `len(pii_columns) > 0`) (2026-05-06)
- `POST /v1/explain` endpoint: returns deny reasons and actionable suggestions for a query without executing it (2026-05-06)
- OPA policy unit tests via `opa test` covering all deny rules and risk scoring (2026-05-06)

### Changed
- OPA policies migrated to Rego v1 syntax (`deny contains reason if`, `:=`, `if` keyword) (2026-05-06)
- Internal services (postgres, analyzer, OPA, proxy) no longer expose ports on the host; only gateway (8080) and dashboard (3000) are reachable from outside Docker (2026-05-07)
- Gateway now refuses to start if `JWT_SECRET` is the default dev value unless `TANKADA_ENV=development`; docker-compose sets `TANKADA_ENV=development` by default for local use (2026-05-07)
- Added "Known limitations" section in README documenting unsupported WHERE filter patterns for tenant isolation (`IN`, `$1`, `current_setting(...)`) (2026-05-07)

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
