<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="brand/wordmark-dark.svg">
    <img src="brand/wordmark-light.svg" alt="Tankada" width="420">
  </picture>
</p>

<p align="center">
  <strong>A proxy that sits between your AI agents and your database<br>and decides whether each query is allowed to run.</strong>
</p>

<p align="center">
  <a href="https://github.com/saluc28/tankada/actions/workflows/ci.yml"><img src="https://github.com/saluc28/tankada/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License: MIT"></a>
  <a href="https://github.com/saluc28/tankada/releases/latest"><img src="https://img.shields.io/github/v/release/saluc28/tankada?label=release" alt="Latest release"></a>
  <a href="https://hub.docker.com/r/saluc28/tankada-gateway"><img src="https://img.shields.io/docker/pulls/saluc28/tankada-gateway" alt="Docker Pulls"></a>
  <a href="https://github.com/saluc28/tankada/commits/main"><img src="https://img.shields.io/github/last-commit/saluc28/tankada" alt="Last commit"></a>
</p>

<p align="center">
  <a href="#quick-start">Quick start</a> ·
  <a href="EXAMPLES.md">Examples</a> ·
  <a href="CONTRIBUTING.md">Contributing</a> ·
  <a href="CHANGELOG.md">Changelog</a>
</p>

---

## The problem

AI agents generate SQL autonomously. They don't know your data boundaries, and they can be manipulated into running queries that look syntactically fine but are dangerous. An agent asked to "show all users" might generate:

```sql
SELECT * FROM users WHERE 1=1   -- tautology, filters nothing
SELECT table_name FROM information_schema.tables  -- schema recon
SELECT email, password FROM users WHERE id > 0 UNION SELECT ...  -- extraction
```

Traditional proxies block `DROP TABLE`. They don't catch any of these.

---

## How it works

Every query goes through four steps before touching the database:

1. **Parse**: sqlglot builds an AST. No regex. Structural analysis of what the query actually does.
2. **Evaluate**: OPA checks the AST against your Rego policies. Rules reload without restart.
3. **Execute or block**: allowed queries run; blocked ones get a structured JSON reason the agent can read and act on.
4. **Log**: every request is written to an audit trail with risk score, agent identity, and the original query text.

---

## Why AST, not regex

String matching works for `DROP TABLE`. It breaks as soon as the query gets slightly creative.

These all pass regex-based tools. Tankada blocks them:

```sql
-- column renamed to dodge keyword matching
SELECT password AS p FROM users WHERE id = 1

-- WHERE is present but filters nothing
SELECT * FROM users WHERE user_id = user_id

-- second statement hidden after semicolon
SELECT id, name FROM products; DROP TABLE sessions--

-- structurally identical to 1=1
SELECT email FROM users WHERE active = active
```

Tankada uses [sqlglot](https://github.com/tobymao/sqlglot) to parse every query into an AST before evaluating it. A tautology is a tautology whether it's `1=1`, `'a'='a'`, or `user_id = user_id`. An alias bypass is caught whether the column is renamed to `p`, `x`, or `data`.

---

## Architecture

```
AI Agent (LangChain, LlamaIndex, AutoGen, custom)
    |
    | POST /v1/query  {"query": "SELECT ...", "context": {...}}
    | Authorization: Bearer <JWT>
    v
┌──────────────────────────────────────────────────────────────────┐
│                          Gateway :8080                           │
│  JWT auth -> Rate limit -> Analyzer -> OPA -> (Proxy if allow)   │
│                              every decision -> Audit log         │
└──────┬──────────────────┬──────────────────┬─────────────────────┘
       │                  │                  │
       v                  v                  v
  Analyzer           OPA :8181          Proxy :8082
   :8001            (Rego policy)       (write block at app layer,
  (sqlglot              allow/deny       SET LOCAL ROLE tankada_app
   AST)              + risk score        + SET LOCAL app.tenant_id
                                          per query)
                                                  │
                                                  v
                                         PostgreSQL :5432
                                      (Row Level Security:
                                       tenant_id enforced
                                       at DB layer, wall 3)
```

Three independent enforcement walls:
1. **OPA**: semantic policy engine, blocks at the query analysis layer
2. **Proxy**: unconditionally rejects write operations at the application layer
3. **PostgreSQL RLS**: enforces tenant isolation at the DB layer via `tankada_app` role and `SET LOCAL` session variables; returns zero rows even if both layers above are bypassed

---

## Detection capabilities

| Pattern | How detected | Default action |
|---|---|---|
| Tautology WHERE (1=1, OR 1=1, col=col, AND of all-tautologies) | AST node analysis (recurses into OR with `any`, AND with `all`) | Deny |
| Schema enumeration (information_schema, pg_catalog, pg_*) | Table/schema name match | Hard deny |
| PII column access (email, password, ssn, iban, credit_card, balance, account_number...) | Column name keyword match (34 keywords) | Deny without scope |
| Cross-tenant access (query touches a tenant-scoped table without `tenant_id = <agent's JWT tenant>` filter) | Top-level AND equality extraction + JWT comparison | Hard deny |
| Subquery on tenant-scoped table without its own `tenant_id` filter (e.g. `... WHERE tenant_id='t1' AND id IN (SELECT customer_id FROM transactions)`) | Per-Subquery WHERE inspection | Hard deny |
| Cross-tenant access at DB layer (even if policy is bypassed) | PostgreSQL RLS via `tankada_app` role + `SET LOCAL app.tenant_id` per transaction | Zero rows returned |
| SELECT without WHERE | `has_where = false` | Deny |
| SELECT * | Star column detection | Deny (configurable) |
| SELECT * without LIMIT | Star column + no limit | Risk +2 |
| High LIMIT (> 500) | Literal value extraction | Deny (configurable) |
| UNION / INTERSECT / EXCEPT | AST union node | Risk +2 |
| SQL comments (-- or /* */) | Raw SQL scan before parse | Risk +1 |
| ORDER BY RANDOM() | AST rand node | Risk +1 |
| Multi-statement injection (`SELECT ...; DROP ...`) | Statement count after parse | Hard deny |
| Destructive operations (DELETE, DROP, TRUNCATE, ALTER) | Query type | Hard deny |
| Invalid/malformed SQL | Unrecognized AST node type | Hard deny (fail closed) |

Risk score >= 7 triggers automatic deny. Threshold is configurable in `policies/query.rego`.

### Scope of per-query enforcement

This repository implements **per-query enforcement**: every query is evaluated in isolation against the policy and the agent's scope. Per-query enforcement catches patterns with a syntactic deny signal (tautology, `SELECT *`, `LIMIT > N`, PII column, missing `tenant_id` filter, destructive operations, schema enumeration).

Some bypass patterns are **intentionally not** covered by the per-query layer because they have no per-query syntactic anomaly:

| Pattern | Per-query outcome | Where it's caught |
|---|---|---|
| Missing LIMIT on a queried data table (specific columns, predicates present) | ALLOW (no anomaly to anchor on) | Session-aware enforcement |
| `ORDER BY RANDOM()` repeated to sample a table | ALLOW (risk score +1, below deny threshold) | Session-aware enforcement |
| `LIMIT/OFFSET` pagination stepping through a table | ALLOW per query (each plausible in isolation) | Session-aware enforcement |

Session-aware enforcement (cross-query state, denied-tables tracking, behavioral risk scoring) lives in the proprietary extension running at [demo.tankada.io](https://demo.tankada.io) and is the subject of the Tankada paper. Auditors of this OSS layer alone will observe the gaps above; the OSS layer is necessary but not sufficient on its own.

---

## Quick start

Requires Docker and Docker Compose.

```bash
git clone https://github.com/saluc28/tankada.git
cd tankada/deploy

docker compose up -d
```

Services exposed on the host:
- Gateway: http://localhost:8080

Analyzer, OPA, proxy, and PostgreSQL run on the internal Docker network only and are not reachable from the host.

The demo dashboard (http://localhost:8090) is **not** managed by docker-compose. It runs as a separate Python process that talks to the gateway over HTTP, so you can swap LLM providers or restart it without affecting the stack.

**Run the demo dashboard (optional):**

```bash
cd sdk/python/dashboard
pip install langgraph pyjwt

# Ollama (default - local, no API key needed)
pip install langchain-ollama
# requires Ollama running with: ollama pull qwen2.5:7b
python server.py

# OpenAI
pip install langchain-openai
LLM_PROVIDER=openai LLM_API_KEY=sk-... python server.py

# Anthropic
pip install langchain-anthropic
LLM_PROVIDER=anthropic LLM_API_KEY=sk-ant-... python server.py
```

Open http://localhost:8090. Override the model with `LLM_MODEL=gpt-4o` etc.

**Generate a JWT token:**

```bash
pip install pyjwt

python - <<'EOF'
import jwt, datetime
token = jwt.encode({
    "agent_id":       "my-agent",
    "tenant_id":      "tenant_1",
    "roles":          ["analyst"],
    "dataActions":    ["tenant_1/financial/accounts/read", "tenant_1/financial/transactions/read"],
    "notDataActions": [],
    "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=2)
}, "dev-secret-change-in-production", algorithm="HS256")
print(token)
EOF
```

`dataActions` use the hierarchical format `{tenant_id}/{sector}/{table}/{action}` and support wildcards per segment (e.g. `tenant_1/*/*/read` for an admin agent). The legacy flat `scopes: [...]` format from 0.1.x still works but emits a deprecation warning. See [CHANGELOG](CHANGELOG.md) 0.2.0 migration guide.

**Send a query:**

```bash
TOKEN="<paste token here>"

# merchants has no tenant_id column, no tenant filter needed
curl -s -X POST http://localhost:8080/v1/query \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"query": "SELECT id, name, category FROM merchants WHERE country = '\''US'\''"}' \
  | jq

# accounts and customers have a tenant_id column, the filter is required
curl -s -X POST http://localhost:8080/v1/query \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"query": "SELECT id, account_number, balance FROM accounts WHERE tenant_id = '\''tenant_1'\'' AND status = '\''active'\''"}' \
  | jq
```

> The seed database (`deploy/postgres/init.sql`) contains rows for `tenant_1` and `tenant_2`. Use `tenant_1` in your JWT and queries to get results from the demo data.

**Response:**
```json
{
  "event_id": "a3f2...",
  "decision": "allow",
  "risk_score": 0,
  "risk_level": "low",
  "result": {
    "columns": ["id", "name", "category"],
    "rows": [[1, "Amazon", "e-commerce"]],
    "row_count": 1
  },
  "latency_ms": 12
}
```

---

## Policy configuration

Policies live in `policies/`. OPA hot-reloads them, no restart needed.

### Policy templates

`policies/templates.json` controls which detection rules are active and their parameters. Toggle any rule without touching Rego:

```json
{
  "tautology_blocker":       {"enabled": true},
  "pii_column_guard":        {"enabled": true},
  "select_star_block":       {"enabled": true},
  "destructive_query_block": {"enabled": true},
  "row_limit_enforcer":      {"enabled": true, "max_limit": 500}
}
```

Set `"enabled": false` to disable a rule. Change `max_limit` to adjust the row cap enforced by `row_limit_enforcer`. OPA reloads the file on next request, no restart needed.

### Custom rules

**Add a sensitive table with its required scope:**
```rego
table_required_scope := {
    "customers":    "customers:read",
    "accounts":     "accounts:read",
    "transactions": "transactions:read",
    "cards":        "cards:read",
    "loans":        "loans:read",
    "credentials":  "admin",
    "secrets":      "admin",
    "pii_data":     "admin",
    "audit_logs":   "admin",
    "salaries":     "salaries:read",   # <- add your table + scope here
}
```
Tables absent from this map are unrestricted (e.g. `merchants`). Admin role bypasses every entry. The agent JWT must carry the listed scope (or `admin` role) to access the table.

**Block a query type:**
```rego
deny contains reason if {
    input.analysis.query_type == "UPDATE"
    reason := "UPDATE operations are not allowed for AI agents"
}
```

**Lower the risk threshold:**
```rego
deny contains reason if {
    risk_score >= 5   # was 7
    reason := sprintf("risk score %v exceeds threshold (5)", [risk_score])
}
```

**Allow PII access for specific scopes:**
The default policy allows PII column access only when the agent holds the per-table scope of the table actually touched (resolved from a v2 `dataActions` entry like `tenant_1/financial/customers/read`, or passed directly via the legacy `scopes: ["customers:read"]` field), or carries `roles: ["admin"]`. To add new tables, extend `table_required_scope` in `query.rego` — the same map drives the `pii_column_guard`, the `missing_scope` deny, and the `sens_score` risk contribution. No separate `agent_has_scope` helper to keep in sync.

**Mark a table as tenant-global (no `tenant_id` column):**
By default, every SELECT on a table must include `tenant_id = <agent's JWT tenant>` as a top-level AND filter. Tables without a `tenant_id` column (lookup tables, shared catalogs) must be listed explicitly:
```rego
tenant_global_tables := {"merchants", "currency_rates"}
```

---

## Known limitations

**WHERE filter extraction for tenant isolation**

The analyzer extracts tenant filters only from simple equality expressions at the top level of the WHERE clause:

```sql
-- recognized: tenant_id = 'tenant_1'
SELECT * FROM accounts WHERE tenant_id = 'tenant_1' AND status = 'active'

-- NOT recognized; query will be denied even if logically correct
SELECT * FROM accounts WHERE tenant_id IN ('tenant_1')
SELECT * FROM accounts WHERE tenant_id = $1
SELECT * FROM accounts WHERE tenant_id = current_setting('app.tenant_id')
```

If your queries use parameterized values, `IN` clauses, or session variables for the tenant filter, add the table to `tenant_global_tables` in `policies/query.rego` and enforce tenant isolation at the database layer via PostgreSQL RLS instead.

Support for `IN`, parameters, and functions in `where_equality_filters` is planned as a future improvement.

**Resolver `knownTables` is hardcoded to the demo fintech schema**

The middleware resolver (`gateway/middleware/resolver.go`) has the 5 fintech demo tables (`accounts`, `customers`, `transactions`, `cards`, `loans`) wired in as Go constants, mapped to sector `financial`. If you fork Tankada and your DB has a different schema (e.g. `orders`, `products`, `users`), v2 `dataActions` for those tables resolve to an empty scope list and OPA denies the queries with `access to table 'X' requires scope 'X:read'`.

Two workarounds today:
- Edit `gateway/middleware/resolver.go` (`knownTables` and `tableSectorMap` constants) and `policies/query.rego` (`table_required_scope` map). Both must stay in sync. Then rebuild the gateway.
- Use legacy v1 `scopes: ["X:read"]` tokens which bypass the resolver entirely (deprecated, removal planned for 0.3.0).

Making the resolver fully schema-agnostic by loading both maps from `templates.json` (single source of truth, hot-reload via OPA data bundle) is tracked in our roadmap and is the recommended long-term fix.

**v2 `dataActions` only support the `read` action today**

The hierarchical path format `{tenant}/{sector}/{table}/{action}` accepts any string in the `{action}` slot, but `knownTables` only maps to `read` scopes. A token like `dataActions: ["tenant_1/financial/accounts/write"]` resolves to an empty scope list and the query is denied. `write` and `admin` actions will be added when a customer use case explicitly requires them.

---

## JWT token structure

Every request needs a signed JWT in `Authorization: Bearer`.

**v2 format (recommended, since 0.2.0):**

```json
{
  "agent_id":       "my-agent-001",
  "owner_user_id":  "alice",
  "tenant_id":      "tenant_1",
  "roles":          ["analyst"],
  "dataActions":    ["tenant_1/financial/accounts/read", "tenant_1/financial/transactions/read"],
  "notDataActions": [],
  "exp":            1234567890
}
```

`dataActions` use the hierarchical path `{tenant_id}/{sector}/{table}/{action}` with `*` wildcards per segment. `notDataActions` lists explicit exclusions applied after `dataActions`. The gateway middleware resolves these into the flat scope list OPA consumes (`accounts:read`, `transactions:read`, ...). Rego policy stays unchanged from earlier versions.

**Tenant invariant:** any path whose first segment doesn't match the JWT `tenant_id` is silently dropped (and logged as `tankada.security.scope_tenant_mismatch`). Defence-in-depth on top of the HMAC signature: an agent of `tenant_a` cannot grant itself `tenant_b/...` scopes by tampering with the payload.

**Wildcard examples:**
- `tenant_1/*/*/read`: read access to every table in the tenant
- `tenant_1/financial/*/read`: every table in the `financial` sector
- `dataActions: ["tenant_1/*/*/read"]` + `notDataActions: ["tenant_1/financial/customers/read"]`: everything except customers

**v1 format (legacy, still accepted until 0.3.0):**

```json
{
  "agent_id": "my-agent-001",
  "tenant_id": "tenant_1",
  "roles":  ["analyst"],
  "scopes": ["accounts:read", "transactions:read"]
}
```

v1 tokens emit a one-shot deprecation warning per `agent_id` (`tankada.security.jwt_v1_deprecated`). Migrate to v2 before 0.3.0. See [CHANGELOG](CHANGELOG.md) 0.2.0 migration guide.

Set `JWT_SECRET` in env. The default (`dev-secret-change-in-production`) is intentionally useless in production; the gateway logs a warning if it's not overridden.

---

## API reference

### `POST /v1/query`

**Headers:** `Authorization: Bearer <token>`, `Content-Type: application/json`

**Body:**
```json
{
  "query": "SELECT id, name, category FROM merchants WHERE country = 'US'",
  "context": {
    "task_description":  "optional human-readable task",
    "user_id":           "optional end-user id"
  }
}
```

**Response (allow):** HTTP 200
```json
{
  "event_id":   "uuid",
  "decision":   "allow",
  "risk_score": 0,
  "risk_level": "low",
  "result":     {"columns": [...], "rows": [...], "row_count": 1},
  "latency_ms": 12
}
```

**Response (deny by policy):** HTTP 403
```json
{
  "event_id":        "uuid",
  "decision":        "deny",
  "reasons":         ["WHERE clause is a tautology (e.g. 1=1)"],
  "deny_categories": ["tautology"],
  "risk_score":      2,
  "risk_level":      "low",
  "latency_ms":      8
}
```

`deny_categories[]` is a machine-readable enum (since 0.2.2) that lets clients decide programmatically how to react to a deny without parsing free-text reasons. Categories group into three behaviour buckets: abort (e.g. `missing_scope`, `pii_violation`, `session_block`), rewrite (e.g. `tautology`, `select_star`), transient (e.g. `rate_limit`, `infrastructure`). See [EXAMPLES.md §6](EXAMPLES.md#6-handling-deny-categories) for the full table and a Python reference pattern.

The `session_block` category is emitted only by Tankada instances that run the proprietary session-scoring extension (cross-query behavioural detection, kept out of the open-source gateway). The constant is documented here so client SDKs that point at a hosted Tankada instance handle the category correctly. The open-source gateway in this repo never produces it.

**Response (fail-closed, analyzer or OPA unreachable):** HTTP 503
```json
{
  "event_id":        "uuid",
  "decision":        "deny",
  "reasons":         ["analyzer unavailable: failing closed"],
  "deny_categories": ["infrastructure"],
  "risk_score":      10,
  "risk_level":      "high",
  "latency_ms":      5002
}
```
Fail-closed denies are also recorded in the audit log with `query_type: "FAIL_CLOSED"` so operators can distinguish infrastructure outages from policy denials.

**Response (rate limit exceeded):** HTTP 429 (same shape as deny by policy, with `deny_categories: ["rate_limit"]`)

### `POST /v1/explain`

Returns what the policy decision **would** be without actually executing the query. Useful for agents that want to validate a draft query before sending it for execution, or for surfacing actionable error messages to the operator. Same JWT auth as `/v1/query`.

**Body:**
```json
{ "query": "SELECT * FROM users WHERE 1=1" }
```

**Response (always HTTP 200, even when the query would be denied):**
```json
{
  "allowed":      false,
  "deny_reasons": ["WHERE clause is a tautology (e.g. 1=1)"],
  "suggestions":  ["Remove the tautological condition from the WHERE clause (e.g. '1=1', 'TRUE', 'id=id')."],
  "risk_score":   2,
  "risk_level":   "low"
}
```

For allowed queries the response is `{"allowed": true, "risk_score": ..., "risk_level": ...}` with `deny_reasons` and `suggestions` omitted.

Suggestions are deterministic, generated from the reason text in `gateway/handler/explain.go`. No LLM call. If analyzer or OPA is unreachable the endpoint returns HTTP 503 (fail-closed, consistent with `/v1/query`).

### `GET /health`

Unauthenticated liveness probe. Returns HTTP 200 with `{"status":"ok","service":"gateway"}`. Used by the Docker healthcheck in `deploy/docker-compose.yml`.

### `POST /analyze` (Analyzer - internal)

Test SQL analysis directly without going through the gateway. The analyzer is only reachable from inside the Docker network, so use `docker compose exec`:

```bash
docker compose exec gateway wget -qO- \
  --header "Content-Type: application/json" \
  --post-data '{"query": "SELECT email FROM customers WHERE 1=1"}' \
  http://analyzer:8001/analyze
```

---

## Observability

Every request is logged as structured JSON to stdout. Pipe it to whatever log stack you use, or run the included dashboard (`sdk/python/dashboard/`) for a live view.

Each event includes:
```json
{
  "event_id":        "uuid",
  "timestamp":       "2026-04-28T...",
  "agent_id":        "my-agent",
  "owner_user_id":   "alice@corp.com",
  "tenant_id":       "tenant_1",
  "query_original":  "SELECT ...",
  "query_type":      "SELECT",
  "tables_accessed": ["merchants"],
  "policy_decision": "allow",
  "policy_reasons":  [],
  "risk_score":      0,
  "risk_level":      "low",
  "latency_ms":      12,
  "session_id":      "sess-abc123"
}
```

`policy_reasons` is omitted when empty (allow path); on deny it carries the same array surfaced in the API response. `session_id` is the value the client passed in `context.session_id`, or a UUID auto-generated by the gateway if none was provided. `owner_user_id` is the JWT `owner_user_id` claim and is empty for service-to-service tokens that don't represent an end user.

---

## Tests

```bash
cd analyzer
pip install pytest sqlglot pydantic
pytest test_analyzer.py -v
# 73 passed
```

---

## Environment variables

| Variable | Default | Description |
|---|---|---|
| `JWT_SECRET` | `dev-secret-change-in-production` | HMAC secret for JWT validation. **Must be set in production.** The gateway refuses to start if this is the default value unless `TANKADA_ENV=development`. |
| `TANKADA_ENV` | `development` | Set to `development` to allow the default JWT secret (local demo only). Any other value enforces a strong `JWT_SECRET` at boot. |
| `PORT` | `8080` | Gateway listen port |
| `ANALYZER_URL` | `http://analyzer:8001` | Analyzer service URL |
| `OPA_URL` | `http://opa:8181` | OPA service URL |
| `PROXY_URL` | `http://proxy:8082` | Proxy service URL |
| `DATABASE_URL` | `postgres://...` | PostgreSQL connection string (proxy) |
| `RATE_LIMIT_QPM` | `60` | Max queries per minute per agent (0 = disabled) |
| `TANKADA_WEBHOOK_URL` | _(unset)_ | If set, a POST is fired on every blocked query. Compatible with Slack, Teams, Google Chat, Discord incoming webhooks. |

---

## License

MIT. See [LICENSE](LICENSE).

---

## Contributing

Issues and PRs welcome. Things that would be useful:
- MySQL, SQLite, MSSQL dialect support (sqlglot handles parsing, the gaps are in detection rules)
- New detection patterns, especially LLM-specific attack vectors that aren't covered yet
- Integration examples with LangChain, LlamaIndex, AutoGen
