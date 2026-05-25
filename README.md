<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="brand/wordmark-dark.svg">
    <img src="brand/wordmark-light.svg" alt="Tankada" width="420">
  </picture>
</p>

<p align="center">
  <strong>An IAM gateway for LLM agents that execute SQL against your database.<br>AST-based per-call enforcement, structured deny categories, JWT scopes, PostgreSQL RLS backstop.</strong>
</p>

<p align="center">
  <a href="https://github.com/saluc28/tankada/actions/workflows/ci.yml"><img src="https://github.com/saluc28/tankada/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-Apache_2.0-blue.svg" alt="License: Apache 2.0"></a>
  <a href="https://github.com/saluc28/tankada/releases/latest"><img src="https://img.shields.io/github/v/release/saluc28/tankada?label=release" alt="Latest release"></a>
  <a href="https://hub.docker.com/r/saluc28/tankada-gateway"><img src="https://img.shields.io/docker/pulls/saluc28/tankada-gateway" alt="Docker Pulls"></a>
  <a href="https://github.com/saluc28/tankada/commits/main"><img src="https://img.shields.io/github/last-commit/saluc28/tankada" alt="Last commit"></a>
</p>

<p align="center">
  <a href="#quick-start">Quick start</a> ·
  <a href="EXAMPLES.md">Examples</a> ·
  <a href="https://demo.tankada.io">Live demo</a> ·
  <a href="#tankada-cloud">Cloud</a> ·
  <a href="CONTRIBUTING.md">Contributing</a> ·
  <a href="CHANGELOG.md">Changelog</a>
</p>

---

## The problem

LLM agents generate SQL autonomously. They do not know your data boundaries, and they will run queries that look syntactically fine but are dangerous. An agent asked to "show all users" might generate:

```sql
SELECT * FROM users WHERE 1=1                              -- tautology, filters nothing
SELECT table_name FROM information_schema.tables           -- schema recon
SELECT email, password FROM users WHERE id > 0 UNION SELECT ...  -- extraction
```

Traditional proxies block `DROP TABLE`. They do not catch any of these. A regex-based filter is brittle the moment the agent renames a column, parameterizes the predicate, or splits the work across multiple queries.

## How it works

Every query goes through four steps before touching the database:

1. **Parse**: sqlglot builds an AST. No regex. Structural analysis of what the query actually does.
2. **Evaluate**: OPA checks the AST against your Rego policies. Rules reload without restart.
3. **Execute or block**: allowed queries run; blocked ones get a structured JSON response the agent can read and act on.
4. **Log**: every request is written to an audit trail with risk score, agent identity, and the original query text.

## Why AST, not regex

String matching works for `DROP TABLE`. It breaks as soon as the query gets slightly creative. These all pass regex-based tools. Tankada blocks them:

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

Tankada uses [sqlglot](https://github.com/tobymao/sqlglot) to parse every query into an AST before evaluating it. A tautology is a tautology whether it is `1=1`, `'a'='a'`, or `user_id = user_id`. An alias bypass is caught whether the column is renamed to `p`, `x`, or `data`.

## Architecture

```
AI Agent (LangChain, LlamaIndex, AutoGen, custom)
    |
    | POST /v1/query  {"query": "SELECT ...", "context": {...}}
    | Authorization: Bearer <JWT>
    v
+-----------------------------------------------------------------+
|                          Gateway :8080                          |
|  JWT auth -> Rate limit -> Analyzer -> OPA -> (Proxy if allow)  |
|                              every decision -> Audit log        |
+------+----------------------+-------------------+---------------+
       |                      |                   |
       v                      v                   v
  Analyzer               OPA :8181            Proxy :8082
   :8001                (Rego policy)         (write block at app layer,
  (sqlglot               allow/deny           SET LOCAL ROLE tankada_app
   AST)                  + risk score         + SET LOCAL app.tenant_id
                                              per query)
                                                  |
                                                  v
                                         PostgreSQL :5432
                                      (Row Level Security:
                                       tenant_id enforced
                                       at DB layer, wall 3)
```

Three independent enforcement walls:

1. **OPA**: semantic policy engine, blocks at the query analysis layer.
2. **Proxy**: unconditionally rejects write operations at the application layer.
3. **PostgreSQL RLS**: enforces tenant isolation at the DB layer via `tankada_app` role and `SET LOCAL` session variables; returns zero rows even if both layers above are bypassed.

## Detection capabilities

| Pattern | How detected | Default action |
|---|---|---|
| Tautology WHERE (1=1, OR 1=1, col=col, AND of all-tautologies) | AST node analysis (recurses into OR with `any`, AND with `all`) | Deny |
| Schema enumeration (information_schema, pg_catalog, pg_*) | Table/schema name match | Hard deny |
| PII column access (email, password, ssn, iban, credit_card, balance, account_number...) | Column name keyword match (34 keywords) | Deny without scope |
| Cross-tenant access (query touches a tenant-scoped table without `tenant_id = <agent's JWT tenant>` filter) | Top-level AND equality extraction + JWT comparison | Hard deny |
| Subquery on tenant-scoped table without its own `tenant_id` filter | Per-subquery WHERE inspection | Hard deny |
| Cross-tenant access at DB layer (even if policy is bypassed) | PostgreSQL RLS via `tankada_app` role + `SET LOCAL app.tenant_id` per transaction | Zero rows returned |
| SELECT without WHERE on a tenant-scoped table | `has_where = false` AND table not in `tenant_global_tables` | Deny |
| SELECT * | Star column detection (aggregate functions like `COUNT(*)`, `SUM(col)` are not flagged as star) | Deny (configurable) |
| SELECT * without LIMIT | Star column + no limit | Risk +2 |
| High LIMIT (> 500) | Literal value extraction | Deny (configurable) |
| UNION / INTERSECT / EXCEPT | AST union node | Risk +2 |
| SQL comments (-- or /* */) | Raw SQL scan before parse | Risk +1 |
| ORDER BY RANDOM() | AST rand node | Risk +1 |
| Multi-statement injection (`SELECT ...; DROP ...`) | Statement count after parse | Hard deny |
| Destructive operations (DELETE, DROP, TRUNCATE, ALTER) | Query type | Hard deny |
| Invalid/malformed SQL | Unrecognized AST node type | Hard deny (fail closed) |

Risk score `>= 7` triggers automatic deny. The threshold is configurable in `policies/query.rego`.

### Scope of per-query enforcement

This repository implements **per-query enforcement**: every query is evaluated in isolation against the policy and the agent's scope. Per-query enforcement catches patterns with a syntactic deny signal (tautology, `SELECT *`, `LIMIT > N`, PII column, missing `tenant_id` filter, destructive operations, schema enumeration).

Some access patterns are **not** covered by per-query enforcement because they have no per-query syntactic anomaly:

| Pattern | Per-query outcome | Where it is caught |
|---|---|---|
| Missing LIMIT on a queried data table (specific columns, predicates present) | ALLOW (no anomaly to anchor on) | Session-aware enforcement |
| `ORDER BY RANDOM()` repeated to sample a table | ALLOW (risk score +1, below deny threshold) | Session-aware enforcement |
| `LIMIT/OFFSET` pagination stepping through a table | ALLOW per query (each plausible in isolation) | Session-aware enforcement |

Session-aware enforcement is a separate layer that tracks cumulative access patterns across the queries an agent issues within a session. It is not implemented in this repository; see [Tankada Cloud](#tankada-cloud) below for the hosted version.

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

# Ollama (default, local, no API key needed)
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

**Response (allow):**

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

## Python SDK

Prefer one line over hand-rolled HTTP. `pip install tankada` gives a client plus drop-in
tools for the major agent frameworks, with good-citizen deny handling built in.

```python
# framework-agnostic client
from tankada import TankadaClient
client = TankadaClient("http://localhost:8080", "<signed JWT>", session_id="sess-1")
r = client.query("SELECT id, balance FROM accounts WHERE tenant_id = 'tenant_1' LIMIT 10")
print(r.allowed, r.tag, r.reasons)   # r.tag = ABORT / REWRITE / TRANSIENT / BLOCKED on a deny

# one line for LangChain (also: llamaindex, openai_agents, autogen)
from tankada import tankada_sql_tool
tool = tankada_sql_tool("http://localhost:8080", "<signed JWT>", session_id="sess-1")
```

Pass a stable `session_id` so session-aware enforcement accumulates across the agent's
queries. See [`sdk/python/`](sdk/python/) for every framework and the deny-tag handling.

## Postgres wire-proxy mode

For the lowest-friction adoption, Tankada also speaks the PostgreSQL wire protocol. An
agent (or any tool) points a stock Postgres driver at the proxy by changing only the
connection string: no SDK, no HTTP calls. Every statement still goes through the same
analyzer plus OPA policy as the HTTP gateway, and PII masking is applied to the rows.

Identity is your Tankada JWT, supplied as the connection password:

```bash
# the proxy listens on :5433 (see deploy/docker-compose.yml)
psql "host=localhost port=5433 user=agent dbname=tankada password=<signed JWT>" \
  -c "SELECT id, email FROM customers WHERE tenant_id = 'tenant_1' LIMIT 10"
```

```python
# any Postgres driver works, e.g. psycopg
import psycopg
conn = psycopg.connect("host=localhost port=5433 user=agent dbname=tankada password=<JWT>")
conn.execute("SELECT id, balance FROM accounts WHERE tenant_id = 'tenant_1' LIMIT 10")
```

How it behaves:

- Both the simple and the extended (prepared-statement) query protocols are supported, so
  ORMs and drivers that use server-side prepared statements work.
- The proxy is read-only: writes are rejected, the same stance as the HTTP proxy.
- A denied query comes back as a normal Postgres error (`ERROR: Tankada policy denied ...`).
- Each connection is pinned to the non-superuser `tankada_app` role and the agent's
  `app.tenant_id`, so RLS isolates the tenant. Session-control statements that could escape
  that scoping (`SET ROLE`, `RESET ALL`, `DISCARD`, `SET SESSION AUTHORIZATION`) are blocked;
  transaction control and safe `SET`/`RESET`/`SHOW` pass through.
- With the `pii_masking` template enabled, sensitive columns come back redacted in the
  result, exactly like the HTTP path.

The `user` and `dbname` are conventional; the JWT in the password is what authenticates and
carries the tenant and scopes. Results are returned in text format.

### Identity modes (friction vs strength)

`PGWIRE_AUTH_MODE` selects how the agent proves who it is:

- `jwt` (default, strong): the password must be a signed Tankada JWT. Identity, tenant, and
  scopes are cryptographically verified, exactly like the HTTP gateway. Use this for
  multi-tenant or untrusted clients.
- `trust` (frictionless, weak): no password. The agent id comes from the connection `user`
  (or `application_name` `agent=...`); the deployment owns scopes/roles/tenant via
  `PGWIRE_TRUST_SCOPES`, `PGWIRE_TRUST_ROLES`, and `PGWIRE_TRUST_TENANT`, so a client cannot
  grant itself authority. When `PGWIRE_TRUST_TENANT` is set it is forced (single-tenant
  safety); if left unset, the client may declare the tenant via `application_name`
  (`tenant=...`). Trust mode does NOT cryptographically authenticate the caller, so use it
  only where the network perimeter is the trust boundary (single-tenant or trusted agents).

```bash
# trust mode: no token to manage, agent id = the Postgres user
# (server started with PGWIRE_AUTH_MODE=trust, PGWIRE_TRUST_TENANT=tenant_1,
#  PGWIRE_TRUST_SCOPES=customers:read,accounts:read)
psql "host=localhost port=5433 user=reporter dbname=tankada" \
  -c "SELECT id, balance FROM accounts WHERE tenant_id = 'tenant_1' LIMIT 10"
```

Configure the proxy with `PGWIRE_ADDR`, `JWT_SECRET`, `ANALYZER_URL`, `OPA_URL`,
`DATABASE_URL`, `PGWIRE_APP_ROLE`, and the `PGWIRE_AUTH_MODE` / `PGWIRE_TRUST_*` knobs above.

## Policy configuration

Policies live in `policies/`. OPA hot-reloads them, no restart needed.

### Policy templates

`policies/templates.json` controls which detection rules are active and their parameters. Toggle any rule without touching Rego:

```json
{
  "tautology_blocker":       {"enabled": true},
  "pii_column_guard":        {"enabled": true},
  "pii_masking":             {"enabled": false, "mask_value": "***"},
  "select_star_block":       {"enabled": true},
  "destructive_query_block": {"enabled": true},
  "row_limit_enforcer":      {"enabled": true, "max_limit": 500}
}
```

Set `"enabled": false` to disable a rule. Change `max_limit` to adjust the row cap. OPA reloads the file on next request.

### PII masking (redact instead of deny)

`pii_column_guard` blocks a query that reaches PII columns without the required scope. `pii_masking` is the softer alternative: when enabled, the query runs and the PII fields come back redacted instead of the agent getting a hard deny. Often more usable for an agent (it gets a result, not a wall) while still keeping the sensitive values out of the response.

```json
"pii_masking": {
  "enabled": false,
  "mask_value": "***",
  "unmask_roles": ["admin"],
  "unmask_scope": "pii:unmask",
  "column_unmask_scopes": {}
}
```

How it works:

- Masking is result-level and orthogonal to the deny rules. It never grants table access, it only governs what an authorized reader sees. An agent still needs the per-table read scope to run the query at all.
- The PII columns detected in the query (same detection used by `pii_column_guard`) are redacted in the response. Matching is case-insensitive on the result's own column names.
- `mask_value` is the placeholder substituted for each masked cell (default `***`).

Who sees a column in clear is configurable:

- `unmask_roles`: roles that see every PII column in clear (default `["admin"]`). Set it to your own roles, or `[]` to disable role-based unmasking.
- `unmask_scope`: a single scope that unmasks every PII column (default `pii:unmask`).
- `column_unmask_scopes`: a per-column map `{column: scope}`. An agent holding that scope sees just that column in clear, while the other PII columns stay masked. Example: with `{"email": "pii:unmask:email", "ssn": "pii:unmask:ssn"}`, an agent with `pii:unmask:email` sees `email` in clear but still gets `ssn` redacted.

When masking redacts a column, the `/v1/query` response lists it in `masked_columns`, and `POST /v1/explain` reports `mask_columns` so an agent can see ahead of time which fields would be redacted.

Known limitation: matching is by column name, so aliasing a PII column to a non-PII name (`SELECT email AS contact`) is not masked. This is the same detection boundary the PII deny already has.

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
    "salaries":     "salaries:read",   # add your table + scope here
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

**Mark a table as tenant-global (no `tenant_id` column):**

```rego
tenant_global_tables := {"merchants", "currency_rates"}
```

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

**Resolver `knownTables` is hardcoded to the demo fintech schema**

The middleware resolver (`gateway/middleware/resolver.go`) has the 5 fintech demo tables (`accounts`, `customers`, `transactions`, `cards`, `loans`) wired in as Go constants, mapped to sector `financial`. If you fork Tankada and your DB has a different schema, v2 `dataActions` for those tables resolve to an empty scope list and OPA denies the queries.

Two workarounds today:

- Edit `gateway/middleware/resolver.go` (`knownTables` and `tableSectorMap` constants) and `policies/query.rego` (`table_required_scope` map). Both must stay in sync. Then rebuild the gateway.
- Use legacy v1 `scopes: ["X:read"]` tokens which bypass the resolver entirely (deprecated).

**v2 `dataActions` only support the `read` action today**

The hierarchical path format `{tenant}/{sector}/{table}/{action}` accepts any string in the `{action}` slot, but `knownTables` only maps to `read` scopes. A token like `dataActions: ["tenant_1/financial/accounts/write"]` resolves to an empty scope list and the query is denied. `write` and `admin` actions will be added when a use case explicitly requires them.

**Postgres wire-proxy returns text-format results**

The wire-proxy (`cmd/pgwire`) normalizes all result columns to text format so PII masking can rewrite cells uniformly, even when a driver requests binary. This is transparent to most drivers. SQL-level cursors (`DECLARE ... CURSOR` / `FETCH` across statements) and `COPY` streaming are not handled yet, and the proxy authenticates with cleartext password (the JWT) so it must be run behind TLS termination in production.

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

**Tenant invariant:** any path whose first segment does not match the JWT `tenant_id` is silently dropped (and logged as `tankada.security.scope_tenant_mismatch`). Defence-in-depth on top of the HMAC signature.

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

v1 tokens emit a one-shot deprecation warning per `agent_id`. Migrate to v2 before 0.3.0. See [CHANGELOG](CHANGELOG.md) 0.2.0 migration guide.

Set `JWT_SECRET` in env. The default (`dev-secret-change-in-production`) is intentionally useless in production; the gateway refuses to start with it unless `TANKADA_ENV=development`.

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

When the `pii_masking` template is enabled and the query reaches PII columns, the allow response additionally carries `masked_columns` and the redacted cells in `result.rows` are replaced with `mask_value` (default `***`):

```json
{
  "event_id":       "uuid",
  "decision":       "allow",
  "result":         {"columns": ["id", "email"], "rows": [[1, "***"]], "row_count": 1},
  "masked_columns": ["email"],
  "risk_score":     0,
  "risk_level":     "low",
  "latency_ms":     14
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

`deny_categories[]` is a machine-readable enum (since 0.2.2) that lets clients decide programmatically how to react to a deny without parsing free-text reasons. Categories group into three behaviour buckets: abort, rewrite, transient. See [EXAMPLES.md Section 6](EXAMPLES.md#6-handling-deny-categories) for the full table and a Python reference pattern.

The `session_block` category is documented in [EXAMPLES.md](EXAMPLES.md) for client SDK completeness. The open-source gateway in this repository does not emit it; it is produced by the hosted Tankada extension only (see [Tankada Cloud](#tankada-cloud) below).

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

Fail-closed denies are recorded in the audit log with `query_type: "FAIL_CLOSED"` so operators can distinguish infrastructure outages from policy denials.

**Response (rate limit exceeded):** HTTP 429 (same shape as deny, with `deny_categories: ["rate_limit"]`).

### `POST /v1/explain`

Returns what the policy decision would be without actually executing the query. Useful for agents that want to validate a draft query before sending it, or for surfacing actionable error messages.

**Body:** `{ "query": "SELECT * FROM users WHERE 1=1" }`

**Response (always HTTP 200):**

```json
{
  "allowed":      false,
  "deny_reasons": ["WHERE clause is a tautology (e.g. 1=1)"],
  "suggestions":  ["Remove the tautological condition from the WHERE clause."],
  "risk_score":   2,
  "risk_level":   "low"
}
```

For allowed queries, `deny_reasons` and `suggestions` are omitted. When the `pii_masking` template is enabled, the response includes `mask_columns` listing the PII columns that would be redacted if the query were executed. Suggestions are deterministic (no LLM call), generated in `gateway/handler/explain.go`.

### `GET /health`

Unauthenticated liveness probe. Returns HTTP 200 with `{"status":"ok","service":"gateway"}`.

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

`policy_reasons` is omitted when empty (allow path); on deny it carries the same array surfaced in the API response. `session_id` is the value the client passed in `context.session_id`, or a UUID auto-generated by the gateway if none was provided.

## Tests

```bash
cd analyzer
pip install pytest sqlglot pydantic
pytest test_analyzer.py -v
```

## Environment variables

| Variable | Default | Description |
|---|---|---|
| `JWT_SECRET` | `dev-secret-change-in-production` | HMAC secret for JWT validation. Must be set in production. The gateway refuses to start with the default value unless `TANKADA_ENV=development`. |
| `TANKADA_ENV` | `development` | Set to `development` to allow the default JWT secret (local demo only). Any other value enforces a strong `JWT_SECRET` at boot. |
| `PORT` | `8080` | Gateway listen port. |
| `ANALYZER_URL` | `http://analyzer:8001` | Analyzer service URL. |
| `OPA_URL` | `http://opa:8181` | OPA service URL. |
| `PROXY_URL` | `http://proxy:8082` | Proxy service URL. |
| `DATABASE_URL` | `postgres://...` | PostgreSQL connection string (proxy). |
| `RATE_LIMIT_QPM` | `60` | Max queries per minute per agent (0 disables). |
| `TANKADA_WEBHOOK_URL` | _(unset)_ | If set, a POST is fired on every blocked query. Compatible with Slack, Teams, Google Chat, Discord incoming webhooks. |
| `PGWIRE_ADDR` | `:5433` | Listen address for the Postgres wire-proxy (`cmd/pgwire`). |
| `PGWIRE_APP_ROLE` | `tankada_app` | Non-superuser role the wire-proxy switches to for RLS scoping (empty to skip). |
| `PGWIRE_AUTH_MODE` | `jwt` | Wire-proxy identity mode: `jwt` (password is a verified JWT) or `trust` (no password, weak identity). |
| `PGWIRE_TRUST_TENANT` | _(unset)_ | Trust mode: forces the tenant for every connection. If unset, the client may declare it via `application_name` (`tenant=...`). |
| `PGWIRE_TRUST_SCOPES` | _(unset)_ | Trust mode: comma-separated scopes granted to every connection (e.g. `customers:read,accounts:read`). |
| `PGWIRE_TRUST_ROLES` | _(unset)_ | Trust mode: comma-separated roles granted to every connection. |

## Tankada Cloud

The open-source gateway in this repository implements the per-call enforcement layer. A hosted Tankada extension adds session-scoped behavioral enforcement on top, for the cumulative-pattern threat class described in "Scope of per-query enforcement" above. See [tankada.io](https://tankada.io).

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

## Contributing

Issues and PRs welcome. Things that would be useful:

- MySQL, SQLite, MSSQL dialect support (sqlglot handles parsing; the gaps are in detection rules)
- New detection patterns, especially LLM-specific attack vectors not yet covered
- Integration examples with LangChain, LlamaIndex, AutoGen, OpenAI Assistants
