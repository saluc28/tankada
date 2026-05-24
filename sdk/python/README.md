# Tankada Python SDK

Drop-in client for [Tankada](https://tankada.io) - the behavioral firewall for SQL by
LLM agents. Route your agent's SQL through Tankada in one line, with good-citizen deny
handling built in.

## Install

```bash
pip install tankada                 # core client
pip install "tankada[langchain]"    # + the LangChain tool
```

## Framework-agnostic client

```python
from tankada import TankadaClient

client = TankadaClient(
    gateway_url="http://localhost:8080",
    agent_token="<signed JWT>",
    session_id="sess-abc123",   # same value for every query in the agent's session
)

r = client.query("SELECT id, balance FROM accounts WHERE tenant_id = 'tenant_1'")
if r.allowed:
    for row in r.as_dicts():
        print(row)
else:
    print(r.tag, r.reasons)   # tag = ABORT / REWRITE / TRANSIENT / BLOCKED
```

## LangChain: one line

```python
from tankada import tankada_sql_tool

tool = tankada_sql_tool(
    gateway_url="http://localhost:8080",
    agent_token="<signed JWT>",
    session_id="sess-abc123",
)
# give `tool` to your LangChain / LangGraph agent
```

The tool sends every query to the gateway instead of the database and prefixes denied
results with a behaviour tag the LLM acts on:

- `[ABORT]` - the task is not possible; the agent must stop (semantic or behavioural
  deny: missing scope, PII, tenant violation, injection, schema enum, **session block**).
- `[REWRITE]` - reformulate and retry (tautology, `SELECT *`, missing WHERE, high LIMIT).
- `[TRANSIENT]` - wait and retry the same query (rate limit, infrastructure).
- `[BLOCKED]` - denied, category not recognised.

## Other frameworks

Same one-line pattern, different import (install the matching extra):

```python
# LlamaIndex  ->  pip install "tankada[llamaindex]"
from tankada.frameworks.llamaindex import tankada_sql_tool
tool = tankada_sql_tool(gateway_url, agent_token, session_id="sess-1")

# OpenAI Agents SDK  ->  pip install "tankada[openai-agents]"
from tankada.frameworks.openai_agents import tankada_sql_tool
tool = tankada_sql_tool(gateway_url, agent_token, session_id="sess-1")

# AutoGen (returns a plain callable to register as a tool; bring your own AutoGen)
from tankada.frameworks.autogen import tankada_sql_function
sql_query = tankada_sql_function(gateway_url, agent_token, session_id="sess-1")
```

Any framework not listed: use the framework-agnostic helper. `guarded_sql` runs a query
and returns the good-citizen-tagged text your tool should return:

```python
from tankada import TankadaClient, guarded_sql

client = TankadaClient(gateway_url, agent_token, session_id="sess-1")
text = guarded_sql(client, "SELECT id FROM accounts WHERE tenant_id = 'tenant_1' LIMIT 10")
# return `text` from your custom tool; it is plain text with [ABORT]/[REWRITE]/[TRANSIENT] tags
```

## Why `session_id` matters

Pass a **stable** `session_id` across all of the agent's queries. The gateway's
behavioural (session-aware) enforcement accumulates state per session: it catches
cumulative exfiltration patterns (repeated unbounded reads, pagination stepping,
`ORDER BY RANDOM()` probing, reformulation loops) that no single-query check can see.
Without a stable `session_id`, you only get per-query enforcement.

## Mapping deny categories yourself

If you are not on LangChain, use `deny_tag` directly:

```python
from tankada import deny_tag

cats = r.deny_categories
tag = deny_tag(cats)   # "ABORT" | "REWRITE" | "TRANSIENT" | "BLOCKED"
```

## Tests

```bash
cd sdk/python
pip install -e ".[dev]"
pytest tests/        # pure unit tests for the deny-tag logic, no gateway needed
```

## End-to-end smoke test

With a gateway running (`cd deploy && docker compose -f docker-compose.yml up -d`):

```bash
pip install pyjwt
python examples/smoke_e2e.py   # 6 allow/deny scenarios; checks decisions and good-citizen tags
```
