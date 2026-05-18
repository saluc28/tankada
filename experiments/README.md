# Tankada experiments

End-to-end test harnesses that exercise the Tankada gateway against a real database and a real LLM agent. Useful for: validating a deployment, comparing the open-source gateway against a Tankada-hosted instance, and producing your own coverage and false-positive numbers on your stack.

Two harnesses are provided:

- **`bypass_coverage.py`**: deterministic, no LLM, no API cost. Sends synthetic SQL queries that exercise three classes of access patterns that per-call enforcement does not catch on its own. Useful for verifying that a session-aware gateway is correctly engaged.
- **`agent_behavior.py`**: LLM-driven. Drives a real LangChain ReAct agent through the gateway across a configurable matrix of LLM backends, task categories, enforcement conditions, and replicas. Useful for measuring how a real agent behaves on top of your gateway configuration.
- **`fp_rate_study.py`**: false-positive harness. Sends a workload of legitimate analyst queries (single queries and multi-query workflows) through the gateway and reports the false-positive rate.

## Setup

```bash
pip install -r requirements.txt
```

Python 3.11+. Tested with `pyjwt 2.10`, `requests 2.32`, `pandas 2.3`, and `langchain` for the agent-driven harness.

## Targets

Each harness can hit either:

- **Local gateway** — the open-source gateway from this repository. Default URL `http://localhost:8080`. Run it locally with `cd ../deploy && docker compose up -d`.
- **Hosted instance** — a Tankada-hosted gateway. Default URL `https://demo.tankada.io`. Requires pre-signed JWTs in `jwt_tokens.json` (committed to this repository for convenience).

The same script targets both. The difference between "open-source gateway" and "Tankada-hosted" is which URL you point at, not a script flag.

## JWT tokens

For **localhost**, the harnesses auto-sign tokens with the dev secret `dev-secret-change-in-production`. No setup needed beyond running the gateway locally.

For **`demo.tankada.io`**, you need pre-signed tokens in `jwt_tokens.json`. The file is committed to the repository so you can reproduce results without contacting the maintainers. Operators regenerating these tokens can use `gen_demo_tokens.py`:

```bash
python gen_demo_tokens.py --env-file /opt/tankada/deploy/.env \
                          --tenant tenant_1 --expiry-days 365 \
                          --output jwt_tokens.json
```

## bypass_coverage.py — per-query bypass classes

```bash
# Both targets, full sweep:
python bypass_coverage.py

# Only the local gateway:
python bypass_coverage.py --target baseline

# Only the hosted instance:
python bypass_coverage.py --target session
```

Output: `results/coverage_<timestamp>.csv` with columns:

- `target`, `target_url`
- `pattern_id` — one of `missing_limit`, `order_by_random`, `offset_stepping`
- `table`, `session_id`, `attempt_index`, `query`
- `http_status`, `client_latency_ms`, `gateway_latency_ms`
- `decision` (allow / deny / error), `risk_score`, `risk_level`, `deny_categories`

A console summary by `(target, pattern_id, decision)` is printed after each run.

### What it shows

Three classes of patterns are exercised against scoped data tables:

| pattern | what it tests |
|---|---|
| `missing_limit` | SELECT without LIMIT on a tenant-scoped data table, repeated in the same session |
| `order_by_random` | `ORDER BY RANDOM()` sampling, repeated in the same session |
| `offset_stepping` | LIMIT/OFFSET pagination, monotonic OFFSET, repeated in the same session |

Each pattern is structured so that a per-query enforcer has nothing syntactic to anchor on per individual query. The cumulative session-level pattern is what makes the difference. Run the script against the local gateway and the hosted instance and compare the `decision` columns to see how the two enforcement modes differ on the same workload.

## agent_behavior.py — agent behavior under enforcement

LLM-driven. Drives a LangChain ReAct agent through the gateway across a matrix of:

- 4 LLM backends (Claude Haiku 4.5, Claude Sonnet 4.6, GPT-4o-mini, Llama 3.3 70B Instruct via Together)
- A set of task categories defined in `tasks.json`
- A set of enforcement conditions (toggling session state, `deny_categories` visibility, and the SDK system-prompt mapping)
- N replicas per cell

```bash
python agent_behavior.py --tasks tasks.json --conditions A,B,C --replicas 4
```

Output: `results/agent_behavior_<timestamp>.csv`. One row per replica with the full ReAct transcript serialized as JSON, the number of `db_query` tool calls the agent issued, the gateway decisions distribution, and whether the agent's final answer contained data from any off-limits table.

Requires API keys for at least one of the providers in `.env`:

```
OPENAI_API_KEY=...
ANTHROPIC_API_KEY=...
TOGETHER_API_KEY=...
```

## fp_rate_study.py — false-positive rate

```bash
python fp_rate_study.py --queries legitimate_queries.json --target session
```

Sends 50 single-query patterns and 16 queries grouped into 3 multi-query workflows through the gateway, all representative of a routine analyst workload. Reports per-query and per-workflow false-positive rate. Useful as a regression suite for policy changes.

## Cost

- `bypass_coverage.py` is free (HTTP traffic only).
- `fp_rate_study.py` is free (HTTP traffic only).
- `agent_behavior.py` uses commercial LLM APIs. Cost depends on the matrix size and the model tier. A full 4-backend sweep across 5 tasks and 3 conditions with 4 replicas (~240 runs) costs around USD 5 to USD 20 depending on the mix.

## Reproducibility against a tagged release

Each tagged release of the gateway corresponds to a fixed policy snapshot. To reproduce a result against a specific release, check out the corresponding tag, run the harness, and inspect the generated CSVs under `results/` (gitignored; regenerated locally each run).

## Reporting issues

If you observe unexpected behavior in either the local gateway or the hosted instance, open an issue at [github.com/saluc28/tankada/issues](https://github.com/saluc28/tankada/issues) with the relevant CSV row, the gateway version (`/health` returns it), and a minimal repro.
