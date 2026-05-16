# Tankada experiments

Reproducibility scripts for the two empirical tables in §6.4 of the Tankada paper:

- **Table 1 — Per-query enforcement coverage** (`bypass_coverage.py`): deterministic, no LLM, no API cost. Compares OSS gateway vs session-aware gateway on three bypass patterns.
- **Table 2 — Agent behavior under per-query vs session enforcement** (`agent_behavior.py`, *next session*): LLM-driven, 180 runs across 3 backends × 5 task categories × 3 conditions × 4 replicas. Total API cost ~$15.

## Setup

```bash
pip install -r requirements.txt
```

Python 3.11+. Tested with `pyjwt 2.10`, `requests 2.32`, `pandas 2.3`.

## Targets

Each experiment hits one or both of:

- **Baseline** — the public OSS gateway with per-query enforcement only. Default URL `http://localhost:8080`. Run it locally with `cd ../deploy && docker compose up -d`.
- **Session-aware** — the hosted gateway with proprietary session scoring. Default URL `https://demo.tankada.io`. Requires pre-signed JWTs in `jwt_tokens.json` (see below).

The same script targets both. The difference between "OSS-only" and "Tankada full" in the paper is which URL you point at, not a script flag.

## JWT tokens

For **localhost**, the scripts auto-sign tokens with the dev secret `dev-secret-change-in-production`. No setup needed beyond running the OSS gateway locally.

For **demo.tankada.io**, you need pre-signed tokens in `jwt_tokens.json`. The file is committed to the repo so reviewers can reproduce the experiment without contacting the maintainers. If you are the maintainer regenerating these, see `gen_demo_tokens.py`:

```bash
# On the VPS (operator only):
python gen_demo_tokens.py --env-file /opt/tankada/deploy/.env \
                          --tenant tenant_1 --expiry-days 365 \
                          --output jwt_tokens.json
```

## Experiment A — Table 1 coverage

```bash
# Both targets, full sweep (~30 seconds against localhost + ~3 minutes against demo):
python bypass_coverage.py

# Only the baseline (no demo tokens needed):
python bypass_coverage.py --target baseline

# Only the session-aware target:
python bypass_coverage.py --target session
```

Output: `results/coverage_<timestamp>.csv` with columns:

- `target`, `target_url` — which endpoint
- `pattern_id` — one of `missing_limit`, `order_by_random`, `offset_stepping`
- `table`, `session_id`, `attempt_index`, `query`
- `http_status`, `client_latency_ms`, `gateway_latency_ms`
- `decision` (allow / deny / error), `risk_score`, `risk_level`, `deny_categories`, `reasons`
- `session_query_count`, `session_denied_count`, `session_denied_tables` — populated by the session-aware target only

The script also prints a console summary by `(target, pattern_id, decision)` after each run.

### What the rows produce in the paper

Table 1 of §6.4 aggregates this CSV as:

| pattern | baseline allow/total | session-aware deny at attempt ≤ N |
|---|---|---|
| `missing_limit` | ~300/300 ALLOW | DENY at ≤ 3 |
| `order_by_random` | ~300/300 ALLOW | DENY at ≤ 5 |
| `offset_stepping` | ~300/300 ALLOW | DENY at ≤ 99 |

The thresholds `3 / 5 / 99` are the session policy parameters. The experiment confirms they are reached on the seed workload.

## Experiment B — Table 2 agent behavior

`agent_behavior.py` — not yet implemented in this commit. See `paper-arxiv.md` §6.2/§6.3/§6.4 for the experimental design. Will arrive in a follow-up commit.

## Cost

Experiment A is free (only HTTP traffic to your own infrastructure).
Experiment B uses commercial LLM APIs (Anthropic Claude Haiku 4.5 + OpenAI GPT-4o-mini + Together Llama 3 70B). Estimated total ~$15 for the full sweep.

## Citing

If you reuse this experimental setup, please cite the Tankada paper (preprint available on arXiv from June 2026).
