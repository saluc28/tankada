"""
bypass_coverage.py — Experiment A from paper-arxiv.md §6.4 Table 1.

Deterministic, no LLM. Generates synthetic SQL queries that exercise each
per-query enforcement bypass pattern from §3.3 (missing LIMIT, ORDER BY
RANDOM(), LIMIT/OFFSET stepping). Sends them to two Tankada endpoints:

  • baseline (default http://localhost:8080) — public OSS gateway, no session.
  • session-aware (default https://demo.tankada.io) — moat-enabled gateway.

For each (pattern × table × attempt) tuple, records the gateway decision.
Output CSV is what populates Table 1 in §6.4 of the paper.

Usage:
  # Both targets in one run (default):
  python bypass_coverage.py

  # Only one target:
  python bypass_coverage.py --target baseline
  python bypass_coverage.py --target session

  # Custom URLs:
  python bypass_coverage.py --baseline-url http://localhost:8080 \\
                            --session-url  https://demo.tankada.io

The script auto-generates JWT tokens for localhost using the dev secret.
For demo.tankada.io it reads pre-signed tokens from jwt_tokens.json.
"""

from __future__ import annotations

import argparse
import datetime
import json
import sys
import time
import uuid
from pathlib import Path
from typing import Any, Iterable

import jwt as pyjwt
import pandas as pd
import requests

HERE = Path(__file__).parent
BYPASSES_FILE = HERE / "bypasses.json"
TOKENS_FILE = HERE / "jwt_tokens.json"
RESULTS_DIR = HERE / "results"

DEV_JWT_SECRET = "dev-secret-change-in-production"
DEFAULT_TIMEOUT = 10.0


# ── JWT helpers ───────────────────────────────────────────────────────────────

def sign_localhost_jwt(role: str) -> str:
    """Sign a v2 JWT for the localhost gateway using its dev secret.

    role: 'analyst' (read on accounts, transactions) or 'admin' (full).
    """
    exp = int(time.time()) + 3600
    if role == "analyst":
        payload = {
            "agent_id":      "experiment-analyst",
            "owner_user_id": "experiment",
            "tenant_id":     "tenant_1",
            "roles":         ["analyst"],
            "dataActions": [
                "tenant_1/financial/accounts/read",
                "tenant_1/financial/transactions/read",
                "tenant_1/financial/cards/read",
                "tenant_1/financial/loans/read",
            ],
            "notDataActions": [],
            "exp":              exp,
        }
    elif role == "admin":
        payload = {
            "agent_id":      "experiment-admin",
            "owner_user_id": "experiment",
            "tenant_id":     "tenant_1",
            "roles":         ["admin"],
            "dataActions":   ["tenant_1/*/*/read"],
            "notDataActions": [],
            "exp":              exp,
        }
    else:
        raise ValueError(f"unknown role: {role}")
    return pyjwt.encode(payload, DEV_JWT_SECRET, algorithm="HS256")


def load_demo_jwt(role: str) -> str:
    """Load a pre-signed JWT for demo.tankada.io from jwt_tokens.json."""
    if not TOKENS_FILE.exists():
        raise FileNotFoundError(
            f"{TOKENS_FILE} not found. To target demo.tankada.io you need "
            f"pre-signed tokens; see README.md §Reproducing the paper."
        )
    tokens = json.loads(TOKENS_FILE.read_text())
    if role not in tokens:
        raise KeyError(f"role {role!r} not in {TOKENS_FILE}")
    return tokens[role]


# ── Query generation ──────────────────────────────────────────────────────────

def generate_queries(pattern: dict[str, Any]) -> Iterable[dict[str, Any]]:
    """Yield dicts with {table, attempt_index, query} for a bypass pattern."""
    pid = pattern["id"]
    template = pattern["template"]
    column_pool = pattern["column_pool"]
    n = pattern["n_per_table"]

    if pid == "missing_limit":
        # Vary the column set per attempt to look like distinct legitimate reads.
        for table, cols in column_pool.items():
            for i in range(n):
                # Rotate column selection: pick 2-4 cols, varying per attempt.
                k = 2 + (i % 3)
                start = i % len(cols)
                picked = [cols[(start + j) % len(cols)] for j in range(k)]
                query = template.format(table=table, cols=", ".join(picked))
                yield {"table": table, "attempt_index": i, "query": query}

    elif pid == "order_by_random":
        for table, cols in column_pool.items():
            for i in range(n):
                col = cols[i % len(cols)]
                query = template.format(table=table, col=col)
                yield {"table": table, "attempt_index": i, "query": query}

    elif pid == "offset_stepping":
        step = pattern.get("offset_step", 100)
        for table, cols in column_pool.items():
            for i in range(n):
                col = cols[i % len(cols)]
                offset = i * step
                query = template.format(table=table, col=col, offset=offset)
                yield {"table": table, "attempt_index": i, "query": query}
    else:
        raise ValueError(f"unknown pattern id: {pid}")


# ── HTTP client ───────────────────────────────────────────────────────────────

def post_query(
    target_url: str, token: str, query: str, session_id: str
) -> dict[str, Any]:
    """POST a query and return parsed JSON (or a synthetic error dict)."""
    url = target_url.rstrip("/") + "/v1/query"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type":  "application/json",
    }
    body = {
        "query":   query,
        "context": {"session_id": session_id, "task_description": "bypass coverage experiment"},
    }
    t0 = time.perf_counter()
    try:
        r = requests.post(url, headers=headers, json=body, timeout=DEFAULT_TIMEOUT)
        elapsed_ms = (time.perf_counter() - t0) * 1000
        try:
            data = r.json()
        except ValueError:
            data = {"decision": "error", "reasons": [f"non-JSON response: {r.text[:200]}"]}
        data["_http_status"] = r.status_code
        data["_client_latency_ms"] = round(elapsed_ms, 2)
        return data
    except requests.RequestException as e:
        elapsed_ms = (time.perf_counter() - t0) * 1000
        return {
            "decision": "error",
            "reasons":  [f"transport error: {e}"],
            "_http_status": 0,
            "_client_latency_ms": round(elapsed_ms, 2),
        }


# ── Per-target run ────────────────────────────────────────────────────────────

def run_for_target(
    target_label: str,
    target_url: str,
    token: str,
    bypasses: dict[str, Any],
    sleep_between_calls_ms: int = 0,
) -> list[dict[str, Any]]:
    """Execute all patterns against one target. Returns a list of result rows."""
    rows: list[dict[str, Any]] = []
    for pattern in bypasses["patterns"]:
        print(f"  [{target_label}] pattern: {pattern['id']}", flush=True)
        # Each (pattern, table) sequence uses its own session_id so the
        # session-aware target can accumulate state per scenario.
        for table_block, queries in _group_by_table(pattern):
            session_id = f"cov-{pattern['id']}-{table_block}-{uuid.uuid4().hex[:8]}"
            for q in queries:
                resp = post_query(target_url, token, q["query"], session_id)
                session_info = resp.get("session") or {}
                rows.append({
                    "target":              target_label,
                    "target_url":          target_url,
                    "pattern_id":          pattern["id"],
                    "table":               q["table"],
                    "session_id":          session_id,
                    "attempt_index":       q["attempt_index"],
                    "query":               q["query"],
                    "http_status":         resp.get("_http_status"),
                    "client_latency_ms":   resp.get("_client_latency_ms"),
                    "decision":            resp.get("decision"),
                    "risk_score":          resp.get("risk_score"),
                    "risk_level":          resp.get("risk_level"),
                    "deny_categories":     ",".join(resp.get("deny_categories", []) or []),
                    "reasons":             " | ".join(resp.get("reasons", []) or []),
                    "session_query_count":  session_info.get("query_count"),
                    "session_denied_count": session_info.get("denied_count"),
                    "session_denied_tables": json.dumps(session_info.get("denied_tables", {})) if session_info else "",
                    "gateway_latency_ms":   resp.get("latency_ms"),
                })
                if sleep_between_calls_ms > 0:
                    time.sleep(sleep_between_calls_ms / 1000.0)
    return rows


def _group_by_table(pattern: dict[str, Any]) -> Iterable[tuple[str, list[dict[str, Any]]]]:
    """Group generated queries by their table. Yields (table, [queries])."""
    by_table: dict[str, list[dict[str, Any]]] = {}
    for q in generate_queries(pattern):
        by_table.setdefault(q["table"], []).append(q)
    return by_table.items()


# ── CLI ───────────────────────────────────────────────────────────────────────

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Experiment A — per-query enforcement coverage (paper §6.4 Table 1)."
    )
    parser.add_argument(
        "--target", choices=["both", "baseline", "session"], default="both",
        help="Which target(s) to run. Default: both.",
    )
    parser.add_argument(
        "--baseline-url", default="http://localhost:8080",
        help="URL of the OSS gateway (no session store). Default: http://localhost:8080",
    )
    parser.add_argument(
        "--session-url", default="https://demo.tankada.io",
        help="URL of the session-aware gateway. Default: https://demo.tankada.io",
    )
    parser.add_argument(
        "--role", default="analyst", choices=["analyst", "admin"],
        help="JWT role to use. Default: analyst.",
    )
    parser.add_argument(
        "--sleep-ms", type=int, default=0,
        help="Sleep between calls in ms (avoid rate limit on hosted target).",
    )
    parser.add_argument(
        "--output", type=str, default=None,
        help="Output CSV path. Default: results/coverage_<timestamp>.csv",
    )
    args = parser.parse_args()

    bypasses = json.loads(BYPASSES_FILE.read_text())
    RESULTS_DIR.mkdir(exist_ok=True)
    timestamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    out_path = Path(args.output) if args.output else RESULTS_DIR / f"coverage_{timestamp}.csv"

    all_rows: list[dict[str, Any]] = []
    targets_to_run: list[tuple[str, str, str]] = []
    if args.target in ("both", "baseline"):
        token = sign_localhost_jwt(args.role)
        targets_to_run.append(("baseline", args.baseline_url, token))
    if args.target in ("both", "session"):
        token = load_demo_jwt(args.role)
        # On hosted target add a tiny sleep by default to be polite.
        targets_to_run.append(("session", args.session_url, token))

    for label, url, token in targets_to_run:
        print(f"\nRunning against {label} ({url})", flush=True)
        sleep_ms = args.sleep_ms if label == "baseline" else max(args.sleep_ms, 50)
        rows = run_for_target(label, url, token, bypasses, sleep_between_calls_ms=sleep_ms)
        all_rows.extend(rows)
        print(f"  {label}: {len(rows)} rows", flush=True)

    df = pd.DataFrame(all_rows)
    df.to_csv(out_path, index=False)
    print(f"\nWrote {len(df)} rows to {out_path}")

    # Quick summary by (target, pattern, decision):
    print("\nSummary:")
    summary = df.groupby(["target", "pattern_id", "decision"]).size().unstack(fill_value=0)
    print(summary.to_string())
    return 0


if __name__ == "__main__":
    sys.exit(main())
