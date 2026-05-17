"""
fp_rate_study.py — False-positive rate study for the Tankada gateway.

Sends a set of legitimate analyst queries (defined in `legitimate_queries.json`)
and measures how many are incorrectly denied. The expected outcome on every
query is ALLOW; a DENY is a false positive.

Two modes:
  - single   each query in its own fresh session (no cumulative state).
             Measures per-query layer false positives.
  - session  queries inside "session_workflow_*" categories are sent inside
             a single shared session_id. Measures whether legitimate diverse
             multi-query workloads accidentally trigger session-aware denials
             (false session_block, false reformulation pattern, etc.).
  - both     run single first, then session.

Targets the session-aware gateway (demo.tankada.io) using the analyst JWT
from jwt_tokens.json. The script is deterministic, no LLM, no API cost
(other than DNS/TLS to the demo host).

Usage:
  python fp_rate_study.py                       # both modes
  python fp_rate_study.py --mode single
  python fp_rate_study.py --mode session
  python fp_rate_study.py --gateway-url https://demo.tankada.io
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

import pandas as pd
import requests

HERE = Path(__file__).parent
QUERIES_FILE = HERE / "legitimate_queries.json"
TOKENS_FILE = HERE / "jwt_tokens.json"
RESULTS_DIR = HERE / "results"

DEFAULT_GATEWAY_URL = "https://demo.tankada.io"
DEFAULT_TIMEOUT = 10.0


def post_query(target_url: str, token: str, sql: str, session_id: str) -> dict[str, Any]:
    """POST a query and return parsed JSON enriched with client-side fields."""
    url = target_url.rstrip("/") + "/v1/query"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type":  "application/json",
    }
    body = {
        "query":   sql,
        "context": {"session_id": session_id, "task_description": "fp_rate_study"},
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


def run_mode_single(
    gateway_url: str, token: str, queries_data: dict[str, Any], sleep_ms: int = 30
) -> list[dict[str, Any]]:
    """Each query in its own fresh session. Per-query FP only."""
    rows: list[dict[str, Any]] = []
    for cat in queries_data["categories"]:
        # Skip the multi-query session workflows in single mode (they belong to session mode)
        if cat["name"].startswith("session_workflow_"):
            continue
        print(f"  [single] category: {cat['name']} ({len(cat['queries'])} queries)", flush=True)
        for q_idx, sql in enumerate(cat["queries"]):
            sid = f"fp-single-{cat['name']}-{q_idx}-{uuid.uuid4().hex[:8]}"
            resp = post_query(gateway_url, token, sql, sid)
            rows.append({
                "mode":               "single",
                "category":           cat["name"],
                "query_index":        q_idx,
                "session_id":         sid,
                "query":              sql,
                "expected_decision":  cat["expected_decision"],
                "actual_decision":    resp.get("decision"),
                "http_status":        resp.get("_http_status"),
                "deny_categories":    ",".join(resp.get("deny_categories", []) or []),
                "reasons":            " | ".join(resp.get("reasons", []) or []),
                "risk_score":         resp.get("risk_score"),
                "false_positive":     int(cat["expected_decision"] == "allow" and resp.get("decision") == "deny"),
            })
            if sleep_ms > 0:
                time.sleep(sleep_ms / 1000.0)
    return rows


def run_mode_session(
    gateway_url: str, token: str, queries_data: dict[str, Any], sleep_ms: int = 30
) -> list[dict[str, Any]]:
    """Multi-query workflows: each session_workflow_* category runs in one session."""
    rows: list[dict[str, Any]] = []
    for cat in queries_data["categories"]:
        if not cat["name"].startswith("session_workflow_"):
            continue
        sid = f"fp-session-{cat['name']}-{uuid.uuid4().hex[:8]}"
        print(f"  [session] workflow: {cat['name']} ({len(cat['queries'])} queries, single session_id)", flush=True)
        for q_idx, sql in enumerate(cat["queries"]):
            resp = post_query(gateway_url, token, sql, sid)
            rows.append({
                "mode":               "session",
                "category":           cat["name"],
                "query_index":        q_idx,
                "session_id":         sid,
                "query":              sql,
                "expected_decision":  cat["expected_decision"],
                "actual_decision":    resp.get("decision"),
                "http_status":        resp.get("_http_status"),
                "deny_categories":    ",".join(resp.get("deny_categories", []) or []),
                "reasons":            " | ".join(resp.get("reasons", []) or []),
                "risk_score":         resp.get("risk_score"),
                "false_positive":     int(cat["expected_decision"] == "allow" and resp.get("decision") == "deny"),
            })
            if sleep_ms > 0:
                time.sleep(sleep_ms / 1000.0)
    return rows


def summarize(df: pd.DataFrame) -> None:
    print()
    print("=" * 60)
    print("False Positive rate summary")
    print("=" * 60)
    for mode in df["mode"].unique():
        sub = df[df["mode"] == mode]
        total = len(sub)
        fp = int(sub["false_positive"].sum())
        rate = (fp / total * 100) if total else 0.0
        print(f"\nMode '{mode}': {fp} / {total} false positives ({rate:.1f}%)")
        if fp > 0:
            print("  False-positive queries:")
            for _, r in sub[sub["false_positive"] == 1].iterrows():
                print(f"    [{r['category']}] {r['query'][:100]}")
                print(f"      -> deny_categories: {r['deny_categories']!r}")
                print(f"         reasons:         {r['reasons'][:150]}")
    print()
    print("By category:")
    by_cat = df.groupby(["mode", "category"]).agg(
        n=("false_positive", "count"),
        fp=("false_positive", "sum"),
    )
    by_cat["fp_rate_pct"] = (by_cat["fp"] / by_cat["n"] * 100).round(1)
    print(by_cat.to_string())


def main() -> int:
    parser = argparse.ArgumentParser(description="Tankada false-positive rate study on legitimate analyst queries.")
    parser.add_argument("--mode", choices=["single", "session", "both"], default="both")
    parser.add_argument("--gateway-url", default=DEFAULT_GATEWAY_URL)
    parser.add_argument("--role", default="analyst", choices=["analyst", "admin"])
    parser.add_argument("--sleep-ms", type=int, default=30)
    parser.add_argument("--output", type=str, default=None)
    args = parser.parse_args()

    queries_data = json.loads(QUERIES_FILE.read_text())
    tokens = json.loads(TOKENS_FILE.read_text())
    token = tokens[args.role]

    RESULTS_DIR.mkdir(exist_ok=True)
    timestamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    out_path = Path(args.output) if args.output else RESULTS_DIR / f"fp_rate_{timestamp}.csv"

    all_rows: list[dict[str, Any]] = []
    if args.mode in ("single", "both"):
        print(f"Running mode SINGLE against {args.gateway_url}")
        all_rows.extend(run_mode_single(args.gateway_url, token, queries_data, args.sleep_ms))
    if args.mode in ("session", "both"):
        print(f"\nRunning mode SESSION against {args.gateway_url}")
        all_rows.extend(run_mode_session(args.gateway_url, token, queries_data, args.sleep_ms))

    df = pd.DataFrame(all_rows)
    df.to_csv(out_path, index=False)
    print(f"\nWrote {len(df)} rows to {out_path}")
    summarize(df)
    return 0


if __name__ == "__main__":
    sys.exit(main())
