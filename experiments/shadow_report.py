#!/usr/bin/env python3
"""
shadow_report.py - "what would I have blocked?" report for Tankada shadow mode (D.5.b).

Run the gateway with TANKADA_MODE=shadow so it logs what enforcement WOULD have
done without blocking anything (each audit line gets mode="shadow" and
shadow_decision="deny"/"allow"). Feed those audit JSON lines to this script to get
a summary an operator can review before turning enforcement on.

Usage:
    docker compose logs --no-log-prefix gateway | python shadow_report.py
    python shadow_report.py audit.jsonl

Reads JSON-lines audit events from a file argument or stdin. Non-JSON lines (e.g.
container log noise) are skipped.
"""
import json
import sys
from collections import Counter


def iter_events(stream):
    for line in stream:
        line = line.strip()
        if not line:
            continue
        # Tolerate log prefixes: find the first '{' and parse from there.
        i = line.find("{")
        if i < 0:
            continue
        try:
            yield json.loads(line[i:])
        except ValueError:
            continue


def main():
    if len(sys.argv) > 1:
        with open(sys.argv[1], "r", encoding="utf-8") as fh:
            events = list(iter_events(fh))
    else:
        events = list(iter_events(sys.stdin))

    shadow = [e for e in events if e.get("mode") == "shadow"]
    would_deny = [e for e in shadow if e.get("shadow_decision") == "deny"]

    total = len(shadow)
    n_deny = len(would_deny)
    pct = (100.0 * n_deny / total) if total else 0.0

    by_reason = Counter()
    by_table = Counter()
    by_agent = Counter()
    for e in would_deny:
        for r in e.get("policy_reasons") or ["(unspecified)"]:
            by_reason[r] += 1
        for t in e.get("tables_accessed") or ["(none)"]:
            by_table[t] += 1
        by_agent[e.get("agent_id", "(unknown)")] += 1

    print("Tankada shadow report - what enforcement WOULD have blocked")
    print("=" * 60)
    print(f"Shadow-mode queries observed : {total}")
    print(f"Would have been DENIED       : {n_deny} ({pct:.1f}%)")
    print(f"Would have been ALLOWED      : {total - n_deny}")
    if not n_deny:
        print("\nNothing would have been blocked. Safe to enable enforcement.")
        return

    print("\nWould-be denials by reason:")
    for reason, n in by_reason.most_common():
        print(f"  {n:5d}  {reason}")

    print("\nWould-be denials by table:")
    for table, n in by_table.most_common():
        print(f"  {n:5d}  {table}")

    print("\nWould-be denials by agent:")
    for agent, n in by_agent.most_common():
        print(f"  {n:5d}  {agent}")


if __name__ == "__main__":
    main()
