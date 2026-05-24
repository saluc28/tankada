"""
End-to-end smoke test for the Tankada Python SDK against a RUNNING gateway.

Prereqs:
  1) Start the stack:   cd ../../deploy && docker compose up -d   (wait until healthy)
  2) Install deps:       py -m pip install -e ".[langchain]" pyjwt   (from sdk/python)
  3) Run:               py examples/smoke_e2e.py

Optional env:
  TANKADA_URL     default http://localhost:8080
  TANKADA_SECRET  default dev-secret-change-in-production  (matches the dev docker-compose)

Exit code 0 = all cases behaved as expected; non-zero = at least one mismatch.
"""
from __future__ import annotations

import datetime
import os
import sys

import jwt  # pyjwt

from tankada import TankadaClient

GATEWAY = os.getenv("TANKADA_URL", "http://localhost:8080")
SECRET = os.getenv("TANKADA_SECRET", "dev-secret-change-in-production")


def make_token() -> str:
    return jwt.encode(
        {
            "agent_id": "smoke-agent",
            "owner_user_id": "smoke",
            "tenant_id": "tenant_1",
            "roles": ["analyst"],
            "dataActions": [
                "tenant_1/financial/accounts/read",
                "tenant_1/financial/transactions/read",
                "tenant_1/financial/cards/read",
                "tenant_1/financial/loans/read",
            ],
            "notDataActions": [],
            "exp": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1),
        },
        SECRET,
        algorithm="HS256",
    )


# (label, sql, expected_decision, expected_tag_or_None)
CASES = [
    ("allow: global table", "SELECT id, name, category FROM merchants WHERE country = 'US' LIMIT 20", "allow", None),
    ("allow: scoped + tenant filter", "SELECT id, account_number, balance FROM accounts WHERE tenant_id = 'tenant_1' AND status = 'active' LIMIT 50", "allow", None),
    ("deny: tautology (rewrite)", "SELECT id, name FROM merchants WHERE 1=1", "deny", "REWRITE"),
    ("deny: select * (rewrite)", "SELECT * FROM accounts WHERE tenant_id = 'tenant_1' AND id = 42", "deny", "REWRITE"),
    ("deny: schema enum (abort)", "SELECT table_name FROM information_schema.tables", "deny", "ABORT"),
    ("deny: missing scope + PII (abort)", "SELECT id, email FROM customers WHERE tenant_id = 'tenant_1' LIMIT 10", "deny", "ABORT"),
]


def main() -> int:
    client = TankadaClient(GATEWAY, make_token(), session_id="smoke-session")
    failures = 0
    print(f"Tankada SDK smoke test against {GATEWAY}\n")
    for label, sql, want_decision, want_tag in CASES:
        try:
            r = client.query(sql, task_description="smoke test")
        except Exception as e:  # noqa: BLE001
            print(f"  ERROR  {label}: {e}")
            failures += 1
            continue
        ok = r.decision == want_decision and (want_tag is None or r.tag == want_tag)
        flag = "OK  " if ok else "FAIL"
        detail = f"rows={r.row_count}" if r.allowed else f"tag={r.tag} cats={r.deny_categories}"
        print(f"  {flag} {label}: [{r.decision}] {detail}")
        if not ok:
            print(f"        expected decision={want_decision} tag={want_tag}; reasons={r.reasons}")
            failures += 1

    print()
    if failures:
        print(f"{failures} case(s) FAILED")
        return 1
    print(f"All {len(CASES)} cases passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
