"""
End-to-end smoke test for the Tankada MCP server.

Spawns `tankada-mcp` over stdio using the official MCP client, runs
list_tools / call_tool against a live gateway, and asserts on:

  - list_tools advertises sql_query + sql_explain
  - sql_query on a legitimate query returns rows (no deny tag)
  - sql_query on SELECT * (with scope + tenant filter otherwise clean) returns [REWRITE]
  - sql_explain on the same SELECT * returns "WOULD BE DENIED"

Requires the gateway stack to be running on localhost:8080 with the bundled
fintech demo schema, and the dev HS256 secret in place.

    pip install -e ".[mcp]" pyjwt
    cd deploy && docker compose up -d
    cd sdk/python && python examples/smoke_mcp_e2e.py
"""
from __future__ import annotations

import asyncio
import os
import subprocess
import sys
import uuid

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


_DEV_SECRET = "devsecretdevsecretdevsecretdevsecretdevsecret12345678"


_SDK_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # sdk/python


def _gen_token() -> str:
    # Match the .env secret the compose stack boots with, and grant
    # accounts:read so the allow + REWRITE paths can actually clear scope.
    out = subprocess.check_output(
        [sys.executable, "generate_token.py", "--raw",
         "--secret", _DEV_SECRET, "--scope", "accounts:read"],
        cwd=_SDK_DIR,
        stderr=subprocess.DEVNULL,
    )
    return out.decode().strip()


async def _run() -> int:
    token = _gen_token()
    print(f"[ok] token generated ({len(token)} chars)")

    env = dict(os.environ)
    env["TANKADA_AGENT_TOKEN"] = token
    env["TANKADA_GATEWAY_URL"] = "http://localhost:8080"
    # Use a fresh session id per run so the gateway's session-aware behavioral
    # enforcement does not carry deny counts across reruns (the smoke
    # intentionally fires denies, so reusing a session id would eventually trip
    # cumulative thresholds and turn the second run's REWRITE into a session
    # block).
    env["TANKADA_SESSION_ID"] = f"smoke-mcp-e2e-{uuid.uuid4()}"

    # On Windows the entry-point .exe lives in Scripts\; the launcher works the
    # same as on POSIX from the MCP client's point of view.
    params = StdioServerParameters(command="tankada-mcp", env=env)

    failures = 0
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as sess:
            await sess.initialize()
            print("[ok] initialize handshake")

            tools = await sess.list_tools()
            names = sorted(t.name for t in tools.tools)
            assert names == ["sql_explain", "sql_query"], names
            print(f"[ok] list_tools -> {names}")

            # 1) allowed query - scope OK, tenant filter present, no PII column.
            r = await sess.call_tool(
                "sql_query",
                {"query": "SELECT id FROM accounts WHERE tenant_id = 'tenant_1' LIMIT 3",
                 "task_description": "smoke: list a few account ids"},
            )
            text = r.content[0].text
            ok = not text.startswith(("[ABORT]", "[REWRITE]", "[TRANSIENT]", "[BLOCKED]"))
            print(f"[{'ok' if ok else 'FAIL'}] sql_query (allow) -> {text[:80]!r}")
            failures += 0 if ok else 1

            # 2) SELECT * with everything else clean -> REWRITE (only select_star fires).
            r = await sess.call_tool(
                "sql_query",
                {"query": "SELECT * FROM accounts WHERE tenant_id = 'tenant_1'"},
            )
            text = r.content[0].text
            ok = text.startswith("[REWRITE]")
            print(f"[{'ok' if ok else 'FAIL'}] sql_query (select_star) -> {text[:140]!r}")
            failures += 0 if ok else 1

            # 3) explain on the same deny query -> WOULD BE DENIED
            r = await sess.call_tool(
                "sql_explain",
                {"query": "SELECT * FROM accounts WHERE tenant_id = 'tenant_1'"},
            )
            text = r.content[0].text
            ok = text.startswith("WOULD BE DENIED")
            print(f"[{'ok' if ok else 'FAIL'}] sql_explain (select_star) -> {text[:140]!r}")
            failures += 0 if ok else 1

    return failures


if __name__ == "__main__":
    rc = asyncio.run(_run())
    print("\nALL OK" if rc == 0 else f"\n{rc} FAILURES")
    sys.exit(rc)
