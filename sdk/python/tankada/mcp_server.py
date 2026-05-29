"""
Tankada MCP server (D.7.a) - expose policy-guarded SQL as Model Context
Protocol tools.

Any MCP-compatible host (Claude Desktop, Cursor, an MCP-native agent runtime)
can add this server to its config and get SQL access that is checked by the
Tankada behavioral firewall on every call. The agent never talks to the
database directly: each tool call is routed to the Tankada gateway, which
parses, evaluates the policy, and either executes or denies with a
good-citizen tag the model can act on.

Two tools are exposed:

  sql_query    Execute a SQL SELECT. Returns rows, or a deny tag
               ([ABORT] / [REWRITE] / [TRANSIENT] / [BLOCKED]) that tells the
               model whether to stop, rewrite, or retry.
  sql_explain  Dry-run: ask what the policy would decide WITHOUT executing.
               Useful for the model to check a query before committing to it.

Transport is stdio (the canonical local MCP transport). Configure via env:

  TANKADA_GATEWAY_URL   gateway base URL (default http://localhost:8080)
  TANKADA_AGENT_TOKEN   signed JWT for the agent (required)
  TANKADA_SESSION_ID    stable session id; pass the SAME value for the whole
                        agent session so the gateway's behavioral enforcement
                        can accumulate across queries (optional but recommended)
  TANKADA_TIMEOUT       per-request timeout in seconds (default 30)

Run it:

  TANKADA_AGENT_TOKEN=... python -m tankada.mcp_server

The `mcp` package is an optional dependency. The pure helpers in this module
(tool definitions, the dispatch, env parsing, explain formatting) import
nothing from `mcp` and are unit-tested directly; only serve()/main() touch the
MCP runtime, lazily, so importing this module does not require `mcp` to be
installed.
"""
from __future__ import annotations

import os
from typing import Any, Dict, List

from .agent import TOOL_DESCRIPTION, guarded_sql
from .client import TankadaClient

# Tool names kept as module constants so tests and the dispatch agree on
# exactly one spelling.
TOOL_QUERY = "sql_query"
TOOL_EXPLAIN = "sql_explain"

_EXPLAIN_DESCRIPTION = (
    "Dry-run a SQL SELECT against the Tankada security policy WITHOUT executing "
    "it. Returns whether the query would be allowed, the deny reasons and "
    "suggestions if not, and a risk score. Use this to check a query before "
    "running it with sql_query."
)


# -- Pure helpers (no `mcp`, no network; unit-tested) -------------------------

def tool_definitions() -> List[Dict[str, Any]]:
    """The MCP tool specs this server advertises, as plain dicts. Pure.

    Kept framework-neutral (name / description / inputSchema) so the wiring in
    serve() can map them onto whatever shape the installed `mcp` version wants,
    and so tests can assert on them without importing `mcp`."""
    return [
        {
            "name": TOOL_QUERY,
            "description": TOOL_DESCRIPTION,
            "inputSchema": {
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "The SQL SELECT query to execute.",
                    },
                    "task_description": {
                        "type": "string",
                        "description": "Brief description of what this query is for.",
                    },
                },
                "required": ["query"],
            },
        },
        {
            "name": TOOL_EXPLAIN,
            "description": _EXPLAIN_DESCRIPTION,
            "inputSchema": {
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "The SQL SELECT query to dry-run against the policy.",
                    },
                },
                "required": ["query"],
            },
        },
    ]


def format_explain(data: Dict[str, Any]) -> str:
    """Render the gateway's /v1/explain JSON as text the model can read. Pure.

    Shape (gateway handler/explain.go): {allowed, deny_reasons[], suggestions[],
    risk_score, risk_level, mask_columns[]}."""
    risk = f"risk {data.get('risk_score', 0)} ({data.get('risk_level', 'unknown')})"
    if data.get("allowed"):
        out = f"ALLOWED - {risk}."
        masked = data.get("mask_columns") or []
        if masked:
            out += f" PII columns that would be masked: {', '.join(masked)}."
        return out
    reasons = "; ".join(data.get("deny_reasons") or []) or "policy violation"
    out = f"WOULD BE DENIED - {risk}. Reasons: {reasons}."
    suggestions = data.get("suggestions") or []
    if suggestions:
        out += " Suggestions: " + "; ".join(suggestions) + "."
    return out


def run_tool(client: TankadaClient, name: str, arguments: Dict[str, Any]) -> str:
    """Dispatch one MCP tool call to the Tankada gateway and return the text
    the model should see. Pure with respect to `mcp`: takes a TankadaClient
    (mockable in tests) and the raw arguments dict, returns a string.

    Raises ValueError on an unknown tool name or a missing required argument so
    serve() can surface it as a tool error rather than crashing the server."""
    if name == TOOL_QUERY:
        query = arguments.get("query")
        if not query:
            raise ValueError("sql_query requires a non-empty 'query' argument")
        return guarded_sql(
            client, query, task_description=arguments.get("task_description", "")
        )
    if name == TOOL_EXPLAIN:
        query = arguments.get("query")
        if not query:
            raise ValueError("sql_explain requires a non-empty 'query' argument")
        return format_explain(client.explain(query))
    raise ValueError(f"unknown tool: {name!r}")


def client_from_env() -> TankadaClient:
    """Build a TankadaClient from environment variables. Raises a clear
    RuntimeError if the agent token is missing (the one thing the operator
    must supply). Pure apart from reading os.environ."""
    token = os.environ.get("TANKADA_AGENT_TOKEN", "").strip()
    if not token:
        raise RuntimeError(
            "TANKADA_AGENT_TOKEN is not set; the MCP server needs a signed agent "
            "JWT to talk to the gateway. Set it in your MCP host's server config."
        )
    gateway_url = os.environ.get("TANKADA_GATEWAY_URL", "http://localhost:8080").strip()
    session_id = os.environ.get("TANKADA_SESSION_ID", "").strip() or None
    try:
        timeout = int(os.environ.get("TANKADA_TIMEOUT", "30"))
    except ValueError:
        timeout = 30
    return TankadaClient(
        gateway_url=gateway_url,
        agent_token=token,
        timeout=timeout,
        session_id=session_id,
    )


# -- MCP runtime wiring (lazy: only this part needs `mcp`) --------------------

async def serve(client: TankadaClient) -> None:
    """Run the MCP server over stdio against the given Tankada client.

    Imports `mcp` lazily so the rest of this module (and `import tankada`) works
    without the optional dependency installed."""
    try:
        import mcp.types as types
        from mcp.server import Server
        from mcp.server.stdio import stdio_server
    except ImportError as e:  # pragma: no cover - exercised only without the extra
        raise RuntimeError(
            "the 'mcp' package is required to run the Tankada MCP server; "
            "install it with: pip install \"tankada[mcp]\""
        ) from e

    server: Server = Server("tankada")

    @server.list_tools()
    async def _list_tools() -> List["types.Tool"]:
        return [types.Tool(**spec) for spec in tool_definitions()]

    @server.call_tool()
    async def _call_tool(name: str, arguments: Dict[str, Any]) -> List["types.TextContent"]:
        try:
            text = run_tool(client, name, arguments or {})
        except ValueError as e:
            text = f"[BLOCKED] {e}"
        return [types.TextContent(type="text", text=text)]

    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


def main() -> None:
    """Console entrypoint: build the client from env and serve over stdio."""
    import asyncio

    client = client_from_env()
    asyncio.run(serve(client))


if __name__ == "__main__":
    main()
