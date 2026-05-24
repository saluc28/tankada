"""
Tankada Python SDK - client for the behavioral firewall for SQL by LLM agents.

Quick start (framework-agnostic):

    from tankada import TankadaClient

    client = TankadaClient("http://localhost:8080", "<signed JWT>", session_id="sess-1")
    r = client.query("SELECT id, balance FROM accounts WHERE tenant_id = 'tenant_1'")
    print(r.allowed, r.tag, r.reasons)

One line for LangChain:

    from tankada import tankada_sql_tool
    tool = tankada_sql_tool("http://localhost:8080", "<signed JWT>", session_id="sess-1")
"""
from __future__ import annotations

from .agent import format_result, guarded_sql
from .client import TankadaClient, QueryResult
from .deny import ABORT, REWRITE, TRANSIENT, deny_tag

__version__ = "0.1.0"

__all__ = [
    "TankadaClient",
    "QueryResult",
    "deny_tag",
    "guarded_sql",
    "format_result",
    "ABORT",
    "REWRITE",
    "TRANSIENT",
    "tankada_sql_tool",
]


def __getattr__(name: str):
    # Lazy import so LangChain stays an optional dependency: `from tankada import
    # tankada_sql_tool` works only if the `langchain` extra is installed, but
    # importing tankada itself never requires LangChain.
    if name == "tankada_sql_tool":
        from .frameworks.langchain import tankada_sql_tool

        return tankada_sql_tool
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
