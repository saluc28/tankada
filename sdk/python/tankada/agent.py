"""
Framework-agnostic helpers.

`guarded_sql` runs a query through Tankada and returns the text an agent tool should
return, with good-citizen deny tags ([ABORT] / [REWRITE] / [TRANSIENT] / [BLOCKED]).
Use it directly in a custom agent, or via the thin per-framework wrappers in
``tankada.frameworks.*``.
"""
from __future__ import annotations

from .client import QueryResult, TankadaClient

_MAX_ROWS = 50

# Shared tool description reused by every framework wrapper.
TOOL_DESCRIPTION = (
    "Execute a SQL SELECT query against the database. Every query is checked by the "
    "Tankada security policy. If the result is prefixed [ABORT], stop and do not try "
    "other queries; [REWRITE] means fix the query and retry; [TRANSIENT] means retry "
    "shortly. Always use an explicit column list and a WHERE clause."
)


def format_result(result: QueryResult, max_rows: int = _MAX_ROWS) -> str:
    """Render a QueryResult as the text the LLM sees, with good-citizen deny tags."""
    if result.allowed:
        if result.row_count == 0:
            return "Query allowed. No rows returned."
        rows = result.as_dicts()
        out = "\n".join(str(r) for r in rows[:max_rows])
        if result.row_count > max_rows:
            out += f"\n... and {result.row_count - max_rows} more rows"
        return out

    reasons = "; ".join(result.reasons) if result.reasons else "policy violation"
    tag = result.tag
    if tag == "ABORT":
        return (
            f"[ABORT] {reasons}. Do NOT attempt alternative queries. "
            "Tell the user the task cannot be completed."
        )
    if tag == "REWRITE":
        return f"[REWRITE] {reasons}. Rewrite the query and try again."
    if tag == "TRANSIENT":
        return f"[TRANSIENT] {reasons}. Wait briefly and retry the same query."
    return f"[BLOCKED] {reasons}."


def guarded_sql(client: TankadaClient, query: str, task_description: str = "") -> str:
    """Run a query through Tankada and return the good-citizen-formatted text."""
    return format_result(client.query(query, task_description=task_description))
