"""
LangChain integration for Tankada - one line to get a policy-guarded SQL tool.

    from tankada import tankada_sql_tool

    tool = tankada_sql_tool(
        gateway_url="http://localhost:8080",
        agent_token="<signed JWT>",
        session_id="sess-abc123",   # enables behavioural (session-aware) enforcement
    )
    # ... give `tool` to your LangChain/LangGraph agent ...

The tool routes every SQL query through the Tankada gateway instead of the database,
and turns deny responses into good-citizen tags ([ABORT] / [REWRITE] / [TRANSIENT])
that tell the LLM how to react. Requires the `langchain` extra:

    pip install "tankada[langchain]"
"""
from __future__ import annotations

from typing import Optional, Type

from langchain_core.tools import BaseTool
from pydantic import BaseModel, Field

from ..client import QueryResult, TankadaClient

_MAX_ROWS = 50


def format_result(result: QueryResult) -> str:
    """Render a QueryResult as the text the LLM sees, with good-citizen deny tags."""
    if result.allowed:
        if result.row_count == 0:
            return "Query allowed. No rows returned."
        rows = result.as_dicts()
        out = "\n".join(str(r) for r in rows[:_MAX_ROWS])
        if result.row_count > _MAX_ROWS:
            out += f"\n... and {result.row_count - _MAX_ROWS} more rows"
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


class _SQLInput(BaseModel):
    query: str = Field(description="The SQL SELECT query to execute")
    task_description: str = Field(
        default="", description="Brief description of what this query is for"
    )


class TankadaSQLTool(BaseTool):
    """LangChain tool that routes SQL through Tankada, with good-citizen deny handling."""

    name: str = "sql_query"
    description: str = (
        "Execute a SQL SELECT query against the database. Every query is checked by the "
        "Tankada security policy. If the result is prefixed [ABORT], stop and do not try "
        "other queries; [REWRITE] means fix the query and retry; [TRANSIENT] means retry "
        "shortly. Always use an explicit column list and a WHERE clause."
    )
    args_schema: Type[BaseModel] = _SQLInput

    gateway_url: str
    agent_token: str
    session_id: Optional[str] = None
    timeout: int = 30

    def _client(self) -> TankadaClient:
        return TankadaClient(
            gateway_url=self.gateway_url,
            agent_token=self.agent_token,
            timeout=self.timeout,
            session_id=self.session_id,
        )

    def _run(self, query: str, task_description: str = "") -> str:
        return format_result(self._client().query(query, task_description=task_description))

    async def _arun(self, query: str, task_description: str = "") -> str:
        return self._run(query, task_description)


def tankada_sql_tool(
    gateway_url: str,
    agent_token: str,
    session_id: Optional[str] = None,
    timeout: int = 30,
) -> TankadaSQLTool:
    """One line: a ready LangChain tool guarded by Tankada.

    Pass a stable ``session_id`` (same value for every query in the agent's session)
    to enable the gateway's behavioural enforcement.
    """
    return TankadaSQLTool(
        gateway_url=gateway_url,
        agent_token=agent_token,
        session_id=session_id,
        timeout=timeout,
    )
