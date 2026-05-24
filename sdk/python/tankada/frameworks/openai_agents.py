"""
OpenAI Agents SDK integration for Tankada - one line to get a policy-guarded SQL tool.

    from tankada.frameworks.openai_agents import tankada_sql_tool

    tool = tankada_sql_tool(
        gateway_url="http://localhost:8080",
        agent_token="<signed JWT>",
        session_id="sess-abc123",
    )
    agent = Agent(name="analyst", tools=[tool])

Requires the `openai-agents` extra:  pip install "tankada[openai-agents]"
"""
from __future__ import annotations

from typing import Optional

from agents import function_tool

from ..agent import guarded_sql
from ..client import TankadaClient


def tankada_sql_tool(
    gateway_url: str,
    agent_token: str,
    session_id: Optional[str] = None,
    timeout: int = 30,
):
    """One line: a ready OpenAI Agents SDK function tool guarded by Tankada."""
    client = TankadaClient(
        gateway_url=gateway_url,
        agent_token=agent_token,
        timeout=timeout,
        session_id=session_id,
    )

    @function_tool
    def sql_query(query: str, task_description: str = "") -> str:
        """Execute a SQL SELECT query, checked by the Tankada security policy.

        If the result is prefixed [ABORT], stop and do not try other queries;
        [REWRITE] means fix the query and retry; [TRANSIENT] means retry shortly.
        """
        return guarded_sql(client, query, task_description)

    return sql_query
