"""
AutoGen integration for Tankada.

AutoGen registers plain Python functions as tools, so this returns a ready callable
with a docstring AutoGen can expose to the LLM. No extra dependency is needed (you
install your own AutoGen flavour: autogen-agentchat / pyautogen / ag2).

    from tankada.frameworks.autogen import tankada_sql_function

    sql_query = tankada_sql_function(
        gateway_url="http://localhost:8080",
        agent_token="<signed JWT>",
        session_id="sess-abc123",
    )
    # register `sql_query` with your AutoGen agent (e.g. tools=[sql_query] or
    # register_function / register_for_llm, depending on your AutoGen version).
"""
from __future__ import annotations

from typing import Callable, Optional

from ..agent import guarded_sql
from ..client import TankadaClient


def tankada_sql_function(
    gateway_url: str,
    agent_token: str,
    session_id: Optional[str] = None,
    timeout: int = 30,
) -> Callable[[str, str], str]:
    """Return a callable ``sql_query(query, task_description="")`` guarded by Tankada."""
    client = TankadaClient(
        gateway_url=gateway_url,
        agent_token=agent_token,
        timeout=timeout,
        session_id=session_id,
    )

    def sql_query(query: str, task_description: str = "") -> str:
        """Execute a SQL SELECT query, checked by the Tankada security policy.

        If the result is prefixed [ABORT], stop and do not try other queries;
        [REWRITE] means fix the query and retry; [TRANSIENT] means retry shortly.
        """
        return guarded_sql(client, query, task_description)

    return sql_query
