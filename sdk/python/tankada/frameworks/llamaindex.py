"""
LlamaIndex integration for Tankada - one line to get a policy-guarded SQL tool.

    from tankada.frameworks.llamaindex import tankada_sql_tool

    tool = tankada_sql_tool(
        gateway_url="http://localhost:8080",
        agent_token="<signed JWT>",
        session_id="sess-abc123",
    )
    # ... give `tool` to your LlamaIndex agent ...

Requires the `llamaindex` extra:  pip install "tankada[llamaindex]"
"""
from __future__ import annotations

from typing import Optional

from llama_index.core.tools import FunctionTool

from ..agent import TOOL_DESCRIPTION, guarded_sql
from ..client import TankadaClient


def tankada_sql_tool(
    gateway_url: str,
    agent_token: str,
    session_id: Optional[str] = None,
    timeout: int = 30,
) -> "FunctionTool":
    """One line: a ready LlamaIndex FunctionTool guarded by Tankada."""
    client = TankadaClient(
        gateway_url=gateway_url,
        agent_token=agent_token,
        timeout=timeout,
        session_id=session_id,
    )

    def sql_query(query: str, task_description: str = "") -> str:
        return guarded_sql(client, query, task_description)

    return FunctionTool.from_defaults(
        fn=sql_query, name="sql_query", description=TOOL_DESCRIPTION
    )
