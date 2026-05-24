"""
LangChain integration for Tankada - one line to get a policy-guarded SQL tool.

    from tankada import tankada_sql_tool

    tool = tankada_sql_tool(
        gateway_url="http://localhost:8080",
        agent_token="<signed JWT>",
        session_id="sess-abc123",   # enables behavioural (session-aware) enforcement
    )
    # ... give `tool` to your LangChain / LangGraph agent ...

Requires the `langchain` extra:  pip install "tankada[langchain]"
"""
from __future__ import annotations

from typing import Optional, Type

from langchain_core.tools import BaseTool
from pydantic import BaseModel, Field

from ..agent import TOOL_DESCRIPTION, guarded_sql
from ..client import TankadaClient


class _SQLInput(BaseModel):
    query: str = Field(description="The SQL SELECT query to execute")
    task_description: str = Field(
        default="", description="Brief description of what this query is for"
    )


class TankadaSQLTool(BaseTool):
    """LangChain tool that routes SQL through Tankada, with good-citizen deny handling."""

    name: str = "sql_query"
    description: str = TOOL_DESCRIPTION
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
        return guarded_sql(self._client(), query, task_description)

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
