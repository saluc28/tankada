"""
Tankada Python SDK - HTTP client for the Tankada gateway.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import requests

from .deny import deny_tag


@dataclass
class QueryResult:
    decision: str
    event_id: str = ""
    risk_score: int = 0
    risk_level: str = "unknown"
    latency_ms: int = 0
    columns: List[str] = field(default_factory=list)
    rows: List[List[Any]] = field(default_factory=list)
    row_count: int = 0
    reasons: List[str] = field(default_factory=list)
    deny_categories: List[str] = field(default_factory=list)

    @property
    def allowed(self) -> bool:
        return self.decision == "allow"

    @property
    def tag(self) -> str:
        """Good-citizen tag for a deny: ABORT / REWRITE / TRANSIENT / BLOCKED."""
        return deny_tag(self.deny_categories)

    def as_dicts(self) -> List[Dict[str, Any]]:
        """Rows as a list of {column: value} dicts."""
        return [dict(zip(self.columns, row)) for row in self.rows]


class TankadaClient:
    """
    Client for the Tankada gateway.

    One client instance models one agent session. Pass a stable ``session_id`` so the
    gateway's behavioural (session-aware) enforcement can accumulate across all the
    queries the agent issues in that session.

    Usage:
        client = TankadaClient(
            gateway_url="http://localhost:8080",
            agent_token="<signed JWT>",
            session_id="sess-abc123",
        )
        result = client.query("SELECT id, balance FROM accounts WHERE tenant_id = 'tenant_1'")
        if result.allowed:
            for row in result.as_dicts():
                print(row)
        else:
            print(result.tag, result.reasons)
    """

    def __init__(
        self,
        gateway_url: str,
        agent_token: str,
        timeout: int = 30,
        session_id: Optional[str] = None,
    ):
        self._url = gateway_url.rstrip("/")
        self._timeout = timeout
        self._session_id = session_id
        self._http = requests.Session()
        self._http.headers.update({
            "Authorization": f"Bearer {agent_token}",
            "Content-Type": "application/json",
        })

    def _context(self, task_description: str, user_id: str) -> Dict[str, Any]:
        ctx: Dict[str, Any] = {}
        if task_description:
            ctx["task_description"] = task_description
        if user_id:
            ctx["user_id"] = user_id
        if self._session_id:
            ctx["session_id"] = self._session_id
        return ctx

    def query(self, sql: str, task_description: str = "", user_id: str = "") -> QueryResult:
        """Send a query to the gateway. Returns a QueryResult (allow or deny)."""
        resp = self._http.post(
            f"{self._url}/v1/query",
            json={"query": sql, "context": self._context(task_description, user_id)},
            timeout=self._timeout,
        )
        data = resp.json()
        result = data.get("result") or {}
        return QueryResult(
            decision=data.get("decision", "deny"),
            event_id=data.get("event_id", ""),
            risk_score=data.get("risk_score", 0),
            risk_level=data.get("risk_level", "unknown"),
            latency_ms=data.get("latency_ms", 0),
            columns=result.get("columns", []),
            rows=result.get("rows", []),
            row_count=result.get("row_count", 0),
            reasons=data.get("reasons", []),
            deny_categories=data.get("deny_categories", []),
        )

    def explain(self, sql: str) -> Dict[str, Any]:
        """Dry-run: ask what the policy would decide, without executing the query.

        Returns the raw gateway JSON: {allowed, deny_reasons[], suggestions[],
        risk_score, risk_level}.
        """
        resp = self._http.post(
            f"{self._url}/v1/explain",
            json={"query": sql},
            timeout=self._timeout,
        )
        return resp.json()
