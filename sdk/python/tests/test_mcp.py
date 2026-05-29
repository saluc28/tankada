"""
Pure unit tests for the Tankada MCP server (D.7.a).

The `mcp` package is NOT imported here: we test the pure helpers (tool defs,
dispatch, explain formatting, env parsing) directly with a fake client. The
mcp-dependent serve()/main() wiring is intentionally thin and not unit-tested.

    cd sdk/python && pip install -e . && pytest tests/test_mcp.py
"""
import pytest

from tankada.client import QueryResult
from tankada.mcp_server import (
    TOOL_EXPLAIN,
    TOOL_QUERY,
    client_from_env,
    format_explain,
    run_tool,
    tool_definitions,
)


class _FakeClient:
    """Stand-in for TankadaClient: records calls, returns canned results."""

    def __init__(self, query_result=None, explain_result=None):
        self._query_result = query_result or QueryResult(decision="allow", row_count=0)
        self._explain_result = explain_result or {"allowed": True, "risk_score": 0, "risk_level": "low"}
        self.query_calls = []
        self.explain_calls = []

    def query(self, sql, task_description="", user_id=""):
        self.query_calls.append((sql, task_description))
        return self._query_result

    def explain(self, sql):
        self.explain_calls.append(sql)
        return self._explain_result


# -- tool_definitions ---------------------------------------------------------

def test_tool_definitions_expose_both_tools():
    defs = tool_definitions()
    names = {d["name"] for d in defs}
    assert names == {TOOL_QUERY, TOOL_EXPLAIN}


def test_tool_definitions_have_required_query_arg():
    for d in tool_definitions():
        schema = d["inputSchema"]
        assert schema["type"] == "object"
        assert "query" in schema["properties"]
        assert "query" in schema["required"]


def test_query_tool_advertises_task_description():
    q = next(d for d in tool_definitions() if d["name"] == TOOL_QUERY)
    assert "task_description" in q["inputSchema"]["properties"]


# -- run_tool: dispatch --------------------------------------------------------

def test_run_tool_query_allow_returns_rows():
    fake = _FakeClient(query_result=QueryResult(
        decision="allow", columns=["id"], rows=[[1], [2]], row_count=2))
    out = run_tool(fake, TOOL_QUERY, {"query": "SELECT id FROM accounts WHERE tenant_id='t1'"})
    assert "[" not in out  # allow -> no deny tag
    assert fake.query_calls[0][0].startswith("SELECT id")


def test_run_tool_query_passes_task_description():
    fake = _FakeClient()
    run_tool(fake, TOOL_QUERY, {"query": "SELECT 1", "task_description": "smoke"})
    assert fake.query_calls[0][1] == "smoke"


def test_run_tool_query_deny_keeps_good_citizen_tag():
    fake = _FakeClient(query_result=QueryResult(
        decision="deny", reasons=["tenant filter missing"], deny_categories=["tautology"]))
    out = run_tool(fake, TOOL_QUERY, {"query": "SELECT * FROM accounts"})
    assert out.startswith("[REWRITE]")


def test_run_tool_explain_allow():
    fake = _FakeClient(explain_result={"allowed": True, "risk_score": 3, "risk_level": "low"})
    out = run_tool(fake, TOOL_EXPLAIN, {"query": "SELECT 1"})
    assert out.startswith("ALLOWED")
    assert fake.explain_calls == ["SELECT 1"]


def test_run_tool_explain_deny():
    fake = _FakeClient(explain_result={
        "allowed": False, "risk_score": 80, "risk_level": "high",
        "deny_reasons": ["no tenant filter"], "suggestions": ["add WHERE tenant_id = ..."]})
    out = run_tool(fake, TOOL_EXPLAIN, {"query": "SELECT * FROM accounts"})
    assert out.startswith("WOULD BE DENIED")
    assert "no tenant filter" in out
    assert "add WHERE tenant_id" in out


def test_run_tool_unknown_name_raises():
    with pytest.raises(ValueError, match="unknown tool"):
        run_tool(_FakeClient(), "drop_everything", {})


def test_run_tool_missing_query_raises():
    with pytest.raises(ValueError, match="non-empty 'query'"):
        run_tool(_FakeClient(), TOOL_QUERY, {})
    with pytest.raises(ValueError, match="non-empty 'query'"):
        run_tool(_FakeClient(), TOOL_EXPLAIN, {"query": ""})


# -- format_explain ------------------------------------------------------------

def test_format_explain_allow_with_mask_columns():
    out = format_explain({"allowed": True, "risk_score": 5, "risk_level": "low",
                          "mask_columns": ["email", "ssn"]})
    assert out.startswith("ALLOWED")
    assert "email" in out and "ssn" in out


def test_format_explain_deny_without_suggestions():
    out = format_explain({"allowed": False, "risk_score": 50, "risk_level": "medium"})
    assert out.startswith("WOULD BE DENIED")
    assert "policy violation" in out  # default reason when none supplied


# -- client_from_env -----------------------------------------------------------

def test_client_from_env_requires_token(monkeypatch):
    monkeypatch.delenv("TANKADA_AGENT_TOKEN", raising=False)
    with pytest.raises(RuntimeError, match="TANKADA_AGENT_TOKEN"):
        client_from_env()


def test_client_from_env_defaults(monkeypatch):
    monkeypatch.setenv("TANKADA_AGENT_TOKEN", "tok")
    monkeypatch.delenv("TANKADA_GATEWAY_URL", raising=False)
    monkeypatch.delenv("TANKADA_SESSION_ID", raising=False)
    c = client_from_env()
    # Internal fields: assert the defaults landed.
    assert c._url == "http://localhost:8080"
    assert c._session_id is None


def test_client_from_env_reads_all_vars(monkeypatch):
    monkeypatch.setenv("TANKADA_AGENT_TOKEN", "tok")
    monkeypatch.setenv("TANKADA_GATEWAY_URL", "https://gw.example/")
    monkeypatch.setenv("TANKADA_SESSION_ID", "sess-1")
    monkeypatch.setenv("TANKADA_TIMEOUT", "5")
    c = client_from_env()
    assert c._url == "https://gw.example"  # trailing slash stripped by client
    assert c._session_id == "sess-1"
    assert c._timeout == 5


def test_client_from_env_bad_timeout_falls_back(monkeypatch):
    monkeypatch.setenv("TANKADA_AGENT_TOKEN", "tok")
    monkeypatch.setenv("TANKADA_TIMEOUT", "not-a-number")
    c = client_from_env()
    assert c._timeout == 30
