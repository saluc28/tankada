"""
Pure unit tests for the framework-agnostic result formatting (good-citizen tags).
No gateway/network needed:  cd sdk/python && pip install -e . && pytest tests/
"""
from tankada.agent import format_result
from tankada.client import QueryResult


def test_allow_with_rows():
    r = QueryResult(decision="allow", columns=["id", "name"], rows=[[1, "a"], [2, "b"]], row_count=2)
    out = format_result(r)
    assert "[" not in out  # no deny tag on an allowed query
    assert "id" in out and "name" in out


def test_allow_empty():
    r = QueryResult(decision="allow", row_count=0)
    assert "No rows" in format_result(r)


def test_allow_truncates():
    rows = [[i] for i in range(100)]
    r = QueryResult(decision="allow", columns=["id"], rows=rows, row_count=100)
    out = format_result(r)
    assert "50 more rows" in out


def test_deny_abort():
    r = QueryResult(decision="deny", reasons=["nope"], deny_categories=["session_block"])
    assert format_result(r).startswith("[ABORT]")


def test_deny_rewrite():
    r = QueryResult(decision="deny", reasons=["fix it"], deny_categories=["tautology"])
    assert format_result(r).startswith("[REWRITE]")


def test_deny_transient():
    r = QueryResult(decision="deny", reasons=["slow down"], deny_categories=["rate_limit"])
    assert format_result(r).startswith("[TRANSIENT]")


def test_deny_blocked_fallback():
    r = QueryResult(decision="deny", reasons=["?"], deny_categories=["unknown"])
    assert format_result(r).startswith("[BLOCKED]")


def test_deny_abort_precedence_over_rewrite():
    # A deny carrying both an abort and a rewrite category must tag ABORT.
    r = QueryResult(decision="deny", reasons=["x"], deny_categories=["tautology", "pii_violation"])
    assert format_result(r).startswith("[ABORT]")
