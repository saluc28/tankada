"""
Pure unit tests for the good-citizen deny-tag logic. No gateway/network needed:
    cd sdk/python && pip install -e . && pytest tests/
"""
from tankada.deny import ABORT, REWRITE, TRANSIENT, deny_tag


def test_abort_precedence():
    assert deny_tag(["session_block"]) == "ABORT"
    assert deny_tag(["pii_violation"]) == "ABORT"
    # ABORT wins even when mixed with a rewrite category
    assert deny_tag(["tautology", "pii_violation"]) == "ABORT"


def test_rewrite():
    assert deny_tag(["tautology"]) == "REWRITE"
    assert deny_tag(["select_star"]) == "REWRITE"
    assert deny_tag(["missing_where"]) == "REWRITE"
    assert deny_tag(["high_limit"]) == "REWRITE"


def test_transient():
    assert deny_tag(["rate_limit"]) == "TRANSIENT"
    assert deny_tag(["infrastructure"]) == "TRANSIENT"


def test_blocked_fallback():
    assert deny_tag([]) == "BLOCKED"
    assert deny_tag(None) == "BLOCKED"
    assert deny_tag(["risk_score"]) == "BLOCKED"   # composite -> not a clear bucket
    assert deny_tag(["unknown"]) == "BLOCKED"
    assert deny_tag(["a_brand_new_category"]) == "BLOCKED"


def test_buckets_are_disjoint():
    assert not (ABORT & REWRITE)
    assert not (ABORT & TRANSIENT)
    assert not (REWRITE & TRANSIENT)


def test_session_block_is_abort():
    # The moat's category must be in the abort bucket: the agent must stop, not retry.
    assert "session_block" in ABORT
