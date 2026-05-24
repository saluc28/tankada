"""
Tankada deny-category handling: the "good citizen" pattern.

When the gateway denies a query it returns ``deny_categories[]``, a machine-readable
enum. This maps those categories into one of four behavioural tags so an agent knows
how to react without parsing free-text reasons:

  ABORT     -> stop; the task is not possible. Do NOT try alternative queries.
  REWRITE   -> reformulate the query and retry.
  TRANSIENT -> wait briefly and retry the same query.
  BLOCKED   -> denied, category not recognised (treat as stop).

This is the SDK-side of the pattern documented in the Tankada repo (EXAMPLES.md
"Handling deny categories"). The category lists MUST stay in sync with the gateway
(gateway/handler/deny_category.go).
"""
from __future__ import annotations

from typing import Iterable, Optional

# Non-recoverable: a semantic/behavioural deny. The agent must stop.
ABORT = frozenset({
    "missing_scope",
    "pii_violation",
    "tenant_violation",
    "injection",
    "destructive_op",
    "schema_enum",
    "parse_error",
    "session_block",
})

# Recoverable by reformulating the query.
REWRITE = frozenset({"tautology", "select_star", "missing_where", "high_limit"})

# Transient: retry the same query after a short backoff.
TRANSIENT = frozenset({"rate_limit", "infrastructure"})


def deny_tag(categories: Optional[Iterable[str]]) -> str:
    """Return "ABORT", "REWRITE", "TRANSIENT" or "BLOCKED" for the given categories.

    ABORT takes precedence (most severe), then REWRITE, then TRANSIENT; anything
    unrecognised (e.g. risk_score, unknown, or an empty list) maps to BLOCKED.
    """
    cats = set(categories or ())
    if cats & ABORT:
        return "ABORT"
    if cats & REWRITE:
        return "REWRITE"
    if cats & TRANSIENT:
        return "TRANSIENT"
    return "BLOCKED"
