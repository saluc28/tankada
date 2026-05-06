package tankada.query_test

import data.tankada.query

# ── Base input (clean — should allow) ────────────────────────────────────────
# products is in tenant_global_tables so no tenant_id filter required.

base_input := {
    "analysis": {
        "query_type": "SELECT",
        "tables": ["products"],
        "columns": ["id"],
        "has_where": true,
        "where_is_tautology": false,
        "having_is_tautology": false,
        "join_count": 0,
        "subquery_count": 0,
        "cte_count": 0,
        "is_aggregation": false,
        "is_write": false,
        "is_schema_enum": false,
        "has_limit": true,
        "limit_value": 10,
        "has_high_limit": false,
        "pii_columns": [],
        "accesses_pii_columns": false,
        "has_comment": false,
        "has_union": false,
        "has_order_by_random": false,
        "multi_statement": false,
        "has_offset": false,
        "where_equality_filters": {},
        "parse_error": "",
    },
    "agent": {
        "agent_id": "agent-1",
        "tenant_id": "tenant-1",
        "roles": [],
        "scopes": [],
    },
}

# ── allow: clean query passes ─────────────────────────────────────────────────

test_allow_clean_query if {
    query.allow with input as base_input
}

# ── Absolute denies ───────────────────────────────────────────────────────────

test_deny_delete if {
    inp := object.union(base_input, {"analysis": object.union(base_input.analysis, {"query_type": "DELETE", "is_write": true})})
    count(query.deny) > 0 with input as inp
}

test_deny_drop if {
    inp := object.union(base_input, {"analysis": object.union(base_input.analysis, {"query_type": "DROP", "is_write": true})})
    count(query.deny) > 0 with input as inp
}

test_deny_truncate if {
    inp := object.union(base_input, {"analysis": object.union(base_input.analysis, {"query_type": "TRUNCATE", "is_write": true})})
    count(query.deny) > 0 with input as inp
}

test_deny_alter if {
    inp := object.union(base_input, {"analysis": object.union(base_input.analysis, {"query_type": "ALTER", "is_write": true})})
    count(query.deny) > 0 with input as inp
}

test_deny_parse_error if {
    inp := object.union(base_input, {"analysis": object.union(base_input.analysis, {"parse_error": "unexpected token"})})
    count(query.deny) > 0 with input as inp
}

# ── LLM-specific hard denies ──────────────────────────────────────────────────

test_deny_multi_statement if {
    inp := object.union(base_input, {"analysis": object.union(base_input.analysis, {"multi_statement": true})})
    "multi-statement query blocked: SQL injection chain pattern detected" in query.deny with input as inp
}

test_deny_schema_enum if {
    inp := object.union(base_input, {"analysis": object.union(base_input.analysis, {"is_schema_enum": true})})
    "schema enumeration query blocked (agent reconnaissance pattern)" in query.deny with input as inp
}

test_deny_pii_without_scope if {
    inp := object.union(base_input, {"analysis": object.union(base_input.analysis, {"pii_columns": ["email"], "accesses_pii_columns": true})})
    count(query.deny) > 0 with input as inp
}

test_allow_pii_with_admin_scope if {
    inp := object.union(base_input, {
        "analysis": object.union(base_input.analysis, {"pii_columns": ["email"], "accesses_pii_columns": true}),
        "agent": object.union(base_input.agent, {"roles": ["admin"]}),
    })
    query.allow with input as inp
}

test_allow_pii_with_users_read_scope if {
    inp := object.union(base_input, {
        "analysis": object.union(base_input.analysis, {"pii_columns": ["email"], "accesses_pii_columns": true}),
        "agent": object.union(base_input.agent, {"scopes": ["users:read"]}),
    })
    query.allow with input as inp
}

# ── Tenant isolation ──────────────────────────────────────────────────────────

test_deny_missing_tenant_filter if {
    inp := object.union(base_input, {"analysis": object.union(base_input.analysis, {
        "tables": ["orders"],
        "where_equality_filters": {},
    })})
    count(query.deny) > 0 with input as inp
}

test_allow_correct_tenant_filter if {
    inp := object.union(base_input, {"analysis": object.union(base_input.analysis, {
        "tables": ["orders"],
        "where_equality_filters": {"tenant_id": "tenant-1"},
    })})
    query.allow with input as inp
}

test_deny_wrong_tenant_filter if {
    inp := object.union(base_input, {"analysis": object.union(base_input.analysis, {
        "tables": ["orders"],
        "where_equality_filters": {"tenant_id": "tenant-evil"},
    })})
    count(query.deny) > 0 with input as inp
}

test_allow_global_table_no_filter if {
    query.allow with input as base_input
}

# ── Contextual denies ─────────────────────────────────────────────────────────

test_deny_select_no_where if {
    inp := object.union(base_input, {"analysis": object.union(base_input.analysis, {"has_where": false})})
    "SELECT without WHERE clause on a named table" in query.deny with input as inp
}

test_deny_sensitive_table_no_scope if {
    inp := object.union(base_input, {"analysis": object.union(base_input.analysis, {
        "tables": ["users"],
        "where_equality_filters": {"tenant_id": "tenant-1"},
    })})
    count(query.deny) > 0 with input as inp
}

test_allow_sensitive_table_with_scope if {
    inp := object.union(base_input, {
        "analysis": object.union(base_input.analysis, {
            "tables": ["users"],
            "where_equality_filters": {"tenant_id": "tenant-1"},
        }),
        "agent": object.union(base_input.agent, {"scopes": ["users:read"]}),
    })
    query.allow with input as inp
}

test_deny_tautology if {
    inp := object.union(base_input, {"analysis": object.union(base_input.analysis, {"where_is_tautology": true})})
    "WHERE clause is a tautology (e.g. 1=1)" in query.deny with input as inp
}

# ── Risk scoring ──────────────────────────────────────────────────────────────

test_risk_score_clean_is_low if {
    query.risk_score < 4 with input as base_input
}

test_risk_score_no_where if {
    inp := object.union(base_input, {"analysis": object.union(base_input.analysis, {"has_where": false})})
    query.no_where_score == 3 with input as inp
}

test_risk_score_star_column if {
    inp := object.union(base_input, {"analysis": object.union(base_input.analysis, {"columns": ["*"]})})
    query.star_score == 2 with input as inp
}

test_risk_score_high_limit if {
    inp := object.union(base_input, {"analysis": object.union(base_input.analysis, {"has_high_limit": true})})
    query.high_limit_score == 2 with input as inp
}

test_risk_score_union if {
    inp := object.union(base_input, {"analysis": object.union(base_input.analysis, {"has_union": true})})
    query.union_score == 2 with input as inp
}

test_risk_score_comment if {
    inp := object.union(base_input, {"analysis": object.union(base_input.analysis, {"has_comment": true})})
    query.comment_score == 1 with input as inp
}

test_risk_score_random_order if {
    inp := object.union(base_input, {"analysis": object.union(base_input.analysis, {"has_order_by_random": true})})
    query.random_order_score == 1 with input as inp
}

test_deny_risk_score_exceeds_threshold if {
    # star(2) + no_limit_star(2) + union(2) + comment(1) = 7 >= 7
    inp := object.union(base_input, {"analysis": object.union(base_input.analysis, {
        "columns": ["*"],
        "has_limit": false,
        "has_union": true,
        "has_comment": true,
        "has_where": true,
    })})
    count(query.deny) > 0 with input as inp
}

# ── Risk level ────────────────────────────────────────────────────────────────

test_risk_level_low if {
    query.risk_level == "low" with input as base_input
}

test_risk_level_medium if {
    # no_where(3) + star(2) = 5, medium range [4,7)
    inp := object.union(base_input, {"analysis": object.union(base_input.analysis, {
        "columns": ["*"],
        "has_where": false,
        "has_limit": true,
    })})
    query.risk_level == "medium" with input as inp
}

test_risk_level_high if {
    # star(2) + no_limit_star(2) + union(2) + comment(1) = 7 >= 7
    inp := object.union(base_input, {"analysis": object.union(base_input.analysis, {
        "columns": ["*"],
        "has_limit": false,
        "has_union": true,
        "has_comment": true,
        "has_where": true,
    })})
    query.risk_level == "high" with input as inp
}
