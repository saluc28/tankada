package tankada.query_test

import data.tankada.query

# ── Base input (clean, should allow) ──────────────────────────────────────────
# merchants is in tenant_global_tables so no tenant_id filter required.

base_input := {
    "analysis": {
        "query_type": "SELECT",
        "tables": ["merchants"],
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

default_templates := {
    "tautology_blocker":      {"enabled": true},
    "pii_column_guard":       {"enabled": true},
    "select_star_block":      {"enabled": true},
    "destructive_query_block": {"enabled": true},
    "row_limit_enforcer":     {"enabled": true, "max_limit": 500},
}

# ── allow: clean query passes ─────────────────────────────────────────────────

test_allow_clean_query if {
    query.allow with input as base_input with data.templates as default_templates
}

# ── Absolute denies (non-template) ────────────────────────────────────────────

test_deny_parse_error if {
    inp := object.union(base_input, {"analysis": object.union(base_input.analysis, {"parse_error": "unexpected token"})})
    count(query.deny) > 0 with input as inp
}

test_deny_multi_statement if {
    inp := object.union(base_input, {"analysis": object.union(base_input.analysis, {"multi_statement": true})})
    "multi-statement query blocked: SQL injection chain pattern detected" in query.deny with input as inp
}

test_deny_schema_enum if {
    inp := object.union(base_input, {"analysis": object.union(base_input.analysis, {"is_schema_enum": true})})
    "schema enumeration query blocked (agent reconnaissance pattern)" in query.deny with input as inp
}

# ── Tenant isolation ──────────────────────────────────────────────────────────

test_deny_missing_tenant_filter if {
    inp := object.union(base_input, {"analysis": object.union(base_input.analysis, {
        "tables": ["accounts"],
        "where_equality_filters": {},
    })})
    count(query.deny) > 0 with input as inp
}

test_allow_correct_tenant_filter if {
    inp := object.union(base_input, {
        "analysis": object.union(base_input.analysis, {
            "tables": ["accounts"],
            "where_equality_filters": {"tenant_id": "tenant-1"},
        }),
        "agent": object.union(base_input.agent, {"scopes": ["accounts:read"]}),
    })
    query.allow with input as inp with data.templates as default_templates
}

test_deny_wrong_tenant_filter if {
    inp := object.union(base_input, {"analysis": object.union(base_input.analysis, {
        "tables": ["accounts"],
        "where_equality_filters": {"tenant_id": "tenant-evil"},
    })})
    count(query.deny) > 0 with input as inp
}

test_allow_global_table_no_filter if {
    query.allow with input as base_input with data.templates as default_templates
}

# ── Template: destructive_query_block ─────────────────────────────────────────

test_deny_delete if {
    inp := object.union(base_input, {"analysis": object.union(base_input.analysis, {"query_type": "DELETE", "is_write": true})})
    count(query.deny) > 0 with input as inp with data.templates as default_templates
}

test_deny_drop if {
    inp := object.union(base_input, {"analysis": object.union(base_input.analysis, {"query_type": "DROP", "is_write": true})})
    count(query.deny) > 0 with input as inp with data.templates as default_templates
}

test_deny_truncate if {
    inp := object.union(base_input, {"analysis": object.union(base_input.analysis, {"query_type": "TRUNCATE", "is_write": true})})
    count(query.deny) > 0 with input as inp with data.templates as default_templates
}

test_deny_alter if {
    inp := object.union(base_input, {"analysis": object.union(base_input.analysis, {"query_type": "ALTER", "is_write": true})})
    count(query.deny) > 0 with input as inp with data.templates as default_templates
}

test_allow_delete_when_destructive_block_disabled if {
    inp := object.union(base_input, {"analysis": object.union(base_input.analysis, {
        "query_type": "DELETE",
        "is_write": true,
        "has_where": true,
        "tables": [],
    })})
    templates := object.union(default_templates, {"destructive_query_block": {"enabled": false}})
    query.allow with input as inp with data.templates as templates
}

# ── Template: tautology_blocker ───────────────────────────────────────────────

test_deny_tautology if {
    inp := object.union(base_input, {"analysis": object.union(base_input.analysis, {"where_is_tautology": true})})
    "WHERE clause is a tautology (e.g. 1=1)" in query.deny with input as inp with data.templates as default_templates
}

test_allow_tautology_when_disabled if {
    inp := object.union(base_input, {"analysis": object.union(base_input.analysis, {"where_is_tautology": true})})
    templates := object.union(default_templates, {"tautology_blocker": {"enabled": false}})
    query.allow with input as inp with data.templates as templates
}

# ── Template: pii_column_guard ────────────────────────────────────────────────

test_deny_pii_without_scope if {
    inp := object.union(base_input, {"analysis": object.union(base_input.analysis, {
        "tables": ["customers"],
        "pii_columns": ["email"],
        "accesses_pii_columns": true,
        "where_equality_filters": {"tenant_id": "tenant-1"},
    })})
    count(query.deny) > 0 with input as inp with data.templates as default_templates
}

test_allow_pii_with_admin_scope if {
    inp := object.union(base_input, {
        "analysis": object.union(base_input.analysis, {
            "tables": ["customers"],
            "pii_columns": ["email"],
            "accesses_pii_columns": true,
            "where_equality_filters": {"tenant_id": "tenant-1"},
        }),
        "agent": object.union(base_input.agent, {"roles": ["admin"]}),
    })
    query.allow with input as inp with data.templates as default_templates
}

test_allow_pii_with_customers_read_scope if {
    inp := object.union(base_input, {
        "analysis": object.union(base_input.analysis, {
            "tables": ["customers"],
            "pii_columns": ["email"],
            "accesses_pii_columns": true,
            "where_equality_filters": {"tenant_id": "tenant-1"},
        }),
        "agent": object.union(base_input.agent, {"scopes": ["customers:read"]}),
    })
    query.allow with input as inp with data.templates as default_templates
}

# pii_column_guard fires only on tenant-scoped tables that the agent cannot
# read. An analyst with the correct per-table scope accessing PII columns on
# that same table must not be blocked by the guard.
test_allow_pii_on_accounts_with_accounts_scope if {
    inp := object.union(base_input, {
        "analysis": object.union(base_input.analysis, {
            "tables": ["accounts"],
            "pii_columns": ["email"],
            "accesses_pii_columns": true,
            "where_equality_filters": {"tenant_id": "tenant-1"},
        }),
        "agent": object.union(base_input.agent, {"scopes": ["accounts:read"]}),
    })
    query.allow with input as inp with data.templates as default_templates
}

test_allow_pii_when_guard_disabled if {
    inp := object.union(base_input, {
        "analysis": object.union(base_input.analysis, {
            "tables": ["customers"],
            "pii_columns": ["email"],
            "accesses_pii_columns": true,
            "where_equality_filters": {"tenant_id": "tenant-1"},
        }),
        "agent": object.union(base_input.agent, {"scopes": ["customers:read"]}),
    })
    templates := object.union(default_templates, {"pii_column_guard": {"enabled": false}})
    query.allow with input as inp with data.templates as templates
}

# ── Template: select_star_block ───────────────────────────────────────────────

test_deny_select_star if {
    inp := object.union(base_input, {"analysis": object.union(base_input.analysis, {"columns": ["*"]})})
    "SELECT * is not allowed; specify columns explicitly" in query.deny with input as inp with data.templates as default_templates
}

test_allow_select_star_when_disabled if {
    inp := object.union(base_input, {"analysis": object.union(base_input.analysis, {"columns": ["*"]})})
    templates := object.union(default_templates, {"select_star_block": {"enabled": false}})
    query.allow with input as inp with data.templates as templates
}

# ── Template: row_limit_enforcer ──────────────────────────────────────────────

test_deny_row_limit_enforcer if {
    inp := object.union(base_input, {"analysis": object.union(base_input.analysis, {"has_high_limit": true})})
    count(query.deny) > 0 with input as inp with data.templates as default_templates
}

test_allow_high_limit_when_disabled if {
    inp := object.union(base_input, {"analysis": object.union(base_input.analysis, {"has_high_limit": true})})
    templates := object.union(default_templates, {"row_limit_enforcer": {"enabled": false}})
    query.allow with input as inp with data.templates as templates
}

# ── Contextual denies (non-template) ──────────────────────────────────────────

test_deny_select_no_where if {
    inp := object.union(base_input, {"analysis": object.union(base_input.analysis, {"has_where": false})})
    "SELECT without WHERE clause on a named table" in query.deny with input as inp
}

test_deny_sensitive_table_no_scope if {
    inp := object.union(base_input, {"analysis": object.union(base_input.analysis, {
        "tables": ["customers"],
        "where_equality_filters": {"tenant_id": "tenant-1"},
    })})
    count(query.deny) > 0 with input as inp with data.templates as default_templates
}

test_allow_sensitive_table_with_scope if {
    inp := object.union(base_input, {
        "analysis": object.union(base_input.analysis, {
            "tables": ["customers"],
            "where_equality_filters": {"tenant_id": "tenant-1"},
        }),
        "agent": object.union(base_input.agent, {"scopes": ["customers:read"]}),
    })
    query.allow with input as inp with data.templates as default_templates
}

# ── Per-table scope: accounts ─────────────────────────────────────────────────

test_deny_accounts_without_scope if {
    inp := object.union(base_input, {"analysis": object.union(base_input.analysis, {
        "tables": ["accounts"],
        "where_equality_filters": {"tenant_id": "tenant-1"},
    })})
    count(query.deny) > 0 with input as inp with data.templates as default_templates
}

test_allow_accounts_with_scope if {
    inp := object.union(base_input, {
        "analysis": object.union(base_input.analysis, {
            "tables": ["accounts"],
            "where_equality_filters": {"tenant_id": "tenant-1"},
        }),
        "agent": object.union(base_input.agent, {"scopes": ["accounts:read"]}),
    })
    query.allow with input as inp with data.templates as default_templates
}

# ── Per-table scope: transactions ─────────────────────────────────────────────

test_deny_transactions_without_scope if {
    inp := object.union(base_input, {"analysis": object.union(base_input.analysis, {
        "tables": ["transactions"],
        "where_equality_filters": {"tenant_id": "tenant-1"},
    })})
    count(query.deny) > 0 with input as inp with data.templates as default_templates
}

test_allow_transactions_with_scope if {
    inp := object.union(base_input, {
        "analysis": object.union(base_input.analysis, {
            "tables": ["transactions"],
            "where_equality_filters": {"tenant_id": "tenant-1"},
        }),
        "agent": object.union(base_input.agent, {"scopes": ["transactions:read"]}),
    })
    query.allow with input as inp with data.templates as default_templates
}

# ── Per-table scope: loans ────────────────────────────────────────────────────

test_deny_loans_without_scope if {
    inp := object.union(base_input, {"analysis": object.union(base_input.analysis, {
        "tables": ["loans"],
        "where_equality_filters": {"tenant_id": "tenant-1"},
    })})
    count(query.deny) > 0 with input as inp with data.templates as default_templates
}

test_allow_loans_with_scope if {
    inp := object.union(base_input, {
        "analysis": object.union(base_input.analysis, {
            "tables": ["loans"],
            "where_equality_filters": {"tenant_id": "tenant-1"},
        }),
        "agent": object.union(base_input.agent, {"scopes": ["loans:read"]}),
    })
    query.allow with input as inp with data.templates as default_templates
}

# ── Per-table scope: cards ────────────────────────────────────────────────────

test_deny_cards_without_scope if {
    inp := object.union(base_input, {"analysis": object.union(base_input.analysis, {
        "tables": ["cards"],
        "where_equality_filters": {"tenant_id": "tenant-1"},
    })})
    count(query.deny) > 0 with input as inp with data.templates as default_templates
}

test_allow_cards_with_scope if {
    inp := object.union(base_input, {
        "analysis": object.union(base_input.analysis, {
            "tables": ["cards"],
            "where_equality_filters": {"tenant_id": "tenant-1"},
        }),
        "agent": object.union(base_input.agent, {"scopes": ["cards:read"]}),
    })
    query.allow with input as inp with data.templates as default_templates
}

# ── Admin bypasses all per-table scope checks ─────────────────────────────────

test_allow_admin_access_loans if {
    inp := object.union(base_input, {
        "analysis": object.union(base_input.analysis, {
            "tables": ["loans"],
            "where_equality_filters": {"tenant_id": "tenant-1"},
        }),
        "agent": object.union(base_input.agent, {"roles": ["admin"]}),
    })
    query.allow with input as inp with data.templates as default_templates
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

# sens_score must NOT penalise an agent that holds the correct scope.
# Without this guard a legitimate analyst accumulates +3 risk on every query
# and approaches the deny threshold as a false positive.

test_sens_score_three_when_agent_lacks_scope if {
    inp := object.union(base_input, {"analysis": object.union(base_input.analysis, {
        "tables": ["customers"],
        "where_equality_filters": {"tenant_id": "tenant-1"},
    })})
    query.sens_score == 3 with input as inp
}

test_sens_score_zero_when_agent_has_scope if {
    inp := object.union(base_input, {
        "analysis": object.union(base_input.analysis, {
            "tables": ["customers"],
            "where_equality_filters": {"tenant_id": "tenant-1"},
        }),
        "agent": object.union(base_input.agent, {"scopes": ["customers:read"]}),
    })
    query.sens_score == 0 with input as inp
}

test_sens_score_zero_for_admin if {
    inp := object.union(base_input, {
        "analysis": object.union(base_input.analysis, {
            "tables": ["customers"],
            "where_equality_filters": {"tenant_id": "tenant-1"},
        }),
        "agent": object.union(base_input.agent, {"roles": ["admin"]}),
    })
    query.sens_score == 0 with input as inp
}

test_sens_score_zero_on_global_table if {
    query.sens_score == 0 with input as base_input
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
    count(query.deny) > 0 with input as inp with data.templates as default_templates
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
