package tankada.query

import rego.v1

# Per-table scope requirements, loaded from the schema config (data.schema, file
# policies/schema.json) so the policy and the gateway resolver share one source of
# truth and onboarding a new schema needs no Rego edit. Admin role bypasses all
# checks. Tables absent from the map are unrestricted (e.g. merchants).
table_required_scope := {t: cfg.scope | some t, cfg in data.schema.tables}

# Tables without a tenant_id column, exempt from the tenant-isolation filter check.
# Also config-driven via data.schema.
tenant_global_tables := {t | some t in data.schema.tenant_global_tables}

# ── Absolute denies (non-template) ────────────────────────────────────────────

deny contains reason if {
    input.analysis.parse_error != ""
    reason := sprintf("query parse failed: %v", [input.analysis.parse_error])
}

deny contains reason if {
    input.analysis.multi_statement == true
    reason := "multi-statement query blocked: SQL injection chain pattern detected"
}

deny contains reason if {
    input.analysis.is_schema_enum == true
    reason := "schema enumeration query blocked (agent reconnaissance pattern)"
}

# ── Tenant isolation (non-template) ───────────────────────────────────────────
# Every SELECT touching a tenant-scoped table must carry a top-level AND filter
# `tenant_id = <agent's JWT tenant>`. Prevents cross-tenant access by a malicious
# or buggy agent that crafts a query with the wrong tenant_id.

deny contains reason if {
    input.analysis.query_type == "SELECT"
    query_touches_tenant_scoped_table
    not has_matching_tenant_filter
    reason := sprintf("query must filter by tenant_id = '%v' on tenant-scoped tables (agent's tenant from JWT)", [input.agent.tenant_id])
}

query_touches_tenant_scoped_table if {
    tbl := input.analysis.tables[_]
    not tenant_global_tables[tbl]
}

has_matching_tenant_filter if {
    input.analysis.where_equality_filters.tenant_id == input.agent.tenant_id
}

# Subquery defense: each Subquery must itself filter by tenant_id on tenant-
# scoped tables. A subquery without its own tenant_id filter that touches a
# tenant-scoped table is an exfiltration path the outer filter does not cover.
# RLS catches this at runtime; this rule keeps the OPA decision consistent
# with the threat model.
deny contains reason if {
    tbl := input.analysis.subquery_tables_without_tenant_filter[_]
    not tenant_global_tables[tbl]
    reason := sprintf("subquery on tenant-scoped table '%v' lacks its own tenant_id filter", [tbl])
}

# ── Template: destructive_query_block ─────────────────────────────────────────

deny contains reason if {
    data.templates.destructive_query_block.enabled
    input.analysis.query_type == "DELETE"
    reason := "destructive operation DELETE is not allowed"
}

deny contains reason if {
    data.templates.destructive_query_block.enabled
    input.analysis.query_type == "DROP"
    reason := "destructive operation DROP is not allowed"
}

deny contains reason if {
    data.templates.destructive_query_block.enabled
    input.analysis.query_type == "TRUNCATE"
    reason := "destructive operation TRUNCATE is not allowed"
}

deny contains reason if {
    data.templates.destructive_query_block.enabled
    input.analysis.query_type == "ALTER"
    reason := "destructive operation ALTER is not allowed"
}

# ── Template: tautology_blocker ───────────────────────────────────────────────

deny contains reason if {
    data.templates.tautology_blocker.enabled
    input.analysis.query_type == "SELECT"
    input.analysis.has_where == true
    input.analysis.where_is_tautology == true
    reason := "WHERE clause is a tautology (e.g. 1=1)"
}

deny contains reason if {
    data.templates.tautology_blocker.enabled
    input.analysis.query_type == "SELECT"
    input.analysis.having_is_tautology == true
    reason := "HAVING clause is a tautology (e.g. 1=1)"
}

# ── Template: pii_column_guard ────────────────────────────────────────────────
# Fires when PII columns are accessed on a tenant-scoped table for which the
# agent does not hold the required per-table scope. Coherent with the per-table
# scope model.

deny contains reason if {
    data.templates.pii_column_guard.enabled
    count(input.analysis.pii_columns) > 0
    tbl := input.analysis.tables[_]
    table_required_scope[tbl]
    not agent_has_table_scope(tbl)
    reason := sprintf("query accesses PII columns %v without required scope for table '%v'", [input.analysis.pii_columns, tbl])
}

# ── Template: pii_masking ─────────────────────────────────────────────────────
# Result-level redaction rather than an outright deny. When enabled, the PII
# columns detected in an allowed query are returned masked in the response
# instead of the agent receiving the data in clear. Orthogonal to the deny
# rules: masking never changes table authorization, it only governs what an
# authorised reader sees.
#
# Who sees a column in clear is configurable (D.2.b):
#   - unmask_roles:         roles that see every PII column in clear (default ["admin"]).
#   - unmask_scope:         a single scope that unmasks every PII column (default "pii:unmask").
#   - column_unmask_scopes: per-column map {column: scope}; holding that scope
#                           unmasks just that column, leaving the others masked.
#
# `mask` is the set of column names the gateway must redact; `mask_value` is the
# placeholder substituted for each masked cell.

mask contains col if {
    data.templates.pii_masking.enabled
    some col in input.analysis.pii_columns
    not agent_can_unmask_column(col)
}

# Roles that see all PII in clear. Defaults to ["admin"] when not configured.
default unmask_roles := ["admin"]

unmask_roles := roles if {
    roles := data.templates.pii_masking.unmask_roles
}

# Scope that unmasks all PII. Defaults to "pii:unmask" when not configured.
default unmask_scope := "pii:unmask"

unmask_scope := scope if {
    scope := data.templates.pii_masking.unmask_scope
}

# Global unmask by role.
agent_can_unmask_column(_) if {
    some r in unmask_roles
    input.agent.roles[_] == r
}

# Global unmask by scope.
agent_can_unmask_column(_) if {
    input.agent.scopes[_] == unmask_scope
}

# Per-column unmask by a column-specific scope.
agent_can_unmask_column(col) if {
    required := data.templates.pii_masking.column_unmask_scopes[col]
    input.agent.scopes[_] == required
}

default mask_value := "***"

mask_value := v if {
    data.templates.pii_masking.enabled
    v := data.templates.pii_masking.mask_value
    v != ""
}

# ── Template: select_star_block ───────────────────────────────────────────────

deny contains reason if {
    data.templates.select_star_block.enabled
    input.analysis.query_type == "SELECT"
    has_star_column
    reason := "SELECT * is not allowed; specify columns explicitly"
}

# ── Template: row_limit_enforcer ──────────────────────────────────────────────

deny contains reason if {
    data.templates.row_limit_enforcer.enabled
    input.analysis.has_high_limit == true
    reason := sprintf("query LIMIT exceeds maximum allowed rows (%v)", [data.templates.row_limit_enforcer.max_limit])
}

# ── Contextual denies (non-template) ──────────────────────────────────────────

deny contains reason if {
    input.analysis.query_type == "SELECT"
    input.analysis.has_where == false
    count(input.analysis.tables) > 0
    not all_tables_are_tenant_global
    reason := "SELECT without WHERE clause on a named table"
}

# A SELECT with no WHERE is legitimate when every table touched is a
# tenant-global lookup table (no tenant_id column to filter on). Catalog
# tables like `merchants` are queried by aggregation or lookup without a
# WHERE clause as part of normal analyst workflow.
all_tables_are_tenant_global if {
    count(input.analysis.tables) > 0
    every tbl in input.analysis.tables {
        tenant_global_tables[tbl]
    }
}

deny contains reason if {
    tbl := input.analysis.tables[_]
    required := table_required_scope[tbl]
    not agent_has_table_scope(tbl)
    reason := sprintf("access to table '%v' requires scope '%v'", [tbl, required])
}

deny contains reason if {
    risk_score >= 7
    reason := sprintf("risk score %v exceeds threshold (7)", [risk_score])
}

# ── Scope checks ──────────────────────────────────────────────────────────────

# Admin role bypasses all per-table restrictions.
agent_has_table_scope(_) if {
    input.agent.roles[_] == "admin"
}

# Agent carries the exact scope required for this table.
agent_has_table_scope(tbl) if {
    required := table_required_scope[tbl]
    input.agent.scopes[_] == required
}

# ── Per-query risk scoring ────────────────────────────────────────────────────

no_where_score := 3 if { input.analysis.has_where == false }
no_where_score := 0 if { input.analysis.has_where == true }

has_star_column if { input.analysis.columns[_] == "*" }

star_score := 2 if { has_star_column }
star_score := 0 if { not has_star_column }

multi_join_score := 2 if { input.analysis.join_count > 1 }
multi_join_score := 0 if { input.analysis.join_count <= 1 }

# Only penalise sensitive-table access when the agent does NOT hold the required
# per-table scope. A legitimate analyst with the correct scope must not accumulate
# +3 risk on every query, or the deny threshold (7) triggers as a false positive
# after a handful of legitimate reads.
sens_score := 3 if {
    tbl := input.analysis.tables[_]
    table_required_scope[tbl]
    not agent_has_table_scope(tbl)
}
sens_score := 0 if { not any_unscoped_sensitive_table }

any_unscoped_sensitive_table if {
    tbl := input.analysis.tables[_]
    table_required_scope[tbl]
    not agent_has_table_scope(tbl)
}

subq_score := 1 if { input.analysis.subquery_count > 2 }
subq_score := 0 if { input.analysis.subquery_count <= 2 }

# SELECT * with no LIMIT: unbounded data extraction
no_limit_star_score := 2 if {
    has_star_column
    input.analysis.has_limit == false
    input.analysis.has_where == true
}
no_limit_star_score := 0 if {
    not has_star_column
}
no_limit_star_score := 0 if {
    input.analysis.has_limit == true
}
no_limit_star_score := 0 if {
    input.analysis.has_where == false
}

# Very high LIMIT: mass data scraping
high_limit_score := 2 if { input.analysis.has_high_limit == true }
high_limit_score := 0 if { input.analysis.has_high_limit == false }

# UNION: data merging across tables, rare in legitimate agent queries
union_score := 2 if { input.analysis.has_union == true }
union_score := 0 if { input.analysis.has_union == false }

# SQL comments: possible injection or intent obfuscation
comment_score := 1 if { input.analysis.has_comment == true }
comment_score := 0 if { input.analysis.has_comment == false }

# ORDER BY RANDOM(): non-deterministic probing
random_order_score := 1 if { input.analysis.has_order_by_random == true }
random_order_score := 0 if { input.analysis.has_order_by_random == false }

# ── Combined risk score ───────────────────────────────────────────────────────

risk_score := s if {
    s := no_where_score + star_score + multi_join_score + sens_score + subq_score +
         no_limit_star_score + high_limit_score + union_score + comment_score + random_order_score
}

# ── Risk level ────────────────────────────────────────────────────────────────

risk_level := "low"    if { risk_score < 4 }
risk_level := "medium" if { risk_score >= 4; risk_score < 7 }
risk_level := "high"   if { risk_score >= 7 }

# ── Final decision ────────────────────────────────────────────────────────────

default allow := false

allow if {
    count(deny) == 0
}
