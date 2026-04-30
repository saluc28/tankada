package tankada.query

sensitive_tables = {"users", "payments", "credentials", "secrets", "pii_data", "audit_logs"}

# Tables without a tenant_id column — exempt from the tenant-isolation filter check.
# Update this list when the schema evolves.
tenant_global_tables = {"products"}

# ── Absolute denies ───────────────────────────────────────────────────────────

deny[reason] {
    input.analysis.query_type == "DELETE"
    reason := "destructive operation DELETE is not allowed"
}

deny[reason] {
    input.analysis.query_type == "DROP"
    reason := "destructive operation DROP is not allowed"
}

deny[reason] {
    input.analysis.query_type == "TRUNCATE"
    reason := "destructive operation TRUNCATE is not allowed"
}

deny[reason] {
    input.analysis.query_type == "ALTER"
    reason := "destructive operation ALTER is not allowed"
}

deny[reason] {
    input.analysis.parse_error != ""
    reason := sprintf("query parse failed: %v", [input.analysis.parse_error])
}

# ── LLM-specific hard denies ──────────────────────────────────────────────────

deny[reason] {
    input.analysis.multi_statement == true
    reason := "multi-statement query blocked: SQL injection chain pattern detected"
}

deny[reason] {
    input.analysis.is_schema_enum == true
    reason := "schema enumeration query blocked (agent reconnaissance pattern)"
}

deny[reason] {
    count(input.analysis.pii_columns) > 0
    not agent_has_scope
    reason := sprintf("query accesses PII columns %v without elevated scope", [input.analysis.pii_columns])
}

# ── Tenant isolation ──────────────────────────────────────────────────────────
# Every SELECT touching a tenant-scoped table must carry a top-level AND filter
# `tenant_id = <agent's JWT tenant>`. Prevents cross-tenant access by a malicious
# or buggy agent that crafts a query with the wrong tenant_id.

deny[reason] {
    input.analysis.query_type == "SELECT"
    query_touches_tenant_scoped_table
    not has_matching_tenant_filter
    reason := sprintf("query must filter by tenant_id = '%v' on tenant-scoped tables (agent's tenant from JWT)", [input.agent.tenant_id])
}

query_touches_tenant_scoped_table {
    tbl := input.analysis.tables[_]
    not tenant_global_tables[tbl]
}

has_matching_tenant_filter {
    input.analysis.where_equality_filters.tenant_id == input.agent.tenant_id
}

# ── Contextual denies ─────────────────────────────────────────────────────────

deny[reason] {
    input.analysis.query_type == "SELECT"
    input.analysis.has_where == false
    count(input.analysis.tables) > 0
    reason := "SELECT without WHERE clause on a named table"
}

deny[reason] {
    tbl := input.analysis.tables[_]
    sensitive_tables[tbl]
    not agent_has_scope
    reason := sprintf("access to sensitive table '%v' requires elevated scope", [tbl])
}

deny[reason] {
    risk_score >= 7
    reason := sprintf("risk score %v exceeds threshold (7)", [risk_score])
}

deny[reason] {
    input.analysis.query_type == "SELECT"
    input.analysis.has_where == true
    input.analysis.where_is_tautology == true
    reason := "WHERE clause is a tautology (e.g. 1=1)"
}

# ── Scope check ───────────────────────────────────────────────────────────────

agent_has_scope {
    input.agent.roles[_] == "admin"
}

agent_has_scope {
    input.agent.scopes[_] == "users:read"
}

agent_has_scope {
    input.agent.scopes[_] == "payments:read"
}

# ── Per-query risk scoring ────────────────────────────────────────────────────

no_where_score = 3 { input.analysis.has_where == false }
no_where_score = 0 { input.analysis.has_where == true }

has_star_column { input.analysis.columns[_] == "*" }

star_score = 2 { has_star_column }
star_score = 0 { not has_star_column }

multi_join_score = 2 { input.analysis.join_count > 1 }
multi_join_score = 0 { input.analysis.join_count <= 1 }

sens_score = 3 { tbl := input.analysis.tables[_]; sensitive_tables[tbl] }
sens_score = 0 { not any_sensitive_table }

any_sensitive_table {
    tbl := input.analysis.tables[_]
    sensitive_tables[tbl]
}

subq_score = 1 { input.analysis.subquery_count > 2 }
subq_score = 0 { input.analysis.subquery_count <= 2 }

# SELECT * with no LIMIT: unbounded data extraction
no_limit_star_score = 2 {
    has_star_column
    input.analysis.has_limit == false
    input.analysis.has_where == true
}
no_limit_star_score = 0 {
    not has_star_column
}
no_limit_star_score = 0 {
    input.analysis.has_limit == true
}
no_limit_star_score = 0 {
    input.analysis.has_where == false
}

# Very high LIMIT: mass data scraping
high_limit_score = 2 { input.analysis.has_high_limit == true }
high_limit_score = 0 { input.analysis.has_high_limit == false }

# UNION: data merging across tables, rare in legitimate agent queries
union_score = 2 { input.analysis.has_union == true }
union_score = 0 { input.analysis.has_union == false }

# SQL comments: possible injection or intent obfuscation
comment_score = 1 { input.analysis.has_comment == true }
comment_score = 0 { input.analysis.has_comment == false }

# ORDER BY RANDOM(): non-deterministic probing
random_order_score = 1 { input.analysis.has_order_by_random == true }
random_order_score = 0 { input.analysis.has_order_by_random == false }

# ── Combined risk score ───────────────────────────────────────────────────────

risk_score = s {
    s := no_where_score + star_score + multi_join_score + sens_score + subq_score +
         no_limit_star_score + high_limit_score + union_score + comment_score + random_order_score
}

# ── Risk level ────────────────────────────────────────────────────────────────

risk_level = "low"    { risk_score < 4 }
risk_level = "medium" { risk_score >= 4; risk_score < 7 }
risk_level = "high"   { risk_score >= 7 }

# ── Final decision ────────────────────────────────────────────────────────────

default allow = false

allow {
    count(deny) == 0
}
