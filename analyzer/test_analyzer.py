"""
Tankada Analyzer test suite
Run: pytest test_analyzer.py -v
"""
import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from analyzer import analyze


# ── helpers ───────────────────────────────────────────────────────────────────

def a(sql):
    return analyze(sql)


# ── query type ────────────────────────────────────────────────────────────────

def test_query_type_select():
    assert a("SELECT id FROM products WHERE id = 1").query_type == "SELECT"

def test_query_type_insert():
    assert a("INSERT INTO products (name) VALUES ('x')").query_type == "INSERT"

def test_query_type_update():
    assert a("UPDATE products SET name = 'x' WHERE id = 1").query_type == "UPDATE"

def test_query_type_delete():
    assert a("DELETE FROM products WHERE id = 1").query_type == "DELETE"

def test_query_type_drop():
    assert a("DROP TABLE products").query_type == "DROP"


# ── tautology detection ───────────────────────────────────────────────────────

def test_tautology_1_eq_1():
    assert a("SELECT id FROM products WHERE 1=1").where_is_tautology is True

def test_tautology_true():
    assert a("SELECT id FROM products WHERE true").where_is_tautology is True

def test_tautology_or():
    assert a("SELECT id FROM products WHERE id > 0 OR 1=1").where_is_tautology is True

def test_tautology_col_eq_col():
    assert a("SELECT id FROM products WHERE id = id").where_is_tautology is True

def test_tautology_string():
    assert a("SELECT id FROM products WHERE 'x'='x'").where_is_tautology is True

def test_no_tautology_normal():
    assert a("SELECT id FROM products WHERE id = 1").where_is_tautology is False

def test_no_tautology_and():
    # AND(1=1, condition) still filters, not flagged
    assert a("SELECT id FROM products WHERE 1=1 AND id = 1").where_is_tautology is False

def test_tautology_paren():
    assert a("SELECT id FROM products WHERE (1=1)").where_is_tautology is True

def test_tautology_paren_or():
    assert a("SELECT id FROM products WHERE (TRUE OR id = 1)").where_is_tautology is True


# ── WHERE clause ──────────────────────────────────────────────────────────────

def test_has_where_true():
    assert a("SELECT id FROM products WHERE id = 1").has_where is True

def test_has_where_false():
    assert a("SELECT id FROM products").has_where is False


# ── SELECT * ──────────────────────────────────────────────────────────────────

def test_star_columns():
    assert a("SELECT * FROM products WHERE id = 1").columns == ["*"]

def test_specific_columns():
    result = a("SELECT id, name FROM products WHERE id = 1")
    assert "id" in result.columns
    assert "name" in result.columns
    assert "*" not in result.columns


# ── schema enumeration ────────────────────────────────────────────────────────

def test_schema_enum_information_schema():
    assert a("SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'").is_schema_enum is True

def test_schema_enum_pg_tables():
    assert a("SELECT * FROM pg_tables WHERE schemaname = 'public'").is_schema_enum is True

def test_schema_enum_pg_catalog():
    assert a("SELECT column_name FROM pg_catalog.pg_attribute WHERE attrelid = 1").is_schema_enum is True

def test_no_schema_enum_normal():
    assert a("SELECT id FROM products WHERE id = 1").is_schema_enum is False


# ── PII column detection ──────────────────────────────────────────────────────

def test_pii_email():
    assert "email" in a("SELECT id, email FROM users WHERE id = 1").pii_columns

def test_pii_password():
    assert "password" in a("SELECT id, password FROM users WHERE id = 1").pii_columns

def test_pii_multiple():
    result = a("SELECT email, password, ssn FROM users WHERE id = 1")
    assert "email" in result.pii_columns
    assert "password" in result.pii_columns
    assert "ssn" in result.pii_columns

def test_pii_in_where():
    # PII keyword in WHERE clause column should also be detected
    result = a("SELECT id FROM users WHERE email = 'test@test.com'")
    assert "email" in result.pii_columns

def test_pii_alias_bypass():
    # SELECT password AS p should still flag PII: alias does not hide the source column
    assert "password" in a("SELECT id, password AS p FROM users WHERE id = 1").pii_columns

def test_pii_alias_email():
    assert "email" in a("SELECT email AS contact FROM users WHERE id = 1").pii_columns

def test_pii_alias_reverse():
    # SELECT p AS password: alias is the PII keyword, source column name is not
    assert "password" in a("SELECT p AS password FROM users WHERE id = 1").pii_columns

def test_no_pii_normal():
    assert a("SELECT id, name, price FROM products WHERE id = 1").pii_columns == []

def test_accesses_pii_columns_true():
    assert a("SELECT id, email FROM users WHERE id = 1").accesses_pii_columns is True

def test_accesses_pii_columns_false():
    assert a("SELECT id, name FROM products WHERE id = 1").accesses_pii_columns is False

def test_accesses_pii_columns_consistent_with_pii_columns():
    result = a("SELECT email, password FROM users WHERE id = 1")
    assert result.accesses_pii_columns is (len(result.pii_columns) > 0)


# ── LIMIT detection ───────────────────────────────────────────────────────────

def test_has_limit():
    assert a("SELECT id FROM products WHERE id > 0 LIMIT 10").has_limit is True

def test_no_limit():
    assert a("SELECT id FROM products WHERE id > 0").has_limit is False

def test_limit_value():
    assert a("SELECT id FROM products WHERE id > 0 LIMIT 42").limit_value == 42

def test_high_limit():
    assert a("SELECT * FROM orders WHERE status = 'open' LIMIT 1000").has_high_limit is True

def test_not_high_limit():
    assert a("SELECT * FROM orders WHERE status = 'open' LIMIT 10").has_high_limit is False

def test_limit_threshold_boundary():
    assert a("SELECT id FROM products WHERE id > 0 LIMIT 500").has_high_limit is False
    assert a("SELECT id FROM products WHERE id > 0 LIMIT 501").has_high_limit is True


# ── UNION detection ───────────────────────────────────────────────────────────

def test_union():
    assert a("SELECT name FROM products WHERE id > 0 UNION SELECT password FROM users WHERE id > 0").has_union is True

def test_union_all():
    assert a("SELECT name FROM products WHERE id = 1 UNION ALL SELECT name FROM orders WHERE id = 1").has_union is True

def test_no_union():
    assert a("SELECT id FROM products WHERE id = 1").has_union is False


# ── ORDER BY RANDOM ───────────────────────────────────────────────────────────

def test_order_by_random():
    assert a("SELECT id FROM products WHERE id > 0 ORDER BY RANDOM()").has_order_by_random is True

def test_no_order_by_random():
    assert a("SELECT id FROM products WHERE id > 0 ORDER BY id").has_order_by_random is False


# ── comment detection ─────────────────────────────────────────────────────────

def test_comment_inline():
    assert a("SELECT id FROM products WHERE id = 1 -- bypass").has_comment is True

def test_comment_block():
    assert a("SELECT id FROM products /* comment */ WHERE id = 1").has_comment is True

def test_no_comment():
    assert a("SELECT id FROM products WHERE id = 1").has_comment is False


# ── write operations ──────────────────────────────────────────────────────────

def test_is_write_delete():
    assert a("DELETE FROM products WHERE id = 1").is_write is True

def test_is_write_insert():
    assert a("INSERT INTO products (name) VALUES ('x')").is_write is True

def test_is_not_write_select():
    assert a("SELECT id FROM products WHERE id = 1").is_write is False


# ── parse error ───────────────────────────────────────────────────────────────

def test_parse_error_invalid_sql():
    result = a("SELEKT * FORM products")
    assert result.parse_error is not None

def test_empty_query():
    result = a("")
    assert result.parse_error is not None


# ── multi-statement detection ─────────────────────────────────────────────────

def test_multi_statement_select_drop():
    result = a("SELECT id FROM products WHERE id = 1; DROP TABLE products")
    assert result.multi_statement is True

def test_multi_statement_select_delete():
    result = a("SELECT id FROM users WHERE id = 1; DELETE FROM users WHERE 1=1")
    assert result.multi_statement is True

def test_single_statement_no_flag():
    assert a("SELECT id FROM products WHERE id = 1").multi_statement is False


# ── join and subquery counts ──────────────────────────────────────────────────

def test_join_count():
    result = a("SELECT o.id, u.name FROM orders o JOIN users u ON o.user_id = u.id WHERE o.status = 'open'")
    assert result.join_count == 1

def test_subquery_count():
    result = a("SELECT id FROM products WHERE id IN (SELECT product_id FROM orders WHERE status = 'open')")
    assert result.subquery_count == 1

def test_tables_extracted():
    result = a("SELECT id FROM products WHERE id = 1")
    assert "products" in result.tables


# ── where equality filters (tenant isolation) ────────────────────────────────

def test_eq_filter_simple():
    r = a("SELECT id FROM orders WHERE tenant_id = 'tenant_1'")
    assert r.where_equality_filters == {"tenant_id": "tenant_1"}

def test_eq_filter_top_level_and():
    r = a("SELECT id FROM orders WHERE tenant_id = 'tenant_1' AND status = 'open'")
    assert r.where_equality_filters == {"tenant_id": "tenant_1", "status": "open"}

def test_eq_filter_literal_on_left():
    r = a("SELECT id FROM orders WHERE 'tenant_1' = tenant_id")
    assert r.where_equality_filters.get("tenant_id") == "tenant_1"

def test_eq_filter_or_not_extracted():
    # OR does not enforce the filter on every row, must NOT be extracted.
    r = a("SELECT id FROM orders WHERE tenant_id = 'tenant_1' OR status = 'open'")
    assert r.where_equality_filters == {}

def test_eq_filter_no_where():
    r = a("SELECT id FROM products")
    assert r.where_equality_filters == {}

def test_eq_filter_non_equality_ignored():
    # Range and inequality predicates are not enforced equality filters.
    r = a("SELECT id FROM orders WHERE tenant_id = 'tenant_1' AND amount > 100")
    assert r.where_equality_filters == {"tenant_id": "tenant_1"}

def test_eq_filter_nested_and():
    r = a("SELECT id FROM orders WHERE (tenant_id = 'tenant_1' AND status = 'open') AND user_id = 'u1'")
    assert r.where_equality_filters == {
        "tenant_id": "tenant_1",
        "status": "open",
        "user_id": "u1",
    }


# ── offset / pagination ───────────────────────────────────────────────────────

def test_offset_detected():
    r = a("SELECT id, email FROM users LIMIT 10 OFFSET 20")
    assert r.has_offset is True

def test_offset_with_limit_zero():
    r = a("SELECT id FROM orders LIMIT 10 OFFSET 0")
    assert r.has_offset is False

def test_no_offset_plain_limit():
    r = a("SELECT id FROM products WHERE id = 1 LIMIT 10")
    assert r.has_offset is False

def test_no_offset_no_limit():
    r = a("SELECT id FROM products WHERE id = 1")
    assert r.has_offset is False


# ── HAVING tautology ──────────────────────────────────────────────────────────

def test_having_tautology():
    assert a("SELECT status, COUNT(*) FROM orders GROUP BY status HAVING 1=1").having_is_tautology is True

def test_having_tautology_true():
    assert a("SELECT status, COUNT(*) FROM orders GROUP BY status HAVING TRUE").having_is_tautology is True

def test_no_having_tautology():
    assert a("SELECT status, COUNT(*) FROM orders GROUP BY status HAVING COUNT(*) > 5").having_is_tautology is False

def test_no_having_no_flag():
    assert a("SELECT id FROM products WHERE id = 1").having_is_tautology is False
