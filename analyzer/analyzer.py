from typing import List, Optional

import sqlglot
from sqlglot import exp

from models import QueryAnalysis

WRITE_TYPES = {"INSERT", "UPDATE", "DELETE", "DROP", "TRUNCATE", "ALTER", "CREATE"}

_TYPE_MAP = {
    "Select": "SELECT",
    "Insert": "INSERT",
    "Update": "UPDATE",
    "Delete": "DELETE",
    "Drop": "DROP",
    "Create": "CREATE",
    "Alter": "ALTER",
    "Command": "COMMAND",
}

_KNOWN_STMT_TYPES = set(_TYPE_MAP.values())

# Tables that indicate schema reconnaissance
_SCHEMA_ENUM_NAMES = {
    "information_schema", "pg_tables", "pg_columns", "pg_namespace",
    "pg_class", "pg_attribute", "pg_views", "pg_indexes",
    "pg_stat_user_tables", "sqlite_master", "sqlite_schema",
    "sysobjects", "syscolumns",
}
_SCHEMA_ENUM_DBS = {"information_schema", "pg_catalog"}

# Column name substrings that signal PII
_PII_KEYWORDS = {
    "email", "mail", "ssn", "social_security", "phone", "mobile",
    "password", "passwd", "pwd", "secret", "token", "api_key", "apikey",
    "credit_card", "card_number", "card_num", "cvv", "cvc",
    "dob", "date_of_birth", "birthdate", "birth_date",
    "address", "zip", "postal_code", "passport", "license",
    "salary", "income", "bank_account", "iban",
}

HIGH_LIMIT_THRESHOLD = 500


def _primitive_tautology(expr) -> bool:
    if expr is None:
        return False
    if isinstance(expr, exp.Boolean) and expr.this is True:
        return True
    if isinstance(expr, exp.EQ):
        left, right = expr.this, expr.expression
        if (isinstance(left, exp.Literal) and isinstance(right, exp.Literal)
                and left.this == right.this
                and left.is_string == right.is_string):
            return True
        if (isinstance(left, exp.Column) and isinstance(right, exp.Column)
                and str(left).lower() == str(right).lower()):
            return True
    if isinstance(expr, exp.Is):
        if isinstance(expr.this, exp.Null) and isinstance(expr.expression, exp.Null):
            return True
    return False


def _where_is_tautology(where_node) -> bool:
    def check(node) -> bool:
        if node is None:
            return False
        if isinstance(node, exp.Paren):
            return check(node.this)
        if _primitive_tautology(node):
            return True
        if isinstance(node, exp.Or):
            return check(node.this) or check(node.expression)
        return False

    return check(where_node.this)


def _extract_top_level_equality_filters(where_node: exp.Where) -> dict:
    # Walk only top-level AND chains: predicates inside OR or other operators
    # are not guaranteed to apply, so they must not be reported as enforced filters.
    filters: dict = {}

    def _walk(node) -> None:
        if node is None:
            return
        if isinstance(node, exp.Paren):
            _walk(node.this)
            return
        if isinstance(node, exp.And):
            _walk(node.this)
            _walk(node.expression)
            return
        if isinstance(node, exp.EQ):
            left, right = node.this, node.expression
            if isinstance(left, exp.Column) and isinstance(right, exp.Literal) and left.name:
                filters[left.name.lower()] = str(right.this)
            elif isinstance(right, exp.Column) and isinstance(left, exp.Literal) and right.name:
                filters[right.name.lower()] = str(left.this)

    _walk(where_node.this)
    return filters


def _detect_pii_columns(stmt) -> List[str]:
    found: List[str] = []
    seen: set = set()

    def _check(name: str) -> None:
        name = name.lower()
        if name in seen:
            return
        seen.add(name)
        for kw in _PII_KEYWORDS:
            if kw in name:
                found.append(name)
                break

    for col in stmt.find_all(exp.Column):
        if col.name:
            _check(col.name)
    # Catch `SELECT password AS p` — the source node inside an Alias may not be
    # an exp.Column if sqlglot omits the Column wrapper for bare identifiers.
    for alias_node in stmt.find_all(exp.Alias):
        src = alias_node.this
        if hasattr(src, "name") and src.name:
            _check(src.name)
        if alias_node.alias:
            _check(alias_node.alias)

    return found


def analyze(sql: str) -> QueryAnalysis:
    # Comment detection must happen on raw SQL before parsing strips them
    has_comment = "--" in sql or "/*" in sql

    try:
        statements = sqlglot.parse(sql.strip(), dialect="postgres")
    except Exception as e:
        return QueryAnalysis(
            query_type="UNKNOWN",
            tables=[], columns=[], has_where=False,
            join_count=0, subquery_count=0, cte_count=0,
            is_aggregation=False, is_write=True,
            has_comment=has_comment,
            parse_error=f"parse failed: {e}",
        )

    if not statements or statements[0] is None:
        return QueryAnalysis(
            query_type="UNKNOWN",
            tables=[], columns=[], has_where=False,
            join_count=0, subquery_count=0, cte_count=0,
            is_aggregation=False, is_write=True,
            has_comment=has_comment,
            parse_error="empty or unparseable statement",
        )

    multi_statement = len([s for s in statements if s is not None]) > 1
    stmt = statements[0]

    # UNION detection — unwrap to get the leftmost SELECT for column analysis
    has_union = isinstance(stmt, (exp.Union, exp.Intersect, exp.Except))
    main_select = stmt
    if has_union:
        while isinstance(main_select, (exp.Union, exp.Intersect, exp.Except)):
            main_select = main_select.this

    node_type = type(main_select).__name__
    query_type = _TYPE_MAP.get(node_type, node_type.upper())

    if query_type not in _KNOWN_STMT_TYPES:
        return QueryAnalysis(
            query_type="UNKNOWN",
            tables=[], columns=[], has_where=False,
            join_count=0, subquery_count=0, cte_count=0,
            is_aggregation=False, is_write=False,
            has_comment=has_comment,
            parse_error=f"unrecognized statement type: {node_type}",
        )

    # Tables — search recursively through entire statement (covers both sides of UNION)
    all_tables = list(stmt.find_all(exp.Table))

    tables = list({
        t.name.lower()
        for t in all_tables
        if t.name and not isinstance(t.parent, exp.Subquery)
    })

    # Schema enumeration: table name or schema prefix matches known system catalogs
    is_schema_enum = any(
        t.name.lower() in _SCHEMA_ENUM_NAMES
        or (t.db or "").lower() in _SCHEMA_ENUM_DBS
        or t.name.lower().startswith("pg_")
        for t in all_tables
    )

    # Columns from the main (leftmost) SELECT
    columns: List[str] = []
    if isinstance(main_select, exp.Select):
        for sel in main_select.selects:
            if isinstance(sel, exp.Star):
                columns = ["*"]
                break
            elif isinstance(sel, exp.Column) and sel.name:
                columns.append(sel.name.lower())
            elif isinstance(sel, exp.Alias):
                columns.append(str(sel.alias).lower())
    if not columns:
        columns = ["*"]

    # PII columns — check SELECT columns + WHERE column references + alias sources
    pii_columns = _detect_pii_columns(stmt)

    where_node = stmt.find(exp.Where)
    has_where = where_node is not None
    where_is_tautology = _where_is_tautology(where_node) if where_node else False
    where_equality_filters = _extract_top_level_equality_filters(where_node) if where_node else {}

    having_node = stmt.find(exp.Having)
    having_is_tautology = _where_is_tautology(having_node) if having_node else False

    join_count = len(list(stmt.find_all(exp.Join)))
    subquery_count = len(list(stmt.find_all(exp.Subquery)))
    cte_count = len(list(stmt.find_all(exp.CTE)))

    agg_nodes = (exp.Count, exp.Sum, exp.Avg, exp.Max, exp.Min)
    is_aggregation = (
        stmt.find(exp.Group) is not None
        or stmt.find(*agg_nodes) is not None
    )

    # LIMIT
    limit_node = stmt.find(exp.Limit)
    has_limit = limit_node is not None
    limit_value: Optional[int] = None
    if limit_node:
        lit = limit_node.find(exp.Literal)
        if lit:
            try:
                limit_value = int(lit.this)
            except (ValueError, TypeError):
                pass
    has_high_limit = limit_value is not None and limit_value > HIGH_LIMIT_THRESHOLD

    # ORDER BY RANDOM()
    order_node = stmt.find(exp.Order)
    has_order_by_random = False
    if order_node:
        has_order_by_random = order_node.find(exp.Rand) is not None
        if not has_order_by_random:
            for anon in order_node.find_all(exp.Anonymous):
                if str(anon.this).lower() in ("random", "rand", "newid"):
                    has_order_by_random = True
                    break

    # OFFSET — pagination pattern (LIMIT N OFFSET M), OFFSET 0 excluded (first page)
    offset_node = stmt.find(exp.Offset)
    if offset_node is None:
        has_offset = False
    else:
        offset_val = offset_node.expression
        if isinstance(offset_val, exp.Literal) and not offset_val.is_string:
            has_offset = float(offset_val.this) > 0
        else:
            has_offset = True

    return QueryAnalysis(
        query_type=query_type,
        tables=tables,
        columns=columns,
        has_where=has_where,
        where_is_tautology=where_is_tautology,
        having_is_tautology=having_is_tautology,
        join_count=join_count,
        subquery_count=subquery_count,
        cte_count=cte_count,
        is_aggregation=is_aggregation,
        is_write=query_type in WRITE_TYPES,
        is_schema_enum=is_schema_enum,
        has_limit=has_limit,
        limit_value=limit_value,
        has_high_limit=has_high_limit,
        pii_columns=pii_columns,
        accesses_pii_columns=len(pii_columns) > 0,
        has_comment=has_comment,
        has_union=has_union,
        has_order_by_random=has_order_by_random,
        multi_statement=multi_statement,
        has_offset=has_offset,
        where_equality_filters=where_equality_filters,
    )
