import json
import os
from typing import List, Optional, Tuple

import sqlglot
from sqlglot import exp

from models import QueryAnalysis

# ── Tenant column (schema-agnostic, B.2.a) ────────────────────────────────────
# Which column carries the tenant id is configurable via the shared schema config
# (policies/schema.json -> schema.tenant_column), the same file OPA and the
# gateway read. Defaults to "tenant_id" when unset, so the demo and most schemas
# need no configuration.
_TENANT_COLUMN = "tenant_id"


def tenant_column() -> str:
    return _TENANT_COLUMN


def set_tenant_column(col: str) -> None:
    global _TENANT_COLUMN
    _TENANT_COLUMN = col or "tenant_id"


def load_schema_config(path: Optional[str] = None) -> None:
    """Load the tenant column from the shared schema config. Non-fatal: the
    analyzer keeps the "tenant_id" default if the file is absent or malformed."""
    path = path or os.getenv("SCHEMA_CONFIG_PATH", "/policies/schema.json")
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        col = (data.get("schema") or {}).get("tenant_column")
        if col:
            set_tenant_column(col)
    except (OSError, ValueError):
        pass

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
    "salary", "income", "bank_account", "account_number", "account_num", "iban", "balance",
    "mrn",
}

# Exact-match PII keywords: catch bare identifiers (e.g. `name`) without
# flagging compound columns that are not personal PII (`merchant_name`,
# `drug_name`, `product_name`, etc.). Substring matching would over-flag.
_PII_KEYWORDS_EXACT = {
    "name",
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
        if isinstance(node, exp.And):
            return check(node.this) and check(node.expression)
        return False

    return check(where_node.this)


def _is_unverifiable_value(node) -> bool:
    """A right-hand value whose actual content is not known at parse time:
    a bind parameter ($1, ?), or current_setting('...'). The filter is recorded
    as *present* (the query does constrain the column) but its value cannot be
    checked by the policy; PostgreSQL RLS is the backstop that enforces the
    real tenant value at the database layer."""
    if isinstance(node, (exp.Parameter, exp.Placeholder)):
        return True
    if isinstance(node, exp.Anonymous) and str(node.this).lower() == "current_setting":
        return True
    return False


def _extract_top_level_filters(where_node: exp.Where) -> Tuple[dict, List[str]]:
    """Walk only top-level AND chains (predicates inside OR or other operators
    are not guaranteed to apply). Returns:
      - equality: {column: literal_value} for `col = 'lit'`, `'lit' = col`, and
        single-value `col IN ('lit')` (value is verifiable by the policy);
      - param_cols: columns constrained by a bind parameter or current_setting
        (present but value not verifiable at parse time).
    Multi-value `IN (...)`, ranges, LIKE, !=, and anything under OR are not
    recorded, so they do not count as a tenant filter."""
    equality: dict = {}
    param_cols: List[str] = []
    seen_param: set = set()

    def _add_param(col: str) -> None:
        c = col.lower()
        if c not in seen_param:
            seen_param.add(c)
            param_cols.append(c)

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
                equality[left.name.lower()] = str(right.this)
            elif isinstance(right, exp.Column) and isinstance(left, exp.Literal) and right.name:
                equality[right.name.lower()] = str(left.this)
            elif isinstance(left, exp.Column) and left.name and _is_unverifiable_value(right):
                _add_param(left.name)
            elif isinstance(right, exp.Column) and right.name and _is_unverifiable_value(left):
                _add_param(right.name)
            return
        if isinstance(node, exp.In):
            col = node.this
            values = node.expressions or []
            # IN (subquery) has no literal expressions -> not a value pin.
            if isinstance(col, exp.Column) and col.name and values and all(
                isinstance(v, exp.Literal) for v in values
            ):
                # A single-value IN pins the column exactly like equality. A
                # multi-value IN does not pin to one tenant, so it is ignored.
                if len(values) == 1:
                    equality[col.name.lower()] = str(values[0].this)
            return

    _walk(where_node.this)
    return equality, param_cols


def _subquery_tables_without_tenant_filter(stmt) -> List[str]:
    """
    Return tables that appear inside a Subquery whose immediate Select WHERE
    lacks a top-level `tenant_id = ...` equality filter. Catches the pattern:
        SELECT id FROM customers WHERE tenant_id='t1'
          AND id IN (SELECT customer_id FROM transactions)
    where the inner SELECT touches a sensitive table without its own tenant
    guard. RLS protects this at runtime; OPA must also catch it as defense in
    depth and so the policy decision is consistent with the threat model.
    """
    out: List[str] = []
    seen: set = set()
    for subq in stmt.find_all(exp.Subquery):
        inner = subq.this
        if not isinstance(inner, exp.Select):
            continue

        inner_where = inner.args.get("where")
        if inner_where is not None:
            inner_eq, inner_params = _extract_top_level_filters(inner_where)
            tcol = tenant_column()
            if tcol in inner_eq or tcol in inner_params:
                continue  # inner SELECT properly scoped (literal or param/current_setting)

        for table_node in inner.find_all(exp.Table):
            if not table_node.name:
                continue
            # Skip tables nested in a deeper Subquery (handled in their own iteration).
            cur = table_node.parent
            inside_nested = False
            while cur is not None and cur is not inner:
                if isinstance(cur, exp.Subquery):
                    inside_nested = True
                    break
                cur = cur.parent
            if inside_nested:
                continue
            name = table_node.name.lower()
            if name not in seen:
                seen.add(name)
                out.append(name)
    return out


def _has_top_level_id_range(where_node) -> bool:
    """True if WHERE has a range/IN/inequality predicate on a PK/FK identifier
    column (`id` or `*_id`, excluding the `tenant_id` multi-tenant
    discriminator) at top-level AND chain. This is the signature of
    batched-dump enumeration (`id BETWEEN 1 AND N`, `customer_id IN
    (1,2,3,...)`), used to trigger `unbounded_pii_iteration`: any query
    that pairs such an identifier-range with PII columns is treated as a
    cumulative-volume attack regardless of how many PII columns it lists.

    Exclusions (to avoid false positives on legitimate analyst queries):
      - ``tenant_id`` is the multi-tenant discriminator, not an enumeration
        target; ``tenant_id IN ('tenant_1')`` or ``tenant_id = current_setting(...)``
        are legitimate row scoping patterns.
      - ``id IN (SELECT ...)`` is correlated analytics, not enumeration. Only
        literal-list IN clauses (`IN (1, 2, 3)`) count as enumeration signals.
    """
    if where_node is None:
        return False
    flag = [False]

    def _is_identifier_column(node) -> bool:
        name = getattr(node, "name", None)
        if not isinstance(name, str):
            return False
        n = name.lower()
        if n == "tenant_id":
            return False
        return n == "id" or n.endswith("_id")

    def _walk(node):
        if node is None or flag[0]:
            return
        if isinstance(node, exp.Paren):
            _walk(node.this)
            return
        if isinstance(node, exp.And):
            _walk(node.this)
            _walk(node.expression)
            return
        if isinstance(node, exp.EQ):
            return
        if isinstance(node, (exp.GT, exp.LT, exp.GTE, exp.LTE, exp.NEQ,
                             exp.Between)):
            if _is_identifier_column(node.this):
                flag[0] = True
            return
        if isinstance(node, exp.In):
            if not _is_identifier_column(node.this):
                return
            # Subquery IN (`id IN (SELECT ...)`) is correlated analytics,
            # not enumeration. Only literal lists count.
            if node.args.get("query") is not None:
                return
            exprs = node.args.get("expressions") or []
            if exprs and all(isinstance(e, exp.Literal) for e in exprs):
                flag[0] = True
            return

    _walk(where_node.this if hasattr(where_node, "this") else where_node)
    return flag[0]


def _compute_query_signature(stmt) -> str:
    """Compute a normalized signature for the query SHAPE.

    Replaces every literal (numeric, string, identifier-bound) with a
    placeholder, then hashes the resulting normalized SQL. Two queries
    with identical structure but different literal values (e.g.
    `WHERE id = 1` vs `WHERE id = 2`) produce the SAME signature.
    The gateway can consume this opaque hash to track repeated query
    shapes across an agent's recent activity.
    """
    import copy
    import hashlib
    try:
        stmt_copy = copy.deepcopy(stmt)
        for lit in list(stmt_copy.find_all(exp.Literal)):
            try:
                lit.replace(exp.Literal.string("?"))
            except Exception:
                continue
        sig_sql = stmt_copy.sql(dialect="postgres")
    except Exception:
        sig_sql = str(stmt)
    return hashlib.md5(sig_sql.encode("utf-8")).hexdigest()[:16]


def _detect_pii_columns(stmt) -> List[str]:
    found: List[str] = []
    seen: set = set()

    def _check(name: str) -> None:
        name = name.lower()
        if name in seen:
            return
        seen.add(name)
        # Exact-match keywords first: catches `name` without flagging
        # `merchant_name`, `drug_name`, etc.
        if name in _PII_KEYWORDS_EXACT:
            for existing in found:
                if existing in name:
                    return
            found.append(name)
            return
        for kw in _PII_KEYWORDS:
            if kw in name:
                # Skip if this name is a superstring of an existing PII entry
                # (e.g. alias `total_balance` containing existing column `balance`).
                # Prevents alias-based double counting on legitimate aggregates
                # like `SUM(balance) AS total_balance` where the underlying column
                # is already flagged.
                for existing in found:
                    if existing in name:
                        return
                found.append(name)
                break

    for col in stmt.find_all(exp.Column):
        if col.name:
            _check(col.name)
    # Catch `SELECT password AS p`: the source node inside an Alias may not be
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

    # UNION detection: unwrap to get the leftmost SELECT for column analysis
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

    # Tables: search recursively through entire statement (covers both sides of UNION)
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

    # Columns from the main (leftmost) SELECT. We track three cases:
    #   1. bare `SELECT *`       -> columns == ["*"], select_star rule should fire
    #   2. aggregate-only SELECTs (`COUNT(*)`, `SUM(col)`, `AVG(col)`, ...) ->
    #      extract the inner column names where possible. Aggregate expressions
    #      must NOT be treated as bare star, so the fallback below is gated.
    #   3. explicit columns or aliases -> the obvious case.
    _AGG_TYPES = (exp.Count, exp.Sum, exp.Avg, exp.Min, exp.Max)
    columns: List[str] = []
    has_explicit_star = False
    saw_aggregate = False
    if isinstance(main_select, exp.Select):
        for sel in main_select.selects:
            # Unwrap an Alias: `SELECT SUM(x) AS total` -> inspect SUM(x).
            inner = sel.this if isinstance(sel, exp.Alias) else sel
            if isinstance(inner, exp.Star):
                has_explicit_star = True
                columns = ["*"]
                break
            if isinstance(inner, _AGG_TYPES):
                saw_aggregate = True
                # Aggregates of the form COUNT(*), SUM(*) - the star inside is
                # an aggregate marker, not a column projection. Skip it.
                arg = inner.this
                if isinstance(arg, exp.Star):
                    continue
                if isinstance(arg, exp.Column) and arg.name:
                    columns.append(arg.name.lower())
                continue
            if isinstance(inner, exp.Column) and inner.name:
                columns.append(inner.name.lower())
                continue
            if isinstance(sel, exp.Alias):
                columns.append(str(sel.alias).lower())
                continue
    # Only fall back to ["*"] when we could not parse any projection AND the
    # query is not an aggregate-only SELECT. Aggregate-only with no inner
    # column (e.g. `COUNT(*)`) legitimately yields an empty columns list and
    # MUST NOT be promoted to `["*"]` because that would trip select_star.
    if not columns and not saw_aggregate and not has_explicit_star:
        columns = ["*"]

    # PII columns: check SELECT columns + WHERE column references + alias sources
    pii_columns = _detect_pii_columns(stmt)
    # Query signature: shape hash for query-repetition detection.
    query_signature = _compute_query_signature(stmt)

    where_node = stmt.find(exp.Where)
    has_where = where_node is not None
    where_is_tautology = _where_is_tautology(where_node) if where_node else False
    if where_node:
        where_equality_filters, where_param_filter_columns = _extract_top_level_filters(where_node)
        has_top_level_id_range = _has_top_level_id_range(where_node)
    else:
        where_equality_filters, where_param_filter_columns = {}, []
        has_top_level_id_range = False

    subquery_tables_without_tenant_filter = _subquery_tables_without_tenant_filter(stmt)

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

    # OFFSET: pagination pattern (LIMIT N OFFSET M), OFFSET 0 excluded (first page)
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
        where_param_filter_columns=where_param_filter_columns,
        subquery_tables_without_tenant_filter=subquery_tables_without_tenant_filter,
        has_top_level_id_range=has_top_level_id_range,
        query_signature=query_signature,
    )
