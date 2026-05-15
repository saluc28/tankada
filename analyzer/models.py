from pydantic import BaseModel, Field
from typing import Dict, List, Optional


class AnalyzeRequest(BaseModel):
    query: str


class QueryAnalysis(BaseModel):
    query_type: str
    tables: List[str]
    columns: List[str]
    has_where: bool
    where_is_tautology: bool = False
    having_is_tautology: bool = False
    join_count: int
    subquery_count: int
    cte_count: int
    is_aggregation: bool
    is_write: bool
    # Schema enumeration
    is_schema_enum: bool = False
    # LIMIT
    has_limit: bool = False
    limit_value: Optional[int] = None
    has_high_limit: bool = False  # limit_value > 500
    # PII column names detected in SELECT or WHERE
    pii_columns: List[str] = []
    accesses_pii_columns: bool = False  # True if pii_columns is non-empty
    # Structural flags
    has_comment: bool = False      # raw SQL contains -- or /*
    has_union: bool = False
    has_order_by_random: bool = False
    multi_statement: bool = False  # multiple statements in a single call (SQL injection chain)
    has_offset: bool = False       # LIMIT ... OFFSET ... pagination pattern
    # column → literal value, only for predicates joined by top-level AND in WHERE.
    # Used by OPA for tenant-isolation enforcement.
    where_equality_filters: Dict[str, str] = Field(default_factory=dict)
    # Tables that appear inside a Subquery whose own WHERE lacks a top-level
    # tenant_id equality filter. OPA denies any sensitive table in this list.
    subquery_tables_without_tenant_filter: List[str] = []
    parse_error: Optional[str] = None
