package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"time"
)

type AnalysisResult struct {
	QueryType         string   `json:"query_type"`
	Tables            []string `json:"tables"`
	Columns           []string `json:"columns"`
	HasWhere          bool     `json:"has_where"`
	WhereIsTautology  bool     `json:"where_is_tautology"`
	HavingIsTautology bool     `json:"having_is_tautology"`
	JoinCount         int      `json:"join_count"`
	SubqueryCount     int      `json:"subquery_count"`
	CTECount          int      `json:"cte_count"`
	IsAggregation     bool     `json:"is_aggregation"`
	IsWrite           bool     `json:"is_write"`
	// LLM-specific threat patterns
	IsSchemaEnum       bool     `json:"is_schema_enum"`
	HasLimit           bool     `json:"has_limit"`
	LimitValue         *int     `json:"limit_value"`
	HasHighLimit       bool     `json:"has_high_limit"`
	PIIColumns         []string `json:"pii_columns"`
	AccessesPIIColumns bool     `json:"accesses_pii_columns"`
	HasComment         bool     `json:"has_comment"`
	HasUnion           bool     `json:"has_union"`
	HasOrderByRandom   bool     `json:"has_order_by_random"`
	MultiStatement     bool     `json:"multi_statement"`
	ParseError         string   `json:"parse_error,omitempty"`
	HasOffset          bool     `json:"has_offset"`
	// Column → literal value, populated only for predicates joined by top-level AND in WHERE.
	// Consumed by OPA for tenant-isolation enforcement.
	WhereEqualityFilters map[string]string `json:"where_equality_filters"`
	// Columns filtered by a bind parameter or current_setting at the top level of
	// WHERE (B.2.a). Present but value-unverifiable; OPA accepts them for tenant
	// isolation and RLS enforces the value. Must be carried here or it never
	// reaches OPA (same data-layout class as BUG-001).
	WhereParamFilterColumns []string `json:"where_param_filter_columns"`
	// Tables inside a Subquery whose own WHERE lacks a top-level tenant_id filter.
	// Consumed by OPA's subquery tenant-isolation rule. Must be present here or the
	// field never reaches OPA and the rule is a silent no-op (regression: BUG-001).
	SubqueryTablesWithoutTenantFilter []string `json:"subquery_tables_without_tenant_filter"`
	// True when WHERE has a range/IN/inequality predicate on `id` or `*_id`
	// at top-level AND chain. Consumed by OPA's unbounded_pii_iteration rule:
	// when paired with at least one PII column, denies batched-dump
	// enumeration (T25-style cumulative-volume attacks).
	HasTopLevelIDRange bool `json:"has_top_level_id_range"`
	// Normalized SQL shape hash. Identical query shape modulo literal
	// values yields the same signature. Available for the gateway to
	// track repeated query shapes across an agent's recent activity.
	QuerySignature string `json:"query_signature"`
}

type AnalyzerClient struct {
	baseURL string
	http    *http.Client
	cache   *analysisCache
}

func NewAnalyzer(baseURL string) *AnalyzerClient {
	return &AnalyzerClient{
		baseURL: baseURL,
		http:    sharedHTTPClient(5 * time.Second),
		cache:   newAnalysisCache(analyzerCacheSize()),
	}
}

// defaultAnalyzerCacheSize is the number of distinct queries whose analysis is
// kept in the per-client LRU cache. Override with ANALYZER_CACHE_SIZE; set it to
// 0 to disable caching entirely.
const defaultAnalyzerCacheSize = 1024

func analyzerCacheSize() int {
	if v := os.Getenv("ANALYZER_CACHE_SIZE"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			return n
		}
	}
	return defaultAnalyzerCacheSize
}

func (c *AnalyzerClient) Analyze(ctx context.Context, query string) (*AnalysisResult, error) {
	if cached, ok := c.cache.get(query); ok {
		return cached, nil
	}

	body, _ := json.Marshal(map[string]string{"query": query})

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/analyze", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("analyzer unreachable: %w", err)
	}
	// Drain before close so the keep-alive connection can be reused.
	defer func() {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("analyzer returned %d", resp.StatusCode)
	}

	var result AnalysisResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("analyzer response decode: %w", err)
	}
	c.cache.put(query, &result)
	return &result, nil
}
