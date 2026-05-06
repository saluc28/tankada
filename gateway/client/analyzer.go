package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type AnalysisResult struct {
	QueryType        string   `json:"query_type"`
	Tables           []string `json:"tables"`
	Columns          []string `json:"columns"`
	HasWhere         bool     `json:"has_where"`
	WhereIsTautology bool     `json:"where_is_tautology"`
	JoinCount        int      `json:"join_count"`
	SubqueryCount    int      `json:"subquery_count"`
	CTECount         int      `json:"cte_count"`
	IsAggregation    bool     `json:"is_aggregation"`
	IsWrite          bool     `json:"is_write"`
	IsSchemaEnum     bool     `json:"is_schema_enum"`
	HasLimit         bool     `json:"has_limit"`
	LimitValue       *int     `json:"limit_value"`
	HasHighLimit     bool     `json:"has_high_limit"`
	PIIColumns           []string `json:"pii_columns"`
	AccessesPIIColumns   bool     `json:"accesses_pii_columns"`
	HasComment           bool     `json:"has_comment"`
	HasUnion         bool     `json:"has_union"`
	HasOrderByRandom bool     `json:"has_order_by_random"`
	MultiStatement   bool     `json:"multi_statement"`
	ParseError       string   `json:"parse_error"`
	// Column → literal value, populated only for predicates joined by top-level AND in WHERE.
	// Consumed by OPA for tenant-isolation enforcement.
	WhereEqualityFilters map[string]string `json:"where_equality_filters"`
}

type AnalyzerClient struct {
	baseURL string
	http    *http.Client
}

func NewAnalyzer(baseURL string) *AnalyzerClient {
	return &AnalyzerClient{
		baseURL: baseURL,
		http:    &http.Client{Timeout: 5 * time.Second},
	}
}

func (c *AnalyzerClient) Analyze(ctx context.Context, query string) (*AnalysisResult, error) {
	body, _ := json.Marshal(map[string]string{"query": query})

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.baseURL+"/analyze", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("analyzer unreachable: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("analyzer returned %d", resp.StatusCode)
	}

	var result AnalysisResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("analyzer response decode: %w", err)
	}
	return &result, nil
}
