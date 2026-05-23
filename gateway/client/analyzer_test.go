package client

import (
	"encoding/json"
	"strings"
	"testing"
)

// Regression test: the analyzer computes fields (subquery_tables_without_tenant_filter,
// having_is_tautology) that OPA policy rules consume. AnalysisResult is the struct that
// carries the analyzer response and is then marshalled into the OPA input
// (OPAInput.Analysis). If a field the policy reads is missing from this struct, it is
// silently dropped before reaching OPA and the corresponding rule becomes a no-op. The
// OPA unit tests cannot catch this because they inject the field directly into the input.
//
// This test guards the contract end to end: an analyzer-shaped response must decode into
// AnalysisResult AND re-marshal (as sent to OPA) with the keys still present.
func TestAnalysisResult_ForwardsOPAConsumedFields(t *testing.T) {
	// Mirrors the shape produced by analyzer/main.py for a query like:
	//   SELECT id FROM customers WHERE tenant_id='t1'
	//     AND id IN (SELECT customer_id FROM transactions)
	//   ... GROUP BY id HAVING 1=1
	raw := `{
		"query_type": "SELECT",
		"tables": ["customers"],
		"where_equality_filters": {"tenant_id": "tenant_1"},
		"subquery_tables_without_tenant_filter": ["transactions"],
		"having_is_tautology": true
	}`

	var ar AnalysisResult
	if err := json.Unmarshal([]byte(raw), &ar); err != nil {
		t.Fatalf("decode analyzer response: %v", err)
	}

	if len(ar.SubqueryTablesWithoutTenantFilter) != 1 || ar.SubqueryTablesWithoutTenantFilter[0] != "transactions" {
		t.Fatalf("subquery_tables_without_tenant_filter not decoded into struct: %+v", ar.SubqueryTablesWithoutTenantFilter)
	}
	if !ar.HavingIsTautology {
		t.Fatal("having_is_tautology not decoded into struct")
	}

	// The struct is what query.go puts in OPAInput.Analysis. Marshalling the OPA input
	// MUST still carry the keys the Rego policy reads.
	out, err := json.Marshal(OPAInput{Analysis: &ar})
	if err != nil {
		t.Fatalf("marshal OPA input: %v", err)
	}
	for _, key := range []string{"subquery_tables_without_tenant_filter", "having_is_tautology"} {
		if !strings.Contains(string(out), key) {
			t.Fatalf("OPA input is missing %q: field dropped by AnalysisResult", key)
		}
	}
}
