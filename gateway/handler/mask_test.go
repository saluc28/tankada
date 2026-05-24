package handler

import (
	"reflect"
	"testing"

	"github.com/tankada/gateway/client"
)

func TestApplyMask_RedactsNamedColumns(t *testing.T) {
	res := &client.ExecuteResponse{
		Columns:  []string{"id", "email", "name"},
		Rows:     [][]interface{}{{1, "a@x.com", "Alice"}, {2, "b@x.com", "Bob"}},
		RowCount: 2,
	}
	masked := applyMask(res, []string{"email"}, "***")
	if !reflect.DeepEqual(masked, []string{"email"}) {
		t.Fatalf("masked columns = %v, want [email]", masked)
	}
	for i, row := range res.Rows {
		if row[1] != "***" {
			t.Fatalf("row %d email not masked: %v", i, row[1])
		}
		if row[0] == "***" || row[2] == "***" {
			t.Fatalf("row %d non-PII column wrongly masked: %v", i, row)
		}
	}
}

func TestApplyMask_CaseInsensitive(t *testing.T) {
	res := &client.ExecuteResponse{
		Columns: []string{"Email"},
		Rows:    [][]interface{}{{"a@x.com"}},
	}
	masked := applyMask(res, []string{"email"}, "***")
	if len(masked) != 1 || res.Rows[0][0] != "***" {
		t.Fatalf("case-insensitive match failed: masked=%v rows=%v", masked, res.Rows)
	}
}

func TestApplyMask_DefaultValueWhenEmpty(t *testing.T) {
	res := &client.ExecuteResponse{
		Columns: []string{"ssn"},
		Rows:    [][]interface{}{{"123-45-6789"}},
	}
	applyMask(res, []string{"ssn"}, "")
	if res.Rows[0][0] != "***" {
		t.Fatalf("expected default mask value '***', got %v", res.Rows[0][0])
	}
}

func TestApplyMask_NoMatchingColumn(t *testing.T) {
	res := &client.ExecuteResponse{
		Columns: []string{"id", "name"},
		Rows:    [][]interface{}{{1, "Alice"}},
	}
	masked := applyMask(res, []string{"email"}, "***")
	if masked != nil {
		t.Fatalf("expected nil masked columns, got %v", masked)
	}
	if res.Rows[0][0] != 1 || res.Rows[0][1] != "Alice" {
		t.Fatalf("rows mutated unexpectedly: %v", res.Rows)
	}
}

func TestApplyMask_NilAndEmptyInputs(t *testing.T) {
	if got := applyMask(nil, []string{"email"}, "***"); got != nil {
		t.Fatalf("nil result should return nil, got %v", got)
	}
	res := &client.ExecuteResponse{Columns: []string{"email"}, Rows: [][]interface{}{{"x"}}}
	if got := applyMask(res, nil, "***"); got != nil {
		t.Fatalf("empty maskCols should return nil, got %v", got)
	}
	if res.Rows[0][0] != "x" {
		t.Fatalf("rows mutated when maskCols empty: %v", res.Rows)
	}
}
