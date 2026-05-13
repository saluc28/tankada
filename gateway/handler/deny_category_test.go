package handler

import (
	"reflect"
	"testing"
)

func TestCategorize_AllKnownPrefixes(t *testing.T) {
	cases := []struct {
		name   string
		reason string
		want   string
	}{
		{"rate limit", "rate limit exceeded: too many queries per minute", CatRateLimit},
		{"analyzer down (fail-closed)", "analyzer unavailable: failing closed", CatInfrastructure},
		{"opa down (fail-closed)", "policy engine unavailable: failing closed", CatInfrastructure},
		{"proxy down (fail-closed)", "proxy unavailable: failing closed", CatInfrastructure},
		{"parse error", "query parse failed: syntax error near 'FORM'", CatParseError},
		{"multi-statement", "multi-statement query blocked: SQL injection chain pattern detected", CatInjection},
		{"schema enum once", "schema enumeration query blocked (agent reconnaissance pattern)", CatSchemaEnum},
		{"schema enum repeated (session-level)", "repeated schema enumeration blocked: active reconnaissance detected in this session", CatSessionBlock},
		{"session suspended after denials", "session suspended: 10 prior denials indicate a malicious query pattern", CatSessionBlock},
		{"exfiltration pagination pattern", "exfiltration pattern: 99 paginated queries detected in this session (LIMIT/OFFSET stepping)", CatSessionBlock},
		{"reformulation pattern", "reformulation pattern: table 'customers' was denied 7 times in this session", CatSessionBlock},
		{"tenant violation", "query must filter by tenant_id = 'tenant_1' on tenant-scoped tables (agent's tenant from JWT)", CatTenantViolation},
		{"destructive delete", "destructive operation DELETE is not allowed", CatDestructiveOp},
		{"destructive drop", "destructive operation DROP is not allowed", CatDestructiveOp},
		{"tautology", "WHERE clause is a tautology (e.g. 1=1)", CatTautology},
		{"pii violation", "query accesses PII columns [email ssn] without required scope for table 'customers'", CatPIIViolation},
		{"select star", "SELECT * is not allowed; specify columns explicitly", CatSelectStar},
		{"high limit", "query LIMIT exceeds maximum allowed rows (500)", CatHighLimit},
		{"missing where", "SELECT without WHERE clause on a named table", CatMissingWhere},
		{"missing scope explicit", "access to table 'customers' requires scope 'customers:read'", CatMissingScope},
		{"risk score", "risk score 8 exceeds threshold (7)", CatRiskScore},
		{"unknown fallback", "some new deny rule reason not yet mapped", CatUnknown},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := categoryFor(tc.reason)
			if got != tc.want {
				t.Fatalf("categoryFor(%q) = %q, want %q", tc.reason, got, tc.want)
			}
		})
	}
}

func TestCategorize_DeduplicatesAndPreservesOrder(t *testing.T) {
	reasons := []string{
		"query accesses PII columns [email] without required scope for table 'customers'",
		"WHERE clause is a tautology (e.g. 1=1)",
		"access to table 'customers' requires scope 'customers:read'",
		"query accesses PII columns [ssn] without required scope for table 'customers'", // duplicate category
	}
	got := categorize(reasons)
	want := []string{CatPIIViolation, CatTautology, CatMissingScope}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("categorize ordering/dedup failed: got %v, want %v", got, want)
	}
}

func TestCategorize_EmptyInput(t *testing.T) {
	got := categorize(nil)
	if len(got) != 0 {
		t.Fatalf("expected empty slice for nil input, got %v", got)
	}
}
