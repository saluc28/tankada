package middleware

import (
	"os"
	"path/filepath"
	"testing"
)

// demoSchema mirrors policies/schema.json and is installed for the whole package
// test run so the resolver tests have a schema to resolve against.
func demoSchema() SchemaConfig {
	return SchemaConfig{
		Tables: map[string]TableConfig{
			"accounts":     {Scope: "accounts:read", Sector: "financial"},
			"customers":    {Scope: "customers:read", Sector: "financial"},
			"transactions": {Scope: "transactions:read", Sector: "financial"},
			"cards":        {Scope: "cards:read", Sector: "financial"},
			"loans":        {Scope: "loans:read", Sector: "financial"},
			"credentials":  {Scope: "admin"},
			"secrets":      {Scope: "admin"},
			"pii_data":     {Scope: "admin"},
			"audit_logs":   {Scope: "admin"},
		},
		TenantGlobalTables: []string{"merchants"},
	}
}

func TestMain(m *testing.M) {
	SetSchemaConfig(demoSchema())
	os.Exit(m.Run())
}

func TestLoadSchemaConfig(t *testing.T) {
	defer SetSchemaConfig(demoSchema()) // restore for the other tests

	dir := t.TempDir()
	path := filepath.Join(dir, "schema.json")
	content := `{"schema":{"tables":{"orders":{"scope":"orders:read","sector":"retail"}},"tenant_global_tables":["catalog"]}}`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write temp schema: %v", err)
	}

	if err := LoadSchemaConfig(path); err != nil {
		t.Fatalf("LoadSchemaConfig: %v", err)
	}

	sc := currentSchema()
	if got := sc.Tables["orders"].Scope; got != "orders:read" {
		t.Fatalf("orders scope = %q, want orders:read", got)
	}
	if got := sc.Tables["orders"].Sector; got != "retail" {
		t.Fatalf("orders sector = %q, want retail", got)
	}
	if len(sc.TenantGlobalTables) != 1 || sc.TenantGlobalTables[0] != "catalog" {
		t.Fatalf("tenant_global_tables = %v, want [catalog]", sc.TenantGlobalTables)
	}

	// A schema-agnostic resolver: a token for the new schema resolves correctly.
	got := resolveDataActions("a", "tenant_1", []string{"tenant_1/retail/orders/read"}, nil)
	if len(got) != 1 || got[0] != "orders:read" {
		t.Fatalf("resolve on loaded schema = %v, want [orders:read]", got)
	}
}

func TestLoadSchemaConfig_Errors(t *testing.T) {
	if err := LoadSchemaConfig(filepath.Join(t.TempDir(), "missing.json")); err == nil {
		t.Fatal("expected error for missing file")
	}
	dir := t.TempDir()
	bad := filepath.Join(dir, "empty.json")
	os.WriteFile(bad, []byte(`{"schema":{"tables":{}}}`), 0o600)
	if err := LoadSchemaConfig(bad); err == nil {
		t.Fatal("expected error for schema with no tables")
	}
}
