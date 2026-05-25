package middleware

import (
	"os"
	"path/filepath"
	"testing"
	"time"
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

func TestReloadIfChanged(t *testing.T) {
	defer SetSchemaConfig(demoSchema())

	dir := t.TempDir()
	path := filepath.Join(dir, "schema.json")
	writeSchema := func(table string) {
		c := `{"schema":{"tables":{"` + table + `":{"scope":"` + table + `:read","sector":"s"}}}}`
		if err := os.WriteFile(path, []byte(c), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
	}

	writeSchema("orders")
	mt, reloaded := reloadIfChanged(path, time.Time{})
	if !reloaded {
		t.Fatal("expected initial reload")
	}
	if _, ok := currentSchema().Tables["orders"]; !ok {
		t.Fatal("orders not loaded")
	}

	// Unchanged mtime -> no reload.
	if _, r := reloadIfChanged(path, mt); r {
		t.Fatal("expected no reload when mtime unchanged")
	}

	// Change content + bump mtime -> reload picks up the new table.
	writeSchema("invoices")
	future := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(path, future, future); err != nil {
		t.Fatalf("chtimes: %v", err)
	}
	mt2, reloaded2 := reloadIfChanged(path, mt)
	if !reloaded2 || currentSchema().Tables["invoices"].Scope == "" {
		t.Fatal("expected reload to load invoices")
	}

	// A half-written / broken file keeps the previous good config.
	if err := os.WriteFile(path, []byte("{ broken"), 0o600); err != nil {
		t.Fatalf("write broken: %v", err)
	}
	future2 := time.Now().Add(4 * time.Second)
	os.Chtimes(path, future2, future2)
	if _, r := reloadIfChanged(path, mt2); r {
		t.Fatal("broken file must not count as a reload")
	}
	if currentSchema().Tables["invoices"].Scope == "" {
		t.Fatal("previous good config must be kept after a broken reload")
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
