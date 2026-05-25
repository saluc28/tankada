package middleware

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
)

// TableConfig is the per-table schema entry: the scope an agent needs to read the
// table, and the sector segment used in the hierarchical dataActions path
// {tenant}/{sector}/{table}/{action}. A table whose scope is "admin" is gated by
// the admin role only and is not grantable via dataActions (the resolver skips it).
type TableConfig struct {
	Scope  string `json:"scope"`
	Sector string `json:"sector,omitempty"`
}

// SchemaConfig is the single source of truth for which tables exist, the scope
// each requires, and which tables are tenant-global. The gateway resolver and the
// OPA policy (data.schema) read the same file (policies/schema.json), so
// onboarding a new schema needs no code change.
type SchemaConfig struct {
	Tables             map[string]TableConfig `json:"tables"`
	TenantGlobalTables []string               `json:"tenant_global_tables"`
	// TenantColumn is the column carrying the tenant id (B.2.a). Defaults to
	// "tenant_id" when empty. Shared with OPA (data.schema.tenant_column) and the
	// analyzer so all layers agree on which column scopes a tenant.
	TenantColumn string `json:"tenant_column"`
}

// schemaFile mirrors the on-disk shape {"schema": {...}}, so the same JSON file
// loads as data.schema in OPA and parses here in the gateway.
type schemaFile struct {
	Schema SchemaConfig `json:"schema"`
}

var (
	schemaMu     sync.RWMutex
	activeSchema SchemaConfig
)

// SetSchemaConfig installs the active schema (used at startup and by tests).
func SetSchemaConfig(s SchemaConfig) {
	schemaMu.Lock()
	activeSchema = s
	schemaMu.Unlock()
}

// currentSchema returns a snapshot of the active schema.
func currentSchema() SchemaConfig {
	schemaMu.RLock()
	defer schemaMu.RUnlock()
	return activeSchema
}

// TenantColumn returns the configured tenant column, defaulting to "tenant_id".
func TenantColumn() string {
	if c := currentSchema().TenantColumn; c != "" {
		return c
	}
	return "tenant_id"
}

// LoadSchemaConfig reads and installs the schema config from a JSON file shaped
// as {"schema": {"tables": {...}, "tenant_global_tables": [...]}}.
func LoadSchemaConfig(path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read schema config %q: %w", path, err)
	}
	var f schemaFile
	if err := json.Unmarshal(b, &f); err != nil {
		return fmt.Errorf("parse schema config %q: %w", path, err)
	}
	if len(f.Schema.Tables) == 0 {
		return fmt.Errorf("schema config %q has no tables", path)
	}
	SetSchemaConfig(f.Schema)
	return nil
}
