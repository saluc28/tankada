package middleware

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strconv"
	"sync"
	"time"
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

// defaultSchemaReloadInterval is how often the watcher polls the schema file.
const defaultSchemaReloadInterval = 15 * time.Second

// schemaReloadInterval reads SCHEMA_RELOAD_INTERVAL (seconds). 0 disables the
// watcher (load-once); unset uses the default.
func schemaReloadInterval() time.Duration {
	if v := os.Getenv("SCHEMA_RELOAD_INTERVAL"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			return time.Duration(n) * time.Second
		}
	}
	return defaultSchemaReloadInterval
}

func schemaModTime(path string) time.Time {
	fi, err := os.Stat(path)
	if err != nil {
		return time.Time{}
	}
	return fi.ModTime()
}

// reloadIfChanged reloads the schema when the file's mtime differs from last.
// A failed reload (e.g. a half-written file) keeps the previous good config.
// Returns the mtime to track next and whether a reload was applied.
func reloadIfChanged(path string, last time.Time) (time.Time, bool) {
	mt := schemaModTime(path)
	if mt.Equal(last) {
		return last, false
	}
	if err := LoadSchemaConfig(path); err != nil {
		log.Printf("warn: schema reload failed, keeping previous config: %v", err)
		return mt, false
	}
	log.Printf("schema config reloaded from %s (tenant_column=%s)", path, TenantColumn())
	return mt, true
}

// WatchSchemaConfig polls the schema file and hot-reloads it on change, so an
// operator can add tables / change scopes or tenant_column without restarting
// the gateway (mirroring OPA's hot-reload of the policy dir). Blocking; run in a
// goroutine. SCHEMA_RELOAD_INTERVAL=0 disables it.
func WatchSchemaConfig(path string) {
	interval := schemaReloadInterval()
	if interval == 0 {
		return
	}
	last := schemaModTime(path)
	for {
		time.Sleep(interval)
		last, _ = reloadIfChanged(path, last)
	}
}
