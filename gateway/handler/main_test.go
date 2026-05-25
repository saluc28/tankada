package handler_test

import (
	"os"
	"testing"

	mw "github.com/tankada/gateway/middleware"
)

// TestMain installs a demo schema so the JWT v2 dataActions-resolution tests have
// a schema to resolve against (the resolver is now config-driven, not hardcoded).
func TestMain(m *testing.M) {
	mw.SetSchemaConfig(mw.SchemaConfig{
		Tables: map[string]mw.TableConfig{
			"accounts":     {Scope: "accounts:read", Sector: "financial"},
			"customers":    {Scope: "customers:read", Sector: "financial"},
			"transactions": {Scope: "transactions:read", Sector: "financial"},
			"cards":        {Scope: "cards:read", Sector: "financial"},
			"loans":        {Scope: "loans:read", Sector: "financial"},
		},
		TenantGlobalTables: []string{"merchants"},
	})
	os.Exit(m.Run())
}
