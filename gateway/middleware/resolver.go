package middleware

import (
	"log"
	"strings"
	"sync"
)

// The set of tables, their required scopes, and their sectors is no longer
// hardcoded here: it is loaded once from the schema config (policies/schema.json
// via middleware.LoadSchemaConfig) and shared with the OPA policy (data.schema),
// so onboarding a new schema needs no code change. Admin-only tables (scope
// "admin") are gated by the admin role in Rego and are not grantable via
// dataActions, so the resolver skips them.

const scopeAction = "read"

// deprecation log dedup: one warning per agent_id, not per request.
var (
	deprecatedAgents sync.Map
	mismatchAgents   sync.Map
)

// resolveDataActions expands a v2 hierarchical scope set into the flat list of
// short scopes ({table}:read) that OPA's agent_has_table_scope already understands.
//
// Algorithm:
//  1. For each known tenant-scoped table, build its canonical path
//     {tenantID}/{sector}/{table}/{action}.
//  2. Keep the table if at least one entry in dataActions matches that path
//     (segment-wise, with "*" wildcard support).
//  3. Drop the table if any entry in notDataActions also matches.
//  4. Emit knownTables[table] for every surviving table.
//
// Tenant invariant: any entry whose first segment != tenantID is silently dropped
// (and logged once per agent_id) before matching. Defence-in-depth on top of the
// JWT signature: an agent of tenant A cannot grant itself tenant B's scopes even
// by tampering with the payload.
func resolveDataActions(agentID, tenantID string, dataActions, notDataActions []string) []string {
	allow := filterByTenant(agentID, tenantID, dataActions)
	deny := filterByTenant(agentID, tenantID, notDataActions)

	tables := currentSchema().Tables
	resolved := make([]string, 0, len(tables))
	for tbl, cfg := range tables {
		// Admin-only tables are not grantable via dataActions.
		if cfg.Scope == "" || cfg.Scope == "admin" {
			continue
		}
		path := buildPath(tenantID, sectorOf(cfg), tbl, scopeAction)
		if !anyMatch(allow, path) {
			continue
		}
		if anyMatch(deny, path) {
			continue
		}
		resolved = append(resolved, cfg.Scope)
	}
	return resolved
}

func sectorOf(cfg TableConfig) string {
	if cfg.Sector != "" {
		return cfg.Sector
	}
	return "generic"
}

func buildPath(tenant, sector, table, action string) string {
	return tenant + "/" + sector + "/" + table + "/" + action
}

// filterByTenant drops entries whose tenant segment doesn't match the JWT tenant.
// Returns the parsed segments of the surviving entries (4 segments each).
func filterByTenant(agentID, tenantID string, entries []string) [][]string {
	out := make([][]string, 0, len(entries))
	for _, e := range entries {
		segs := strings.Split(e, "/")
		if len(segs) != 4 {
			continue
		}
		if segs[0] != tenantID {
			logTenantMismatch(agentID, e)
			continue
		}
		out = append(out, segs)
	}
	return out
}

func anyMatch(patterns [][]string, path string) bool {
	target := strings.Split(path, "/")
	for _, p := range patterns {
		if matchSegments(p, target) {
			return true
		}
	}
	return false
}

func matchSegments(pattern, target []string) bool {
	if len(pattern) != len(target) {
		return false
	}
	for i := range pattern {
		if pattern[i] == "*" {
			continue
		}
		if pattern[i] != target[i] {
			return false
		}
	}
	return true
}

// LogJWTV1Deprecation emits a deprecation warning at most once per agent_id.
func LogJWTV1Deprecation(agentID string) {
	if _, loaded := deprecatedAgents.LoadOrStore(agentID, struct{}{}); loaded {
		return
	}
	log.Printf("warn: tankada.security.jwt_v1_deprecated agent_id=%s: JWT uses legacy scopes[]; migrate to dataActions[]", agentID)
}

func logTenantMismatch(agentID, entry string) {
	key := agentID + "|" + entry
	if _, loaded := mismatchAgents.LoadOrStore(key, struct{}{}); loaded {
		return
	}
	log.Printf("warn: tankada.security.scope_tenant_mismatch agent_id=%s entry=%q: entry tenant != JWT tenant, ignored", agentID, entry)
}
