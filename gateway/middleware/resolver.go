package middleware

import (
	"log"
	"strings"
	"sync"
)

// knownTables maps a tenant-scoped table to the short scope OPA expects.
// MUST stay in sync with table_required_scope in policies/query.rego.
// Admin-only tables (credentials, secrets, pii_data, audit_logs) are intentionally
// excluded: they are gated exclusively by the "admin" role check in Rego and
// cannot be granted via dataActions.
var knownTables = map[string]string{
	"accounts":     "accounts:read",
	"customers":    "customers:read",
	"transactions": "transactions:read",
	"cards":        "cards:read",
	"loans":        "loans:read",
}

// tableSectorMap assigns each known table to a sector segment used in the
// hierarchical scope path {tenant}/{sector}/{table}/{action}. Tables without a
// specific sector use "generic". Hardcoded for now; will be moved to
// templates.json or the role catalog in a later iteration.
var tableSectorMap = map[string]string{
	"accounts":     "financial",
	"customers":    "financial",
	"transactions": "financial",
	"cards":        "financial",
	"loans":        "financial",
}

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

	resolved := make([]string, 0, len(knownTables))
	for tbl, scope := range knownTables {
		path := buildPath(tenantID, sectorOf(tbl), tbl, scopeAction)
		if !anyMatch(allow, path) {
			continue
		}
		if anyMatch(deny, path) {
			continue
		}
		resolved = append(resolved, scope)
	}
	return resolved
}

func sectorOf(tbl string) string {
	if s, ok := tableSectorMap[tbl]; ok {
		return s
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
