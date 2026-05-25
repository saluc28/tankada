package pgwire

import (
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5/pgproto3"

	mw "github.com/tankada/gateway/middleware"
)

// trustIdentity builds the agent claims for a trust-mode (weak, frictionless)
// connection. No password is involved: the agent id (and, only when the
// deployment leaves it open, the tenant) come from the connection's
// application_name / user, while scopes, roles, and the tenant default are owned
// by the deployment so a client cannot grant itself authority.
func (s *Server) trustIdentity(startup *pgproto3.StartupMessage) (*mw.AgentClaims, error) {
	params := startup.Parameters
	kv := parseAppName(params["application_name"])

	// Tenant: the deployment's TrustTenant wins (single-tenant safety). Only when
	// it is left unset may the client declare the tenant via application_name.
	tenant := s.cfg.TrustTenant
	if tenant == "" {
		tenant = kv["tenant"]
	}
	if tenant == "" {
		return nil, fmt.Errorf("trust mode requires a tenant (set PGWIRE_TRUST_TENANT or pass application_name 'tenant=...')")
	}

	// Agent id: application_name agent=... wins, otherwise the connection user.
	agent := kv["agent"]
	if agent == "" {
		agent = params["user"]
	}
	if agent == "" {
		agent = "wire-trust"
	}

	return &mw.AgentClaims{
		AgentID:     agent,
		OwnerUserID: agent,
		TenantID:    tenant,
		Roles:       s.cfg.TrustRoles,
		Scopes:      s.cfg.TrustScopes,
	}, nil
}

// parseAppName extracts key=value tokens from a Postgres application_name string.
// Tokens are separated by spaces, commas, semicolons, or tabs; keys are
// lower-cased. A plain application_name with no "key=value" token (e.g. "psql")
// yields an empty map. Used by trust mode to read optional tenant= / agent= hints.
func parseAppName(s string) map[string]string {
	out := map[string]string{}
	if s == "" {
		return out
	}
	fields := strings.FieldsFunc(s, func(r rune) bool {
		return r == ' ' || r == ',' || r == ';' || r == '\t'
	})
	for _, f := range fields {
		eq := strings.IndexByte(f, '=')
		if eq <= 0 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(f[:eq]))
		val := strings.TrimSpace(f[eq+1:])
		if key != "" && val != "" {
			out[key] = val
		}
	}
	return out
}
