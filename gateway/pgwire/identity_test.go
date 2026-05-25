package pgwire

import (
	"reflect"
	"testing"

	"github.com/jackc/pgx/v5/pgproto3"
)

func TestParseAppName(t *testing.T) {
	cases := []struct {
		in   string
		want map[string]string
	}{
		{"", map[string]string{}},
		{"psql", map[string]string{}},
		{"tenant=tenant_1", map[string]string{"tenant": "tenant_1"}},
		{"tenant=tenant_1 agent=reporter", map[string]string{"tenant": "tenant_1", "agent": "reporter"}},
		{"tenant=tenant_1,agent=reporter", map[string]string{"tenant": "tenant_1", "agent": "reporter"}},
		{"tenant=tenant_1;agent=reporter", map[string]string{"tenant": "tenant_1", "agent": "reporter"}},
		{"Tenant=TENANT_1", map[string]string{"tenant": "TENANT_1"}}, // key lowercased, value preserved
		{"  spaced   tenant=t1  ", map[string]string{"tenant": "t1"}},
	}
	for _, c := range cases {
		if got := parseAppName(c.in); !reflect.DeepEqual(got, c.want) {
			t.Errorf("parseAppName(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func startup(params map[string]string) *pgproto3.StartupMessage {
	return &pgproto3.StartupMessage{Parameters: params}
}

func TestTrustIdentity_ConfigTenantWins(t *testing.T) {
	s := &Server{cfg: Config{TrustTenant: "tenant_1", TrustScopes: []string{"customers:read"}, TrustRoles: []string{"analyst"}}}
	// Client tries to claim tenant_2 via application_name; config must win.
	c, err := s.trustIdentity(startup(map[string]string{"user": "reporter", "application_name": "tenant=tenant_2"}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.TenantID != "tenant_1" {
		t.Fatalf("config tenant must win: got %q", c.TenantID)
	}
	if c.AgentID != "reporter" {
		t.Fatalf("agent should fall back to user: got %q", c.AgentID)
	}
	if !reflect.DeepEqual(c.Scopes, []string{"customers:read"}) {
		t.Fatalf("scopes must come from config: got %v", c.Scopes)
	}
	if !reflect.DeepEqual(c.Roles, []string{"analyst"}) {
		t.Fatalf("roles must come from config: got %v", c.Roles)
	}
}

func TestTrustIdentity_TenantFromAppNameWhenConfigEmpty(t *testing.T) {
	s := &Server{cfg: Config{TrustScopes: []string{"accounts:read"}}}
	c, err := s.trustIdentity(startup(map[string]string{"user": "u", "application_name": "tenant=tenant_9 agent=bot"}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.TenantID != "tenant_9" {
		t.Fatalf("tenant should come from application_name: got %q", c.TenantID)
	}
	if c.AgentID != "bot" {
		t.Fatalf("agent= in application_name should win over user: got %q", c.AgentID)
	}
}

func TestTrustIdentity_NoTenantIsError(t *testing.T) {
	s := &Server{cfg: Config{TrustScopes: []string{"accounts:read"}}}
	if _, err := s.trustIdentity(startup(map[string]string{"user": "u", "application_name": "psql"})); err == nil {
		t.Fatal("expected error when no tenant can be resolved")
	}
}

func TestTrustIdentity_AgentFallbackWhenNoUser(t *testing.T) {
	s := &Server{cfg: Config{TrustTenant: "tenant_1"}}
	c, err := s.trustIdentity(startup(map[string]string{"application_name": "psql"}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.AgentID != "wire-trust" {
		t.Fatalf("agent should fall back to wire-trust: got %q", c.AgentID)
	}
}
