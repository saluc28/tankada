package middleware

import (
	"sort"
	"testing"
)

func sortedEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	x := append([]string(nil), a...)
	y := append([]string(nil), b...)
	sort.Strings(x)
	sort.Strings(y)
	for i := range x {
		if x[i] != y[i] {
			return false
		}
	}
	return true
}

func TestResolver_ExactMatch(t *testing.T) {
	got := resolveDataActions("agent-1", "tenant_1",
		[]string{"tenant_1/financial/accounts/read", "tenant_1/financial/transactions/read"},
		nil)
	want := []string{"accounts:read", "transactions:read"}
	if !sortedEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestResolver_TripleWildcardCoversAllKnownTables(t *testing.T) {
	got := resolveDataActions("agent-1", "tenant_1",
		[]string{"tenant_1/*/*/read"}, nil)
	want := []string{"accounts:read", "customers:read", "transactions:read", "cards:read", "loans:read"}
	if !sortedEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestResolver_SectorWildcardCoversFinancialOnly(t *testing.T) {
	// All known tables today are financial — wildcard sector "financial" must cover all of them.
	got := resolveDataActions("agent-1", "tenant_1",
		[]string{"tenant_1/financial/*/read"}, nil)
	want := []string{"accounts:read", "customers:read", "transactions:read", "cards:read", "loans:read"}
	if !sortedEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestResolver_UnknownSectorMatchesNothing(t *testing.T) {
	got := resolveDataActions("agent-1", "tenant_1",
		[]string{"tenant_1/healthcare/*/read"}, nil)
	if len(got) != 0 {
		t.Fatalf("expected empty, got %v", got)
	}
}

func TestResolver_NotDataActionsRemovesExact(t *testing.T) {
	got := resolveDataActions("agent-1", "tenant_1",
		[]string{"tenant_1/*/*/read"},
		[]string{"tenant_1/financial/customers/read", "tenant_1/financial/cards/read"})
	want := []string{"accounts:read", "transactions:read", "loans:read"}
	if !sortedEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestResolver_NotDataActionsWildcard(t *testing.T) {
	got := resolveDataActions("agent-1", "tenant_1",
		[]string{"tenant_1/*/*/read"},
		[]string{"tenant_1/financial/*/read"})
	if len(got) != 0 {
		t.Fatalf("expected empty (all financial excluded), got %v", got)
	}
}

func TestResolver_TenantMismatchSilentlyDropped(t *testing.T) {
	// Agent for tenant_1 but JWT carries a path for globobank: must not yield any scope.
	got := resolveDataActions("agent-1", "tenant_1",
		[]string{"globobank/financial/accounts/read"}, nil)
	if len(got) != 0 {
		t.Fatalf("cross-tenant scope must be ignored, got %v", got)
	}
}

func TestResolver_TenantMismatchInNotDataActionsAlsoDropped(t *testing.T) {
	// Cross-tenant entry in notDataActions must NOT exclude legitimate matches.
	got := resolveDataActions("agent-1", "tenant_1",
		[]string{"tenant_1/financial/accounts/read"},
		[]string{"globobank/financial/accounts/read"})
	want := []string{"accounts:read"}
	if !sortedEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestResolver_MalformedEntryIgnored(t *testing.T) {
	// Wrong segment count: must be skipped without crashing.
	got := resolveDataActions("agent-1", "tenant_1",
		[]string{"tenant_1/financial/accounts", "tenant_1/financial/accounts/read"}, nil)
	want := []string{"accounts:read"}
	if !sortedEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestResolver_EmptyInputProducesEmptyOutput(t *testing.T) {
	got := resolveDataActions("agent-1", "tenant_1", nil, nil)
	if len(got) != 0 {
		t.Fatalf("expected empty, got %v", got)
	}
}

func TestResolver_ActionWildcard(t *testing.T) {
	// {tenant}/financial/accounts/* must cover read since action wildcard matches.
	got := resolveDataActions("agent-1", "tenant_1",
		[]string{"tenant_1/financial/accounts/*"}, nil)
	want := []string{"accounts:read"}
	if !sortedEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestResolver_NonReadActionDoesNotMatch(t *testing.T) {
	// "write" action explicitly: no known table requires it, so nothing emitted.
	got := resolveDataActions("agent-1", "tenant_1",
		[]string{"tenant_1/financial/accounts/write"}, nil)
	if len(got) != 0 {
		t.Fatalf("write action must not yield read scope, got %v", got)
	}
}
