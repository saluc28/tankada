// Tests for per-tenant key isolation (C.1.b): a JWK tagged with
// `tankada_tenant` must only validate tokens whose `tenant_id` matches.
// Untagged JWKs are permissive by default (warn + allow) and strict-rejected
// when JWT_JWKS_REQUIRE_TENANT_BINDING=true (the verifier's
// `requireTenantBinding` flag).
package middleware

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

// jwksWithKeys writes a JWKS containing the given (kid, tenant) entries and
// returns the file path plus a map of {kid: private key}.
func jwksWithKeys(t *testing.T, entries map[string]string) (string, map[string]*rsa.PrivateKey) {
	t.Helper()
	keys := make(map[string]*rsa.PrivateKey, len(entries))
	jwks := make([]jwkKey, 0, len(entries))
	for kid, tenant := range entries {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("rsa gen: %v", err)
		}
		keys[kid] = k
		jwks = append(jwks, jwkKey{
			Kty:           "RSA",
			Kid:           kid,
			Alg:           "RS256",
			N:             base64.RawURLEncoding.EncodeToString(k.N.Bytes()),
			E:             base64.RawURLEncoding.EncodeToString(big.NewInt(int64(k.E)).Bytes()),
			TankadaTenant: tenant,
		})
	}
	body, _ := json.Marshal(jwksDoc{Keys: jwks})
	dir := t.TempDir()
	path := filepath.Join(dir, "jwks.json")
	if err := os.WriteFile(path, body, 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
	return path, keys
}

func tenantClaims(tenant string) jwt.MapClaims {
	return jwt.MapClaims{
		"agent_id":  "a1",
		"tenant_id": tenant,
		"scopes":    []string{"customers:read"},
	}
}

// ── happy path: matching binding ─────────────────────────────────────────────

func TestTenantBinding_kidBoundToTenant_acceptsMatchingTenantClaim(t *testing.T) {
	path, keys := jwksWithKeys(t, map[string]string{"k1": "acme"})
	j, _ := LoadJWKSFromFile(path)
	defer j.Stop()
	v := NewRS256Verifier(j, false)

	tok := signRS256(t, keys["k1"], "k1", tenantClaims("acme"))
	claims, err := ParseAndResolve(v, tok)
	if err != nil {
		t.Fatalf("expected accept, got %v", err)
	}
	if claims.TenantID != "acme" {
		t.Fatalf("tenant_id = %q, want acme", claims.TenantID)
	}
}

// ── core C.1.b: kid bound to A, token claims B -> REJECT ─────────────────────

func TestTenantBinding_kidBoundToA_rejectsTokenClaimingB(t *testing.T) {
	path, keys := jwksWithKeys(t, map[string]string{"k_acme": "acme"})
	j, _ := LoadJWKSFromFile(path)
	defer j.Stop()
	v := NewRS256Verifier(j, false)

	// Attacker holds k_acme (legit acme key) but tries to sign as tenant=beta.
	tok := signRS256(t, keys["k_acme"], "k_acme", tenantClaims("beta"))
	_, err := ParseAndResolve(v, tok)
	if err == nil {
		t.Fatal("kid_acme + tenant=beta MUST be rejected (impersonation)")
	}
	if !strings.Contains(err.Error(), "tenant binding violation") {
		t.Fatalf("wrong error: %v", err)
	}
}

// ── two-tenant JWKS: each kid only verifies its own tenant ───────────────────

func TestTenantBinding_twoTenants_areIsolated(t *testing.T) {
	path, keys := jwksWithKeys(t, map[string]string{
		"k_acme": "acme",
		"k_beta": "beta",
	})
	j, _ := LoadJWKSFromFile(path)
	defer j.Stop()
	v := NewRS256Verifier(j, false)

	// acme key + acme token: OK
	if _, err := ParseAndResolve(v, signRS256(t, keys["k_acme"], "k_acme", tenantClaims("acme"))); err != nil {
		t.Fatalf("k_acme+acme should pass: %v", err)
	}
	// beta key + beta token: OK
	if _, err := ParseAndResolve(v, signRS256(t, keys["k_beta"], "k_beta", tenantClaims("beta"))); err != nil {
		t.Fatalf("k_beta+beta should pass: %v", err)
	}
	// CROSS: acme key + beta token: REJECT
	if _, err := ParseAndResolve(v, signRS256(t, keys["k_acme"], "k_acme", tenantClaims("beta"))); err == nil {
		t.Fatal("k_acme+beta must reject (cross-tenant impersonation)")
	}
	// CROSS: beta key + acme token: REJECT
	if _, err := ParseAndResolve(v, signRS256(t, keys["k_beta"], "k_beta", tenantClaims("acme"))); err == nil {
		t.Fatal("k_beta+acme must reject (cross-tenant impersonation)")
	}
}

// ── untagged kid: permissive by default (legacy C.1.a JWKS) ─────────────────

func TestTenantBinding_untaggedKid_permissiveAcceptsAnyTenant(t *testing.T) {
	path, keys := jwksWithKeys(t, map[string]string{"k_legacy": ""}) // empty -> no tankada_tenant field
	j, _ := LoadJWKSFromFile(path)
	defer j.Stop()
	v := NewRS256Verifier(j, false) // requireTenantBinding=false (default)

	for _, ten := range []string{"acme", "beta", "tenant_42"} {
		tok := signRS256(t, keys["k_legacy"], "k_legacy", tenantClaims(ten))
		if _, err := ParseAndResolve(v, tok); err != nil {
			t.Fatalf("untagged kid + tenant=%s should pass in permissive mode: %v", ten, err)
		}
	}
}

// ── strict mode (JWT_JWKS_REQUIRE_TENANT_BINDING=true): untagged -> REJECT ──

func TestTenantBinding_untaggedKid_strictRejects(t *testing.T) {
	path, keys := jwksWithKeys(t, map[string]string{"k_legacy": ""})
	j, _ := LoadJWKSFromFile(path)
	defer j.Stop()
	v := NewRS256Verifier(j, true) // requireTenantBinding=true

	tok := signRS256(t, keys["k_legacy"], "k_legacy", tenantClaims("acme"))
	_, err := ParseAndResolve(v, tok)
	if err == nil {
		t.Fatal("strict mode must reject untagged kids")
	}
	if !strings.Contains(err.Error(), "tenant binding required") {
		t.Fatalf("wrong error: %v", err)
	}
}

// ── strict mode still accepts properly-tagged kids ──────────────────────────

func TestTenantBinding_strictMode_acceptsTaggedKid(t *testing.T) {
	path, keys := jwksWithKeys(t, map[string]string{"k_acme": "acme"})
	j, _ := LoadJWKSFromFile(path)
	defer j.Stop()
	v := NewRS256Verifier(j, true)

	tok := signRS256(t, keys["k_acme"], "k_acme", tenantClaims("acme"))
	if _, err := ParseAndResolve(v, tok); err != nil {
		t.Fatalf("strict + tagged kid + matching tenant should pass: %v", err)
	}
}

// ── JWKS introspection helpers ──────────────────────────────────────────────

func TestJWKS_TenantBindings_countsTaggedKids(t *testing.T) {
	path, _ := jwksWithKeys(t, map[string]string{
		"k1": "acme",
		"k2": "beta",
		"k3": "", // untagged
	})
	j, _ := LoadJWKSFromFile(path)
	defer j.Stop()
	if j.TenantBindings() != 2 {
		t.Fatalf("TenantBindings = %d, want 2", j.TenantBindings())
	}
	if j.TenantFor("k1") != "acme" {
		t.Fatalf("TenantFor(k1) = %q, want acme", j.TenantFor("k1"))
	}
	if j.TenantFor("k3") != "" {
		t.Fatalf("TenantFor(k3) should be empty, got %q", j.TenantFor("k3"))
	}
	if j.TenantFor("ghost") != "" {
		t.Fatalf("TenantFor(unknown) should be empty, got %q", j.TenantFor("ghost"))
	}
}
