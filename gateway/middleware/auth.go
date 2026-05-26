package middleware

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

type AgentClaims struct {
	AgentID        string   `json:"agent_id"`
	OwnerUserID    string   `json:"owner_user_id"`
	TenantID       string   `json:"tenant_id"`
	Roles          []string `json:"roles"`
	Scopes         []string `json:"scopes"`          // v1 (legacy) and resolver output
	DataActions    []string `json:"dataActions"`     // v2: hierarchical paths
	NotDataActions []string `json:"notDataActions"`  // v2: explicit exclusions
	jwt.RegisteredClaims
}

type contextKey string

const ClaimsKey contextKey = "agent_claims"

// Verifier wraps the two ways Tankada can verify a JWT: shared HMAC secret
// (HS256, dev / single-tenant) or asymmetric RSA via a JWKS (RS256, multi-
// tenant / production). Exactly one of the two fields is populated.
//
// Selection is a deployment-time choice: in production you want
// RS256/JWKS so the signing key (held by the dashboard/control plane) never
// ships to the verifier (the gateway). With HS256 a leaked gateway secret
// also leaks the signer's authority -- not acceptable for a multi-tenant
// product.
//
// Per-tenant key isolation (C.1.b): in RS256 mode, JWKs MAY carry a custom
// `tankada_tenant` field that binds the kid to a specific tenant. When a
// token is verified with such a kid, the token's `tenant_id` claim MUST
// equal the kid's tankada_tenant -- otherwise customer A who legitimately
// holds key_A could mint a token with `tenant_id: B` and impersonate B.
// `requireTenantBinding` makes this strict (every kid must be tagged, untagged
// kids reject the token); the default is permissive (untagged kids accept
// any tenant, with a warning) to keep C.1.a deployments working unchanged.
type Verifier struct {
	secret               string // HS256 mode; empty in JWKS mode
	jwks                 *JWKS  // RS256 mode; nil in HS256 mode
	requireTenantBinding bool   // RS256 mode only: untagged kids reject the token
}

// NewHS256Verifier configures the verifier for symmetric HMAC. Suitable for
// dev / single-tenant deployments where the same actor signs and verifies.
func NewHS256Verifier(secret string) *Verifier {
	return &Verifier{secret: secret}
}

// NewRS256Verifier configures the verifier for asymmetric RSA-SHA256 with a
// JWKS keyset. Tokens MUST carry a `kid` header that resolves to a key in the
// set. Suitable for multi-tenant deployments (signing key stays on the
// signer; only public keys ship to verifiers).
//
// `requireTenantBinding`: when true, every JWK in the JWKS MUST declare a
// `tankada_tenant` field and the token's `tenant_id` MUST match it. False
// (default at boot) keeps backward-compat with C.1.a JWKS files that don't
// carry the tag yet; untagged kids accept any tenant_id but a warning is
// logged on every use.
func NewRS256Verifier(jwks *JWKS, requireTenantBinding bool) *Verifier {
	return &Verifier{jwks: jwks, requireTenantBinding: requireTenantBinding}
}

// Mode returns a short human-readable label ("HS256" or "RS256/JWKS").
func (v *Verifier) Mode() string {
	if v.jwks != nil {
		return "RS256/JWKS"
	}
	return "HS256"
}

// JWT returns the HTTP middleware that validates Bearer tokens with the given
// verifier and stashes the resolved claims on the request context.
func JWT(v *Verifier) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			raw := r.Header.Get("Authorization")
			if raw == "" {
				writeErr(w, http.StatusUnauthorized, "missing Authorization header")
				return
			}
			parts := strings.SplitN(raw, " ", 2)
			if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") {
				writeErr(w, http.StatusUnauthorized, "invalid Authorization format, expected: Bearer <token>")
				return
			}

			claims, err := ParseAndResolve(v, parts[1])
			if err != nil {
				writeErr(w, http.StatusUnauthorized, "invalid or expired token")
				return
			}

			ctx := context.WithValue(r.Context(), ClaimsKey, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// ParseAndResolve validates a Tankada JWT with the configured Verifier and
// returns the resolved agent claims. v2 dataActions are resolved to flat
// scopes; v1 scopes are passed through. Shared by the HTTP middleware and the
// Postgres wire-proxy so both front-ends apply identical identity and scope
// rules.
//
// Algorithm whitelist is strict: HS256 mode accepts only HS256; RS256 mode
// accepts only RS256. `alg: none` is always rejected. This is the kind of
// check the canonical "JWT algorithm confusion" CVEs were caused by missing.
func ParseAndResolve(v *Verifier, tokenString string) (*AgentClaims, error) {
	if v == nil {
		return nil, fmt.Errorf("no JWT verifier configured")
	}
	claims := &AgentClaims{}
	keyfunc := func(t *jwt.Token) (any, error) {
		switch v.Mode() {
		case "HS256":
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("expected HS256 algorithm, got %v", t.Header["alg"])
			}
			return []byte(v.secret), nil
		case "RS256/JWKS":
			if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
				return nil, fmt.Errorf("expected RS256 algorithm, got %v", t.Header["alg"])
			}
			kid, _ := t.Header["kid"].(string)
			key, err := v.jwks.KeyFor(kid)
			if err != nil {
				return nil, err
			}
			return key, nil
		default:
			return nil, fmt.Errorf("unknown verifier mode %q", v.Mode())
		}
	}
	parsedTok, err := jwt.ParseWithClaims(tokenString, claims, keyfunc,
		jwt.WithValidMethods(validMethodsFor(v)))
	if err != nil {
		return nil, err
	}

	if claims.AgentID == "" || claims.TenantID == "" {
		return nil, fmt.Errorf("token missing required claims: agent_id, tenant_id")
	}

	// Per-tenant key isolation (C.1.b). In RS256 mode, if the kid that signed
	// this token is tagged with a `tankada_tenant`, the claim MUST match.
	// Untagged kids: permissive by default (warn), strict if requireTenantBinding.
	if v.jwks != nil {
		kid, _ := parsedTok.Header["kid"].(string)
		boundTenant := v.jwks.TenantFor(kid)
		switch {
		case boundTenant != "" && boundTenant != claims.TenantID:
			return nil, fmt.Errorf("tenant binding violation: kid %q is bound to tenant %q, token claims tenant %q",
				kid, boundTenant, claims.TenantID)
		case boundTenant == "" && v.requireTenantBinding:
			return nil, fmt.Errorf("tenant binding required but kid %q has no tankada_tenant in JWKS", kid)
		case boundTenant == "":
			LogJWKSUntaggedKid(kid, claims.TenantID)
		}
	}

	// JWT v1 (legacy scopes[]) vs v2 (dataActions[] hierarchical paths).
	// v2 wins when both are present: dataActions is the new authoritative
	// source and overwrites any legacy scopes carried alongside.
	switch {
	case len(claims.DataActions) > 0 || len(claims.NotDataActions) > 0:
		claims.Scopes = resolveDataActions(
			claims.AgentID,
			claims.TenantID,
			claims.DataActions,
			claims.NotDataActions,
		)
	case len(claims.Scopes) > 0:
		LogJWTV1Deprecation(claims.AgentID)
	}

	return claims, nil
}

// validMethodsFor returns the algorithm whitelist passed to jwt.ParseWithClaims
// so the parser refuses signatures with an algorithm we don't support, BEFORE
// our keyfunc is even called. Belt-and-braces vs algorithm confusion.
func validMethodsFor(v *Verifier) []string {
	if v.jwks != nil {
		return []string{"RS256"}
	}
	return []string{"HS256"}
}

// Suppress unused-import warning when only RS256 path is exercised; the rsa
// type is used implicitly through jwks.KeyFor's *rsa.PublicKey return.
var _ *rsa.PublicKey

func ClaimsFromCtx(ctx context.Context) *AgentClaims {
	c, _ := ctx.Value(ClaimsKey).(*AgentClaims)
	return c
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
