// Command pgwire runs the Tankada PostgreSQL wire-protocol proxy: agents point a
// stock Postgres driver at it (changing only the connection string) and every
// statement is enforced by the same analyzer + OPA pipeline as the HTTP gateway,
// with PII masking applied to results. Identity is the Tankada JWT, supplied as
// the connection password.
package main

import (
	"fmt"
	"log"
	"os"
	"strings"

	mw "github.com/tankada/gateway/middleware"
	"github.com/tankada/gateway/pgwire"
)

func main() {
	// Schema config shared with OPA (data.schema); needed to resolve JWT v2
	// dataActions in jwt mode. Fail closed at boot if missing.
	schemaPath := os.Getenv("SCHEMA_CONFIG_PATH")
	if schemaPath == "" {
		schemaPath = "/policies/schema.json"
	}
	if err := mw.LoadSchemaConfig(schemaPath); err != nil {
		log.Fatalf("failed to load schema config: %v", err)
	}
	// Hot-reload the schema on change (B.1.c), like OPA reloads the policy dir.
	go mw.WatchSchemaConfig(schemaPath)

	// JWT verifier (C.1.a). Identical wiring to gateway/main.go: JWKS_URL
	// wins, then JWKS_PATH, then HS256 from JWT_SECRET (dev fallback).
	verifier, err := buildVerifier()
	if err != nil {
		log.Fatalf("failed to build JWT verifier: %v", err)
	}
	log.Printf("pgwire JWT verifier: %s", verifier.Mode())

	cfg := pgwire.Config{
		ListenAddr:  envOr("PGWIRE_ADDR", ":5433"),
		JWTVerifier: verifier,
		AnalyzerURL: envOr("ANALYZER_URL", "http://analyzer:8001"),
		OPAURL:      envOr("OPA_URL", "http://opa:8181"),
		DatabaseURL: envOr("DATABASE_URL", "postgres://tankada:tankada@postgres:5432/tankada?sslmode=disable"),
		AppRole:     envOr("PGWIRE_APP_ROLE", "tankada_app"),

		// Identity mode (D.1.c). Defaults to the strong JWT-in-password mode.
		AuthMode:    envOr("PGWIRE_AUTH_MODE", pgwire.AuthJWT),
		TrustTenant: os.Getenv("PGWIRE_TRUST_TENANT"),
		TrustScopes: envList("PGWIRE_TRUST_SCOPES"),
		TrustRoles:  envList("PGWIRE_TRUST_ROLES"),
	}

	srv := pgwire.New(cfg)
	log.Fatal(srv.ListenAndServe())
}

// buildVerifier mirrors gateway/main.go's buildVerifier: JWKS_URL > JWKS_PATH >
// HS256 secret (dev only). Kept here as a sibling implementation rather than in
// the middleware package, to keep the env-reading logic close to each binary's
// main() and avoid coupling middleware to env conventions.
func buildVerifier() (*mw.Verifier, error) {
	requireBind := envOr("JWT_JWKS_REQUIRE_TENANT_BINDING", "false") == "true"
	if u := os.Getenv("JWT_JWKS_URL"); u != "" {
		refresh := envOrInt("JWT_JWKS_REFRESH_SEC", 300)
		j, err := mw.LoadJWKSFromURL(u, refresh)
		if err != nil {
			return nil, err
		}
		log.Printf("pgwire JWKS: %s (%d keys, %d tenant-tagged, refresh every %ds, require_tenant_binding=%v)",
			j.Source(), j.Size(), j.TenantBindings(), refresh, requireBind)
		return mw.NewRS256Verifier(j, requireBind), nil
	}
	if p := os.Getenv("JWT_JWKS_PATH"); p != "" {
		j, err := mw.LoadJWKSFromFile(p)
		if err != nil {
			return nil, err
		}
		log.Printf("pgwire JWKS: %s (%d keys, %d tenant-tagged, static, require_tenant_binding=%v)",
			j.Source(), j.Size(), j.TenantBindings(), requireBind)
		return mw.NewRS256Verifier(j, requireBind), nil
	}
	secret := envOr("JWT_SECRET", "dev-secret-change-in-production")
	return mw.NewHS256Verifier(secret), nil
}

func envOrInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		var n int
		if _, err := fmt.Sscanf(v, "%d", &n); err == nil && n >= 0 {
			return n
		}
	}
	return def
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// envList parses a comma-separated env var into a trimmed, empty-free slice.
func envList(key string) []string {
	raw := os.Getenv(key)
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	var out []string
	for _, p := range strings.Split(raw, ",") {
		if v := strings.TrimSpace(p); v != "" {
			out = append(out, v)
		}
	}
	return out
}
