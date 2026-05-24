// Command pgwire runs the Tankada PostgreSQL wire-protocol proxy: agents point a
// stock Postgres driver at it (changing only the connection string) and every
// statement is enforced by the same analyzer + OPA pipeline as the HTTP gateway,
// with PII masking applied to results. Identity is the Tankada JWT, supplied as
// the connection password.
package main

import (
	"log"
	"os"

	"github.com/tankada/gateway/pgwire"
)

func main() {
	cfg := pgwire.Config{
		ListenAddr:  envOr("PGWIRE_ADDR", ":5433"),
		JWTSecret:   envOr("JWT_SECRET", "dev-secret-change-in-production"),
		AnalyzerURL: envOr("ANALYZER_URL", "http://analyzer:8001"),
		OPAURL:      envOr("OPA_URL", "http://opa:8181"),
		DatabaseURL: envOr("DATABASE_URL", "postgres://tankada:tankada@postgres:5432/tankada?sslmode=disable"),
		AppRole:     envOr("PGWIRE_APP_ROLE", "tankada_app"),
	}

	srv := pgwire.New(cfg)
	log.Fatal(srv.ListenAndServe())
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
