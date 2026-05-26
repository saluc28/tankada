package main

import (
	"log"
	"net/http"
	"os"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"

	"github.com/tankada/gateway/handler"
	mw "github.com/tankada/gateway/middleware"
	"github.com/tankada/gateway/ratelimit"
)

func main() {
	cfg := configFromEnv()

	// Schema config (tables, scopes, sectors, tenant-global) is loaded from a
	// single file shared with OPA (data.schema). Fail closed at boot if missing.
	schemaPath := os.Getenv("SCHEMA_CONFIG_PATH")
	if schemaPath == "" {
		schemaPath = "/policies/schema.json"
	}
	if err := mw.LoadSchemaConfig(schemaPath); err != nil {
		log.Fatalf("failed to load schema config: %v", err)
	}
	// Hot-reload the schema on change (B.1.c), like OPA reloads the policy dir.
	go mw.WatchSchemaConfig(schemaPath)

	// JWT verifier (C.1.a): RS256/JWKS if configured, otherwise HS256 fallback.
	verifier, err := buildVerifier(cfg)
	if err != nil {
		log.Fatalf("failed to build JWT verifier: %v", err)
	}
	log.Printf("JWT verifier: %s", verifier.Mode())

	r := chi.NewRouter()
	r.Use(chimw.RequestID)
	r.Use(chimw.RealIP)
	r.Use(chimw.Logger)
	r.Use(chimw.Recoverer)

	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"ok","service":"gateway"}`))
	})

	limiter := ratelimit.NewLimiter(cfg.RateLimitQPM)
	qh := handler.NewQueryHandler(cfg.AnalyzerURL, cfg.OPAURL, cfg.ProxyURL, cfg.WebhookURL, limiter, cfg.ShadowMode)
	eh := handler.NewExplainHandler(cfg.AnalyzerURL, cfg.OPAURL)

	r.Route("/v1", func(r chi.Router) {
		r.Use(mw.JWT(verifier))
		r.Post("/query", qh.Handle)
		r.Post("/explain", eh.Handle)
	})

	log.Printf("gateway starting on :%s", cfg.Port)
	log.Fatal(http.ListenAndServe(":"+cfg.Port, r))
}

// buildVerifier picks the JWT verifier from config: JWKS URL > JWKS file >
// HS256 secret. Shared by main.go and cmd/pgwire/main.go (identical wiring).
func buildVerifier(cfg Config) (*mw.Verifier, error) {
	switch {
	case cfg.JWKSURL != "":
		jwks, err := mw.LoadJWKSFromURL(cfg.JWKSURL, cfg.JWKSRefresh)
		if err != nil {
			return nil, err
		}
		log.Printf("JWKS: %s (%d keys, refresh every %ds)", jwks.Source(), jwks.Size(), cfg.JWKSRefresh)
		return mw.NewRS256Verifier(jwks), nil
	case cfg.JWKSPath != "":
		jwks, err := mw.LoadJWKSFromFile(cfg.JWKSPath)
		if err != nil {
			return nil, err
		}
		log.Printf("JWKS: %s (%d keys, static)", jwks.Source(), jwks.Size())
		return mw.NewRS256Verifier(jwks), nil
	default:
		return mw.NewHS256Verifier(cfg.JWTSecret), nil
	}
}
