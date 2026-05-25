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
	qh := handler.NewQueryHandler(cfg.AnalyzerURL, cfg.OPAURL, cfg.ProxyURL, cfg.WebhookURL, limiter)
	eh := handler.NewExplainHandler(cfg.AnalyzerURL, cfg.OPAURL)

	r.Route("/v1", func(r chi.Router) {
		r.Use(mw.JWT(cfg.JWTSecret))
		r.Post("/query", qh.Handle)
		r.Post("/explain", eh.Handle)
	})

	log.Printf("gateway starting on :%s", cfg.Port)
	log.Fatal(http.ListenAndServe(":"+cfg.Port, r))
}
