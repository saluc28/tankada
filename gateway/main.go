package main

import (
	"log"
	"net/http"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"

	"github.com/tankada/gateway/handler"
	mw "github.com/tankada/gateway/middleware"
	"github.com/tankada/gateway/ratelimit"
)

func main() {
	cfg := configFromEnv()

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
	qh := handler.NewQueryHandler(cfg.AnalyzerURL, cfg.OPAURL, cfg.ProxyURL, limiter)

	r.Route("/v1", func(r chi.Router) {
		r.Use(mw.JWT(cfg.JWTSecret))
		r.Post("/query", qh.Handle)
	})

	log.Printf("gateway starting on :%s", cfg.Port)
	log.Fatal(http.ListenAndServe(":"+cfg.Port, r))
}
