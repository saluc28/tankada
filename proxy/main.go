package main

import (
	"context"
	"log"
	"net/http"
	"os"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"

	"github.com/tankada/proxy/db"
	"github.com/tankada/proxy/handler"
)

func main() {
	ctx := context.Background()

	if err := db.Connect(ctx); err != nil {
		log.Fatalf("cannot connect to database: %v", err)
	}
	defer db.Close()

	r := chi.NewRouter()
	r.Use(chimw.RequestID)
	r.Use(chimw.Logger)
	r.Use(chimw.Recoverer)

	// The proxy only accepts connections from the gateway (enforced via NetworkPolicy in k8s).
	// No JWT needed here; the gateway already authenticated the agent.
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"ok","service":"proxy"}`))
	})

	r.Post("/execute", handler.Execute)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8082"
	}
	log.Printf("proxy starting on :%s", port)
	log.Fatal(http.ListenAndServe(":"+port, r))
}
