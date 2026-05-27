package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"

	"github.com/tankada/gateway/handler"
	mw "github.com/tankada/gateway/middleware"
	"github.com/tankada/gateway/ratelimit"
	"github.com/tankada/gateway/telemetry"
)

// GatewayVersion is overridden at build time with -ldflags "-X main.GatewayVersion=...".
var GatewayVersion = "dev"

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

	// Telemetry (C.2.b). Opt-in via TANKADA_TELEMETRY_URL; nil reporter when
	// disabled. Handler treats nil as no-op (zero-cost when telemetry is off).
	telem := telemetry.NewReporter(telemetry.Config{
		URL:            os.Getenv("TANKADA_TELEMETRY_URL"),
		Token:          os.Getenv("TANKADA_TELEMETRY_TOKEN"),
		Interval:       envDurationSec("TANKADA_TELEMETRY_INTERVAL_SEC", 3600),
		DryRun:         os.Getenv("TANKADA_TELEMETRY_DRY_RUN") == "true",
		SiteID:         os.Getenv("TANKADA_SITE_ID"),
		PolicyDir:      pathDir(schemaPath),
		BundleVersion:  readBundleVersion(),
		GatewayVersion: GatewayVersion,
		Env:            os.Getenv("TANKADA_ENV"),
	})
	telem.Start(context.Background())

	qh := handler.NewQueryHandler(cfg.AnalyzerURL, cfg.OPAURL, cfg.ProxyURL, cfg.WebhookURL, limiter, cfg.ShadowMode, telem)
	eh := handler.NewExplainHandler(cfg.AnalyzerURL, cfg.OPAURL)

	r.Route("/v1", func(r chi.Router) {
		r.Use(mw.JWT(verifier))
		r.Post("/query", qh.Handle)
		r.Post("/explain", eh.Handle)
	})

	log.Printf("gateway starting on :%s", cfg.Port)
	log.Fatal(http.ListenAndServe(":"+cfg.Port, r))
}

// envDurationSec reads an integer "seconds" env var with a fallback default,
// returning a time.Duration. Negative or unparseable values fall back to def.
func envDurationSec(key string, defaultSec int) time.Duration {
	if v := os.Getenv(key); v != "" {
		var n int
		if _, err := fmt.Sscanf(v, "%d", &n); err == nil && n > 0 {
			return time.Duration(n) * time.Second
		}
	}
	return time.Duration(defaultSec) * time.Second
}

// pathDir returns the directory part of `p` (for telemetry's PolicyDir).
func pathDir(p string) string {
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '/' || p[i] == '\\' {
			return p[:i]
		}
	}
	return "."
}

// readBundleVersion reads the deploy/VERSION file the bundle ships with (C.2.a)
// from a couple of likely locations. Empty string when not found.
func readBundleVersion() string {
	for _, p := range []string{"/policies/VERSION", "/VERSION", "VERSION"} {
		if b, err := os.ReadFile(p); err == nil {
			s := string(b)
			for len(s) > 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == '\r' || s[len(s)-1] == ' ') {
				s = s[:len(s)-1]
			}
			return s
		}
	}
	return ""
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
		log.Printf("JWKS: %s (%d keys, %d tenant-tagged, refresh every %ds, require_tenant_binding=%v)",
			jwks.Source(), jwks.Size(), jwks.TenantBindings(), cfg.JWKSRefresh, cfg.JWKSRequireTenantBind)
		return mw.NewRS256Verifier(jwks, cfg.JWKSRequireTenantBind), nil
	case cfg.JWKSPath != "":
		jwks, err := mw.LoadJWKSFromFile(cfg.JWKSPath)
		if err != nil {
			return nil, err
		}
		log.Printf("JWKS: %s (%d keys, %d tenant-tagged, static, require_tenant_binding=%v)",
			jwks.Source(), jwks.Size(), jwks.TenantBindings(), cfg.JWKSRequireTenantBind)
		return mw.NewRS256Verifier(jwks, cfg.JWKSRequireTenantBind), nil
	default:
		return mw.NewHS256Verifier(cfg.JWTSecret), nil
	}
}
