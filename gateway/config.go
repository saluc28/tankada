package main

import (
	"log"
	"os"
	"strconv"
)

const defaultDevJWTSecret = "dev-secret-change-in-production"

type Config struct {
	Port         string
	JWTSecret    string // HS256 mode (dev / single-tenant); empty when JWKS mode
	JWKSURL      string // RS256 mode: URL of a JWKS endpoint (production / multi-tenant)
	JWKSPath     string // RS256 mode: path to a static JWKS JSON on disk (air-gapped)
	JWKSRefresh  int    // seconds between JWKS URL refreshes (0 disables; minimum 30s honored)
	AnalyzerURL  string
	OPAURL       string
	ProxyURL     string
	RateLimitQPM int    // max queries per minute per agent_id; 0 = disabled
	WebhookURL   string // optional; if set, a POST is fired on every deny
	ShadowMode   bool   // TANKADA_MODE=shadow: observe + log would-be denies, do not block
}

func configFromEnv() Config {
	jwksURL := os.Getenv("JWT_JWKS_URL")
	jwksPath := os.Getenv("JWT_JWKS_PATH")
	jwtSecret := os.Getenv("JWT_SECRET")

	// RS256/JWKS takes precedence: if either source is configured, the gateway
	// runs in JWKS mode and ignores any JWT_SECRET (logs a warning so misconfig
	// is visible). HS256 only when no JWKS source is set -- dev / single-tenant.
	jwksMode := jwksURL != "" || jwksPath != ""
	if jwksMode {
		if jwtSecret != "" {
			log.Println("WARNING: both JWT_SECRET and JWT_JWKS_* are set; JWKS wins, JWT_SECRET ignored")
		}
		jwtSecret = "" // make HS256 unavailable in this mode
	} else {
		if jwtSecret == "" {
			jwtSecret = defaultDevJWTSecret
		}
		if jwtSecret == defaultDevJWTSecret {
			if os.Getenv("TANKADA_ENV") == "development" {
				log.Println("WARNING: using dev JWT secret. Set JWT_SECRET (or JWT_JWKS_URL/JWT_JWKS_PATH) before deploying to production.")
			} else {
				log.Fatal("FATAL: JWT_SECRET is set to the default dev secret and no JWT_JWKS_* configured. Set a strong JWT_SECRET, configure JWKS, or set TANKADA_ENV=development to run locally.")
			}
		}
	}

	return Config{
		Port:         getEnv("PORT", "8080"),
		JWTSecret:    jwtSecret,
		JWKSURL:      jwksURL,
		JWKSPath:     jwksPath,
		JWKSRefresh:  getEnvInt("JWT_JWKS_REFRESH_SEC", 300),
		AnalyzerURL:  getEnv("ANALYZER_URL", "http://analyzer:8001"),
		OPAURL:       getEnv("OPA_URL", "http://opa:8181"),
		ProxyURL:     getEnv("PROXY_URL", "http://proxy:8082"),
		RateLimitQPM: getEnvInt("RATE_LIMIT_QPM", 60),
		WebhookURL:   os.Getenv("TANKADA_WEBHOOK_URL"),
		ShadowMode:   getEnv("TANKADA_MODE", "enforce") == "shadow",
	}
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func getEnvInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			return n
		}
	}
	return fallback
}
