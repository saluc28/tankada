package main

import (
	"log"
	"os"
	"strconv"
)

const defaultDevJWTSecret = "dev-secret-change-in-production"

type Config struct {
	Port         string
	JWTSecret    string
	AnalyzerURL  string
	OPAURL       string
	ProxyURL     string
	RateLimitQPM int    // max queries per minute per agent_id; 0 = disabled
	WebhookURL   string // optional; if set, a POST is fired on every deny
}

func configFromEnv() Config {
	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		jwtSecret = defaultDevJWTSecret
	}

	if jwtSecret == defaultDevJWTSecret {
		if os.Getenv("TANKADA_ENV") == "development" {
			log.Println("WARNING: using dev JWT secret. Set JWT_SECRET before deploying to production.")
		} else {
			log.Fatal("FATAL: JWT_SECRET is set to the default dev secret. Set a strong JWT_SECRET or set TANKADA_ENV=development to run locally.")
		}
	}

	return Config{
		Port:         getEnv("PORT", "8080"),
		JWTSecret:    jwtSecret,
		AnalyzerURL:  getEnv("ANALYZER_URL", "http://analyzer:8001"),
		OPAURL:       getEnv("OPA_URL", "http://opa:8181"),
		ProxyURL:     getEnv("PROXY_URL", "http://proxy:8082"),
		RateLimitQPM: getEnvInt("RATE_LIMIT_QPM", 60),
		WebhookURL:   os.Getenv("TANKADA_WEBHOOK_URL"),
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
