package middleware

import (
	"context"
	"encoding/json"
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

func JWT(secret string) func(http.Handler) http.Handler {
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

			claims := &AgentClaims{}
			_, err := jwt.ParseWithClaims(parts[1], claims, func(t *jwt.Token) (any, error) {
				if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, jwt.ErrSignatureInvalid
				}
				return []byte(secret), nil
			})
			if err != nil {
				writeErr(w, http.StatusUnauthorized, "invalid or expired token")
				return
			}

			if claims.AgentID == "" || claims.TenantID == "" {
				writeErr(w, http.StatusUnauthorized, "token missing required claims: agent_id, tenant_id")
				return
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

			ctx := context.WithValue(r.Context(), ClaimsKey, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func ClaimsFromCtx(ctx context.Context) *AgentClaims {
	c, _ := ctx.Value(ClaimsKey).(*AgentClaims)
	return c
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
