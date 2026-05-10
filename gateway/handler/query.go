package handler

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/tankada/gateway/audit"
	"github.com/tankada/gateway/client"
	mw "github.com/tankada/gateway/middleware"
	"github.com/tankada/gateway/ratelimit"
	"github.com/tankada/gateway/webhook"
)

type QueryRequest struct {
	Query   string       `json:"query"`
	Context QueryContext `json:"context"`
}

type QueryContext struct {
	TaskDescription string `json:"task_description,omitempty"`
	UserID          string `json:"user_id,omitempty"`
	SessionID       string `json:"session_id,omitempty"`
}

type QueryResponse struct {
	EventID        string                  `json:"event_id"`
	Decision       string                  `json:"decision"`
	Reasons        []string                `json:"reasons,omitempty"`
	DenyCategories []string                `json:"deny_categories,omitempty"`
	RiskScore      int                     `json:"risk_score"`
	RiskLevel      string                  `json:"risk_level"`
	Result         *client.ExecuteResponse `json:"result,omitempty"`
	LatencyMs      int64                   `json:"latency_ms"`
}

type QueryHandler struct {
	analyzer   *client.AnalyzerClient
	opa        *client.OPAClient
	proxy      *client.ProxyClient
	limiter    *ratelimit.Limiter
	webhookURL string
}

func NewQueryHandler(analyzerURL, opaURL, proxyURL, webhookURL string, limiter *ratelimit.Limiter) *QueryHandler {
	return &QueryHandler{
		analyzer:   client.NewAnalyzer(analyzerURL),
		opa:        client.NewOPA(opaURL),
		proxy:      client.NewProxy(proxyURL),
		limiter:    limiter,
		webhookURL: webhookURL,
	}
}

func (h *QueryHandler) Handle(w http.ResponseWriter, r *http.Request) {
	start   := time.Now()
	eventID := uuid.New().String()

	claims := mw.ClaimsFromCtx(r.Context())
	if claims == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing claims"})
		return
	}

	var req QueryRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}
	req.Query = strings.TrimSpace(req.Query)
	if req.Query == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "query cannot be empty"})
		return
	}

	sessionID := req.Context.SessionID
	if sessionID == "" {
		sessionID = uuid.New().String()
	}

	// ── 0. Rate limit check ───────────────────────────────────────────────
	if !h.limiter.Allow(claims.AgentID) {
		reason := "rate limit exceeded: too many queries per minute"
		audit.Log(audit.Event{
			EventID: eventID, Timestamp: time.Now(),
			AgentID: claims.AgentID, OwnerUserID: claims.OwnerUserID, TenantID: claims.TenantID,
			QueryOriginal: req.Query, QueryType: "RATE_LIMITED",
			PolicyDecision: "deny", PolicyReasons: []string{reason},
			RiskScore: 0, RiskLevel: "low",
			LatencyMs: time.Since(start).Milliseconds(), SessionID: sessionID,
		})
		go webhook.Send(h.webhookURL, webhook.BlockEvent{
			EventID: eventID, AgentID: claims.AgentID, TenantID: claims.TenantID,
			Query: req.Query, Reasons: []string{reason},
			RiskScore: 0, RiskLevel: "low",
			Timestamp: time.Now().UTC().Format(time.RFC3339),
		})
		writeJSON(w, http.StatusTooManyRequests, QueryResponse{
			EventID:        eventID,
			Decision:       "deny",
			Reasons:        []string{reason},
			DenyCategories: categorize([]string{reason}),
			RiskScore:      0,
			RiskLevel:      "low",
			LatencyMs:      time.Since(start).Milliseconds(),
		})
		return
	}

	// ── 1. Analyze query ──────────────────────────────────────────────────
	analysis, err := h.analyzer.Analyze(r.Context(), req.Query)
	if err != nil {
		reason := "analyzer unavailable: failing closed"
		auditFailClosed(eventID, claims, req.Query, sessionID, reason, start)
		respondDeny(w, http.StatusServiceUnavailable, eventID, []string{reason}, 10, "high", start)
		return
	}

	// ── 2. Evaluate policy (OPA) ──────────────────────────────────────────
	opaInput := client.OPAInput{
		Agent: client.OPAAgent{
			AgentID:     claims.AgentID,
			OwnerUserID: claims.OwnerUserID,
			TenantID:    claims.TenantID,
			Roles:       claims.Roles,
			Scopes:      claims.Scopes,
		},
		Analysis: analysis,
	}

	decision, err := h.opa.Evaluate(r.Context(), opaInput)
	if err != nil {
		reason := "policy engine unavailable: failing closed"
		auditFailClosed(eventID, claims, req.Query, sessionID, reason, start)
		respondDeny(w, http.StatusServiceUnavailable, eventID, []string{reason}, 10, "high", start)
		return
	}

	// ── 3. Enforce ────────────────────────────────────────────────────────
	if !decision.Allow {
		reasons := decision.Deny
		if len(reasons) == 0 {
			reasons = []string{"denied by policy"}
		}
		audit.Log(audit.Event{
			EventID: eventID, Timestamp: time.Now(),
			AgentID: claims.AgentID, OwnerUserID: claims.OwnerUserID, TenantID: claims.TenantID,
			QueryOriginal: req.Query, QueryType: analysis.QueryType,
			TablesAccessed: analysis.Tables, PolicyDecision: "deny", PolicyReasons: reasons,
			RiskScore: decision.RiskScore, RiskLevel: decision.RiskLevel,
			LatencyMs: time.Since(start).Milliseconds(), SessionID: sessionID,
		})
		go webhook.Send(h.webhookURL, webhook.BlockEvent{
			EventID: eventID, AgentID: claims.AgentID, TenantID: claims.TenantID,
			Query: req.Query, Reasons: reasons,
			RiskScore: decision.RiskScore, RiskLevel: decision.RiskLevel,
			Timestamp: time.Now().UTC().Format(time.RFC3339),
		})
		respondDeny(w, http.StatusForbidden, eventID, reasons, decision.RiskScore, decision.RiskLevel, start)
		return
	}

	// ── 4. Execute via proxy ──────────────────────────────────────────────
	result, err := h.proxy.Execute(r.Context(), client.ExecuteRequest{
		Query:    req.Query,
		AgentID:  claims.AgentID,
		TenantID: claims.TenantID,
	})
	if err != nil {
		auditFailClosed(eventID, claims, req.Query, sessionID, "proxy unavailable: failing closed", start)
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "proxy execution failed: upstream proxy unavailable"})
		return
	}

	audit.Log(audit.Event{
		EventID: eventID, Timestamp: time.Now(),
		AgentID: claims.AgentID, OwnerUserID: claims.OwnerUserID, TenantID: claims.TenantID,
		QueryOriginal: req.Query, QueryType: analysis.QueryType,
		TablesAccessed: analysis.Tables, PolicyDecision: "allow", PolicyReasons: decision.Deny,
		RiskScore: decision.RiskScore, RiskLevel: decision.RiskLevel,
		LatencyMs: time.Since(start).Milliseconds(), SessionID: sessionID,
	})

	resp := QueryResponse{
		EventID:   eventID,
		Decision:  "allow",
		RiskScore: decision.RiskScore,
		RiskLevel: decision.RiskLevel,
		Result:    result,
		LatencyMs: time.Since(start).Milliseconds(),
	}
	writeJSON(w, http.StatusOK, resp)
}

// respondDeny writes the deny response with the given HTTP status. Use 403 for
// policy denials and 5xx for infrastructure fail-closed denials so monitoring
// can distinguish the two.
func respondDeny(w http.ResponseWriter, status int, eventID string, reasons []string,
	riskScore int, riskLevel string, start time.Time) {
	writeJSON(w, status, QueryResponse{
		EventID:        eventID,
		Decision:       "deny",
		Reasons:        reasons,
		DenyCategories: categorize(reasons),
		RiskScore:      riskScore,
		RiskLevel:      riskLevel,
		LatencyMs:      time.Since(start).Milliseconds(),
	})
}

// auditFailClosed records fail-closed denies (analyzer/OPA unreachable). These
// must be logged so operators can see the system was actively refusing traffic
// during the outage, not silently passing it.
func auditFailClosed(eventID string, claims *mw.AgentClaims, query, sessionID, reason string, start time.Time) {
	audit.Log(audit.Event{
		EventID: eventID, Timestamp: time.Now(),
		AgentID: claims.AgentID, OwnerUserID: claims.OwnerUserID, TenantID: claims.TenantID,
		QueryOriginal: query, QueryType: "FAIL_CLOSED",
		PolicyDecision: "deny", PolicyReasons: []string{reason},
		RiskScore: 10, RiskLevel: "high",
		LatencyMs: time.Since(start).Milliseconds(), SessionID: sessionID,
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
