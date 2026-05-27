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
	"github.com/tankada/gateway/telemetry"
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
	MaskedColumns  []string                `json:"masked_columns,omitempty"`
	Shadow         *ShadowInfo             `json:"shadow,omitempty"`
	LatencyMs      int64                   `json:"latency_ms"`
}

// ShadowInfo is attached in shadow/observe mode (TANKADA_MODE=shadow) when the
// policy WOULD have denied the query. The query still ran (decision "allow"),
// but this records what enforcement would have done so operators can tune
// policies before turning enforcement on.
type ShadowInfo struct {
	WouldDeny      bool     `json:"would_deny"`
	Reasons        []string `json:"reasons,omitempty"`
	DenyCategories []string `json:"deny_categories,omitempty"`
}

type QueryHandler struct {
	analyzer   *client.AnalyzerClient
	opa        *client.OPAClient
	proxy      *client.ProxyClient
	limiter    *ratelimit.Limiter
	webhookURL string
	shadowMode bool
	telemetry  *telemetry.Reporter // C.2.b: nil-safe opt-in heartbeat counters
}

func NewQueryHandler(analyzerURL, opaURL, proxyURL, webhookURL string, limiter *ratelimit.Limiter, shadowMode bool, telem *telemetry.Reporter) *QueryHandler {
	return &QueryHandler{
		analyzer:   client.NewAnalyzer(analyzerURL),
		opa:        client.NewOPA(opaURL),
		proxy:      client.NewProxy(proxyURL),
		limiter:    limiter,
		webhookURL: webhookURL,
		shadowMode: shadowMode,
		telemetry:  telem,
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

	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
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
		cats := categorize([]string{reason})
		writeJSON(w, http.StatusTooManyRequests, QueryResponse{
			EventID:        eventID,
			Decision:       "deny",
			Reasons:        []string{reason},
			DenyCategories: cats,
			RiskScore:      0,
			RiskLevel:      "low",
			LatencyMs:      time.Since(start).Milliseconds(),
		})
		if len(cats) > 0 {
			h.telemetry.IncrDeny(cats[0])
		} else {
			h.telemetry.IncrDeny("")
		}
		return
	}

	// ── 1. Analyze query ──────────────────────────────────────────────────
	analysis, err := h.analyzer.Analyze(r.Context(), req.Query)
	if err != nil {
		reason := "analyzer unavailable: failing closed"
		auditFailClosed(eventID, claims, req.Query, sessionID, reason, start)
		respondDeny(w, http.StatusServiceUnavailable, eventID, []string{reason}, 10, "high", start, h.telemetry)
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
		respondDeny(w, http.StatusServiceUnavailable, eventID, []string{reason}, 10, "high", start, h.telemetry)
		return
	}

	// ── 3. Enforce (or observe, in shadow mode) ───────────────────────────
	var shadow *ShadowInfo
	if !decision.Allow {
		reasons := decision.Deny
		if len(reasons) == 0 {
			reasons = []string{"denied by policy"}
		}
		if !h.shadowMode {
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
			respondDeny(w, http.StatusForbidden, eventID, reasons, decision.RiskScore, decision.RiskLevel, start, h.telemetry)
			return
		}
		// Shadow/observe: record what enforcement WOULD have denied, then run the
		// query anyway so the operator can tune policies before turning on enforce.
		shadow = &ShadowInfo{WouldDeny: true, Reasons: reasons, DenyCategories: categorize(reasons)}
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

	// Redact PII columns in the result when the policy asked for masking
	// (pii_masking template). Masking applies only to allowed queries: the
	// query ran, but sensitive fields are returned redacted.
	maskedCols := applyMask(result, decision.Mask, decision.MaskValue)

	// Shadow-mode audit markers: tag the event so the report can tell which
	// allowed executions would actually have been denied under enforcement.
	mode, shadowDecision := "", ""
	auditReasons := decision.Deny
	if h.shadowMode {
		mode = "shadow"
		shadowDecision = "allow"
		if shadow != nil {
			shadowDecision = "deny"
			auditReasons = shadow.Reasons
		}
	}

	audit.Log(audit.Event{
		EventID: eventID, Timestamp: time.Now(),
		AgentID: claims.AgentID, OwnerUserID: claims.OwnerUserID, TenantID: claims.TenantID,
		QueryOriginal: req.Query, QueryType: analysis.QueryType,
		TablesAccessed: analysis.Tables, PolicyDecision: "allow", PolicyReasons: auditReasons,
		RiskScore: decision.RiskScore, RiskLevel: decision.RiskLevel,
		LatencyMs: time.Since(start).Milliseconds(), SessionID: sessionID,
		MaskedColumns:  maskedCols,
		Mode:           mode,
		ShadowDecision: shadowDecision,
	})

	resp := QueryResponse{
		EventID:       eventID,
		Decision:      "allow",
		RiskScore:     decision.RiskScore,
		RiskLevel:     decision.RiskLevel,
		Result:        result,
		MaskedColumns: maskedCols,
		Shadow:        shadow,
		LatencyMs:     time.Since(start).Milliseconds(),
	}

	// C.2.b: counters telemetry (nil-safe when telemetry is disabled).
	if shadow != nil && shadow.WouldDeny {
		h.telemetry.IncrShadow()
	} else {
		h.telemetry.IncrAllow()
	}

	writeJSON(w, http.StatusOK, resp)
}

// applyMask redacts, in place, every cell of result that belongs to a column
// named in maskCols (case-insensitive match against the result's own column
// names). It returns the list of column names actually redacted, in result
// column order, so the caller can report them. A nil/empty maskCols or result
// is a no-op. maskValue defaults to "***" when empty.
func applyMask(result *client.ExecuteResponse, maskCols []string, maskValue string) []string {
	if result == nil || len(maskCols) == 0 {
		return nil
	}
	if maskValue == "" {
		maskValue = "***"
	}

	want := make(map[string]bool, len(maskCols))
	for _, c := range maskCols {
		want[strings.ToLower(c)] = true
	}

	var idxs []int
	var masked []string
	for i, col := range result.Columns {
		if want[strings.ToLower(col)] {
			idxs = append(idxs, i)
			masked = append(masked, col)
		}
	}
	if len(idxs) == 0 {
		return nil
	}

	for _, row := range result.Rows {
		for _, i := range idxs {
			if i < len(row) {
				row[i] = maskValue
			}
		}
	}
	return masked
}

// respondDeny writes the deny response with the given HTTP status. Use 403 for
// policy denials and 5xx for infrastructure fail-closed denials so monitoring
// can distinguish the two. The Reporter is nil-safe (telemetry off) and the
// primary deny category is bumped for the heartbeat (C.2.b).
func respondDeny(w http.ResponseWriter, status int, eventID string, reasons []string,
	riskScore int, riskLevel string, start time.Time, telem *telemetry.Reporter) {
	cats := categorize(reasons)
	writeJSON(w, status, QueryResponse{
		EventID:        eventID,
		Decision:       "deny",
		Reasons:        reasons,
		DenyCategories: cats,
		RiskScore:      riskScore,
		RiskLevel:      riskLevel,
		LatencyMs:      time.Since(start).Milliseconds(),
	})
	if len(cats) > 0 {
		telem.IncrDeny(cats[0])
	} else {
		telem.IncrDeny("")
	}
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

// maxRequestBodyBytes caps the JSON body size accepted by /v1/query and
// /v1/explain. 1 MB is comfortably above any legitimate SQL payload (the
// largest common queries with embedded VALUES blocks stay well under 256 KB)
// and prevents memory-exhaustion DoS from a misbehaving or hostile client.
const maxRequestBodyBytes = 1 << 20

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
