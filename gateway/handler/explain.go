package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/tankada/gateway/client"
	mw "github.com/tankada/gateway/middleware"
)

type ExplainRequest struct {
	Query string `json:"query"`
}

type ExplainResponse struct {
	Allowed     bool     `json:"allowed"`
	DenyReasons []string `json:"deny_reasons,omitempty"`
	Suggestions []string `json:"suggestions,omitempty"`
	RiskScore   int      `json:"risk_score"`
	RiskLevel   string   `json:"risk_level"`
}

type ExplainHandler struct {
	analyzer *client.AnalyzerClient
	opa      *client.OPAClient
}

func NewExplainHandler(analyzerURL, opaURL string) *ExplainHandler {
	return &ExplainHandler{
		analyzer: client.NewAnalyzer(analyzerURL),
		opa:      client.NewOPA(opaURL),
	}
}

func (h *ExplainHandler) Handle(w http.ResponseWriter, r *http.Request) {
	claims := mw.ClaimsFromCtx(r.Context())
	if claims == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing claims"})
		return
	}

	var req ExplainRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Query == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing query"})
		return
	}

	ctx := r.Context()

	analysis, err := h.analyzer.Analyze(ctx, req.Query)
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "analyzer unavailable"})
		return
	}

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

	policy, err := h.opa.Evaluate(ctx, opaInput)
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "OPA unavailable"})
		return
	}

	suggestions := suggestionsFor(policy.Deny, claims.TenantID)

	writeJSON(w, http.StatusOK, ExplainResponse{
		Allowed:     policy.Allow,
		DenyReasons: policy.Deny,
		Suggestions: suggestions,
		RiskScore:   policy.RiskScore,
		RiskLevel:   policy.RiskLevel,
	})
}

func suggestionsFor(reasons []string, tenantID string) []string {
	out := make([]string, 0, len(reasons))
	for _, r := range reasons {
		out = append(out, suggestionFor(r, tenantID))
	}
	return out
}

func suggestionFor(reason, tenantID string) string {
	switch {
	case strings.HasPrefix(reason, "destructive operation"):
		return "Use SELECT instead. Write operations (DELETE, DROP, TRUNCATE, ALTER) are not permitted."
	case strings.HasPrefix(reason, "query parse failed"):
		return "Fix the SQL syntax error before sending the query."
	case reason == "multi-statement query blocked: SQL injection chain pattern detected":
		return "Send one SQL statement at a time. Multiple statements separated by ';' are not allowed."
	case reason == "schema enumeration query blocked (agent reconnaissance pattern)":
		return "Queries against system catalogs (information_schema, pg_tables, pg_catalog) are not allowed."
	case strings.HasPrefix(reason, "query accesses PII columns"):
		return "Request the 'customers:read' or 'cards:read' scope to access PII columns (email, ssn, card_number, etc.)."
	case strings.HasPrefix(reason, "query must filter by tenant_id"):
		return fmt.Sprintf("Add WHERE tenant_id = '%s' to your query. Every query on tenant-scoped tables must include this filter.", tenantID)
	case reason == "SELECT without WHERE clause on a named table":
		return "Add a WHERE clause to narrow the result set. Unbounded SELECT is not allowed."
	case strings.HasPrefix(reason, "access to sensitive table"):
		return "Request elevated scope ('customers:read' or 'cards:read') to access this table."
	case strings.HasPrefix(reason, "risk score"):
		return "Reduce query risk: avoid SELECT *, add a LIMIT clause, remove UNION, avoid SQL comments, avoid ORDER BY RANDOM()."
	case reason == "WHERE clause is a tautology (e.g. 1=1)":
		return "Remove the tautological condition from the WHERE clause (e.g. '1=1', 'TRUE', 'id=id')."
	default:
		return "Review your query against the security policy."
	}
}
