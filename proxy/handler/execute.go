package handler

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/tankada/proxy/db"
)

type ExecuteRequest struct {
	Query    string `json:"query"`
	AgentID  string `json:"agent_id"`
	TenantID string `json:"tenant_id"`
}

// blockedTypes are rejected at the proxy level regardless of what the gateway says.
// This is the defense-in-depth enforcement layer.
var blockedTypes = []string{"DELETE ", "DROP ", "TRUNCATE ", "ALTER ", "INSERT ", "UPDATE ", "CREATE "}

func Execute(w http.ResponseWriter, r *http.Request) {
	var req ExecuteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request body")
		return
	}

	query := strings.TrimSpace(req.Query)
	if query == "" {
		writeErr(w, http.StatusBadRequest, "query cannot be empty")
		return
	}

	// Defense in depth: reject any write operation unconditionally
	upper := strings.ToUpper(query)
	for _, blocked := range blockedTypes {
		if strings.HasPrefix(upper, blocked) {
			writeErr(w, http.StatusForbidden, "write operations are not permitted via this proxy")
			return
		}
	}

	result, err := db.Execute(r.Context(), query)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "query execution failed: "+err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
