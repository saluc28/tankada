package audit

import (
	"encoding/json"
	"log"
	"os"
	"time"
)

type Event struct {
	EventID        string    `json:"event_id"`
	Timestamp      time.Time `json:"timestamp"`
	AgentID        string    `json:"agent_id"`
	OwnerUserID    string    `json:"owner_user_id"`
	TenantID       string    `json:"tenant_id"`
	QueryOriginal  string    `json:"query_original"`
	QueryType      string    `json:"query_type"`
	TablesAccessed []string  `json:"tables_accessed"`
	PolicyDecision string    `json:"policy_decision"`
	PolicyReasons  []string  `json:"policy_reasons,omitempty"`
	RiskScore      int       `json:"risk_score"`
	RiskLevel      string    `json:"risk_level"`
	LatencyMs      int64     `json:"latency_ms"`
	SessionID      string    `json:"session_id"`
}

var logger = log.New(os.Stdout, "", 0)

// Log writes an audit event as a single JSON line to stdout.
func Log(e Event) {
	b, err := json.Marshal(e)
	if err != nil {
		logger.Printf(`{"error":"audit marshal failed","event_id":%q}`, e.EventID)
		return
	}
	logger.Println(string(b))
}
