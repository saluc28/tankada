package webhook

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"time"
)

type BlockEvent struct {
	EventID   string   `json:"event_id"`
	AgentID   string   `json:"agent_id"`
	TenantID  string   `json:"tenant_id"`
	Query     string   `json:"query"`
	Reasons   []string `json:"reasons"`
	RiskScore int      `json:"risk_score"`
	RiskLevel string   `json:"risk_level"`
	Timestamp string   `json:"timestamp"`
}

var httpClient = &http.Client{Timeout: 5 * time.Second}

// Send posts a BlockEvent to url. Runs in its own goroutine — never blocks the
// query response path. Silently drops the notification if url is empty or the
// request fails.
func Send(url string, event BlockEvent) {
	if url == "" {
		return
	}
	body, err := json.Marshal(event)
	if err != nil {
		return
	}
	resp, err := httpClient.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		log.Printf("webhook: delivery failed: %v", err)
		return
	}
	resp.Body.Close()
}
