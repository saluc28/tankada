package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type OPAInput struct {
	Agent    OPAAgent    `json:"agent"`
	Analysis interface{} `json:"analysis"`
}

type OPAAgent struct {
	AgentID     string   `json:"agent_id"`
	OwnerUserID string   `json:"owner_user_id"`
	TenantID    string   `json:"tenant_id"`
	Roles       []string `json:"roles"`
	Scopes      []string `json:"scopes"`
}

type OPAResult struct {
	Allow     bool     `json:"allow"`
	Deny      []string `json:"deny"`
	RiskScore int      `json:"risk_score"`
	RiskLevel string   `json:"risk_level"`
}

type OPAClient struct {
	baseURL string
	http    *http.Client
}

func NewOPA(baseURL string) *OPAClient {
	return &OPAClient{
		baseURL: baseURL,
		http:    &http.Client{Timeout: 3 * time.Second},
	}
}

func (c *OPAClient) Evaluate(ctx context.Context, input OPAInput) (*OPAResult, error) {
	payload := map[string]interface{}{"input": input}
	body, _ := json.Marshal(payload)

	url := c.baseURL + "/v1/data/tankada/query"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("OPA unreachable: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OPA returned %d", resp.StatusCode)
	}

	var wrapper struct {
		Result OPAResult `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&wrapper); err != nil {
		return nil, fmt.Errorf("OPA response decode: %w", err)
	}
	return &wrapper.Result, nil
}
