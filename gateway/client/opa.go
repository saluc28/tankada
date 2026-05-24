package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
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
	// Mask is the set of column names the gateway must redact in the proxy
	// result before returning it (pii_masking template). Empty when masking is
	// disabled or the agent is allowed to see PII in clear.
	Mask      []string `json:"mask"`
	// MaskValue is the placeholder substituted for each masked cell.
	MaskValue string   `json:"mask_value"`
}

type OPAClient struct {
	baseURL string
	http    *http.Client
}

func NewOPA(baseURL string) *OPAClient {
	return &OPAClient{
		baseURL: baseURL,
		http:    sharedHTTPClient(3 * time.Second),
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
	// Drain before close so the keep-alive connection can be reused.
	defer func() {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}()

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
