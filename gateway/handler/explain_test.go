package handler_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/tankada/gateway/handler"
)

func TestExplain_MissingClaims_Returns401(t *testing.T) {
	h := handler.NewExplainHandler("http://unused", "http://unused")
	body, _ := json.Marshal(map[string]string{"query": "SELECT 1"})
	req := httptest.NewRequest(http.MethodPost, "/v1/explain", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	h.Handle(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 when claims are nil, got %d (regression for issue #2: explain handler must guard against nil claims to avoid panic)", rr.Code)
	}
}
