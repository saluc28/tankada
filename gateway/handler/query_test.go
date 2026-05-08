package handler_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/tankada/gateway/handler"
	mw "github.com/tankada/gateway/middleware"
	"github.com/tankada/gateway/ratelimit"
)

// ── helpers ───────────────────────────────────────────────────────────────────

var defaultClaims = &mw.AgentClaims{
	AgentID:     "agent-test",
	OwnerUserID: "user-1",
	TenantID:    "tenant-1",
	Roles:       []string{"analyst"},
	Scopes:      []string{"customers:read"},
}

func withClaims(r *http.Request) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), mw.ClaimsKey, defaultClaims))
}

func queryReq(t *testing.T, query string) *http.Request {
	t.Helper()
	b, _ := json.Marshal(map[string]interface{}{
		"query":   query,
		"context": map[string]string{"session_id": "test-sess"},
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/query", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	return req
}

func newHandler(t *testing.T, analyzerURL, opaURL, proxyURL string) *handler.QueryHandler {
	t.Helper()
	return handler.NewQueryHandler(
		analyzerURL, opaURL, proxyURL, "",
		ratelimit.NewLimiter(100),
	)
}

func analyzerSrv(t *testing.T, analysis map[string]interface{}) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(analysis)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func opaSrv(t *testing.T, allow bool, deny []string, score int, level string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"result": map[string]interface{}{
				"allow":      allow,
				"deny":       deny,
				"risk_score": score,
				"risk_level": level,
			},
		})
	}))
	t.Cleanup(srv.Close)
	return srv
}

func proxySrv(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"columns":   []string{"id", "name"},
			"rows":      [][]interface{}{{1, "Alice"}},
			"row_count": 1,
		})
	}))
	t.Cleanup(srv.Close)
	return srv
}

func errSrv(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	return srv
}

var goodAnalysis = map[string]interface{}{
	"query_type": "SELECT",
	"tables":     []string{"users"},
	"has_where":  true,
}

// ── tests ─────────────────────────────────────────────────────────────────────

func TestHandle_MissingClaims_Returns401(t *testing.T) {
	h := newHandler(t, "http://unused", "http://unused", "http://unused")
	rr := httptest.NewRecorder()
	h.Handle(rr, queryReq(t, "SELECT 1"))
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
}

func TestHandle_EmptyQuery_Returns400(t *testing.T) {
	h := newHandler(t, "http://unused", "http://unused", "http://unused")
	b, _ := json.Marshal(map[string]string{"query": ""})
	req := httptest.NewRequest(http.MethodPost, "/v1/query", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req = withClaims(req)
	rr := httptest.NewRecorder()
	h.Handle(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
}

func TestHandle_InvalidJSON_Returns400(t *testing.T) {
	h := newHandler(t, "http://unused", "http://unused", "http://unused")
	req := httptest.NewRequest(http.MethodPost, "/v1/query", bytes.NewReader([]byte(`not json`)))
	req.Header.Set("Content-Type", "application/json")
	req = withClaims(req)
	rr := httptest.NewRecorder()
	h.Handle(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
}

func TestHandle_RateLimitExceeded_Returns429(t *testing.T) {
	limiter := ratelimit.NewLimiter(1)
	limiter.Allow("agent-test") // consume the single slot; next call will be denied
	h := handler.NewQueryHandler(
		"http://unused", "http://unused", "http://unused", "",
		limiter,
	)
	rr := httptest.NewRecorder()
	h.Handle(rr, withClaims(queryReq(t, "SELECT 1")))
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d", rr.Code)
	}
}

func TestHandle_AnalyzerDown_Returns503(t *testing.T) {
	h := newHandler(t, errSrv(t).URL, "http://unused", "http://unused")
	rr := httptest.NewRecorder()
	h.Handle(rr, withClaims(queryReq(t, "SELECT 1")))
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", rr.Code)
	}
}

func TestHandle_OPADown_Returns503(t *testing.T) {
	h := newHandler(t, analyzerSrv(t, goodAnalysis).URL, errSrv(t).URL, "http://unused")
	rr := httptest.NewRecorder()
	h.Handle(rr, withClaims(queryReq(t, "SELECT 1")))
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", rr.Code)
	}
}

func TestHandle_ProxyDown_Returns502(t *testing.T) {
	h := newHandler(t,
		analyzerSrv(t, goodAnalysis).URL,
		opaSrv(t, true, nil, 0, "low").URL,
		errSrv(t).URL,
	)
	rr := httptest.NewRecorder()
	h.Handle(rr, withClaims(queryReq(t, "SELECT 1")))
	if rr.Code != http.StatusBadGateway {
		t.Fatalf("expected 502, got %d", rr.Code)
	}
}

func TestHandle_QueryDeniedByOPA_Returns403WithReasons(t *testing.T) {
	h := newHandler(t,
		analyzerSrv(t, goodAnalysis).URL,
		opaSrv(t, false, []string{"tautology detected: WHERE 1=1"}, 5, "medium").URL,
		"http://unused",
	)
	rr := httptest.NewRecorder()
	h.Handle(rr, withClaims(queryReq(t, "SELECT * FROM users WHERE 1=1")))

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rr.Code)
	}
	var resp map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp["decision"] != "deny" {
		t.Fatalf("expected decision=deny, got %v", resp["decision"])
	}
	reasons, _ := resp["reasons"].([]interface{})
	if len(reasons) == 0 {
		t.Fatal("expected at least one deny reason in response")
	}
}

func TestHandle_QueryAllowed_Returns200WithResult(t *testing.T) {
	h := newHandler(t,
		analyzerSrv(t, goodAnalysis).URL,
		opaSrv(t, true, nil, 0, "low").URL,
		proxySrv(t).URL,
	)
	rr := httptest.NewRecorder()
	h.Handle(rr, withClaims(queryReq(t, "SELECT id, name FROM users")))

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d; body: %s", rr.Code, rr.Body.String())
	}
	var resp map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp["decision"] != "allow" {
		t.Fatalf("expected decision=allow, got %v", resp["decision"])
	}
	if resp["result"] == nil {
		t.Fatal("expected result to be present on allowed query")
	}
}
