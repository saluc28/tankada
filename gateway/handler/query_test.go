package handler_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

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
		false,
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
		false,
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
	var resp map[string]string
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !strings.Contains(resp["error"], "proxy") {
		t.Fatalf("expected error message to mention 'proxy' (regression for issue #3: error must identify which upstream failed), got %q", resp["error"])
	}
}

func TestHandle_QueryDeniedByOPA_Returns403WithReasons(t *testing.T) {
	h := newHandler(t,
		analyzerSrv(t, goodAnalysis).URL,
		opaSrv(t, false, []string{"WHERE clause is a tautology (e.g. 1=1)"}, 5, "medium").URL,
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
	cats, _ := resp["deny_categories"].([]interface{})
	if len(cats) != 1 || cats[0] != "tautology" {
		t.Fatalf("expected deny_categories=[tautology] for tautology reason, got %v", cats)
	}
}

// ── JWT v1 / v2 end-to-end (middleware + handler) ─────────────────────────────

const testJWTSecret = "test-secret"

func signToken(t *testing.T, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	s, err := tok.SignedString([]byte(testJWTSecret))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return s
}

func captureOPA(t *testing.T, captured *[]string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var payload struct {
			Input struct {
				Agent struct {
					Scopes []string `json:"scopes"`
				} `json:"agent"`
			} `json:"input"`
		}
		_ = json.Unmarshal(body, &payload)
		*captured = payload.Input.Agent.Scopes

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"result": map[string]interface{}{
				"allow": true, "deny": []string{}, "risk_score": 0, "risk_level": "low",
			},
		})
	}))
	t.Cleanup(srv.Close)
	return srv
}

func chainWithJWT(h *handler.QueryHandler) http.Handler {
	return mw.JWT(mw.NewHS256Verifier(testJWTSecret))(http.HandlerFunc(h.Handle))
}

func TestHandle_JWTv1Legacy_PassesScopesThroughUnchanged(t *testing.T) {
	var seen []string
	h := newHandler(t,
		analyzerSrv(t, goodAnalysis).URL,
		captureOPA(t, &seen).URL,
		proxySrv(t).URL,
	)
	now := time.Now()
	tok := signToken(t, jwt.MapClaims{
		"sub": "analyst-agent", "agent_id": "analyst-agent", "tenant_id": "tenant_1",
		"roles":  []string{"analyst"},
		"scopes": []string{"accounts:read", "transactions:read"},
		"iat":    now.Unix(),
		"exp":    now.Add(time.Hour).Unix(),
	})

	req := queryReq(t, "SELECT id FROM accounts")
	req.Header.Set("Authorization", "Bearer "+tok)
	rr := httptest.NewRecorder()
	chainWithJWT(h).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d; body=%s", rr.Code, rr.Body.String())
	}
	want := []string{"accounts:read", "transactions:read"}
	if !sortedEqualScopes(seen, want) {
		t.Fatalf("v1 scopes must reach OPA unchanged: got %v want %v", seen, want)
	}
}

func TestHandle_JWTv2_DataActionsResolvedToFlatScopes(t *testing.T) {
	var seen []string
	h := newHandler(t,
		analyzerSrv(t, goodAnalysis).URL,
		captureOPA(t, &seen).URL,
		proxySrv(t).URL,
	)
	now := time.Now()
	tok := signToken(t, jwt.MapClaims{
		"sub": "analyst-agent", "agent_id": "analyst-agent", "tenant_id": "tenant_1",
		"roles":          []string{"analyst"},
		"dataActions":    []string{"tenant_1/financial/accounts/read", "tenant_1/financial/transactions/read"},
		"notDataActions": []string{},
		"iat":            now.Unix(),
		"exp":            now.Add(time.Hour).Unix(),
	})

	req := queryReq(t, "SELECT id FROM accounts")
	req.Header.Set("Authorization", "Bearer "+tok)
	rr := httptest.NewRecorder()
	chainWithJWT(h).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d; body=%s", rr.Code, rr.Body.String())
	}
	want := []string{"accounts:read", "transactions:read"}
	if !sortedEqualScopes(seen, want) {
		t.Fatalf("v2 must resolve to flat scopes: got %v want %v", seen, want)
	}
}

func TestHandle_JWTv2_WildcardAndNotDataActions(t *testing.T) {
	var seen []string
	h := newHandler(t,
		analyzerSrv(t, goodAnalysis).URL,
		captureOPA(t, &seen).URL,
		proxySrv(t).URL,
	)
	now := time.Now()
	tok := signToken(t, jwt.MapClaims{
		"sub": "admin-agent", "agent_id": "admin-agent", "tenant_id": "tenant_1",
		"roles":          []string{"admin"},
		"dataActions":    []string{"tenant_1/*/*/read"},
		"notDataActions": []string{"tenant_1/financial/customers/read", "tenant_1/financial/cards/read"},
		"iat":            now.Unix(),
		"exp":            now.Add(time.Hour).Unix(),
	})

	req := queryReq(t, "SELECT id FROM accounts")
	req.Header.Set("Authorization", "Bearer "+tok)
	rr := httptest.NewRecorder()
	chainWithJWT(h).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d; body=%s", rr.Code, rr.Body.String())
	}
	want := []string{"accounts:read", "transactions:read", "loans:read"}
	if !sortedEqualScopes(seen, want) {
		t.Fatalf("v2 wildcard - exclusions: got %v want %v", seen, want)
	}
}

func TestHandle_JWTv2_CrossTenantScopeIgnored(t *testing.T) {
	var seen []string
	h := newHandler(t,
		analyzerSrv(t, goodAnalysis).URL,
		captureOPA(t, &seen).URL,
		proxySrv(t).URL,
	)
	now := time.Now()
	tok := signToken(t, jwt.MapClaims{
		"sub": "evil-agent", "agent_id": "evil-agent", "tenant_id": "tenant_1",
		"roles":       []string{"analyst"},
		"dataActions": []string{"globobank/financial/accounts/read"},
		"iat":         now.Unix(),
		"exp":         now.Add(time.Hour).Unix(),
	})

	req := queryReq(t, "SELECT id FROM accounts")
	req.Header.Set("Authorization", "Bearer "+tok)
	rr := httptest.NewRecorder()
	chainWithJWT(h).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 (OPA mock allows), got %d; body=%s", rr.Code, rr.Body.String())
	}
	if len(seen) != 0 {
		t.Fatalf("cross-tenant scope must be dropped before OPA: got %v", seen)
	}
}

func sortedEqualScopes(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	m := map[string]int{}
	for _, x := range a {
		m[x]++
	}
	for _, y := range b {
		m[y]--
	}
	for _, v := range m {
		if v != 0 {
			return false
		}
	}
	return true
}

func opaSrvMask(t *testing.T, mask []string, maskValue string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"result": map[string]interface{}{
				"allow": true, "deny": []string{}, "risk_score": 0, "risk_level": "low",
				"mask": mask, "mask_value": maskValue,
			},
		})
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestHandle_QueryAllowed_MasksPIIColumns(t *testing.T) {
	// proxySrv returns columns [id, name] with row {1, "Alice"}; ask to mask "name".
	h := newHandler(t,
		analyzerSrv(t, goodAnalysis).URL,
		opaSrvMask(t, []string{"name"}, "***").URL,
		proxySrv(t).URL,
	)
	rr := httptest.NewRecorder()
	h.Handle(rr, withClaims(queryReq(t, "SELECT id, name FROM users")))
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d; body: %s", rr.Code, rr.Body.String())
	}
	var resp struct {
		MaskedColumns []string `json:"masked_columns"`
		Result        struct {
			Columns []string        `json:"columns"`
			Rows    [][]interface{} `json:"rows"`
		} `json:"result"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.MaskedColumns) != 1 || resp.MaskedColumns[0] != "name" {
		t.Fatalf("expected masked_columns=[name], got %v", resp.MaskedColumns)
	}
	if got := resp.Result.Rows[0][1]; got != "***" {
		t.Fatalf("expected name redacted to ***, got %v", got)
	}
	if got := resp.Result.Rows[0][0]; got == "***" {
		t.Fatalf("id should not be masked, got %v", got)
	}
}

func TestHandle_ShadowMode_DeniedQueryExecutesWithShadowFlag(t *testing.T) {
	// OPA denies, but shadow mode must NOT block: run the query and flag it.
	h := handler.NewQueryHandler(
		analyzerSrv(t, goodAnalysis).URL,
		opaSrv(t, false, []string{"WHERE clause is a tautology (e.g. 1=1)"}, 5, "medium").URL,
		proxySrv(t).URL,
		"", ratelimit.NewLimiter(100), true,
	)
	rr := httptest.NewRecorder()
	h.Handle(rr, withClaims(queryReq(t, "SELECT * FROM users WHERE 1=1")))
	if rr.Code != http.StatusOK {
		t.Fatalf("shadow mode must not block: got %d body=%s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Decision string `json:"decision"`
		Shadow   *struct {
			WouldDeny      bool     `json:"would_deny"`
			DenyCategories []string `json:"deny_categories"`
		} `json:"shadow"`
		Result map[string]interface{} `json:"result"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Decision != "allow" {
		t.Fatalf("expected decision=allow in shadow, got %q", resp.Decision)
	}
	if resp.Shadow == nil || !resp.Shadow.WouldDeny {
		t.Fatal("expected shadow.would_deny=true")
	}
	if len(resp.Shadow.DenyCategories) != 1 || resp.Shadow.DenyCategories[0] != "tautology" {
		t.Fatalf("expected shadow deny_categories=[tautology], got %v", resp.Shadow)
	}
	if resp.Result == nil {
		t.Fatal("shadow mode must still return the executed result")
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
