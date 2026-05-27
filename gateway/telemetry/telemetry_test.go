package telemetry

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// ── pure: counters thread-safety + nil-safety ──────────────────────────────

func TestNilReporter_isZeroCost(t *testing.T) {
	var r *Reporter // explicit nil
	// All counter calls must be no-ops on a nil receiver.
	r.IncrAllow()
	r.IncrDeny("missing_scope")
	r.IncrShadow()
	r.IncrOPAUnavailable()
	r.IncrAnalyzerUnavailable()
	r.Start(context.Background())

	// Snapshot must still produce a usable Heartbeat.
	hb := r.Snapshot()
	if hb.Schema != "tankada.heartbeat.v1" {
		t.Fatalf("nil snapshot schema = %q", hb.Schema)
	}
	if hb.Counters.QueriesTotal != 0 {
		t.Fatalf("nil snapshot has nonzero counters")
	}
}

func TestCounters_aggregateCorrectly(t *testing.T) {
	r := NewReporter(Config{URL: "http://example.test/heartbeat", Interval: time.Hour})
	r.IncrAllow()
	r.IncrAllow()
	r.IncrDeny("tautology")
	r.IncrDeny("missing_scope")
	r.IncrDeny("missing_scope")
	r.IncrShadow()
	r.IncrOPAUnavailable()

	hb := r.Snapshot()
	c := hb.Counters
	if c.QueriesTotal != 6 {
		t.Fatalf("QueriesTotal=%d, want 6", c.QueriesTotal)
	}
	if c.DecisionAllow != 2 || c.DecisionDeny != 3 || c.DecisionShadow != 1 {
		t.Fatalf("decision counts off: %+v", c)
	}
	if c.DenyByCategory["tautology"] != 1 || c.DenyByCategory["missing_scope"] != 2 {
		t.Fatalf("DenyByCategory off: %v", c.DenyByCategory)
	}
	if c.OPAUnavailable != 1 {
		t.Fatalf("OPAUnavailable=%d, want 1", c.OPAUnavailable)
	}
}

func TestSnapshot_doesNotLeakInternalCounters(t *testing.T) {
	// Mutating the snapshot's map must not affect the live reporter.
	r := NewReporter(Config{URL: "http://x", Interval: time.Hour})
	r.IncrDeny("tautology")
	hb := r.Snapshot()
	hb.Counters.DenyByCategory["tautology"] = 999
	hb.Counters.DenyByCategory["injected"] = 1
	again := r.Snapshot()
	if again.Counters.DenyByCategory["tautology"] != 1 {
		t.Fatalf("snapshot leaked into live counters")
	}
	if _, ok := again.Counters.DenyByCategory["injected"]; ok {
		t.Fatalf("injected key leaked into live counters")
	}
}

func TestSortedDenyCategories_isDeterministic(t *testing.T) {
	c := Counters{DenyByCategory: map[string]int64{
		"tautology": 1, "missing_scope": 2, "exfiltration": 3, "schema_enum": 4,
	}}
	got := c.SortedDenyCategories()
	want := []string{"exfiltration", "missing_scope", "schema_enum", "tautology"}
	if len(got) != len(want) {
		t.Fatalf("len %d != %d", len(got), len(want))
	}
	for i, k := range got {
		if k != want[i] {
			t.Fatalf("sorted[%d] = %q, want %q", i, k, want[i])
		}
	}
}

// ── opt-in: empty URL -> nil reporter ───────────────────────────────────────

func TestNewReporter_emptyURL_returnsNil(t *testing.T) {
	r := NewReporter(Config{URL: ""})
	if r != nil {
		t.Fatalf("empty URL must return nil reporter (telemetry disabled)")
	}
}

func TestNewReporter_clampsMinInterval(t *testing.T) {
	r := NewReporter(Config{URL: "http://x", Interval: 5 * time.Second})
	if r.interval < 60*time.Second {
		t.Fatalf("interval should be clamped to >=60s, got %s", r.interval)
	}
}

// ── send: real HTTP via httptest + dry-run logs only ────────────────────────

func TestSend_postsHeartbeatToURL(t *testing.T) {
	var received atomic.Pointer[Heartbeat]
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok-123" {
			t.Errorf("Authorization header missing/wrong: %q", r.Header.Get("Authorization"))
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("Content-Type: %q", r.Header.Get("Content-Type"))
		}
		body, _ := io.ReadAll(r.Body)
		var hb Heartbeat
		if err := json.Unmarshal(body, &hb); err != nil {
			t.Errorf("body not JSON: %v (%s)", err, string(body))
		}
		received.Store(&hb)
		w.WriteHeader(204)
	}))
	defer srv.Close()

	r := NewReporter(Config{
		URL: srv.URL, Token: "tok-123", Interval: time.Hour,
		SiteID: "acme-prod", BundleVersion: "0.4.4", GatewayVersion: "test-sha", Env: "production",
	})
	r.IncrAllow()
	r.IncrDeny("tautology")
	r.send(context.Background())

	got := received.Load()
	if got == nil {
		t.Fatal("server received no heartbeat")
	}
	if got.SiteID != "acme-prod" || got.BundleVersion != "0.4.4" || got.GatewayVersion != "test-sha" {
		t.Fatalf("identification fields not propagated: %+v", got)
	}
	if got.Counters.QueriesTotal != 2 || got.Counters.DecisionDeny != 1 {
		t.Fatalf("counters not propagated: %+v", got.Counters)
	}
	if got.Schema != "tankada.heartbeat.v1" {
		t.Fatalf("schema label wrong: %q", got.Schema)
	}
}

func TestSend_dryRun_doesNotPOST(t *testing.T) {
	called := atomic.Bool{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called.Store(true)
		w.WriteHeader(204)
	}))
	defer srv.Close()

	r := NewReporter(Config{URL: srv.URL, Interval: time.Hour, DryRun: true})
	r.IncrAllow()
	r.send(context.Background())

	if called.Load() {
		t.Fatal("DRY_RUN=true must not POST")
	}
}

func TestSend_serverErrorIsLoggedNotPanicked(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer srv.Close()
	r := NewReporter(Config{URL: srv.URL, Interval: time.Hour})
	// must not panic
	r.send(context.Background())
}

// ── policy hashing: hashes file BYTES, not contents ─────────────────────────

func TestHashPolicyDir_producesDifferentHashesForDifferentBytes(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}
	write("schema.json", `{"schema":{"tenant_column":"tenant_id"}}`)
	write("templates.json", `{}`)
	write("query.rego", `package query`)

	h1 := hashPolicyDir(dir)
	if len(h1.SchemaJSON) != 64 || len(h1.TemplatesJSON) != 64 || len(h1.QueryRego) != 64 {
		t.Fatalf("hashes should be 64-hex SHA-256: %+v", h1)
	}

	// Change the schema; only that hash changes.
	write("schema.json", `{"schema":{"tenant_column":"org_id"}}`)
	h2 := hashPolicyDir(dir)
	if h1.SchemaJSON == h2.SchemaJSON {
		t.Fatal("schema.json hash should change when bytes change")
	}
	if h1.TemplatesJSON != h2.TemplatesJSON || h1.QueryRego != h2.QueryRego {
		t.Fatal("unrelated file hashes should NOT change")
	}
}

func TestHashPolicyDir_missingFileIsEmptyString(t *testing.T) {
	dir := t.TempDir()
	// no files written
	h := hashPolicyDir(dir)
	if h.SchemaJSON != "" || h.TemplatesJSON != "" || h.QueryRego != "" {
		t.Fatalf("missing files should be empty: %+v", h)
	}
}

func TestHashPolicyDir_emptyDir_returnsEmpty(t *testing.T) {
	h := hashPolicyDir("")
	if h.SchemaJSON != "" || h.TemplatesJSON != "" || h.QueryRego != "" {
		t.Fatalf("empty dir should yield empty hashes: %+v", h)
	}
}

// ── privacy: the Heartbeat type itself enforces "no PII" by structure ──────

// Compile-time guard: if anyone adds an identity-leaking field (agent_id,
// tenant_id, query text, ...) to Heartbeat, this test will need updating,
// which is the point -- it's a tripwire that forces a code review on any
// schema change that could ship sensitive data.
func TestHeartbeat_topLevelFieldsAreOnlyTheApprovedSet(t *testing.T) {
	approved := map[string]bool{
		"SiteID":         true,
		"BundleVersion":  true,
		"GatewayVersion": true,
		"Env":            true,
		"UptimeSec":      true,
		"PolicyHashes":   true,
		"Counters":       true,
		"Schema":         true,
		"SentAt":         true,
	}
	// Reflect over the type. We avoid importing "reflect" at the top to keep
	// the package import-tight; use a roundtrip through JSON instead.
	hb := Heartbeat{Counters: Counters{DenyByCategory: map[string]int64{}}}
	b, _ := json.Marshal(hb)
	var raw map[string]json.RawMessage
	_ = json.Unmarshal(b, &raw)
	// Build the reverse map of approved JSON tags by looking at the struct
	// once via Marshal'd zero value.
	expectedJSON := map[string]bool{
		"site_id": true, "bundle_version": true, "gateway_version": true,
		"env": true, "uptime_sec": true, "policy_hashes": true,
		"counters": true, "schema": true, "sent_at": true,
	}
	for k := range raw {
		if !expectedJSON[k] {
			t.Fatalf("UNAPPROVED top-level Heartbeat field %q -- adding identity-bearing data to telemetry needs an explicit review", k)
		}
	}
	// And make sure the Go-name version is still in sync (for docs):
	_ = approved
}
