// Package telemetry is the Tankada gateway's opt-in heartbeat reporter (C.2.b).
//
// What it sends: bundle version, gateway version, uptime, env (production /
// staging / development), policy bundle hash, aggregate counters (queries
// allowed / denied / shadow, by deny category), and a customer-supplied site
// id. Counters are in-process aggregates only -- nothing identifies an agent,
// a tenant, a user, a table, a column, or a query string. Hashes are over
// policy files (schema.json, templates.json, query.rego), not data.
//
// What it never sends: SQL text, tenant_id, agent_id, owner_user_id, table /
// column names, audit log lines, JWT/secrets, DB connection strings, row
// samples. The "what we send" struct is the entire surface; if you want to
// audit, the dry-run mode (TANKADA_TELEMETRY_DRY_RUN=true) prints the exact
// JSON to the gateway log instead of POSTing it.
//
// Opt-in: TANKADA_TELEMETRY_URL must be set for telemetry to do anything.
// Empty URL -> the reporter is a no-op (NewReporter returns nil-with-stats).
// Default in compose is empty.
package telemetry

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// Heartbeat is the exact JSON payload sent to TANKADA_TELEMETRY_URL. Adding
// any field to this struct ships it to the vendor -- think twice on every add.
// In particular: NO field here may identify an agent, a tenant, an end user, a
// specific table/column/query, or contain a sample of data. Hashes only.
type Heartbeat struct {
	// Identification (vendor-side bookkeeping; customer-controlled).
	SiteID         string `json:"site_id"`          // operator-supplied label, e.g. "acme-prod"
	BundleVersion  string `json:"bundle_version"`   // from deploy/VERSION
	GatewayVersion string `json:"gateway_version"`  // build-time string, set at compile time
	Env            string `json:"env"`              // TANKADA_ENV value
	UptimeSec      int64  `json:"uptime_sec"`       // since process start

	// Policy bundle fingerprint (so the vendor knows which schema/policy is
	// live without ever seeing the contents).
	PolicyHashes PolicyHashes `json:"policy_hashes"`

	// Aggregate counters since process start. Sums, not rates; the vendor
	// computes rates over the heartbeat interval.
	Counters Counters `json:"counters"`

	// Self-describing metadata for the receiver.
	Schema    string    `json:"schema"`     // always "tankada.heartbeat.v1"
	SentAt    time.Time `json:"sent_at"`
}

// PolicyHashes carries SHA-256 digests of the live policy files. Empty hash =
// file not present. Hashes change on every edit, giving the vendor "which
// rev of the policy is active" without ever needing the file's contents.
type PolicyHashes struct {
	SchemaJSON    string `json:"schema_json,omitempty"`
	TemplatesJSON string `json:"templates_json,omitempty"`
	QueryRego     string `json:"query_rego,omitempty"`
}

// Counters are the cumulative-since-boot counts the gateway exposes. By
// category, not by identity: "how many denies" not "who got denied".
type Counters struct {
	QueriesTotal       int64            `json:"queries_total"`
	DecisionAllow      int64            `json:"decision_allow"`
	DecisionDeny       int64            `json:"decision_deny"`
	DecisionShadow     int64            `json:"decision_shadow"`     // D.5 mode: would-deny but executed
	DenyByCategory     map[string]int64 `json:"deny_by_category"`    // tautology / select_star / missing_scope / ...
	OPAUnavailable     int64            `json:"opa_unavailable"`
	AnalyzerUnavailable int64           `json:"analyzer_unavailable"`
}

// ── Reporter ─────────────────────────────────────────────────────────────────

// Reporter holds the thread-safe counters + the network knobs to ship them.
// One Reporter per process. Nil-safe: calls on a nil Reporter are no-ops, so
// the query handler can blindly call r.IncrAllow() without nil checks.
type Reporter struct {
	url        string
	token      string
	interval   time.Duration
	dryRun     bool
	siteID     string
	policyDir  string
	bundleVer  string
	gatewayVer string
	env        string
	startedAt  time.Time
	http       *http.Client

	mu       sync.Mutex
	counters Counters
}

// Config is what main.go passes in. Empty URL means "telemetry disabled".
type Config struct {
	URL            string        // TANKADA_TELEMETRY_URL; empty disables
	Token          string        // TANKADA_TELEMETRY_TOKEN; sent as Bearer
	Interval       time.Duration // heartbeat period; minimum 60s honored
	DryRun         bool          // TANKADA_TELEMETRY_DRY_RUN; logs JSON instead of POST
	SiteID         string        // TANKADA_SITE_ID; operator-chosen label
	PolicyDir      string        // where to hash schema.json / templates.json / query.rego
	BundleVersion  string        // from deploy/VERSION baked in or read at boot
	GatewayVersion string        // -ldflags-injected build SHA, or "dev"
	Env            string        // TANKADA_ENV
}

// NewReporter builds a reporter; returns nil if telemetry is disabled (so the
// caller can hold a *Reporter without branching on every counter call).
func NewReporter(cfg Config) *Reporter {
	if cfg.URL == "" {
		return nil
	}
	if cfg.Interval < 60*time.Second {
		cfg.Interval = 60 * time.Second
	}
	return &Reporter{
		url:        cfg.URL,
		token:      cfg.Token,
		interval:   cfg.Interval,
		dryRun:     cfg.DryRun,
		siteID:     cfg.SiteID,
		policyDir:  cfg.PolicyDir,
		bundleVer:  cfg.BundleVersion,
		gatewayVer: cfg.GatewayVersion,
		env:        cfg.Env,
		startedAt:  time.Now(),
		http:       &http.Client{Timeout: 10 * time.Second},
		counters:   Counters{DenyByCategory: map[string]int64{}},
	}
}

// Start spawns the background heartbeat loop. Returns immediately; the goroutine
// honors ctx.Done() for shutdown. Nil-safe.
func (r *Reporter) Start(ctx context.Context) {
	if r == nil {
		return
	}
	log.Printf("telemetry: enabled, url=%s, interval=%s, dry_run=%v, site_id=%q",
		r.url, r.interval, r.dryRun, r.siteID)
	go r.loop(ctx)
}

func (r *Reporter) loop(ctx context.Context) {
	// Send one heartbeat shortly after boot (gives the vendor a "deployment is
	// alive" signal even if it crashes 5 minutes in), then on every interval.
	bootTicker := time.NewTimer(30 * time.Second)
	defer bootTicker.Stop()
	intervalTicker := time.NewTicker(r.interval)
	defer intervalTicker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-bootTicker.C:
			r.send(ctx)
		case <-intervalTicker.C:
			r.send(ctx)
		}
	}
}

func (r *Reporter) send(ctx context.Context) {
	hb := r.snapshot()
	if r.dryRun {
		out, _ := json.MarshalIndent(hb, "", "  ")
		log.Printf("telemetry (DRY-RUN, would POST): %s", string(out))
		return
	}
	body, err := json.Marshal(hb)
	if err != nil {
		log.Printf("telemetry: marshal failed: %v", err)
		return
	}
	req, _ := http.NewRequestWithContext(ctx, "POST", r.url, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "tankada-gateway/"+r.gatewayVer)
	if r.token != "" {
		req.Header.Set("Authorization", "Bearer "+r.token)
	}
	resp, err := r.http.Do(req)
	if err != nil {
		log.Printf("telemetry: POST failed: %v (will retry at next interval)", err)
		return
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body) // drain so the connection can be reused
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		log.Printf("telemetry: vendor returned %d", resp.StatusCode)
	}
}

// snapshot copies the live counters under the lock and assembles the
// Heartbeat. Pure-ish: the only impure inputs are the lock and the clock.
func (r *Reporter) snapshot() Heartbeat {
	r.mu.Lock()
	counters := cloneCounters(r.counters)
	r.mu.Unlock()
	return Heartbeat{
		SiteID:         r.siteID,
		BundleVersion:  r.bundleVer,
		GatewayVersion: r.gatewayVer,
		Env:            r.env,
		UptimeSec:      int64(time.Since(r.startedAt).Seconds()),
		PolicyHashes:   hashPolicyDir(r.policyDir),
		Counters:       counters,
		Schema:         "tankada.heartbeat.v1",
		SentAt:         time.Now().UTC(),
	}
}

// ── Counter API (called by query handler) ────────────────────────────────────

// IncrAllow / IncrDeny / IncrShadow bump cumulative counters. Nil-safe: when
// telemetry is disabled (r == nil) these are zero-cost no-ops.
func (r *Reporter) IncrAllow()  { r.bump(func(c *Counters) { c.QueriesTotal++; c.DecisionAllow++ }) }
func (r *Reporter) IncrDeny(category string) {
	r.bump(func(c *Counters) {
		c.QueriesTotal++
		c.DecisionDeny++
		if category != "" {
			c.DenyByCategory[category]++
		}
	})
}
func (r *Reporter) IncrShadow() { r.bump(func(c *Counters) { c.QueriesTotal++; c.DecisionShadow++ }) }
func (r *Reporter) IncrOPAUnavailable()      { r.bump(func(c *Counters) { c.OPAUnavailable++ }) }
func (r *Reporter) IncrAnalyzerUnavailable() { r.bump(func(c *Counters) { c.AnalyzerUnavailable++ }) }

func (r *Reporter) bump(f func(*Counters)) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	f(&r.counters)
}

// Snapshot exposes the current counters for tests + the /telemetry/preview
// endpoint (so the operator can see what would be sent).
func (r *Reporter) Snapshot() Heartbeat {
	if r == nil {
		return Heartbeat{Schema: "tankada.heartbeat.v1", Counters: Counters{DenyByCategory: map[string]int64{}}}
	}
	return r.snapshot()
}

func cloneCounters(c Counters) Counters {
	out := c
	out.DenyByCategory = make(map[string]int64, len(c.DenyByCategory))
	for k, v := range c.DenyByCategory {
		out.DenyByCategory[k] = v
	}
	return out
}

// ── Policy hashing (pure; testable) ──────────────────────────────────────────

// hashPolicyDir computes SHA-256 of schema.json, templates.json, query.rego in
// `dir`. Missing files yield empty strings (the field is omitempty in the
// JSON). The hashes are over file BYTES, not content -- the vendor never sees
// what's inside the file.
func hashPolicyDir(dir string) PolicyHashes {
	if dir == "" {
		return PolicyHashes{}
	}
	return PolicyHashes{
		SchemaJSON:    sha256File(filepath.Join(dir, "schema.json")),
		TemplatesJSON: sha256File(filepath.Join(dir, "templates.json")),
		QueryRego:     sha256File(filepath.Join(dir, "query.rego")),
	}
}

func sha256File(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}

// SchemaForVendor describes the public contract of the heartbeat -- useful for
// the operator to copy into a compliance doc or to inspect via the helper
// command below.
func SchemaForVendor() string {
	exemplar := Heartbeat{
		Counters: Counters{DenyByCategory: map[string]int64{}},
		Schema:   "tankada.heartbeat.v1",
	}
	b, _ := json.MarshalIndent(exemplar, "", "  ")
	return string(b)
}

// SortedDenyCategories returns the categories sorted alphabetically; used by
// the dry-run printer + tests where we want a deterministic order.
func (c Counters) SortedDenyCategories() []string {
	keys := make([]string, 0, len(c.DenyByCategory))
	for k := range c.DenyByCategory {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// Ensure fmt import is referenced even if the package only logs (defensive).
var _ = fmt.Sprintf
