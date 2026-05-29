package audit

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// ChainStateEnv names the env var that points to the file where the gateway
// persists the chain's tail (the last emitted Hash). Setting it makes the
// chain CONTINUOUS across gateway restarts: the next boot resumes from the
// recorded hash instead of from GenesisHash. Unset / empty means "in-memory
// only" - every boot starts a fresh chain, which is still SOC2-defensible
// per-segment but loses tamper-evidence across downtime.
const ChainStateEnv = "AUDIT_CHAIN_STATE_PATH"

// SigningKeyEnv names the env var that points to a PEM file containing the
// Ed25519 PKCS8 private key the gateway uses to sign every audit event's
// hash (D.4.b). When set, every line gets a `signature`; when unset the
// chain still works (D.4.a) but only detects tampering, it does not prove
// authorship.
const SigningKeyEnv = "AUDIT_SIGNING_KEY_PATH"

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
	MaskedColumns  []string  `json:"masked_columns,omitempty"`
	// Shadow/observe mode (D.5). Mode is "shadow" when enforcement is disabled;
	// ShadowDecision is what the policy WOULD have decided ("deny"/"allow") while
	// the query was executed anyway. Both omitted in normal enforce mode.
	Mode           string `json:"mode,omitempty"`
	ShadowDecision string `json:"shadow_decision,omitempty"`
	// Tamper-evident chain (D.4.a). Every event carries the hash of the
	// previous event (`prev_hash`) and its own `hash`, both hex sha256. The
	// first event of a chain has prev_hash = audit.GenesisHash. `boot_id` is
	// the UUID of the gateway instance that emitted the event - lets a
	// verifier tell which run produced which segment of the chain. All three
	// are intentionally NOT omitempty: they must appear on every line so the
	// chain is structurally visible to a SOC2 auditor at a glance.
	BootID   string `json:"boot_id"`
	PrevHash string `json:"prev_hash"`
	Hash     string `json:"hash"`
	// Signature (D.4.b) is the base64 Ed25519 signature of the bytes of the
	// Hash hex string. Present iff the gateway boot had AUDIT_SIGNING_KEY_PATH
	// configured. Verified by audit-verify with --public-key + (optionally)
	// --require-signature. omitempty so logs from a gateway without a signing
	// key keep their previous shape exactly.
	Signature string `json:"signature,omitempty"`
}

// state holds the mutable side of the audit logger: the writer, the chain
// head, the boot identity, the (optional) chain-state path, and the
// (optional) Ed25519 signing key. Everything in here is guarded by mu - the
// public Log() must be safe to call from many goroutines.
type state struct {
	mu        sync.Mutex
	out       *log.Logger
	bootID    string
	lastHash  string
	statePath string             // empty -> no persistence (per-boot chain)
	signer    ed25519.PrivateKey // nil -> events go out unsigned
}

func newState(out io.Writer, statePath string) *state {
	s := &state{
		out:       log.New(out, "", 0),
		bootID:    uuid.New().String(),
		lastHash:  GenesisHash,
		statePath: strings.TrimSpace(statePath),
	}
	if s.statePath != "" {
		if h, err := readChainState(s.statePath); err == nil && h != "" {
			s.lastHash = h
		} else if err != nil && !os.IsNotExist(err) {
			// Recoverable: the file is unreadable or corrupt. Start fresh from
			// genesis - the next emit will overwrite the file. We warn on
			// stderr because losing chain continuity is the kind of thing an
			// operator wants to see in the boot log.
			fmt.Fprintf(os.Stderr,
				"audit: chain state at %q unreadable (%v); starting from genesis\n",
				s.statePath, err)
		}
	}
	// D.4.b: load the optional Ed25519 signing key from disk. We deliberately
	// FAIL CLOSED if a path is set but the file is missing or malformed: a
	// gateway booting with "signing requested but no signer" is a security
	// regression, not a recoverable warning.
	if keyPath := strings.TrimSpace(os.Getenv(SigningKeyEnv)); keyPath != "" {
		pemBytes, err := os.ReadFile(keyPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "audit: cannot read signing key at %q: %v\n", keyPath, err)
			os.Exit(2)
		}
		priv, err := LoadSignerFromPEM(pemBytes)
		if err != nil {
			fmt.Fprintf(os.Stderr, "audit: cannot load signing key from %q: %v\n", keyPath, err)
			os.Exit(2)
		}
		s.signer = priv
	}
	return s
}

// defaultState is the package-level logger used by Log(). It is rebuilt at
// process start with the configured state path; tests swap it out via
// WithState() so they can capture writes and use a tempdir for persistence.
var defaultState = newState(os.Stdout, os.Getenv(ChainStateEnv))

// Log writes an audit event as a single JSON line, computing and persisting
// the tamper-evident chain link (D.4.a). Safe to call concurrently.
func Log(e Event) { defaultState.emit(e) }

func (s *state) emit(e Event) {
	s.mu.Lock()
	defer s.mu.Unlock()

	e.BootID = s.bootID
	e.PrevHash = s.lastHash
	body, err := MarshalForHash(e)
	if err != nil {
		s.out.Printf(`{"error":"audit marshal failed","event_id":%q}`, e.EventID)
		return
	}
	e.Hash = ComputeHash(e.PrevHash, body)
	// D.4.b: sign AFTER hashing. The signature attests to the hash, and the
	// hash already covers the whole event minus Hash + Signature themselves
	// (MarshalForHash clears both), so this single Ed25519 op authenticates
	// the entire line *and* its chain position in one shot.
	if s.signer != nil {
		e.Signature = SignHash(s.signer, e.Hash)
	}

	final, err := json.Marshal(e)
	if err != nil {
		s.out.Printf(`{"error":"audit final marshal failed","event_id":%q}`, e.EventID)
		return
	}
	s.out.Println(string(final))
	s.lastHash = e.Hash

	if s.statePath != "" {
		if err := writeChainStateAtomic(s.statePath, s.lastHash); err != nil {
			// Non-fatal: the chain is still verifiable from the log file
			// itself. The state file is a convenience for cross-boot
			// continuity; if it fails the worst case is the next boot
			// re-starting from genesis (and the verifier surfacing the cut).
			fmt.Fprintf(os.Stderr,
				"audit: failed to persist chain state to %q: %v\n", s.statePath, err)
		}
	}
}

// readChainState reads a persisted prev_hash. Returns "" when the file is
// empty (treated as "start from genesis"). Rejects garbage with a clear
// error so corruption is loud, not silent.
func readChainState(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	h := strings.TrimSpace(string(b))
	if h == "" {
		return "", nil
	}
	if len(h) != 64 {
		return "", fmt.Errorf("invalid chain state: expected 64 hex chars, got %d", len(h))
	}
	for _, c := range h {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return "", fmt.Errorf("invalid chain state: non-hex char %q", c)
		}
	}
	return h, nil
}

// writeChainStateAtomic writes the new tail hash via tmp+rename so a crash
// in the middle of the write leaves the previous good value in place. Uses
// fsync on the tmp file so the OS does not return success on a write that
// the disk has not yet committed - the whole point of a tamper-evident chain
// is that a power-cut does not silently break it.
func writeChainStateAtomic(path, h string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".chain.*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	// belt-and-suspenders: clean up on early return; once rename succeeds
	// the tmp file no longer exists, so Remove on it becomes a no-op.
	defer os.Remove(tmpName)
	if _, err := tmp.WriteString(h); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

// BootID returns the UUID assigned to this process's audit chain. Exposed for
// tests and for the verifier CLI ("which run produced this segment?").
func BootID() string {
	defaultState.mu.Lock()
	defer defaultState.mu.Unlock()
	return defaultState.bootID
}

// SwapDefaultStateForTesting replaces the package-level state so tests can
// capture writes and use a tempdir for persistence. Returns the previous
// state so the test can restore it on cleanup. NOT for production use.
func SwapDefaultStateForTesting(out io.Writer, statePath string) *state {
	old := defaultState
	defaultState = newState(out, statePath)
	return old
}

// RestoreDefaultStateForTesting puts back a state previously captured by
// SwapDefaultStateForTesting. NOT for production use.
func RestoreDefaultStateForTesting(s *state) {
	defaultState = s
}
