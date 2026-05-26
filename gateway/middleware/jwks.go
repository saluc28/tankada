// JWKS (RFC 7517) support for verifying RS256-signed Tankada JWTs.
//
// Two source kinds are supported:
//   - file: a static JWKS JSON on disk (mounted via volume or baked in).
//   - url:  a remote JWKS endpoint refreshed in the background.
//
// The verifier picks the public key by `kid` header. A token missing `kid` or
// referencing an unknown `kid` is rejected. Only RSA keys (kty=RSA) are
// honoured today; EC support can be added later without changing callers.
//
// Refresh strategy: a background goroutine re-fetches the URL every
// `refreshSec` seconds (best-effort; on error the previous keyset is kept).
// `ForceRefresh` is exposed so callers can trigger a one-shot refresh after a
// kid miss (useful right after a key rotation).
package middleware

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"sync"
	"time"
)

// JWKS holds the parsed public keys keyed by their `kid`.
type JWKS struct {
	mu        sync.RWMutex
	keys      map[string]*rsa.PublicKey
	source    string  // "file:/path" or "url:https://..."
	url       string  // non-empty iff URL-sourced
	refreshSec int
	stop      chan struct{}
}

// jwkKey is the on-wire representation of a single key in a JWKS document
// (RFC 7517). Only the fields we use are parsed; unknown ones are tolerated.
type jwkKey struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type jwksDoc struct {
	Keys []jwkKey `json:"keys"`
}

// ── Pure parser (unit-tested without HTTP / fs) ─────────────────────────────

// ParseJWKSBytes parses a JWKS JSON document into a {kid -> *rsa.PublicKey}
// map. RSA keys missing `kid`, with `kty` != "RSA", or with `alg` declared and
// not "RS256" are skipped with a warning. Returns an error if the document
// itself is malformed or produces an empty keyset.
func ParseJWKSBytes(data []byte) (map[string]*rsa.PublicKey, error) {
	var doc jwksDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("jwks: invalid JSON: %w", err)
	}
	out := make(map[string]*rsa.PublicKey, len(doc.Keys))
	for i, k := range doc.Keys {
		if k.Kty != "RSA" {
			continue // skip non-RSA keys silently (forward-compat)
		}
		if k.Alg != "" && k.Alg != "RS256" {
			continue // we only verify RS256 today
		}
		if k.Kid == "" {
			log.Printf("jwks: key #%d skipped (missing kid)", i)
			continue
		}
		pub, err := jwkToRSA(k)
		if err != nil {
			log.Printf("jwks: key #%d (kid=%q) skipped: %v", i, k.Kid, err)
			continue
		}
		out[k.Kid] = pub
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("jwks: no usable RSA keys in document")
	}
	return out, nil
}

func jwkToRSA(k jwkKey) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
	if err != nil {
		return nil, fmt.Errorf("decode n: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
	if err != nil {
		return nil, fmt.Errorf("decode e: %w", err)
	}
	if len(nBytes) == 0 || len(eBytes) == 0 {
		return nil, fmt.Errorf("empty modulus or exponent")
	}
	e := 0
	for _, b := range eBytes {
		e = e<<8 | int(b)
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: e}, nil
}

// ── Loaders (thin I/O wrappers around the pure parser) ───────────────────────

// LoadJWKSFromFile parses a JWKS JSON file. No background refresh: the keyset
// only changes if the file is re-read (e.g. on gateway restart). Suitable for
// air-gapped/baked-in deployments.
func LoadJWKSFromFile(path string) (*JWKS, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("jwks: read %q: %w", path, err)
	}
	keys, err := ParseJWKSBytes(data)
	if err != nil {
		return nil, err
	}
	return &JWKS{keys: keys, source: "file:" + path}, nil
}

// LoadJWKSFromURL fetches and parses a JWKS document at `url`, then spawns a
// background goroutine that re-fetches every `refreshSec` seconds (0 disables
// refresh; minimum honoured is 30s to avoid hot-looping). On a fetch error the
// previous keyset is kept; we never go to "no keys".
func LoadJWKSFromURL(url string, refreshSec int) (*JWKS, error) {
	keys, err := fetchJWKS(url)
	if err != nil {
		return nil, err
	}
	j := &JWKS{
		keys:       keys,
		source:     "url:" + url,
		url:        url,
		refreshSec: refreshSec,
		stop:       make(chan struct{}),
	}
	if refreshSec > 0 {
		if refreshSec < 30 {
			refreshSec = 30
		}
		go j.refreshLoop(time.Duration(refreshSec) * time.Second)
	}
	return j, nil
}

func fetchJWKS(url string) (map[string]*rsa.PublicKey, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("jwks: GET %q: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("jwks: GET %q returned %d", url, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1 MiB cap
	if err != nil {
		return nil, fmt.Errorf("jwks: read body: %w", err)
	}
	return ParseJWKSBytes(body)
}

func (j *JWKS) refreshLoop(every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			if keys, err := fetchJWKS(j.url); err == nil {
				j.mu.Lock()
				j.keys = keys
				j.mu.Unlock()
				log.Printf("jwks: refreshed from %s (%d keys)", j.url, len(keys))
			} else {
				log.Printf("jwks: refresh failed from %s: %v (keeping previous keyset)", j.url, err)
			}
		case <-j.stop:
			return
		}
	}
}

// Stop terminates the background refresh goroutine. Idempotent.
func (j *JWKS) Stop() {
	if j.stop != nil {
		select {
		case <-j.stop:
			// already closed
		default:
			close(j.stop)
		}
	}
}

// KeyFor returns the RSA public key registered under `kid`, or an error if the
// kid is unknown. Thread-safe.
func (j *JWKS) KeyFor(kid string) (*rsa.PublicKey, error) {
	if kid == "" {
		return nil, fmt.Errorf("jwks: token has no kid header")
	}
	j.mu.RLock()
	defer j.mu.RUnlock()
	k, ok := j.keys[kid]
	if !ok {
		return nil, fmt.Errorf("jwks: unknown kid %q (%d keys loaded from %s)", kid, len(j.keys), j.source)
	}
	return k, nil
}

// Size returns how many keys are currently loaded (used by /health and logs).
func (j *JWKS) Size() int {
	j.mu.RLock()
	defer j.mu.RUnlock()
	return len(j.keys)
}

// Source returns a human-readable description of where the keyset came from
// (used by startup logs).
func (j *JWKS) Source() string { return j.source }
