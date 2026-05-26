package middleware

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ── helpers ──────────────────────────────────────────────────────────────────

func mustJWKFor(t *testing.T, kid string) (jwkKey, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa gen: %v", err)
	}
	n := base64.RawURLEncoding.EncodeToString(key.N.Bytes())
	eBytes := big.NewInt(int64(key.E)).Bytes()
	e := base64.RawURLEncoding.EncodeToString(eBytes)
	return jwkKey{Kty: "RSA", Kid: kid, Alg: "RS256", Use: "sig", N: n, E: e}, key
}

func jwksDocBytes(t *testing.T, keys ...jwkKey) []byte {
	t.Helper()
	b, err := json.Marshal(jwksDoc{Keys: keys})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

// ── ParseJWKSBytes ────────────────────────────────────────────────────────────

func TestParseJWKSBytes_parsesRSA(t *testing.T) {
	k1, priv := mustJWKFor(t, "k1")
	out, _, err := ParseJWKSBytes(jwksDocBytes(t, k1))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("expected 1 key, got %d", len(out))
	}
	got := out["k1"]
	if got == nil || got.N.Cmp(priv.N) != 0 || got.E != priv.E {
		t.Fatalf("parsed key does not match generated key")
	}
}

func TestParseJWKSBytes_skipsNonRSA(t *testing.T) {
	k1, _ := mustJWKFor(t, "k1")
	ec := jwkKey{Kty: "EC", Kid: "k2", Alg: "ES256"}
	out, _, err := ParseJWKSBytes(jwksDocBytes(t, k1, ec))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if _, ok := out["k2"]; ok {
		t.Fatalf("EC key should have been skipped silently")
	}
	if _, ok := out["k1"]; !ok {
		t.Fatalf("RSA key should have survived")
	}
}

func TestParseJWKSBytes_skipsNonRS256Alg(t *testing.T) {
	k1, _ := mustJWKFor(t, "k1")
	k1.Alg = "RS512" // unsupported today
	_, _, err := ParseJWKSBytes(jwksDocBytes(t, k1))
	if err == nil {
		t.Fatalf("expected error for empty usable keyset")
	}
	if !strings.Contains(err.Error(), "no usable RSA keys") {
		t.Fatalf("wrong error: %v", err)
	}
}

func TestParseJWKSBytes_skipsKeyWithoutKid(t *testing.T) {
	k, _ := mustJWKFor(t, "")
	good, _ := mustJWKFor(t, "good")
	out, _, err := ParseJWKSBytes(jwksDocBytes(t, k, good))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if _, ok := out[""]; ok {
		t.Fatalf("empty-kid key should be dropped")
	}
	if _, ok := out["good"]; !ok {
		t.Fatalf("named key should be kept")
	}
}

func TestParseJWKSBytes_rejectsMalformedJSON(t *testing.T) {
	_, _, err := ParseJWKSBytes([]byte("not json"))
	if err == nil || !strings.Contains(err.Error(), "invalid JSON") {
		t.Fatalf("expected 'invalid JSON' error, got %v", err)
	}
}

func TestParseJWKSBytes_rejectsEmptyKeyset(t *testing.T) {
	_, _, err := ParseJWKSBytes([]byte(`{"keys":[]}`))
	if err == nil || !strings.Contains(err.Error(), "no usable RSA keys") {
		t.Fatalf("expected 'no usable RSA keys' error, got %v", err)
	}
}

// ── LoadJWKSFromFile + KeyFor ────────────────────────────────────────────────

func TestLoadJWKSFromFile_andKeyFor(t *testing.T) {
	k1, _ := mustJWKFor(t, "k1")
	k2, _ := mustJWKFor(t, "k2")
	dir := t.TempDir()
	path := filepath.Join(dir, "jwks.json")
	if err := os.WriteFile(path, jwksDocBytes(t, k1, k2), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
	j, err := LoadJWKSFromFile(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	defer j.Stop()
	if j.Size() != 2 {
		t.Fatalf("size = %d, want 2", j.Size())
	}
	if _, err := j.KeyFor("k1"); err != nil {
		t.Fatalf("KeyFor(k1): %v", err)
	}
	if _, err := j.KeyFor("k2"); err != nil {
		t.Fatalf("KeyFor(k2): %v", err)
	}
	if _, err := j.KeyFor("ghost"); err == nil {
		t.Fatalf("KeyFor(ghost) should fail")
	}
}

func TestKeyFor_emptyKidErrors(t *testing.T) {
	k1, _ := mustJWKFor(t, "k1")
	dir := t.TempDir()
	path := filepath.Join(dir, "jwks.json")
	_ = os.WriteFile(path, jwksDocBytes(t, k1), 0644)
	j, _ := LoadJWKSFromFile(path)
	defer j.Stop()
	if _, err := j.KeyFor(""); err == nil || !strings.Contains(err.Error(), "no kid") {
		t.Fatalf("expected 'no kid' error, got %v", err)
	}
}

// ── LoadJWKSFromURL ──────────────────────────────────────────────────────────

func TestLoadJWKSFromURL_fetchesAndParses(t *testing.T) {
	k1, _ := mustJWKFor(t, "k1")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(jwksDocBytes(t, k1))
	}))
	defer srv.Close()

	j, err := LoadJWKSFromURL(srv.URL, 0)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	defer j.Stop()
	if _, err := j.KeyFor("k1"); err != nil {
		t.Fatalf("KeyFor(k1): %v", err)
	}
}

func TestLoadJWKSFromURL_propagates500(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()
	if _, err := LoadJWKSFromURL(srv.URL, 0); err == nil {
		t.Fatalf("expected error for 500")
	}
}
