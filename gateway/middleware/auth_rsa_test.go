package middleware

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// ── helpers ──────────────────────────────────────────────────────────────────

// genJWKSWithKey creates a one-key JWKS on disk and returns its path + the
// matching private key for signing tokens.
func genJWKSWithKey(t *testing.T, kid string) (string, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa gen: %v", err)
	}
	n := base64.RawURLEncoding.EncodeToString(key.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())
	doc := jwksDoc{Keys: []jwkKey{{Kty: "RSA", Kid: kid, Alg: "RS256", N: n, E: e}}}
	body, _ := json.Marshal(doc)
	dir := t.TempDir()
	path := filepath.Join(dir, "jwks.json")
	if err := os.WriteFile(path, body, 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
	return path, key
}

func signRS256(t *testing.T, key *rsa.PrivateKey, kid string, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = kid
	s, err := tok.SignedString(key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return s
}

func defaultClaims() jwt.MapClaims {
	return jwt.MapClaims{
		"agent_id":  "agent-rsa",
		"tenant_id": "tenant_1",
		"roles":     []string{"analyst"},
		"scopes":    []string{"customers:read"},
		"exp":       time.Now().Add(time.Hour).Unix(),
	}
}

// ── happy path ───────────────────────────────────────────────────────────────

func TestParseAndResolve_RS256_acceptsValidToken(t *testing.T) {
	path, key := genJWKSWithKey(t, "k1")
	j, _ := LoadJWKSFromFile(path)
	defer j.Stop()
	v := NewRS256Verifier(j)

	tok := signRS256(t, key, "k1", defaultClaims())
	claims, err := ParseAndResolve(v, tok)
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	if claims.AgentID != "agent-rsa" || claims.TenantID != "tenant_1" {
		t.Fatalf("claims not populated: %+v", claims)
	}
}

func TestVerifier_Mode_reportsCorrectly(t *testing.T) {
	if NewHS256Verifier("x").Mode() != "HS256" {
		t.Fatal("HS256 mode label wrong")
	}
	path, _ := genJWKSWithKey(t, "k1")
	j, _ := LoadJWKSFromFile(path)
	defer j.Stop()
	if NewRS256Verifier(j).Mode() != "RS256/JWKS" {
		t.Fatal("RS256 mode label wrong")
	}
}

// ── algorithm whitelist (the canonical JWT pitfall) ──────────────────────────

func TestParseAndResolve_RS256_rejectsHS256Token(t *testing.T) {
	path, _ := genJWKSWithKey(t, "k1")
	j, _ := LoadJWKSFromFile(path)
	defer j.Stop()
	v := NewRS256Verifier(j)

	// Sign with HS256 instead of RS256 -> verifier in RS256 mode must reject.
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, defaultClaims())
	tok.Header["kid"] = "k1"
	signed, _ := tok.SignedString([]byte("attacker-secret"))

	if _, err := ParseAndResolve(v, signed); err == nil {
		t.Fatal("RS256 verifier must reject HS256-signed token (algorithm confusion)")
	}
}

func TestParseAndResolve_HS256_rejectsRS256Token(t *testing.T) {
	v := NewHS256Verifier("test-secret")
	_, key := genJWKSWithKey(t, "k1")

	tok := signRS256(t, key, "k1", defaultClaims())
	if _, err := ParseAndResolve(v, tok); err == nil {
		t.Fatal("HS256 verifier must reject RS256-signed token")
	}
}

func TestParseAndResolve_rejectsAlgNone(t *testing.T) {
	path, _ := genJWKSWithKey(t, "k1")
	j, _ := LoadJWKSFromFile(path)
	defer j.Stop()
	v := NewRS256Verifier(j)

	// hand-craft an unsigned "alg: none" token
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT","kid":"k1"}`))
	body, _ := json.Marshal(defaultClaims())
	payload := base64.RawURLEncoding.EncodeToString(body)
	tok := header + "." + payload + "."

	if _, err := ParseAndResolve(v, tok); err == nil {
		t.Fatal("alg=none must always be rejected")
	}
}

// ── JWKS-side failures ───────────────────────────────────────────────────────

func TestParseAndResolve_RS256_rejectsUnknownKid(t *testing.T) {
	path, key := genJWKSWithKey(t, "k1")
	j, _ := LoadJWKSFromFile(path)
	defer j.Stop()
	v := NewRS256Verifier(j)

	tok := signRS256(t, key, "ghost", defaultClaims())
	_, err := ParseAndResolve(v, tok)
	if err == nil || !strings.Contains(err.Error(), "unknown kid") {
		t.Fatalf("expected 'unknown kid' error, got %v", err)
	}
}

func TestParseAndResolve_RS256_rejectsMissingKid(t *testing.T) {
	path, key := genJWKSWithKey(t, "k1")
	j, _ := LoadJWKSFromFile(path)
	defer j.Stop()
	v := NewRS256Verifier(j)

	// sign without setting a kid header
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, defaultClaims())
	s, _ := tok.SignedString(key)
	_, err := ParseAndResolve(v, s)
	if err == nil || !strings.Contains(err.Error(), "no kid") {
		t.Fatalf("expected 'no kid' error, got %v", err)
	}
}

func TestParseAndResolve_RS256_rejectsSignatureMismatch(t *testing.T) {
	path, _ := genJWKSWithKey(t, "k1")
	j, _ := LoadJWKSFromFile(path)
	defer j.Stop()
	v := NewRS256Verifier(j)

	// Sign with a DIFFERENT key but advertise kid=k1
	_, attacker := genJWKSWithKey(t, "k1") // separate key, same kid
	tok := signRS256(t, attacker, "k1", defaultClaims())
	if _, err := ParseAndResolve(v, tok); err == nil {
		t.Fatal("signature from wrong key must be rejected")
	}
}

// ── missing claims (regardless of algorithm) ─────────────────────────────────

func TestParseAndResolve_RS256_rejectsMissingAgentID(t *testing.T) {
	path, key := genJWKSWithKey(t, "k1")
	j, _ := LoadJWKSFromFile(path)
	defer j.Stop()
	v := NewRS256Verifier(j)

	c := defaultClaims()
	delete(c, "agent_id")
	tok := signRS256(t, key, "k1", c)
	if _, err := ParseAndResolve(v, tok); err == nil {
		t.Fatal("missing agent_id must be rejected")
	}
}

// ── nil verifier ─────────────────────────────────────────────────────────────

func TestParseAndResolve_nilVerifierErrors(t *testing.T) {
	if _, err := ParseAndResolve(nil, "anything"); err == nil {
		t.Fatal("nil verifier must error")
	}
}
