// Pure tests for the D.4.b Ed25519 helpers. No I/O - keys generated in
// memory and round-tripped through PEM in the same test.
package audit

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
)

func newPair(t *testing.T) (ed25519.PrivateKey, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	return priv, pub
}

func TestSignAndVerify_HappyPath(t *testing.T) {
	priv, pub := newPair(t)
	hash := strings.Repeat("a", 64)
	sig := SignHash(priv, hash)
	if err := VerifyHashSignature(pub, hash, sig); err != nil {
		t.Fatalf("expected verify to pass, got %v", err)
	}
}

func TestVerify_RejectsAlteredHash(t *testing.T) {
	priv, pub := newPair(t)
	sig := SignHash(priv, strings.Repeat("a", 64))
	err := VerifyHashSignature(pub, strings.Repeat("b", 64), sig)
	if err == nil {
		t.Fatal("verify must reject a signature against a different hash")
	}
}

func TestVerify_RejectsWrongPublicKey(t *testing.T) {
	priv, _ := newPair(t)
	_, otherPub := newPair(t)
	sig := SignHash(priv, strings.Repeat("a", 64))
	if err := VerifyHashSignature(otherPub, strings.Repeat("a", 64), sig); err == nil {
		t.Fatal("verify must reject a signature with the wrong public key")
	}
}

func TestVerify_RejectsMalformedBase64(t *testing.T) {
	_, pub := newPair(t)
	if err := VerifyHashSignature(pub, strings.Repeat("a", 64), "not-base64!@#$"); err == nil {
		t.Fatal("verify must reject non-base64 signature")
	}
}

// --- PEM roundtrip ---------------------------------------------------------

func TestSignerPEM_Roundtrip(t *testing.T) {
	priv, _ := newPair(t)
	pem, err := MarshalSignerPEM(priv)
	if err != nil {
		t.Fatalf("MarshalSignerPEM: %v", err)
	}
	if !strings.Contains(string(pem), "BEGIN PRIVATE KEY") {
		t.Errorf("expected PRIVATE KEY block, got %s", pem)
	}
	loaded, err := LoadSignerFromPEM(pem)
	if err != nil {
		t.Fatalf("LoadSignerFromPEM: %v", err)
	}
	// Sign with original, verify with loaded's public half: must match.
	sig := SignHash(priv, "deadbeef")
	pub := loaded.Public().(ed25519.PublicKey)
	if err := VerifyHashSignature(pub, "deadbeef", sig); err != nil {
		t.Errorf("roundtripped key cannot verify its own twin's signature: %v", err)
	}
}

func TestVerifierPEM_Roundtrip(t *testing.T) {
	priv, pub := newPair(t)
	pemBytes, err := MarshalVerifierPEM(pub)
	if err != nil {
		t.Fatalf("MarshalVerifierPEM: %v", err)
	}
	if !strings.Contains(string(pemBytes), "BEGIN PUBLIC KEY") {
		t.Errorf("expected PUBLIC KEY block, got %s", pemBytes)
	}
	loaded, err := LoadVerifierFromPEM(pemBytes)
	if err != nil {
		t.Fatalf("LoadVerifierFromPEM: %v", err)
	}
	sig := SignHash(priv, "deadbeef")
	if err := VerifyHashSignature(loaded, "deadbeef", sig); err != nil {
		t.Errorf("verify with loaded public key failed: %v", err)
	}
}

// --- PEM error paths -------------------------------------------------------

func TestLoadSignerFromPEM_EmptyInput(t *testing.T) {
	if _, err := LoadSignerFromPEM(nil); err == nil {
		t.Fatal("empty PEM must be rejected")
	}
}

func TestLoadSignerFromPEM_GarbageInput(t *testing.T) {
	if _, err := LoadSignerFromPEM([]byte("this is not a PEM file\n")); err == nil {
		t.Fatal("garbage must be rejected as missing PEM block")
	}
}

func TestLoadSignerFromPEM_WrongBlockType(t *testing.T) {
	// Wrap a valid PKCS8 in a PUBLIC KEY block to flip the type.
	priv, _ := newPair(t)
	good, _ := MarshalSignerPEM(priv)
	bad := strings.Replace(string(good), "PRIVATE KEY", "PUBLIC KEY", 2)
	if _, err := LoadSignerFromPEM([]byte(bad)); err == nil {
		t.Fatal("wrong PEM block type must be rejected")
	}
}

func TestLoadVerifierFromPEM_WrongBlockType(t *testing.T) {
	_, pub := newPair(t)
	good, _ := MarshalVerifierPEM(pub)
	bad := strings.Replace(string(good), "PUBLIC KEY", "PRIVATE KEY", 2)
	if _, err := LoadVerifierFromPEM([]byte(bad)); err == nil {
		t.Fatal("wrong PEM block type must be rejected")
	}
}
