// D.4.b: Ed25519 signature on top of the audit hash chain.
//
// The chain (D.4.a) already detects tampering for anyone who can recompute
// hashes; the firma chiude il gap restante - "se chi ha accesso al log puo'
// riscrivere ogni riga, anche la catena", che e' la situazione tipica di un
// log conservato dal cliente. La chiave privata vive solo dove la firma viene
// emessa (vendor-side per Cloud, in `signing/` del bundle B2 per customer
// self-hosted): chi possiede il log NON puo' produrre firme valide nuove.
//
// Cosa firmiamo: il campo `hash` di ogni evento (i 64 caratteri hex). `hash`
// e' gia' una sintesi crittografica dell'intero evento (incluso `prev_hash`),
// quindi firmare `hash` attesta l'intera riga *e* il legame col precedente in
// un singolo Ed25519 op. La firma serializzata e' base64 standard (88 caratteri,
// gli stessi che JOSE/JWT usa per Ed25519DSA).
//
// Le funzioni qui sono pure: nessun I/O, nessun side effect. Il logger
// (logger.go) carica la chiave una volta al boot e la riusa sotto mutex;
// il verifier (cmd/audit-verify) carica la public key e la passa per evento.
package audit

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
)

// pemBlockPrivate is the PEM block label produced by `x509.MarshalPKCS8PrivateKey`
// when wrapped in a PEM block. Same label used by openssl, kubernetes, JWKS gen
// tools - keeps interop trivial.
const pemBlockPrivate = "PRIVATE KEY"

// pemBlockPublic is the standard PEM block label for a PKIX-encoded public key.
const pemBlockPublic = "PUBLIC KEY"

// LoadSignerFromPEM parses an Ed25519 private key from a PKCS8-encoded PEM
// block. Returns an error on the usual missteps: empty input, wrong block
// type, non-Ed25519 key inside a PKCS8 envelope. Pure.
func LoadSignerFromPEM(pemBytes []byte) (ed25519.PrivateKey, error) {
	if len(pemBytes) == 0 {
		return nil, errors.New("audit signing key: empty PEM input")
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("audit signing key: no PEM block found")
	}
	if block.Type != pemBlockPrivate {
		return nil, fmt.Errorf("audit signing key: PEM block type %q, want %q", block.Type, pemBlockPrivate)
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("audit signing key: PKCS8 parse: %w", err)
	}
	priv, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("audit signing key: PEM contained %T, want ed25519.PrivateKey", key)
	}
	return priv, nil
}

// LoadVerifierFromPEM parses an Ed25519 public key from a PKIX-encoded PEM
// block. Symmetric counterpart of LoadSignerFromPEM. Pure.
func LoadVerifierFromPEM(pemBytes []byte) (ed25519.PublicKey, error) {
	if len(pemBytes) == 0 {
		return nil, errors.New("audit verifying key: empty PEM input")
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("audit verifying key: no PEM block found")
	}
	if block.Type != pemBlockPublic {
		return nil, fmt.Errorf("audit verifying key: PEM block type %q, want %q", block.Type, pemBlockPublic)
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("audit verifying key: PKIX parse: %w", err)
	}
	pub, ok := key.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("audit verifying key: PEM contained %T, want ed25519.PublicKey", key)
	}
	return pub, nil
}

// MarshalSignerPEM is the inverse of LoadSignerFromPEM: encode an Ed25519
// private key as PKCS8 inside a PEM block. Used by the audit-keygen helper
// and by tests that construct a signer in memory. Pure.
func MarshalSignerPEM(priv ed25519.PrivateKey) ([]byte, error) {
	b, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("marshal pkcs8: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: pemBlockPrivate, Bytes: b}), nil
}

// MarshalVerifierPEM encodes an Ed25519 public key as PKIX inside a PEM
// block. Pure.
func MarshalVerifierPEM(pub ed25519.PublicKey) ([]byte, error) {
	b, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("marshal pkix: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: pemBlockPublic, Bytes: b}), nil
}

// SignHash signs the bytes of the hex hash string and returns a base64
// (standard, padded) signature. Pure.
//
// We sign the hex string verbatim (`[]byte(hashHex)`) rather than the 32
// decoded bytes so that the verifier does not need to decode hex: anyone
// reading a log file can lift `hash` and `signature` as strings and check
// the signature with a one-liner. The two choices are equivalently strong;
// this one is friendlier to humans.
func SignHash(priv ed25519.PrivateKey, hashHex string) string {
	sig := ed25519.Sign(priv, []byte(hashHex))
	return base64.StdEncoding.EncodeToString(sig)
}

// VerifyHashSignature checks a base64 signature against the bytes of the
// hex hash string. Returns nil on success, a descriptive error otherwise.
// Pure.
func VerifyHashSignature(pub ed25519.PublicKey, hashHex, sigBase64 string) error {
	sig, err := base64.StdEncoding.DecodeString(sigBase64)
	if err != nil {
		return fmt.Errorf("signature is not valid base64: %w", err)
	}
	if !ed25519.Verify(pub, []byte(hashHex), sig) {
		return errors.New("signature does not verify against the event hash with the supplied public key")
	}
	return nil
}
