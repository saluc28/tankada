// Command audit-keygen produces a fresh Ed25519 keypair for the D.4.b audit
// signing path: a PKCS8-PEM private key (used by the gateway via
// AUDIT_SIGNING_KEY_PATH) and the matching PKIX-PEM public key (used by
// `audit-verify --public-key`).
//
// Usage:
//
//	audit-keygen --private private.pem --public public.pem
//	audit-keygen                                 # writes ./audit_signing.pem + ./audit_verifying.pem
//
// Refuses to overwrite an existing file: a regenerated keypair invalidates
// every signature ever produced, that decision should be explicit (delete
// the old file first).
//
// Exit codes:
//
//	0  keypair written
//	1  write error
//	2  flag error (e.g. file already exists)
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"flag"
	"fmt"
	"os"

	"github.com/tankada/gateway/audit"
)

const (
	defaultPrivPath = "audit_signing.pem"
	defaultPubPath  = "audit_verifying.pem"
)

func main() {
	privPath := flag.String("private", defaultPrivPath, "output path for the PKCS8 Ed25519 private key")
	pubPath := flag.String("public", defaultPubPath, "output path for the PKIX Ed25519 public key")
	flag.Parse()

	for _, p := range []string{*privPath, *pubPath} {
		if _, err := os.Stat(p); err == nil {
			fmt.Fprintf(os.Stderr, "audit-keygen: %q already exists; refusing to overwrite (delete it first)\n", p)
			os.Exit(2)
		}
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Fprintf(os.Stderr, "audit-keygen: GenerateKey: %v\n", err)
		os.Exit(1)
	}
	privPEM, err := audit.MarshalSignerPEM(priv)
	if err != nil {
		fmt.Fprintf(os.Stderr, "audit-keygen: MarshalSignerPEM: %v\n", err)
		os.Exit(1)
	}
	pubPEM, err := audit.MarshalVerifierPEM(pub)
	if err != nil {
		fmt.Fprintf(os.Stderr, "audit-keygen: MarshalVerifierPEM: %v\n", err)
		os.Exit(1)
	}

	// Tight mode on the private key so it does not silently end up
	// world-readable; the public key can be 0644.
	if err := os.WriteFile(*privPath, privPEM, 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "audit-keygen: write private: %v\n", err)
		os.Exit(1)
	}
	if err := os.WriteFile(*pubPath, pubPEM, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "audit-keygen: write public: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("OK: wrote private (%s, mode 0600) and public (%s, mode 0644).\n", *privPath, *pubPath)
	fmt.Println("Hand the public key to your SOC2 auditor and keep the private key away from the audit log.")
}
