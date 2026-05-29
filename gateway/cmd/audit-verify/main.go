// Command audit-verify validates the hash-chain integrity of a Tankada audit
// log (.jsonl, one Event per line, D.4.a).
//
// Usage:
//
//	audit-verify --log audit.jsonl
//	docker compose logs gateway --no-log-prefix | audit-verify
//
// Modes:
//
//	--mode strict   (default) the chain is one continuous string of hashes
//	                from GenesisHash to the last line, even across gateway
//	                restarts. Requires the production deployment to set
//	                AUDIT_CHAIN_STATE_PATH so the chain survives reboot.
//	--mode per-boot the chain restarts from GenesisHash whenever boot_id
//	                changes. Use this when running without persistence (dev
//	                or after a deliberate state-file reset).
//
// Other flags:
//
//	--start-prev <hex>      prev_hash expected for the first event. Default:
//	                        GenesisHash (strict mode) or auto-detected from
//	                        the first event's PrevHash (per-boot mode).
//	--public-key <path>     PEM file with the Ed25519 public key (PKIX). When
//	                        set, every event with a Signature is verified
//	                        against it. Events without a Signature are
//	                        skipped unless --require-signature is also set.
//	--require-signature     fail (exit 1) if any event is missing a
//	                        Signature, or if any present Signature fails to
//	                        verify. Implies --public-key.
//
// Exit codes:
//
//	0  chain valid (and signatures verify if --public-key was provided)
//	1  chain broken, or signature missing/invalid under --require-signature
//	2  input or flag error
//
// The verifier is the *same code* used at write-time (`gateway/audit.VerifyChain`),
// so the canonical-JSON encoding of an Event cannot drift between writer and
// verifier - they share the Go struct definition.
package main

import (
	"bufio"
	"crypto/ed25519"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/tankada/gateway/audit"
)

const (
	exitOK     = 0
	exitFailed = 1
	exitInput  = 2
)

func main() {
	logPath := flag.String("log", "", "audit log file to verify (default: stdin)")
	mode := flag.String("mode", "strict", `"strict" (one chain across boots) or "per-boot" (restart at every boot_id change)`)
	startPrev := flag.String("start-prev", audit.GenesisHash, "expected prev_hash of the first event (default: GenesisHash)")
	pubKeyPath := flag.String("public-key", "", "PEM file with the Ed25519 public key for signature verification (D.4.b)")
	requireSig := flag.Bool("require-signature", false, "fail if any event is missing a signature, or if a signature fails to verify (implies --public-key)")
	flag.Parse()

	if *mode != "strict" && *mode != "per-boot" {
		fmt.Fprintf(os.Stderr, "audit-verify: --mode must be strict or per-boot, got %q\n", *mode)
		os.Exit(exitInput)
	}
	if *requireSig && *pubKeyPath == "" {
		fmt.Fprintln(os.Stderr, "audit-verify: --require-signature requires --public-key")
		os.Exit(exitInput)
	}

	// Load the optional public key once, ahead of any verification work.
	var pub ed25519.PublicKey
	if *pubKeyPath != "" {
		pemBytes, err := os.ReadFile(*pubKeyPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "audit-verify: cannot read public key %q: %v\n", *pubKeyPath, err)
			os.Exit(exitInput)
		}
		pub, err = audit.LoadVerifierFromPEM(pemBytes)
		if err != nil {
			fmt.Fprintf(os.Stderr, "audit-verify: cannot load public key %q: %v\n", *pubKeyPath, err)
			os.Exit(exitInput)
		}
	}

	var r io.Reader = os.Stdin
	if *logPath != "" {
		f, err := os.Open(*logPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "audit-verify: %v\n", err)
			os.Exit(exitInput)
		}
		defer f.Close()
		r = f
	}

	events, parseErrs := readEvents(r)
	if len(parseErrs) > 0 {
		for _, e := range parseErrs {
			fmt.Fprintf(os.Stderr, "audit-verify: %s\n", e)
		}
		os.Exit(exitInput)
	}
	if len(events) == 0 {
		fmt.Fprintln(os.Stderr, "audit-verify: no events to verify (file was empty)")
		os.Exit(exitInput)
	}

	switch *mode {
	case "strict":
		ok, idx, why := audit.VerifyChain(events, *startPrev)
		if !ok {
			report(events, ok, idx, why, 0)
		}
	case "per-boot":
		ok, idx, why := verifyPerBoot(events)
		if !ok {
			report(events, ok, idx, why, 0)
		}
	}

	// Chain check passed; verify signatures if a key was provided.
	signedCount := 0
	if pub != nil {
		for i, ev := range events {
			if ev.Signature == "" {
				if *requireSig {
					report(events, false, i,
						fmt.Sprintf("event %d (id=%s) has no signature but --require-signature is set", i, ev.EventID),
						signedCount)
				}
				continue
			}
			if err := audit.VerifyHashSignature(pub, ev.Hash, ev.Signature); err != nil {
				report(events, false, i,
					fmt.Sprintf("signature verify failed at event %d (id=%s): %v", i, ev.EventID, err),
					signedCount)
			}
			signedCount++
		}
	}

	report(events, true, -1, "", signedCount)
}

// readEvents parses one Event per non-empty line. Returns a slice of parse
// errors (with line numbers) so the operator can see ALL the bad lines, not
// only the first.
func readEvents(r io.Reader) ([]audit.Event, []string) {
	events := []audit.Event{}
	var errs []string
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1<<20), 1<<24) // tolerate long audit lines (1 MiB max)
	line := 0
	for sc.Scan() {
		line++
		raw := sc.Bytes()
		if len(raw) == 0 {
			continue
		}
		var ev audit.Event
		if err := json.Unmarshal(raw, &ev); err != nil {
			errs = append(errs, fmt.Sprintf("line %d: %v", line, err))
			continue
		}
		events = append(events, ev)
	}
	if err := sc.Err(); err != nil {
		errs = append(errs, fmt.Sprintf("read: %v", err))
	}
	return events, errs
}

// verifyPerBoot splits the event stream at every boot_id boundary and
// verifies each segment from GenesisHash. A boot whose first event has
// PrevHash != GenesisHash is itself a failure (the per-boot mode expects
// every boot to start fresh).
func verifyPerBoot(events []audit.Event) (bool, int, string) {
	if len(events) == 0 {
		return true, -1, ""
	}
	segStart := 0
	segBoot := events[0].BootID
	for i := 1; i < len(events); i++ {
		if events[i].BootID != segBoot {
			ok, off, why := audit.VerifyChain(events[segStart:i], audit.GenesisHash)
			if !ok {
				return false, segStart + off, why
			}
			segStart = i
			segBoot = events[i].BootID
		}
	}
	ok, off, why := audit.VerifyChain(events[segStart:], audit.GenesisHash)
	if !ok {
		return false, segStart + off, why
	}
	return true, -1, ""
}

func report(events []audit.Event, ok bool, idx int, why string, signedCount int) {
	if ok {
		fmt.Printf("OK: %d events verified.\n", len(events))
		fmt.Printf("    first event: %s (boot %s, prev=%s)\n",
			events[0].EventID, events[0].BootID, events[0].PrevHash)
		fmt.Printf("    last event:  %s (boot %s, hash=%s)\n",
			events[len(events)-1].EventID,
			events[len(events)-1].BootID,
			events[len(events)-1].Hash)
		if signedCount > 0 {
			fmt.Printf("    signatures:  %d of %d verified\n", signedCount, len(events))
		}
		os.Exit(exitOK)
	}
	fmt.Fprintf(os.Stderr, "FAIL at event %d: %s\n", idx, why)
	if idx >= 0 && idx < len(events) {
		bad := events[idx]
		fmt.Fprintf(os.Stderr, "  event_id: %s\n  boot_id:  %s\n  timestamp: %s\n",
			bad.EventID, bad.BootID, bad.Timestamp.Format("2006-01-02T15:04:05Z07:00"))
	}
	os.Exit(exitFailed)
}
