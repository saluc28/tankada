// Targeted tests for the verifyPerBoot splitting logic. The rest of the
// command (flag parsing, file I/O, exit codes) is exercised by the live E2E
// smoke + the strict path that gateway/audit/chain_test.go already covers.
package main

import (
	"bytes"
	"testing"

	"github.com/tankada/gateway/audit"
)

// chainBoot builds a valid per-boot chain of n events with the given bootID,
// starting from GenesisHash. Returns the events.
func chainBoot(t *testing.T, bootID string, n int) []audit.Event {
	t.Helper()
	var buf bytes.Buffer
	old := audit.SwapDefaultStateForTesting(&buf, "")
	defer audit.RestoreDefaultStateForTesting(old)
	// Force the new state's bootID via a second swap so each call uses the
	// requested id. SwapDefaultStateForTesting() generates a random uuid; we
	// reach in via the exported helpers to set what we need.
	// Simpler: just emit n events through the swapped state, then re-tag
	// BootID to bootID after the fact - the chain is recomputed against the
	// new BootID by the helper below.
	events := []audit.Event{}
	prev := audit.GenesisHash
	for i := 0; i < n; i++ {
		e := audit.Event{
			EventID:       "evt-" + bootID + "-" + itoa(i),
			AgentID:       "agent",
			TenantID:      "tenant",
			QueryOriginal: "SELECT " + itoa(i),
			QueryType:     "SELECT",
			BootID:        bootID,
			PrevHash:      prev,
		}
		body, err := audit.MarshalForHash(e)
		if err != nil {
			t.Fatalf("MarshalForHash: %v", err)
		}
		e.Hash = audit.ComputeHash(e.PrevHash, body)
		events = append(events, e)
		prev = e.Hash
	}
	return events
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}

func TestVerifyPerBoot_HappyPath_OneBoot(t *testing.T) {
	events := chainBoot(t, "boot-A", 4)
	ok, idx, why := verifyPerBoot(events)
	if !ok {
		t.Fatalf("single-boot chain should pass: idx=%d why=%s", idx, why)
	}
}

func TestVerifyPerBoot_HappyPath_TwoBoots(t *testing.T) {
	a := chainBoot(t, "boot-A", 3)
	b := chainBoot(t, "boot-B", 2)
	all := append(append([]audit.Event{}, a...), b...)
	ok, idx, why := verifyPerBoot(all)
	if !ok {
		t.Fatalf("two-boot chain should pass: idx=%d why=%s", idx, why)
	}
}

func TestVerifyPerBoot_TamperInSecondBoot_FaultIndexIsAbsolute(t *testing.T) {
	a := chainBoot(t, "boot-A", 3)
	b := chainBoot(t, "boot-B", 3)
	all := append(append([]audit.Event{}, a...), b...)
	// Tamper event at absolute index 4 (i.e. b[1]).
	all[4].QueryOriginal = "SELECT EVIL"
	ok, idx, _ := verifyPerBoot(all)
	if ok {
		t.Fatal("tamper in second boot must fail")
	}
	if idx != 4 {
		t.Errorf("expected absolute index 4 for the tampered event, got %d", idx)
	}
}

func TestVerifyPerBoot_EmptyIsOk(t *testing.T) {
	ok, idx, why := verifyPerBoot(nil)
	if !ok || idx != -1 || why != "" {
		t.Errorf("empty stream should pass: %v %d %q", ok, idx, why)
	}
}
