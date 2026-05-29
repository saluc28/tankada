// Pure tests for the hash-chain helpers. No file I/O, no goroutines, no
// stdout - the logger's runtime side is covered in logger_test.go.
package audit

import (
	"strings"
	"testing"
	"time"
)

// chainOf is a tiny helper that walks a fresh chain producing realistic
// events. Returns the events plus the final prev_hash so further tests can
// extend or splice from the tail.
func chainOf(t *testing.T, n int, boot string) []Event {
	t.Helper()
	events := make([]Event, 0, n)
	prev := GenesisHash
	for i := 0; i < n; i++ {
		e := Event{
			EventID:        "evt-" + boot + "-" + itoa(i),
			Timestamp:      time.Unix(int64(1_700_000_000+i), 0).UTC(),
			AgentID:        "agent",
			TenantID:       "tenant",
			QueryOriginal:  "SELECT " + itoa(i),
			QueryType:      "SELECT",
			TablesAccessed: []string{"customers"},
			PolicyDecision: "allow",
			RiskScore:      0,
			RiskLevel:      "low",
			LatencyMs:      int64(i),
			SessionID:      "s-" + boot,
			BootID:         boot,
			PrevHash:       prev,
		}
		body, err := MarshalForHash(e)
		if err != nil {
			t.Fatalf("MarshalForHash: %v", err)
		}
		e.Hash = ComputeHash(e.PrevHash, body)
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

// --- ComputeHash / MarshalForHash ------------------------------------------

func TestComputeHash_DeterminismAcrossRuns(t *testing.T) {
	e := chainOf(t, 1, "b1")[0]
	body, _ := MarshalForHash(e)
	h1 := ComputeHash(e.PrevHash, body)
	h2 := ComputeHash(e.PrevHash, body)
	if h1 != h2 {
		t.Fatalf("hash not deterministic: %s vs %s", h1, h2)
	}
	if len(h1) != 64 {
		t.Errorf("hex sha256 must be 64 chars, got %d (%s)", len(h1), h1)
	}
}

func TestMarshalForHash_ClearsHashField(t *testing.T) {
	e := Event{EventID: "x", Hash: "this-should-be-cleared"}
	body, err := MarshalForHash(e)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(body), "this-should-be-cleared") {
		t.Errorf("Hash field leaked into canonical bytes: %s", body)
	}
}

func TestMarshalForHash_DoesNotMutateInput(t *testing.T) {
	e := Event{EventID: "x", Hash: "keep-me"}
	_, _ = MarshalForHash(e)
	if e.Hash != "keep-me" {
		t.Errorf("MarshalForHash mutated caller's event: Hash now %q", e.Hash)
	}
}

// --- VerifyChain happy path -------------------------------------------------

func TestVerifyChain_HappyPath(t *testing.T) {
	events := chainOf(t, 5, "boot-1")
	ok, idx, why := VerifyChain(events, GenesisHash)
	if !ok {
		t.Fatalf("expected ok, got fail at %d: %s", idx, why)
	}
	if idx != -1 {
		t.Errorf("expected faulty index -1 on success, got %d", idx)
	}
}

func TestVerifyChain_StartPrevMustMatchFirstEvent(t *testing.T) {
	events := chainOf(t, 2, "boot-1")
	ok, idx, why := VerifyChain(events, "deadbeef")
	if ok {
		t.Fatal("expected failure when startPrev does not match first event")
	}
	if idx != 0 {
		t.Errorf("expected faulty index 0, got %d (%s)", idx, why)
	}
}

// --- VerifyChain tamper detection ------------------------------------------

func TestVerifyChain_DetectsFieldTamper(t *testing.T) {
	events := chainOf(t, 3, "boot-1")
	// Sneak in a different query at index 1, leaving everything else as-is.
	events[1].QueryOriginal = "SELECT 999"
	ok, idx, why := VerifyChain(events, GenesisHash)
	if ok {
		t.Fatal("tamper on event 1 should be detected")
	}
	if idx != 1 {
		t.Errorf("expected faulty index 1, got %d (%s)", idx, why)
	}
	if !strings.Contains(why, "hash mismatch") {
		t.Errorf("expected hash-mismatch reason, got %q", why)
	}
}

func TestVerifyChain_DetectsRowDeletion(t *testing.T) {
	events := chainOf(t, 4, "boot-1")
	// Drop event index 2. Index 3 still references index 2's hash, which is
	// no longer the previous event in the truncated slice.
	tampered := append([]Event{}, events[:2]...)
	tampered = append(tampered, events[3])
	ok, idx, why := VerifyChain(tampered, GenesisHash)
	if ok {
		t.Fatal("removing an event must break the chain")
	}
	if idx != 2 {
		t.Errorf("expected faulty index 2, got %d (%s)", idx, why)
	}
	if !strings.Contains(why, "prev_hash mismatch") {
		t.Errorf("expected prev_hash mismatch, got %q", why)
	}
}

func TestVerifyChain_DetectsRowReordering(t *testing.T) {
	events := chainOf(t, 4, "boot-1")
	events[1], events[2] = events[2], events[1] // swap
	ok, idx, _ := VerifyChain(events, GenesisHash)
	if ok {
		t.Fatal("swapped events must break the chain")
	}
	if idx != 1 {
		t.Errorf("expected fault to surface at index 1, got %d", idx)
	}
}

func TestVerifyChain_DetectsHashFieldTamper(t *testing.T) {
	events := chainOf(t, 2, "boot-1")
	// Forge the second event's hash without recomputing.
	events[1].Hash = strings.Repeat("a", 64)
	ok, idx, why := VerifyChain(events, GenesisHash)
	if ok {
		t.Fatal("forged hash must be detected")
	}
	if idx != 1 {
		t.Errorf("expected faulty index 1, got %d (%s)", idx, why)
	}
}

// --- VerifyChain over multi-segment / startPrev splicing -------------------

func TestVerifyChain_TailSegmentVerifiesWithLastGoodHash(t *testing.T) {
	all := chainOf(t, 5, "boot-1")
	// Verify only the tail [2:] starting from event[1].Hash.
	ok, idx, why := VerifyChain(all[2:], all[1].Hash)
	if !ok {
		t.Fatalf("tail verify should pass: idx=%d why=%s", idx, why)
	}
}

// --- Edge cases -------------------------------------------------------------

func TestVerifyChain_EmptyChainIsOk(t *testing.T) {
	ok, idx, why := VerifyChain(nil, GenesisHash)
	if !ok || idx != -1 || why != "" {
		t.Errorf("empty chain should be ok: %v %d %q", ok, idx, why)
	}
}
