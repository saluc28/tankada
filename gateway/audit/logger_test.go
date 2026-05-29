// Runtime-side tests for the audit logger: thread-safety, chain continuity,
// state-file persistence across "restart" (newState() with the same path).
// Pure-chain tests live in chain_test.go.
package audit

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// parseLines decodes a buffer of newline-delimited audit JSON into Events.
func parseLines(t *testing.T, buf *bytes.Buffer) []Event {
	t.Helper()
	out := []Event{}
	for _, raw := range strings.Split(strings.TrimRight(buf.String(), "\n"), "\n") {
		if raw == "" {
			continue
		}
		var e Event
		if err := json.Unmarshal([]byte(raw), &e); err != nil {
			t.Fatalf("unmarshal %q: %v", raw, err)
		}
		out = append(out, e)
	}
	return out
}

func sampleEvent(i int) Event {
	return Event{
		EventID:        "evt-" + itoa(i),
		Timestamp:      time.Unix(int64(1_700_000_000+i), 0).UTC(),
		AgentID:        "agent",
		TenantID:       "tenant",
		QueryOriginal:  "SELECT " + itoa(i),
		QueryType:      "SELECT",
		TablesAccessed: []string{"customers"},
		PolicyDecision: "allow",
		RiskLevel:      "low",
		SessionID:      "s",
	}
}

func TestEmit_FirstEventStartsFromGenesisHash(t *testing.T) {
	var buf bytes.Buffer
	s := newState(&buf, "")
	s.emit(sampleEvent(0))
	events := parseLines(t, &buf)
	if got := events[0].PrevHash; got != GenesisHash {
		t.Errorf("first event PrevHash = %q, want GenesisHash", got)
	}
	if events[0].Hash == "" || len(events[0].Hash) != 64 {
		t.Errorf("first event Hash invalid: %q", events[0].Hash)
	}
	if events[0].BootID == "" {
		t.Error("BootID was not populated")
	}
}

func TestEmit_LinksConsecutiveEvents(t *testing.T) {
	var buf bytes.Buffer
	s := newState(&buf, "")
	for i := 0; i < 4; i++ {
		s.emit(sampleEvent(i))
	}
	events := parseLines(t, &buf)
	ok, idx, why := VerifyChain(events, GenesisHash)
	if !ok {
		t.Fatalf("chain broken at idx %d: %s", idx, why)
	}
}

func TestEmit_AllEventsShareBootID(t *testing.T) {
	var buf bytes.Buffer
	s := newState(&buf, "")
	for i := 0; i < 3; i++ {
		s.emit(sampleEvent(i))
	}
	events := parseLines(t, &buf)
	boot := events[0].BootID
	if boot == "" {
		t.Fatal("BootID empty")
	}
	for i, e := range events[1:] {
		if e.BootID != boot {
			t.Errorf("event %d BootID = %q, want %q", i+1, e.BootID, boot)
		}
	}
}

func TestEmit_ConcurrentCallsProduceValidChain(t *testing.T) {
	var buf bytes.Buffer
	// Wrap the buffer in a mutex'd writer because bytes.Buffer is not
	// goroutine-safe; the state's mu serialises emit() but the underlying
	// writer must also be safe.
	mw := &lockedWriter{w: &buf}
	s := newState(mw, "")

	const N = 200
	var wg sync.WaitGroup
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			s.emit(sampleEvent(i))
		}(i)
	}
	wg.Wait()

	events := parseLines(t, &buf)
	if len(events) != N {
		t.Fatalf("expected %d events, got %d", N, len(events))
	}
	ok, idx, why := VerifyChain(events, GenesisHash)
	if !ok {
		t.Fatalf("chain broken under concurrency at idx %d: %s", idx, why)
	}
}

type lockedWriter struct {
	mu sync.Mutex
	w  *bytes.Buffer
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

// --- Persistence across restart -------------------------------------------

func TestEmit_PersistsLastHash_ResumeAfterRestart(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "chain.state")

	// First "boot": emit 3 events.
	var buf1 bytes.Buffer
	s1 := newState(&buf1, statePath)
	for i := 0; i < 3; i++ {
		s1.emit(sampleEvent(i))
	}
	boot1 := s1.bootID
	events1 := parseLines(t, &buf1)
	tailHash := events1[len(events1)-1].Hash

	// State file should now hold tailHash.
	persisted, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatalf("state file: %v", err)
	}
	if strings.TrimSpace(string(persisted)) != tailHash {
		t.Fatalf("state file = %q, want %q", string(persisted), tailHash)
	}

	// Second "boot": fresh state from same path. Emit 2 more events.
	var buf2 bytes.Buffer
	s2 := newState(&buf2, statePath)
	if s2.bootID == boot1 {
		t.Error("boot id should differ between newState invocations")
	}
	if s2.lastHash != tailHash {
		t.Errorf("after restart lastHash = %q, want %q", s2.lastHash, tailHash)
	}
	for i := 3; i < 5; i++ {
		s2.emit(sampleEvent(i))
	}
	events2 := parseLines(t, &buf2)

	// The cross-boot chain must validate when stitched together.
	full := append([]Event{}, events1...)
	full = append(full, events2...)
	ok, idx, why := VerifyChain(full, GenesisHash)
	if !ok {
		t.Fatalf("cross-boot chain broken at %d: %s", idx, why)
	}
}

func TestNewState_RejectsCorruptStateFile_StartsFromGenesis(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "chain.state")
	// Write garbage shorter than 64 chars.
	if err := os.WriteFile(statePath, []byte("not-a-hash"), 0o644); err != nil {
		t.Fatalf("seed corrupt state: %v", err)
	}
	var buf bytes.Buffer
	s := newState(&buf, statePath)
	if s.lastHash != GenesisHash {
		t.Errorf("corrupt state should fall back to genesis, got %q", s.lastHash)
	}
}

func TestNewState_MissingStateFileIsTreatedAsGenesis(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "does-not-exist", "chain.state")
	var buf bytes.Buffer
	s := newState(&buf, statePath)
	if s.lastHash != GenesisHash {
		t.Errorf("missing state should imply genesis, got %q", s.lastHash)
	}
}

// --- Atomic write -----------------------------------------------------------

func TestWriteChainStateAtomic_LeavesNoTmpFiles(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "chain.state")
	hash := strings.Repeat("a", 64)
	if err := writeChainStateAtomic(statePath, hash); err != nil {
		t.Fatalf("write: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".chain.") && strings.HasSuffix(e.Name(), ".tmp") {
			t.Errorf("leftover tmp file: %s", e.Name())
		}
	}
}
