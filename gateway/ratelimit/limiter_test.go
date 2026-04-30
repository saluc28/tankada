package ratelimit

import (
	"testing"
)

func TestAllowUnderThreshold(t *testing.T) {
	l := NewLimiter(5)
	for i := 0; i < 5; i++ {
		if !l.Allow("agent-1") {
			t.Fatalf("expected allow on call %d", i+1)
		}
	}
}

func TestDenyOnThresholdExceeded(t *testing.T) {
	l := NewLimiter(3)
	for i := 0; i < 3; i++ {
		l.Allow("agent-1")
	}
	if l.Allow("agent-1") {
		t.Fatal("expected deny after threshold exceeded")
	}
}

func TestAgentsAreIsolated(t *testing.T) {
	l := NewLimiter(2)
	l.Allow("agent-1")
	l.Allow("agent-1")
	// agent-1 is now at limit; agent-2 should still be allowed
	if !l.Allow("agent-2") {
		t.Fatal("agent-2 should not be affected by agent-1 limit")
	}
}

func TestWindowResetAllowsTraffic(t *testing.T) {
	l := NewLimiter(1)
	if !l.Allow("agent-1") {
		t.Fatal("first call should be allowed")
	}
	if l.Allow("agent-1") {
		t.Fatal("second call within window should be denied")
	}
	// Manually expire the window to simulate a new minute
	l.mu.Lock()
	l.windows["agent-1"].start = l.windows["agent-1"].start.Add(-windowDuration)
	l.mu.Unlock()
	if !l.Allow("agent-1") {
		t.Fatal("first call in new window should be allowed")
	}
}
