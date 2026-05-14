package ratelimit

import (
	"sync"
	"time"
)

const (
	windowDuration = time.Minute

	// janitorInterval is how often the background goroutine sweeps stale entries
	// out of the per-agent window map. Set to several windows so the cost stays
	// negligible relative to the request path; entries are kept around for a
	// couple of windows beyond their last use.
	janitorInterval = 5 * time.Minute

	// staleWindowAge is how old a window must be (relative to now) before the
	// janitor evicts it. Two window durations gives a quiet agent one full
	// idle minute before its bookkeeping is reclaimed, avoiding churn on
	// agents that go silent for short periods.
	staleWindowAge = 2 * windowDuration
)

type window struct {
	start time.Time
	count int
}

// Limiter is a fixed-window per-agent rate limiter.
// Each agent gets an independent 1-minute window; the counter resets when the window expires.
// A threshold of 0 disables the limiter (every call is allowed).
type Limiter struct {
	mu        sync.Mutex
	windows   map[string]*window
	threshold int
}

func NewLimiter(queriesPerMinute int) *Limiter {
	l := &Limiter{
		windows:   make(map[string]*window),
		threshold: queriesPerMinute,
	}
	go l.janitor()
	return l
}

func (l *Limiter) janitor() {
	ticker := time.NewTicker(janitorInterval)
	defer ticker.Stop()
	for range ticker.C {
		cutoff := time.Now().Add(-staleWindowAge)
		l.mu.Lock()
		for id, w := range l.windows {
			if w.start.Before(cutoff) {
				delete(l.windows, id)
			}
		}
		l.mu.Unlock()
	}
}

// Allow returns true if the agent is within its rate limit for the current window.
// Thread-safe. A threshold of 0 means rate limiting is disabled and every call returns true.
func (l *Limiter) Allow(agentID string) bool {
	if l.threshold == 0 {
		return true
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	w, ok := l.windows[agentID]
	if !ok || now.Sub(w.start) >= windowDuration {
		l.windows[agentID] = &window{start: now, count: 1}
		return true
	}
	w.count++
	return w.count <= l.threshold
}
