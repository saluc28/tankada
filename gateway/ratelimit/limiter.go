package ratelimit

import (
	"sync"
	"time"
)

const windowDuration = time.Minute

type window struct {
	start time.Time
	count int
}

// Limiter is a fixed-window per-agent rate limiter.
// Each agent gets an independent 1-minute window; the counter resets when the window expires.
type Limiter struct {
	mu        sync.Mutex
	windows   map[string]*window
	threshold int
}

func NewLimiter(queriesPerMinute int) *Limiter {
	return &Limiter{
		windows:   make(map[string]*window),
		threshold: queriesPerMinute,
	}
}

// Allow returns true if the agent is within its rate limit for the current window.
// Thread-safe.
func (l *Limiter) Allow(agentID string) bool {
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
